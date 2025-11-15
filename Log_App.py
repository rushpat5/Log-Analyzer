# app.py
import streamlit as st
import pandas as pd
import re
import io
import hashlib
from datetime import datetime
from dateutil import parser as dtparser
from urllib.parse import urlparse, parse_qs, unquote
import plotly.express as px
import string

# -------------------------
# Page config
# -------------------------
st.set_page_config(page_title="SFLA — Screaming-Frog-like Log Analyzer", layout="wide")
st.markdown("""
<style>
  body {background:#0f1117;color:#e8e8e8}
  .block-container{padding-top:1rem}
  .stDownloadButton>button{background:#0b84ff}
</style>
""", unsafe_allow_html=True)
st.title("SFLA — Screaming-Frog-style Log Analyzer (Bot & SEO)")

# -------------------------
# Encoding detection (heuristic)
# -------------------------
def score_decoding(b: bytes, enc: str) -> float:
    try:
        s = b.decode(enc, errors="replace")
    except Exception:
        return -1.0
    if not s:
        return -1.0
    printable = set(string.printable)
    good = sum(1 for ch in s if ch in printable)
    return good / max(1, len(s))

def detect_best_encoding(sample: bytes, candidates=("utf-8","utf-16","latin-1","cp1252")) -> str:
    best, best_score = None, -1.0
    for e in candidates:
        sc = score_decoding(sample, e)
        if sc > best_score:
            best_score, best = sc, e
    return best or "utf-8"

# -------------------------
# UA cleaning and dynamic detection
# -------------------------
CANONICAL_UA_PATTERNS = [
    (r'chatgpt-user', 'ChatGPT-User/1.0'),
    (r'gptbot', 'GPTBot/1.0'),
    (r'googlebot', 'Googlebot/2.1'),
    (r'bingbot', 'Bingbot/2.0'),
]

BOT_SIGNALS = [r'bot', r'spider', r'crawler', r'fetch', r'scrap', r'preview', r'probe', r'index', r'validator', r'curl', r'wget']
AI_SIGNALS = [r'\bai\b', r'\bml\b', r'-user\b', r'-agent\b', r'assistant']

def clean_ua(raw: str) -> str:
    if not raw:
        return "-"
    s = "".join(ch if ch.isprintable() else " " for ch in raw)
    s = re.sub(r'\s+', ' ', s).strip()
    return s or "-"

def canonicalize_ua(cleaned: str) -> str:
    low = (cleaned or "").lower()
    for pat, canon in CANONICAL_UA_PATTERNS:
        if re.search(pat, low):
            return canon
    return cleaned

def detect_group(cleaned: str) -> str:
    low = (cleaned or "").lower()
    for p in AI_SIGNALS:
        if re.search(p, low):
            return "AI/LLM"
    for p in BOT_SIGNALS:
        if re.search(p, low):
            return "GenericBot"
    return "Other"

# -------------------------
# Request extraction
# -------------------------
REQ_STRICT = re.compile(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s"]+)(?:\s+HTTP/\d\.\d)?"', re.I)
REQ_RELAX = re.compile(r'(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(/[^ \t\n\r"]+)', re.I)

def extract_request(entry: str):
    m = REQ_STRICT.search(entry)
    if m:
        return m.group(1), m.group(2)
    m2 = REQ_RELAX.search(entry)
    if m2:
        return m2.group(1), m2.group(2)
    return "-", "-"

# -------------------------
# Time parsing
# -------------------------
def parse_time_token(ts: str):
    if not ts or ts.strip() in ("-", ""):
        return None
    try:
        return dtparser.parse(ts)
    except Exception:
        try:
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            try:
                return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
            except Exception:
                return None

# -------------------------
# Start detection (filename:lineno:IP or IP)
# -------------------------
START_INFO_RE = re.compile(r'^(?:(?P<file>[^:\s]+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s')

def start_of_entry(line: str) -> bool:
    if not line:
        return False
    if START_INFO_RE.match(line):
        return True
    if line.startswith('[') and re.search(r'\d{1,2}/[A-Za-z]{3}/\d{4}', line):
        return True
    return False

# -------------------------
# Streaming reader
# -------------------------
def stream_lines_from_uploaded(f):
    try:
        f.seek(0)
    except Exception:
        pass
    sample = f.read(65536)
    sample_bytes = sample.encode('utf-8', errors='replace') if isinstance(sample, str) else (sample or b'')
    enc = detect_best_encoding(sample_bytes)
    try:
        f.seek(0)
    except Exception:
        pass
    try:
        wrapper = io.TextIOWrapper(f, encoding=enc, errors='replace')
        for line in wrapper:
            yield line.rstrip('\n').rstrip('\r')
    except Exception:
        f.seek(0)
        allb = f.read()
        text = allb.decode(enc, errors='replace') if isinstance(allb, bytes) else str(allb)
        for line in text.splitlines():
            yield line.rstrip('\n').rstrip('\r')

# -------------------------
# Parse single entry
# -------------------------
def parse_single_entry(entry: str):
    m_start = START_INFO_RE.match(entry)
    file_src = m_start.group('file') if m_start and m_start.group('file') else "-"
    lineno = m_start.group('lineno') if m_start and m_start.group('lineno') else "-"
    client_ip = m_start.group('ip') if m_start and m_start.group('ip') else "-"

    m_time = re.search(r'\[([^\]]+)\]', entry)
    time_tok = m_time.group(1) if m_time else "-"
    dt = parse_time_token(time_tok)

    method, path = extract_request(entry)
    path_clean = "-"
    query = ""
    query_params = {}
    if path and path != "-":
        try:
            p = urlparse(unquote(path))
            path_clean = p.path or path
            query = p.query or ""
            query_params = dict(parse_qs(p.query)) if p.query else {}
        except Exception:
            path_clean = path

    m_status = re.search(r'\s(\d{3})\s+(-|\d+)', entry)
    status = m_status.group(1) if m_status else "-"
    bytes_sent = m_status.group(2) if m_status else "-"

    quoted = re.findall(r'"([^"]*)"', entry, flags=re.DOTALL)
    referer = quoted[1].strip() if len(quoted) >= 2 else "-"
    ua_raw = quoted[-1].strip() if quoted else "-"
    ua_clean = clean_ua(ua_raw)
    ua_canon = canonicalize_ua(ua_clean)
    ua_group = detect_group(ua_clean)

    is_static = bool(re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)(?:$|\?)', path_clean, re.I))
    section = path_clean.split('/')[1] if path_clean and path_clean.startswith('/') and len(path_clean.split('/')) > 1 else "-"

    hour_bucket = dt.replace(minute=0, second=0, microsecond=0) if dt else None
    sid = hashlib.sha1(f"{client_ip}|{ua_clean}|{hour_bucket.isoformat() if hour_bucket else time_tok}".encode()).hexdigest()[:12]

    return {
        "File": file_src,
        "LineNo": lineno,
        "ClientIP": client_ip,
        "Time": dt,
        "Time_raw": time_tok,
        "Method": method,
        "Path": path,
        "PathClean": path_clean,
        "Query": query,
        "QueryParams": query_params,
        "Status": status,
        "Bytes": bytes_sent,
        "Referer": referer,
        "User-Agent-Raw": ua_raw,
        "User-Agent": ua_canon,
        "User-Agent-Clean": ua_clean,
        "UA-Group": ua_group,
        "IsStatic": is_static,
        "Section": section,
        "SessionID": sid,
        "RawEntry": entry
    }

# -------------------------
# Parse log stream (reconstruct multi-line)
# -------------------------
def parse_log_stream(lines):
    rows = []
    diag = {"total": 0, "parsed": 0, "failed": 0, "samples": []}
    buf = []
    for ln in lines:
        diag["total"] += 1
        if start_of_entry(ln):
            if buf:
                ent = " ".join(buf).strip()
                try:
                    r = parse_single_entry(ent)
                    rows.append(r)
                    diag["parsed"] += 1
                except Exception:
                    diag["failed"] += 1
                    if len(diag["samples"]) < 5:
                        diag["samples"].append(ent)
                buf = [ln]
            else:
                buf = [ln]
        else:
            if buf:
                buf.append(ln)
            else:
                ent = ln.strip()
                try:
                    r = parse_single_entry(ent)
                    rows.append(r)
                    diag["parsed"] += 1
                except Exception:
                    diag["failed"] += 1
                    if len(diag["samples"]) < 5:
                        diag["samples"].append(ent)
    if buf:
        ent = " ".join(buf).strip()
        try:
            r = parse_single_entry(ent)
            rows.append(r)
            diag["parsed"] += 1
        except Exception:
            diag["failed"] += 1
            if len(diag["samples"]) < 5:
                diag["samples"].append(ent)
    return rows, diag

# -------------------------
# UI controls
# -------------------------
st.sidebar.header("Upload / Options")
uploaded = st.sidebar.file_uploader("Upload per-bot log file (one bot per file recommended)", type=None)
if not uploaded:
    st.info("Upload a per-bot log file (example: access239.log:... lines).")
    st.stop()

top_n = st.sidebar.slider("Top N", 5, 200, 20)
exclude_dash = st.sidebar.checkbox("Exclude unknown '-' paths from top lists", value=True)
only_dynamic = st.sidebar.checkbox("Exclude static assets in charts", value=False)
show_failed = st.sidebar.checkbox("Show parse-failed samples", value=True)

# -------------------------
# Parse file
# -------------------------
with st.spinner("Detecting encoding & parsing..."):
    try:
        uploaded.seek(0)
    except Exception:
        pass
    # detect encoding for diagnostics
    sample = uploaded.read(65536)
    sample_bytes = sample.encode('utf-8', errors='replace') if isinstance(sample, str) else (sample or b'')
    chosen_enc = detect_best_encoding(sample_bytes)
    try:
        uploaded.seek(0)
    except Exception:
        pass
    lines = stream_lines_from_uploaded(uploaded)
    rows, diag = parse_log_stream(lines)

df = pd.DataFrame(rows)
df["Time"] = pd.to_datetime(df["Time"], errors="coerce")

# -------------------------
# Diagnostics
# -------------------------
st.subheader("Parsing diagnostics")
c1, c2, c3 = st.columns(3)
c1.metric("Lines processed", f"{diag.get('total',0):,}")
c2.metric("Parsed entries", f"{diag.get('parsed',0):,}")
c3.metric("Failed parsings", f"{diag.get('failed',0):,}")
st.markdown(f"**Encoding (heuristic):** `{chosen_enc}`")
if show_failed and diag.get("samples"):
    st.markdown("Sample failed entries")
    for s in diag["samples"]:
        st.code(s)

# -------------------------
# Overview KPIs (Screaming Frog style)
# -------------------------
total_hits = len(df)
unique_urls = df["PathClean"].nunique(dropna=True)
unique_pages = df[df["IsStatic"]==False]["PathClean"].nunique(dropna=True) if "IsStatic" in df.columns else unique_urls
unique_ips = df["ClientIP"].nunique()
avg_bytes = int(df["Bytes"].replace("-",0).astype(int).mean()) if not df.empty and (df["Bytes"] != "-").any() else 0
pct_success = round(((df['Status'].astype(str).str.startswith('2') | df['Status'].astype(str).str.startswith('3')).sum() / (total_hits or 1)) * 100, 1)

st.subheader("Overview")
c1,c2,c3,c4,c5 = st.columns(5)
c1.metric("Total requests", f"{total_hits:,}")
c2.metric("Unique URLs", f"{unique_urls:,}")
c3.metric("Unique pages (non-static)", f"{unique_pages:,}")
c4.metric("Unique IPs", f"{unique_ips:,}")
c5.metric("Avg bytes", f"{avg_bytes:,}")

# -------------------------
# Response codes (table + chart)
# -------------------------
st.subheader("Response Codes")
if not df.empty:
    resp = df['Status'].replace("-", pd.NA).fillna("unknown").value_counts().reset_index()
    resp.columns = ['Status','Count']
    st.dataframe(resp, use_container_width=True)
    fig = px.bar(resp, x='Status', y='Count', title="Response Codes")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No parsed rows for response codes.")

# -------------------------
# Redirects and error pages (SEO)
# -------------------------
st.subheader("Redirect chains & errors (SEO focus)")
reds = df[df["Status"].astype(str).str.startswith('3')]
errors_4xx = df[df["Status"].astype(str).str.startswith('4')]
errors_5xx = df[df["Status"].astype(str).str.startswith('5')]

st.markdown("**Top redirects (3xx)**")
if not reds.empty:
    st.dataframe(reds.groupby("PathClean").size().reset_index(name="Count").sort_values("Count", ascending=False).head(top_n), use_container_width=True)
else:
    st.write("No 3xx found")

st.markdown("**Top client errors (4xx)**")
if not errors_4xx.empty:
    st.dataframe(errors_4xx.groupby("PathClean").size().reset_index(name="Count").sort_values("Count", ascending=False).head(top_n), use_container_width=True)
else:
    st.write("No 4xx found")

st.markdown("**Top server errors (5xx)**")
if not errors_5xx.empty:
    st.dataframe(errors_5xx.groupby("PathClean").size().reset_index(name="Count").sort_values("Count", ascending=False).head(top_n), use_container_width=True)
else:
    st.write("No 5xx found")

# -------------------------
# Top URLs & crawl depth
# -------------------------
st.subheader("Top URLs / Crawl depth")
top_src = df if not exclude_dash else df[df["PathClean"] != "-"]
top_urls = top_src["PathClean"].value_counts().reset_index().head(top_n)
top_urls.columns = ["Path","Hits"]
st.dataframe(top_urls, use_container_width=True)

# Crawl depth
depth_counts = top_src["PathClean"].fillna("-").apply(lambda p: len([seg for seg in str(p).split('/') if seg])) \
               .value_counts().reset_index().sort_values("index")
depth_counts.columns = ["Depth","Count"]
st.markdown("Crawl depth distribution (number of path segments)")
st.dataframe(depth_counts, use_container_width=True)

# -------------------------
# Section distribution (useful for SEO)
# -------------------------
st.subheader("Section distribution")
sections = df["Section"].replace("", "-").fillna("-").value_counts().reset_index()
sections.columns = ["Section","Hits"]
st.dataframe(sections, use_container_width=True, height=220)

# -------------------------
# Hourly heatmap (crawl activity)
# -------------------------
st.subheader("Hourly crawl heatmap")
ts = df[df["Time"].notna()].copy()
if not ts.empty:
    ts["Hour"] = ts["Time"].dt.floor("H")
    agg = ts.groupby(["Hour"]).size().reset_index(name="Count")
    fig = px.bar(agg, x="Hour", y="Count", title="Hits per hour")
    st.plotly_chart(fig, use_container_width=True)
    # optional heatmap by hour vs section
    heat = ts.copy()
    heat['HourStr'] = heat['Time'].dt.strftime('%Y-%m-%d %H:00')
    heat_agg = heat.groupby(['HourStr','Section']).size().reset_index(name='Count').pivot(index='Section', columns='HourStr', values='Count').fillna(0)
    st.markdown("Hourly by section (heatmap)")
    st.dataframe(heat_agg, use_container_width=True, height=300)
else:
    st.info("No timestamps to produce hourly charts.")

# -------------------------
# User-agents and IPs
# -------------------------
st.subheader("Top User-Agents (canonical) and top raw UA strings")
ua_canonical = df["User-Agent"].fillna("-").value_counts().reset_index().head(50)
ua_canonical.columns = ["User-Agent (canonical)","Count"]
st.dataframe(ua_canonical, use_container_width=True)

ua_raw = df["User-Agent-Raw"].fillna("-").value_counts().reset_index().head(50)
ua_raw.columns = ["User-Agent (raw)","Count"]
st.dataframe(ua_raw, use_container_width=True)

st.subheader("Top Client IPs")
top_ips = df["ClientIP"].value_counts().reset_index().head(200)
top_ips.columns = ["IP","Hits"]
st.dataframe(top_ips, use_container_width=True)

# -------------------------
# Crawl frequency and hits per page (estimate)
# -------------------------
st.subheader("Crawl frequency & hits/day per page")
if not df["Time"].isna().all():
    tmin = df["Time"].min()
    tmax = df["Time"].max()
    days = max(1.0, (tmax - tmin).total_seconds() / 86400.0) if tmin and tmax else 1.0
    freq = df.groupby("PathClean").size().reset_index(name="Hits")
    freq["HitsPerDay"] = (freq["Hits"]/days).round(2)
    st.dataframe(freq.sort_values("HitsPerDay", ascending=False).head(100), use_container_width=True)
else:
    st.info("No timestamps to compute frequency.")

# -------------------------
# SEO actionables (concise)
# -------------------------
st.subheader("SEO Actionables (log-only)")
actions = []
if not errors_4xx.empty:
    actions.append(f"{len(errors_4xx['PathClean'].unique())} pages returned 4xx — check canonicalization & internal links.")
if not errors_5xx.empty:
    actions.append(f"{len(errors_5xx['PathClean'].unique())} pages returned 5xx — server issue priority.")
if not reds.empty:
    actions.append(f"{reds.shape[0]} redirect hits — check redirect chains and canonical URLs.")
heavy = top_src["PathClean"].value_counts().head(20)
actions.append(f"Top heavily crawled pages (top 20) — consider robots/x-robots-tag if not useful.")
if not df[df["UA-Group"]=="AI/LLM"].empty:
    actions.append("AI/LLM crawlers seen — review content meta & structured data for quality & copyright concerns.")
if not actions:
    actions.append("No immediate actionable issues detected from logs.")

for a in actions:
    st.markdown(f"- {a}")

# -------------------------
# Sample rows & export
# -------------------------
st.subheader("Sample parsed rows (first 30)")
if not df.empty:
    st.code("\n\n".join(df["RawEntry"].head(30).tolist()))
else:
    st.info("No parsed rows.")

st.subheader("Export")
csv = df.to_csv(index=False).encode('utf-8')
st.download_button("Download parsed CSV", csv, "parsed_log.csv", "text/csv")

# End app
