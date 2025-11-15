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
st.set_page_config(page_title="Bot-Focused Log Analyzer — SEO Actionables", layout="wide")
st.markdown("""
<style>
  body {background-color:#0f1117;color:#e8e8e8}
  .block-container{padding-top:1rem;}
  .stDownloadButton>button{background:#0b84ff}
</style>
""", unsafe_allow_html=True)
st.title("Bot-Focused Log Analyzer — SEO Actionables")

# -------------------------
# Utilities: encoding detection
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
# UA cleaning & dynamic detection (no fixed list required)
# -------------------------
# small canonical map for common well-known tokens (keeps UI tidy but is optional)
CANONICAL_UA_PATTERNS = [
    (r'chatgpt-user', 'ChatGPT-User/1.0'),
    (r'gptbot', 'GPTBot/1.0'),
    (r'googlebot', 'Googlebot/2.1'),
    (r'bingbot', 'Bingbot/2.0'),
    (r'perplexitybot', 'PerplexityBot/1.0'),
    (r'claude', 'ClaudeBot/1.0'),
]

BOT_SIGNALS = [r'bot', r'spider', r'crawler', r'fetch', r'scrap', r'preview', r'probe', r'index', r'validator', r'httpclient', r'curl', r'wget', r'python-requests']
AI_SIGNALS = [r'\bai\b', r'\bml\b', r'-user\b', r'-agent\b', r'assistant', r'language-model']

def clean_ua(raw: str) -> str:
    if not raw:
        return "-"
    # strip nonprintables and collapse whitespace
    s = "".join(ch if ch.isprintable() else " " for ch in raw)
    s = re.sub(r'\s+', ' ', s).strip()
    return s or "-"

def canonicalize_ua(cleaned_ua: str) -> str:
    low = cleaned_ua.lower()
    for pat, canon in CANONICAL_UA_PATTERNS:
        if re.search(pat, low):
            return canon
    return cleaned_ua  # fallback, dynamic

def detect_group_from_ua(cleaned_ua: str) -> str:
    low = cleaned_ua.lower()
    for p in AI_SIGNALS:
        if re.search(p, low):
            return "AI/LLM"
    for p in BOT_SIGNALS:
        if re.search(p, low):
            return "GenericBot"
    return "Other"

# -------------------------
# Request extraction (strict + relaxed)
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
# Start-of-entry detection (supports file:lineno:ip and plain ip)
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
# Streaming read util (choose encoding by sample)
# -------------------------
def stream_lines_from_uploaded(uploaded_file):
    try:
        uploaded_file.seek(0)
    except Exception:
        pass
    sample = uploaded_file.read(65536)
    if isinstance(sample, str):
        sample_bytes = sample.encode('utf-8', errors='replace')
    else:
        sample_bytes = sample or b''
    enc = detect_best_encoding(sample_bytes)
    try:
        uploaded_file.seek(0)
    except Exception:
        pass
    try:
        wrapper = io.TextIOWrapper(uploaded_file, encoding=enc, errors="replace")
        for line in wrapper:
            yield line.rstrip('\n').rstrip('\r')
    except Exception:
        # fallback: read all and split
        uploaded_file.seek(0)
        allb = uploaded_file.read()
        if isinstance(allb, bytes):
            text = allb.decode(enc, errors='replace')
        else:
            text = str(allb)
        for line in text.splitlines():
            yield line.rstrip('\n').rstrip('\r')

# -------------------------
# Parse single entry (after reconstruction)
# -------------------------
def parse_single_entry(entry: str) -> dict:
    m_start = START_INFO_RE.match(entry)
    file_src = m_start.group('file') if m_start and m_start.group('file') else "-"
    lineno = m_start.group('lineno') if m_start and m_start.group('lineno') else "-"
    client_ip = m_start.group('ip') if m_start and m_start.group('ip') else "-"

    m_time = re.search(r'\[([^\]]+)\]', entry)
    time_token = m_time.group(1) if m_time else "-"
    dt = parse_time_token(time_token)

    method, path = extract_request(entry)
    path_clean = "-"
    query_string = ""
    query_params = {}
    if path and path != "-":
        try:
            p = urlparse(unquote(path))
            path_clean = p.path or path
            query_string = p.query or ""
            query_params = dict(parse_qs(p.query)) if p.query else {}
        except Exception:
            path_clean = path

    m_status = re.search(r'\s(\d{3})\s+(-|\d+)', entry)
    status = m_status.group(1) if m_status else "-"
    bytes_sent = m_status.group(2) if m_status else "-"

    quoted = re.findall(r'"([^"]*)"', entry, flags=re.DOTALL)
    referer = quoted[1].strip() if len(quoted) >= 2 else "-"
    ua_raw = quoted[-1].strip() if quoted else "-"
    ua_cleaned = clean_ua(ua_raw)
    ua_canonical = canonicalize_ua(ua_cleaned)
    ua_group = detect_group_from_ua(ua_cleaned)

    is_static = bool(re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)(?:$|\?)', path_clean, re.I))
    section = path_clean.split('/')[1] if path_clean and path_clean.startswith('/') and len(path_clean.split('/')) > 1 else "-"

    hour_bucket = dt.replace(minute=0, second=0, microsecond=0) if dt else None
    sid_base = f"{client_ip}|{ua_cleaned}|{hour_bucket.isoformat() if hour_bucket else time_token}"
    session_id = hashlib.sha1(sid_base.encode('utf-8')).hexdigest()[:12]

    return {
        "File": file_src,
        "LineNo": lineno,
        "ClientIP": client_ip,
        "Time": dt,
        "Time_raw": time_token,
        "Method": method,
        "Path": path,
        "PathClean": path_clean,
        "Query": query_string,
        "QueryParams": query_params,
        "Status": status,
        "Bytes": bytes_sent,
        "Referer": referer,
        "User-Agent-Raw": ua_raw,
        "User-Agent": ua_canonical,
        "User-Agent-Clean": ua_cleaned,
        "UA-Group": ua_group,
        "IsStatic": is_static,
        "Section": section,
        "SessionID": session_id,
        "RawEntry": entry
    }

# -------------------------
# Parse a stream into reconstructed entries
# -------------------------
def parse_log_stream(lines):
    rows = []
    diag = {"total": 0, "parsed": 0, "failed": 0, "samples": []}
    buf = []
    for ln in lines:
        diag["total"] += 1
        if start_of_entry(ln):
            if buf:
                entry = " ".join(buf).strip()
                try:
                    r = parse_single_entry(entry)
                    rows.append(r)
                    diag["parsed"] += 1
                except Exception:
                    diag["failed"] += 1
                    if len(diag["samples"]) < 5:
                        diag["samples"].append(entry)
                buf = [ln]
            else:
                buf = [ln]
        else:
            if buf:
                buf.append(ln)
            else:
                # orphan line
                entry = ln.strip()
                try:
                    r = parse_single_entry(entry)
                    rows.append(r)
                    diag["parsed"] += 1
                except Exception:
                    diag["failed"] += 1
                    if len(diag["samples"]) < 5:
                        diag["samples"].append(entry)
    if buf:
        entry = " ".join(buf).strip()
        try:
            r = parse_single_entry(entry)
            rows.append(r)
            diag["parsed"] += 1
        except Exception:
            diag["failed"] += 1
            if len(diag["samples"]) < 5:
                diag["samples"].append(entry)
    return rows, diag

# -------------------------
# UI Controls
# -------------------------
st.sidebar.header("Upload / Options")
uploaded = st.sidebar.file_uploader("Upload per-bot log file (one bot per file recommended)", type=None)
top_n = st.sidebar.slider("Top N URLs", min_value=5, max_value=200, value=20)
exclude_dash = st.sidebar.checkbox("Exclude unknown '-' paths from top URLs", value=True)
only_dynamic = st.sidebar.checkbox("Only dynamic (exclude static) in charts", value=False)
show_failed = st.sidebar.checkbox("Show parse-failed samples", value=True)

if not uploaded:
    st.info("Upload a log file (per-bot split) to begin.")
    st.stop()

# -------------------------
# Parse file
# -------------------------
with st.spinner("Detecting encoding and parsing..."):
    # detect encoding for display in diagnostics
    try:
        uploaded.seek(0)
        sample = uploaded.read(65536)
        if isinstance(sample, str):
            sample_bytes = sample.encode('utf-8', errors='replace')
        else:
            sample_bytes = sample or b''
        chosen_enc = detect_best_encoding(sample_bytes)
    except Exception:
        chosen_enc = "utf-8"
    # rewind and parse streaming
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
c3.metric("Failed samples", f"{diag.get('failed',0):,}")
st.markdown(f"**Encoding chosen (heuristic):** `{chosen_enc}`")
if show_failed and diag.get("samples"):
    st.markdown("**Sample failed entries**")
    for s in diag["samples"]:
        st.code(s)

# -------------------------
# Executive KPIs
# -------------------------
total_hits = len(df)
unique_paths = df["PathClean"].nunique(dropna=True)
unique_ips = df["ClientIP"].nunique()
pct_success = round(((df['Status'].astype(str).str.startswith('2') | df['Status'].astype(str).str.startswith('3')).sum() / (total_hits or 1)) * 100, 1)

st.subheader("Executive summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total hits", f"{total_hits:,}")
c2.metric("Unique pages (PathClean)", f"{unique_paths:,}")
c3.metric("Unique IPs", f"{unique_ips:,}")
c4.metric("% 2xx/3xx", f"{pct_success}%")

# -------------------------
# Bot / UA group summary
# -------------------------
st.subheader("UA groups (dynamic + canonical)")
group_tab = df["UA-Group"].value_counts(dropna=False).reset_index()
group_tab.columns = ["Group","Hits"]
st.dataframe(group_tab, use_container_width=True, height=220)

# common canonical UAs (collapsed)
st.subheader("Top canonical User-Agents")
ua_tab = df["User-Agent"].fillna("-").value_counts().reset_index().head(30)
ua_tab.columns = ["Canonical UA","Hits"]
st.dataframe(ua_tab, use_container_width=True)

# -------------------------
# Top URLs and status distribution
# -------------------------
st.subheader("Top URLs (by hits)")
top_src = df if not exclude_dash else df[df["PathClean"] != "-"]
top_urls = top_src["PathClean"].value_counts().reset_index().head(top_n)
top_urls.columns = ["Path","Hits"]
st.dataframe(top_urls, use_container_width=True)

st.subheader("Status class distribution (by UA group)")
status_tab = df.groupby(["UA-Group","Status"]).size().reset_index(name="Count")
if not status_tab.empty:
    status_pivot = status_tab.pivot(index="UA-Group", columns="Status", values="Count").fillna(0).astype(int)
    st.dataframe(status_pivot, use_container_width=True)
else:
    st.info("No status data available.")

# -------------------------
# Section distribution (SEO view)
# -------------------------
st.subheader("Section distribution (where bots are crawling)")
sec = df["Section"].replace("", "-").fillna("-").value_counts().reset_index()
sec.columns = ["Section","Hits"]
st.dataframe(sec, use_container_width=True, height=220)

# -------------------------
# Pages with errors -> Actionable
# -------------------------
st.subheader("Actionables for SEO")
# pages with lots of errors (4xx/5xx)
err = df[df["Status"].astype(str).str.startswith(('4','5'))]
err_by_page = err.groupby("PathClean").agg(Errors=("Status","count"), ExampleStatus=("Status",lambda s: s.mode().iat[0] if not s.mode().empty else "-"), LastSeen=("Time","max")).reset_index().sort_values("Errors", ascending=False).head(50)
if not err_by_page.empty:
    st.markdown("**Pages with most 4xx/5xx errors (high priority)**")
    st.dataframe(err_by_page, use_container_width=True)
else:
    st.markdown("No 4xx/5xx errors found in parsed rows.")

# pages heavily crawled by bots (potentially crawl budget waste)
hits_by_page = df.groupby("PathClean").agg(Hits=("PathClean","size"), UniqueIPs=("ClientIP","nunique"), LastSeen=("Time","max")).reset_index().sort_values("Hits", ascending=False).head(50)
st.markdown("**Heavily crawled pages (top)**")
st.dataframe(hits_by_page, use_container_width=True)

# pages crawled by AI/LLM group specifically
ai_rows = df[df["UA-Group"] == "AI/LLM"]
if not ai_rows.empty:
    ai_by_page = ai_rows.groupby("PathClean").size().reset_index(name="AI_Hits").sort_values("AI_Hits", ascending=False).head(50)
    st.markdown("**Pages crawled by AI/LLM (inspect for content quality / metadata)**")
    st.dataframe(ai_by_page, use_container_width=True)
else:
    st.markdown("No AI/LLM-classified hits found.")

# -------------------------
# Crawl frequency per page (hits/day estimate)
# -------------------------
st.subheader("Crawl frequency (per page)")
if not df["Time"].isna().all():
    # compute days span and hits/day per page
    time_min = df["Time"].min()
    time_max = df["Time"].max()
    days = max(1.0, (time_max - time_min).total_seconds() / 86400.0) if time_min and time_max else 1.0
    freq = df.groupby("PathClean").size().reset_index(name="Hits")
    freq["HitsPerDay"] = (freq["Hits"] / days).round(2)
    freq_sorted = freq.sort_values("HitsPerDay", ascending=False).head(50)
    st.dataframe(freq_sorted, use_container_width=True)
else:
    st.info("No valid timestamps to compute frequency.")

# -------------------------
# Hourly distribution chart (valid times only)
# -------------------------
ts = df[df["Time"].notna()].copy()
if not ts.empty:
    ts["Hour"] = ts["Time"].dt.floor("H")
    agg = ts.groupby(["Hour","UA-Group"]).size().reset_index(name="Count")
    fig = px.area(agg, x="Hour", y="Count", color="UA-Group", title="Hourly Bot Activity")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No valid timestamps to render hourly chart.")

# -------------------------
# Top IPs & UA variants for forensic analysis
# -------------------------
st.subheader("Top Client IPs (possible crawler pools)")
top_ips = df["ClientIP"].value_counts().reset_index().head(200)
top_ips.columns = ["IP","Hits"]
st.dataframe(top_ips, use_container_width=True)

st.subheader("Top raw User-Agent strings (for manual review)")
top_uas = df["User-Agent-Raw"].fillna("-").value_counts().reset_index().head(50)
top_uas.columns = ["User-Agent (raw)","Count"]
st.dataframe(top_uas, use_container_width=True)

# -------------------------
# Sample rows for auditing
# -------------------------
st.subheader("Sample parsed rows (first 30)")
if not df.empty:
    st.code("\n\n".join(df["RawEntry"].head(30).tolist()))
else:
    st.info("No parsed rows to display.")

# -------------------------
# Exports
# -------------------------
st.subheader("Export")
csv = df.to_csv(index=False).encode("utf-8")
st.download_button("Download parsed CSV", csv, file_name="parsed_log.csv", mime="text/csv")

# small auto-generated findings summary (editable)
st.subheader("Auto-generated findings (editable)")
findings = (
    f"Total hits: {total_hits}\n"
    f"Unique pages: {unique_paths}\n"
    f"Unique IPs: {unique_ips}\n"
    f"% success (2xx/3xx): {pct_success}%\n\n"
    "Priority actionables (from above):\n"
    "- Fix top pages returning 4xx/5xx (see table)\n"
    "- Identify heavily crawled pages that waste crawl budget\n"
    "- Review pages crawled by AI/LLM for content & metadata quality\n"
    "- If you want, upload sitemap or GSC CSV to compute coverage and impressions (optional)\n"
)
st.text_area("Findings", value=findings, height=200)

# End of app
