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

st.set_page_config(page_title="Robust Log Analyzer", layout="wide")
st.title("Robust Log Analyzer — Encoding-safe, resilient parsing, diagnostics")

# -------------------------
# Utilities: encoding detection by scoring printable ratio
# -------------------------
def score_decoding(b: bytes, enc: str) -> float:
    try:
        s = b.decode(enc, errors="replace")
    except Exception:
        return -1.0
    if not s:
        return -1.0
    # ratio of printable (including common whitespace) to total
    printable = set(string.printable)
    good = sum(1 for ch in s if ch in printable)
    return good / max(1, len(s))

def detect_best_encoding(sample: bytes, candidates=("utf-8","utf-16","latin-1","cp1252")) -> str:
    best = None
    best_score = -1.0
    for enc in candidates:
        sc = score_decoding(sample, enc)
        if sc > best_score:
            best_score = sc
            best = enc
    # fallback
    return best or "utf-8"

# -------------------------
# Clean UA to remove unprintable characters and collapse whitespace
# -------------------------
def clean_ua(raw: str) -> str:
    if raw is None:
        return "-"
    # remove control characters
    s = "".join(ch if ch.isprintable() else " " for ch in raw)
    # collapse whitespace
    s = re.sub(r'\s+', ' ', s).strip()
    if not s:
        return "-"
    return s

# -------------------------
# Dynamic classification (no predefined vendor list)
# -------------------------
BOT_CORE_PATTERNS = [r"bot", r"spider", r"crawler", r"fetch", r"scrap", r"preview", r"monitor", r"probe", r"index", r"validator", r"httpclient", r"curl", r"wget", r"python-requests"]
AI_LLM_PATTERNS = [r"\bai\b", r"\bml\b", r"-user\b", r"-agent\b", r"assistant", r"language-model"]

def classify_ua_dynamic(ua_raw: str):
    if not ua_raw or ua_raw.strip() in ("-", ""):
        return "Unknown"
    ua = ua_raw.lower()
    for p in AI_LLM_PATTERNS:
        if re.search(p, ua):
            return "AI/LLM"
    for p in BOT_CORE_PATTERNS:
        if re.search(p, ua):
            return "Bot"
    return "Other"

# -------------------------
# Request extraction: strict then relaxed fallbacks
# -------------------------
REQ_STRICT = re.compile(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s"]+)(?:\s+HTTP/\d\.\d)?"', re.I)
REQ_RELAX = re.compile(r'(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(/[^ \t\n\r"]+)', re.I)
REQ_WITHOUT_QUOTES = re.compile(r'([A-Z]{3,7})\s+(/[^ \t"]+)', re.I)

def extract_request(entry: str):
    m = REQ_STRICT.search(entry)
    if m:
        return m.group(1), m.group(2)
    m = REQ_RELAX.search(entry)
    if m:
        return m.group(1), m.group(2)
    m = REQ_WITHOUT_QUOTES.search(entry)
    if m:
        return m.group(1), m.group(2)
    return "-", "-"

# -------------------------
# Time parsing with safe fallbacks
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
# Start-of-entry detection: accepts file:lineno:ip and plain ip lines
# -------------------------
START_INFO_RE = re.compile(r'^(?:(?P<file>[^:\s]+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s')

def start_of_entry(line: str) -> bool:
    if not line:
        return False
    if START_INFO_RE.match(line):
        return True
    if line.startswith('[') and re.search(r'\d{1,2}/[A-Za-z]{3}/\d{4}', line):
        return True
    if re.match(r'^\d', line):
        return True
    return False

# -------------------------
# Stream lines from uploaded file with robust encoding selection
# -------------------------
def stream_lines_from_uploaded(uploaded_file):
    # read a sample bytes to detect encoding
    try:
        pos = uploaded_file.tell()
    except Exception:
        pos = None
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
    # rewind and create TextIOWrapper for streaming
    try:
        uploaded_file.seek(0)
    except Exception:
        pass
    # If uploaded_file provides bytes-like chunks, TextIOWrapper works; otherwise fallback to reading full bytes and splitting
    try:
        wrapper = io.TextIOWrapper(uploaded_file, encoding=enc, errors="replace")
        for line in wrapper:
            yield line.rstrip("\n").rstrip("\r")
    except Exception:
        # fallback: read entire file (last resort)
        try:
            uploaded_file.seek(0)
            raw = uploaded_file.read()
            if isinstance(raw, bytes):
                text = raw.decode(enc, errors="replace")
            else:
                text = str(raw)
            for line in text.splitlines():
                yield line.rstrip("\n").rstrip("\r")
        except Exception:
            return

# -------------------------
# Parse single reconstructed entry
# -------------------------
def parse_single_entry(entry: str):
    m_start = START_INFO_RE.match(entry)
    file_src = m_start.group('file') if m_start and m_start.group('file') else "-"
    lineno = m_start.group('lineno') if m_start and m_start.group('lineno') else "-"
    client_ip = m_start.group('ip') if m_start and m_start.group('ip') else "-"

    # timestamp
    m_time = re.search(r'\[([^\]]+)\]', entry)
    time_token = m_time.group(1) if m_time else "-"
    dt = parse_time_token(time_token)

    # request
    method, path = extract_request(entry)
    path_clean = "-"
    query_string = ""
    query_params = {}
    if path and path != "-":
        try:
            parsed = urlparse(unquote(path))
            path_clean = parsed.path or path
            query_string = parsed.query or ""
            query_params = dict(parse_qs(parsed.query)) if parsed.query else {}
        except Exception:
            path_clean = path

    # status/bytes
    m_status = re.search(r'\s(\d{3})\s+(-|\d+)', entry)
    status = m_status.group(1) if m_status else "-"
    bytes_sent = m_status.group(2) if m_status else "-"

    # quoted parts
    quoted = re.findall(r'"([^"]*)"', entry, flags=re.DOTALL)
    referer = quoted[1].strip() if len(quoted) >= 2 else "-"
    ua_raw = quoted[-1].strip() if quoted else "-"
    ua_cleaned = clean_ua(ua_raw)
    ua_group = classify_ua_dynamic(ua_cleaned)

    is_static = bool(re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)(?:$|\?)', path_clean, re.I))
    is_mobile = bool(re.search(r'\b(Mobile|iPhone|Android)\b', ua_raw, re.I))
    section = path_clean.split('/')[1] if path_clean and path_clean.startswith('/') and len(path_clean.split('/')) > 1 else "-"

    # session heuristic
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
        "User-Agent": ua_cleaned,
        "UA-Group": ua_group,
        "IsStatic": is_static,
        "IsMobile": is_mobile,
        "Section": section,
        "SessionID": session_id,
        "RawEntry": entry
    }

# -------------------------
# parse log stream into rows handling multi-line entries
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
                # orphan line - attempt parse
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
# UI Controls
# -------------------------
st.sidebar.header("Upload / Options")
uploaded_file = st.sidebar.file_uploader("Upload per-bot log file (recommended <=200MB)", type=None)
top_n = st.sidebar.slider("Top N URLs", 5, 200, 20)
exclude_dash = st.sidebar.checkbox("Exclude unknown '-' paths from Top URLs", value=True)
dynamic_detection_only = st.sidebar.checkbox("Show only 'Bot' and 'AI/LLM' groups in charts", value=False)

if not uploaded_file:
    st.info("Upload a log file to begin.")
    st.stop()

# -------------------------
# Parse streaming with chosen encoding detection
# -------------------------
with st.spinner("Detecting encoding and parsing (streaming)..."):
    try:
        lines = stream_lines_from_uploaded(uploaded_file)
        rows, diag = parse_log_stream(lines)
    except Exception as e:
        st.error(f"Parsing failed: {e}")
        raise

df = pd.DataFrame(rows)

# convert times safely
df["Time"] = pd.to_datetime(df["Time"], errors="coerce")

# show encoding diagnostic (best-effort): we re-run detect on first sample bytes to show choice
try:
    uploaded_file.seek(0)
    sample = uploaded_file.read(65536)
    if isinstance(sample, str):
        sample_bytes = sample.encode('utf-8', errors='replace')
    else:
        sample_bytes = sample or b''
    chosen_enc = detect_best_encoding(sample_bytes)
except Exception:
    chosen_enc = "unknown"

# -------------------------
# Diagnostics panel
# -------------------------
st.subheader("Parsing diagnostics")
c1, c2, c3 = st.columns(3)
c1.metric("Lines processed", f"{diag.get('total',0):,}")
c2.metric("Parsed entries", f"{diag.get('parsed',0):,}")
c3.metric("Failed parse samples", f"{diag.get('failed',0):,}")
st.markdown(f"**Encoding chosen (heuristic):** `{chosen_enc}`")
if diag.get("samples"):
    st.markdown("**Sample failed entries (first 5)**")
    for s in diag["samples"]:
        st.code(s)

# -------------------------
# Executive summary
# -------------------------
total_hits = len(df)
unique_paths = df["PathClean"].nunique(dropna=True)
unique_ips = df["ClientIP"].nunique()

st.subheader("Executive Summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total hits", f"{total_hits:,}")
c2.metric("Unique paths (PathClean)", f"{unique_paths:,}")
c3.metric("Unique IPs", f"{unique_ips:,}")
pct_success = round(((df['Status'].astype(str).str.startswith('2') | df['Status'].astype(str).str.startswith('3')).sum() / (total_hits or 1)) * 100, 1)
c4.metric("% 2xx/3xx", f"{pct_success}%")

# -------------------------
# Groups summary
# -------------------------
st.subheader("UA Groups (dynamic detection)")
group_counts = df["UA-Group"].value_counts(dropna=False).reset_index()
group_counts.columns = ["Group", "Hits"]
st.dataframe(group_counts, use_container_width=True, height=220)

# -------------------------
# Filters and time-series (only use valid timestamps for series)
# -------------------------
dff = df.copy()
if dynamic_detection_only:
    dff = dff[dff["UA-Group"].isin(["Bot","AI/LLM"])]

# time series
ts = dff[dff["Time"].notna()].copy()
if not ts.empty:
    ts["Hour"] = ts["Time"].dt.floor("H")
    ts_agg = ts.groupby(["Hour","UA-Group"]).size().reset_index(name="Count")
    st.subheader("Hourly distribution (rows with valid timestamps)")
    fig = px.area(ts_agg, x="Hour", y="Count", color="UA-Group", title="Hits by Hour")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No valid timestamps to build time-series. See diagnostics.")

# -------------------------
# Top URLs (exclude '-' optionally)
# -------------------------
st.subheader("Top URLs")
valid_for_top = dff if not exclude_dash else dff[dff["PathClean"] != "-"]
top = valid_for_top["PathClean"].value_counts().reset_index().head(top_n)
top.columns = ["Path", "Hits"]
st.dataframe(top, use_container_width=True)

# -------------------------
# UA variants and top IPs
# -------------------------
st.subheader("Top User-Agents (raw)")
ua_tab = dff["User-Agent-Raw"].fillna("-").value_counts().reset_index().head(50)
ua_tab.columns = ["User-Agent", "Count"]
st.dataframe(ua_tab, use_container_width=True)

st.subheader("Top Client IPs")
ip_tab = dff["ClientIP"].value_counts().reset_index().head(200)
ip_tab.columns = ["IP", "Count"]
st.dataframe(ip_tab, use_container_width=True)

# -------------------------
# Sample raw rows for inspection
# -------------------------
st.subheader("Sample Raw Parsed Entries (first 30)")
if not df.empty:
    st.code("\n\n".join(df["RawEntry"].head(30).tolist()))
else:
    st.info("No parsed entries to display.")

# -------------------------
# Export
# -------------------------
st.subheader("Export")
csv_bytes = dff.to_csv(index=False).encode("utf-8")
st.download_button("Download filtered CSV", csv_bytes, file_name="parsed_log.csv", mime="text/csv")
