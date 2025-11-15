import streamlit as st
import pandas as pd
import re
import io
from datetime import datetime
from dateutil import parser as dtparser
from urllib.parse import urlparse, unquote
import plotly.express as px

st.set_page_config(page_title="Bot-Focused Log Analyzer — Robust", layout="wide")
st.title("Bot-Focused Log Analyzer — Robust & Diagnostic")

# -----------------------
# Canonical UA mapping
# -----------------------
BOT_MAP = {
    r"chatgpt-user": "ChatGPT-User/1.0",
    r"gptbot": "GPTBot/1.0",
    r"perplexitybot": "PerplexityBot/1.0",
    r"claude-user": "Claude-User/1.0",
    r"claudebot": "ClaudeBot/1.0",
    r"googlebot": "Googlebot/2.1",
    r"bingbot": "Bingbot/2.0",
    r"bingpreview": "BingPreview/1.0",
    r"ahrefsbot": "AhrefsBot/1.0",
    r"semrushbot": "SemrushBot/1.0",
    r"mj12bot": "MJ12Bot/1.0",
}

def normalize_ua(raw):
    if not raw or raw.strip() == "-" or raw.strip() == "":
        return "UnknownBot/1.0"
    ua = raw.lower().strip()
    # remove common appended tokens & artifacts
    ua = re.sub(r",?\s*(gzip|gfe|gzip\(gfe\)|bot\.html|bot\.htm|;\s*+$)", "", ua, flags=re.I)
    # if multiple comma-separated parts, pick the one that contains a known token (prefer first meaningful)
    parts = [p.strip() for p in re.split(r'\s*,\s*', ua) if p.strip()]
    for p in parts:
        for pat, norm in BOT_MAP.items():
            if re.search(pat, p, re.I):
                return norm
    # try whole ua
    for pat, norm in BOT_MAP.items():
        if re.search(pat, ua, re.I):
            return norm
    # fallback: return first 80 chars as label
    return raw.strip()[:80]

def classify_group(norm):
    nl = norm.lower()
    if "googlebot" in nl:
        return "Google"
    if "bing" in nl:
        return "Bing"
    if any(k in nl for k in ["chatgpt", "gptbot", "claude", "perplexity"]):
        return "AI/LLM"
    return "Other"

# -----------------------
# Request extraction
# -----------------------
REQUEST_RE = re.compile(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s"]+)(?:\s+HTTP/\d\.\d)?"', re.I)
# relaxed fallback: find method and path without requiring closing quote
RELAXED_REQUEST_RE = re.compile(r'(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(/[^ \t\n\r"]+)', re.I)

def extract_request(entry):
    m = REQUEST_RE.search(entry)
    if m:
        return m.group(1), m.group(2)
    m2 = RELAXED_REQUEST_RE.search(entry)
    if m2:
        return m2.group(1), m2.group(2)
    return "-", "-"

# -----------------------
# Time parsing
# -----------------------
def parse_time_str(ts):
    if not ts or ts.strip() in ("-", ""):
        return None
    try:
        return dtparser.parse(ts)
    except Exception:
        try:
            # try common format fallback
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            try:
                return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
            except Exception:
                return None

# -----------------------
# Start-of-entry detection
# Accept either:
#   ip ...
# or file:lineno:ip ...
# -----------------------
START_INFO_RE = re.compile(r'^(?:(?P<file>[^:\s]+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s')

def start_of_entry(line):
    if not line:
        return False
    if START_INFO_RE.match(line):
        return True
    # fallback: if line begins with [dd/Mon/YYYY: or numeric date stamp
    if line.startswith('[') and re.search(r'\d{1,2}/[A-Za-z]{3}/\d{4}', line):
        return True
    if re.match(r'^\d', line):
        return True
    return False

# -----------------------
# Streaming read of uploaded file (no full read)
# -----------------------
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
    enc = "utf-8"
    for e in ("utf-8", "utf-16", "latin-1"):
        try:
            sample_bytes.decode(e)
            enc = e
            break
        except Exception:
            pass
    try:
        uploaded_file.seek(0)
    except Exception:
        pass
    wrapper = io.TextIOWrapper(uploaded_file, encoding=enc, errors="replace")
    for raw in wrapper:
        yield raw.rstrip("\n").rstrip("\r")

# -----------------------
# Parse a single reconstructed entry
# -----------------------
def parse_single_entry(entry):
    # file/lineno/ip
    m_start = START_INFO_RE.match(entry)
    file_src = m_start.group('file') if m_start and m_start.group('file') else "-"
    lineno = m_start.group('lineno') if m_start and m_start.group('lineno') else ""
    client_ip = m_start.group('ip') if m_start and m_start.group('ip') else "-"

    # time inside []
    m_time = re.search(r'\[([^\]]+)\]', entry)
    time_str = m_time.group(1) if m_time else "-"
    dt = parse_time_str(time_str)

    # request extraction (robust)
    method, path = extract_request(entry)

    # path clean
    try:
        p = urlparse(unquote(path))
        path_clean = p.path if p.path else "-"
    except Exception:
        path_clean = "-"

    # status and bytes
    m_status = re.search(r'\s(\d{3})\s+(-|\d+)', entry)
    status = m_status.group(1) if m_status else "-"

    # user-agent (last quoted component usually)
    quoted = re.findall(r'"([^"]*)"', entry, flags=re.DOTALL)
    ua_raw = quoted[-1].strip() if quoted else "-"
    ua_clean = normalize_ua(ua_raw)
    bot_group = classify_group(ua_clean)

    is_static = bool(re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)(?:$|\?)', path_clean, re.I))

    return {
        "File": file_src,
        "LineNo": lineno,
        "ClientIP": client_ip,
        "Time": dt,                     # may be None -> handled later
        "Method": method,
        "Path": path,
        "PathClean": path_clean,
        "Status": status,
        "Bytes": m_status.group(2) if m_status else "-",
        "Referer": (quoted[1].strip() if len(quoted) >= 2 else "-") if quoted else "-",
        "User-Agent-Raw": ua_raw,
        "User-Agent": ua_clean,
        "BotGroup": bot_group,
        "IsStatic": is_static,
        "RawEntry": entry
    }

# -----------------------
# Parse stream into rows (handles multi-line entries)
# -----------------------
def parse_log_stream(lines):
    rows = []
    diag = {"total": 0, "parsed": 0, "failed": 0, "samples": []}
    buf = []

    for ln in lines:
        diag["total"] += 1
        if start_of_entry(ln):
            if buf:
                entry = " ".join(buf).strip()
                r = parse_single_entry(entry)
                if r:
                    rows.append(r)
                    diag["parsed"] += 1
                else:
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
                # orphan line treat as a single entry
                entry = ln.strip()
                r = parse_single_entry(entry)
                if r:
                    rows.append(r)
                    diag["parsed"] += 1
                else:
                    diag["failed"] += 1
                    if len(diag["samples"]) < 5:
                        diag["samples"].append(entry)

    if buf:
        entry = " ".join(buf).strip()
        r = parse_single_entry(entry)
        if r:
            rows.append(r)
            diag["parsed"] += 1
        else:
            diag["failed"] += 1
            if len(diag["samples"]) < 5:
                diag["samples"].append(entry)

    return rows, diag

# -----------------------
# UI: upload and run
# -----------------------
st.sidebar.header("Upload / Controls")
uploaded_file = st.sidebar.file_uploader("Upload per-bot log file (one bot per file recommended)", type=None)

if not uploaded_file:
    st.info("Upload a per-bot log file to begin parsing.")
    st.stop()

# stream parse
lines = stream_lines_from_uploaded(uploaded_file)
rows, diag = parse_log_stream(lines)
df = pd.DataFrame(rows)

# convert Time safely (keep NaT rows)
df["Time"] = pd.to_datetime(df["Time"], errors="coerce")

# Executive summary (do not drop NaT; still count hits)
total_hits = len(df)
unique_pages = df["PathClean"].nunique(dropna=True)
unique_ips = df["ClientIP"].nunique()

st.subheader("Parsing diagnostics")
c1, c2, c3 = st.columns(3)
c1.metric("Total lines processed (approx)", diag.get("total", 0))
c2.metric("Parsed entries", diag.get("parsed", 0))
c3.metric("Failed parse samples", diag.get("failed", 0))
if diag.get("samples"):
    st.markdown("**Sample failed entries**")
    for s in diag["samples"]:
        st.code(s)

st.subheader("Executive Summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total bot hits", total_hits)
c2.metric("Unique pages (PathClean)", unique_pages)
c3.metric("Unique bot IPs", unique_ips)
pct_success = round(((df['Status'].astype(str).str.startswith('2') | df['Status'].astype(str).str.startswith('3')).sum() / (total_hits or 1)) * 100, 1)
c4.metric("% 2xx/3xx", f"{pct_success}%")

# Bot groups
st.subheader("Bot groups")
bot_counts = df['BotGroup'].value_counts(dropna=False).reset_index()
bot_counts.columns = ["BotGroup", "Hits"]
st.dataframe(bot_counts, use_container_width=True, height=220)

# Filters
st.sidebar.header("Filters")
group_filter = st.sidebar.multiselect("BotGroup", options=sorted(df['BotGroup'].dropna().unique().tolist()), default=None)
status_filter = st.sidebar.multiselect("StatusClass (prefix)", options=None, default=None)
only_dynamic = st.sidebar.checkbox("Only dynamic (exclude static file extensions)", value=False)

dff = df.copy()
# StatusClass derive
dff['StatusClass'] = dff['Status'].astype(str).str[0].fillna('-') + "xx"
if group_filter:
    dff = dff[dff['BotGroup'].isin(group_filter)]
if only_dynamic:
    dff = dff[~dff['IsStatic']]

# Time-series: compute hourly only from rows with valid Time
ts_df = dff[dff['Time'].notna()].copy()
if not ts_df.empty:
    ts_df['Hour'] = ts_df['Time'].dt.floor('H')
    st.subheader("Hourly distribution (from entries with valid timestamps)")
    agg = ts_df.groupby(['Hour', 'BotGroup']).size().reset_index(name='Count')
    if not agg.empty:
        fig = px.area(agg, x='Hour', y='Count', color='BotGroup', title="Bot hits over time (hourly)")
        st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No valid timestamps to build hourly distribution. See 'Sample Raw Entries' for diagnostics.")

# Top URLs: exclude placeholder '-' but do not drop rows globally
st.subheader("Top URLs (excluding unknown '-')")
valid_urls = dff[dff['PathClean'] != "-"]
top_n = st.slider("Top N URLs", min_value=5, max_value=200, value=20)
top_urls = valid_urls['PathClean'].value_counts().reset_index().head(top_n)
top_urls.columns = ["Path", "Hits"]
st.dataframe(top_urls, use_container_width=True)

# UA variants (top)
st.subheader("User-Agent variants (top)")
ua_tab = dff['User-Agent'].value_counts().reset_index().head(50)
ua_tab.columns = ["User-Agent", "Count"]
st.dataframe(ua_tab, use_container_width=True)

# IP table
st.subheader("Bot IPs (top)")
ip_tab = dff['ClientIP'].value_counts().reset_index().head(200)
ip_tab.columns = ["IP", "Count"]
st.dataframe(ip_tab, use_container_width=True)

# Raw diagnostics: show ambiguous/malformed rows
st.subheader("Sample Raw Entries (first 30 parsed rows)")
st.code("\n\n".join(df['RawEntry'].head(30).tolist()))

# Export filtered CSV
st.subheader("Export")
csv_bytes = dff.to_csv(index=False).encode('utf-8')
st.download_button("Download filtered CSV", csv_bytes, file_name="bot_filtered.csv", mime="text/csv")

# End
