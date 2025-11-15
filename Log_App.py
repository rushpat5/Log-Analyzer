import streamlit as st
import pandas as pd
import re
import io
import hashlib
from datetime import datetime
from dateutil import parser as dtparser
from urllib.parse import urlparse, parse_qs, unquote
import plotly.express as px

# ==========================================
# Page config
# ==========================================
st.set_page_config(page_title="Dynamic Log Analyzer — Bot & LLM Insights", layout="wide")

st.title("🧠 Dynamic Log Analyzer – Bot & AI/LLM Insights (No Predefined Bot List)")
st.caption("Fully automatic bot & AI detection. No hardcoded bot names. Future-proof classification.")

# ==========================================
# Dynamic Bot Detection (no predefined list)
# ==========================================

# structural patterns reliably indicating bots
BOT_CORE_PATTERNS = [
    r"bot", r"spider", r"crawler", r"fetch", r"scrap", r"preview", r"monitor",
    r"probe", r"archive", r"validator", r"index", r"httpclient",
    r"python-requests", r"wget", r"curl"
]

# structural patterns indicating AI/LLM agents
AI_LLM_PATTERNS = [
    r"\bai\b", r"\bml\b", r"-user\b", r"-agent\b", r"assistant",
    r"language-model", r"model-fetch"
]

def classify_ua(raw_ua: str):
    if not raw_ua or raw_ua.strip() == "-":
        return "Unknown", "Unknown"

    ua = raw_ua.lower()

    # AI/LLM signals
    for p in AI_LLM_PATTERNS:
        if re.search(p, ua, re.I):
            return "AI/LLM", raw_ua

    # generic bot signals
    for p in BOT_CORE_PATTERNS:
        if re.search(p, ua, re.I):
            return "Bot", raw_ua

    return "Other", raw_ua


# ==========================================
# Request Extraction (robust)
# ==========================================
REQ_RE_STRICT = re.compile(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s"]+)', re.I)
REQ_RE_RELAX = re.compile(r'(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(/[^\s"]+)', re.I)

def extract_request(entry):
    m = REQ_RE_STRICT.search(entry)
    if m:
        return m.group(1), m.group(2)
    m = REQ_RE_RELAX.search(entry)
    if m:
        return m.group(1), m.group(2)
    return "-", "-"

# ==========================================
# Timestamp extraction
# ==========================================
def parse_ts(t):
    if not t:
        return None
    try:
        return dtparser.parse(t)
    except:
        try:
            return datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z")
        except:
            try:
                return datetime.strptime(t, "%d/%b/%Y:%H:%M:%S")
            except:
                return None

# ==========================================
# Entry start detection
# Supports IP and filename:line:IP
# ==========================================
START_RE = re.compile(r'^(?:(?P<file>[^:\s]+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s')

def is_entry_start(line: str) -> bool:
    if START_RE.match(line):
        return True
    if line.startswith('[') and re.search(r'\d{1,2}/[A-Za-z]{3}/\d{4}', line):
        return True
    return False

# ==========================================
# Read lines streaming
# ==========================================
def stream_lines(file):
    file.seek(0)
    sample = file.read(65536)
    enc = "utf-8"
    for e in ("utf-8","latin-1","utf-16"):
        try:
            sample.decode(e)
            enc = e
            break
        except:
            continue

    file.seek(0)
    wrapper = io.TextIOWrapper(file, encoding=enc, errors="replace")
    for line in wrapper:
        yield line.rstrip("\n").rstrip("\r")

# ==========================================
# Parse complete entry
# ==========================================
def parse_entry(entry):
    m_start = START_RE.match(entry)
    ip = m_start.group("ip") if m_start else "-"
    file_src = m_start.group("file") if m_start else "-"
    lineno = m_start.group("lineno") if m_start else "-"

    # timestamp
    m_time = re.search(r'\[([^\]]+)\]', entry)
    raw_ts = m_time.group(1) if m_time else "-"
    dt = parse_ts(raw_ts)

    # request
    method, path = extract_request(entry)
    try:
        parsed = urlparse(unquote(path))
        path_clean = parsed.path or "-"
        query_str = parsed.query
    except:
        path_clean = path
        query_str = ""

    # status
    m_status = re.search(r'\s(\d{3})\s+(-|\d+)', entry)
    status = m_status.group(1) if m_status else "-"
    bytes_sent = m_status.group(2) if m_status else "-"

    # quoted blocks → referer + UA
    q = re.findall(r'"([^"]*)"', entry)
    referer = q[1] if len(q) >= 2 else "-"
    ua = q[-1] if q else "-"

    category, canonical_ua = classify_ua(ua)

    return {
        "IP": ip,
        "File": file_src,
        "LineNo": lineno,
        "Time": dt,
        "Time_raw": raw_ts,
        "Method": method,
        "Path": path,
        "PathClean": path_clean,
        "Query": query_str,
        "Status": status,
        "Bytes": bytes_sent,
        "Referer": referer,
        "UA_Raw": ua,
        "UA": canonical_ua,
        "Group": category,
        "Raw": entry
    }


# ==========================================
# Multi-line reconstruction
# ==========================================
def parse_stream(stream):
    rows = []
    buf = []
    for ln in stream:
        if is_entry_start(ln):
            if buf:
                rows.append(parse_entry(" ".join(buf)))
            buf = [ln]
        else:
            buf.append(ln)
    if buf:
        rows.append(parse_entry(" ".join(buf)))
    return rows


# ==========================================
# UI
# ==========================================
uploaded = st.file_uploader("Upload log file", type=None)

if not uploaded:
    st.info("Upload a log file.")
    st.stop()

with st.spinner("Parsing file…"):
    lines = stream_lines(uploaded)
    rows = parse_stream(lines)

df = pd.DataFrame(rows)
df["Time"] = pd.to_datetime(df["Time"], errors="coerce")

# ==========================================
# KPIs
# ==========================================
st.subheader("Executive Summary")
c1, c2, c3 = st.columns(3)
c1.metric("Total Hits", len(df))
c2.metric("Unique Paths", df["PathClean"].nunique())
c3.metric("Unique IPs", df["IP"].nunique())

# ==========================================
# Group Summary (dynamic bot detection)
# ==========================================
st.subheader("Groups (Dynamic Bot Detection)")
group_tab = df["Group"].value_counts().reset_index()
group_tab.columns = ["Group", "Hits"]
st.dataframe(group_tab, use_container_width=True)

# ==========================================
# Hourly Distribution
# ==========================================
valid_ts = df[df["Time"].notna()].copy()
if not valid_ts.empty:
    valid_ts["Hour"] = valid_ts["Time"].dt.floor("H")
    agg = valid_ts.groupby(["Hour", "Group"]).size().reset_index(name="Count")
    fig = px.area(agg, x="Hour", y="Count", color="Group")
    st.plotly_chart(fig, use_container_width=True)

# ==========================================
# Top Paths
# ==========================================
st.subheader("Top Paths")
top_paths = df["PathClean"].value_counts().reset_index().head(30)
top_paths.columns = ["Path", "Hits"]
st.dataframe(top_paths, use_container_width=True)

# ==========================================
# UA variants
# ==========================================
st.subheader("Top User-Agents")
ua_tab = df["UA_Raw"].value_counts().reset_index().head(50)
ua_tab.columns = ["User-Agent", "Count"]
st.dataframe(ua_tab, use_container_width=True)

# ==========================================
# Export
# ==========================================
csv = df.to_csv(index=False).encode()
st.download_button("Download CSV", csv, "parsed_log.csv", "text/csv")
