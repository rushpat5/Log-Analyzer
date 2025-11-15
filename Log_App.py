import streamlit as st
import pandas as pd
import re
import io
from datetime import datetime
from dateutil import parser as dtparser
from urllib.parse import urlparse, parse_qs, unquote
import hashlib
import plotly.express as px
import string

st.set_page_config(page_title="Screaming-Frog Style Log Analyzer", layout="wide")

st.markdown("""
<style>
body {background:#0f1117;color:#e8e8e8;}
.block-container{padding-top:1rem;}
</style>
""", unsafe_allow_html=True)

st.title("Screaming Frog–Style Log Analyzer (SEO-Focused)")


# ============================================================
# ENCODING DETECTION
# ============================================================

def score_decoding(b: bytes, enc: str) -> float:
    try:
        s = b.decode(enc, errors="replace")
    except Exception:
        return -1
    printable = string.printable
    if not s:
        return -1
    good = sum(1 for ch in s if ch in printable)
    return good / len(s)


def detect_best_encoding(sample: bytes) -> str:
    candidates = ["utf-8", "latin-1", "utf-16", "cp1252"]
    best, best_score = "utf-8", -1
    for enc in candidates:
        sc = score_decoding(sample, enc)
        if sc > best_score:
            best_score = sc
            best = enc
    return best


def stream_lines(uploaded_file):
    uploaded_file.seek(0)
    b = uploaded_file.read(65536)
    enc = detect_best_encoding(b)
    uploaded_file.seek(0)
    wrapper = io.TextIOWrapper(uploaded_file, encoding=enc, errors="replace")
    for line in wrapper:
        yield line.rstrip("\n").rstrip("\r"), enc


# ============================================================
# UA CLEANING & DYNAMIC BOT DETECTION
# ============================================================

BOT_KEYWORDS = [
    r'bot', r'crawler', r'spider', r'index', r'fetch', r'scrap', r'probe', r'preview'
]
AI_KEYWORDS = [
    r'-user\b', r'\bai\b', r'chatgpt', r'claude', r'mistral', r'perplexity'
]

CANONICAL_MAP = [
    (r'chatgpt-user', 'ChatGPT-User/1.0'),
    (r'gptbot', 'GPTBot/1.0'),
    (r'googlebot', 'Googlebot/2.1'),
    (r'bingbot', 'Bingbot/2.0'),
]


def clean_ua(raw: str) -> str:
    if not raw:
        return "-"
    cleaned = "".join(ch if ch.isprintable() else " " for ch in raw)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned or "-"


def canonicalize(ua: str) -> str:
    low = ua.lower()
    for pat, rep in CANONICAL_MAP:
        if re.search(pat, low):
            return rep
    return ua


def detect_group(ua: str) -> str:
    low = ua.lower()
    for p in AI_KEYWORDS:
        if re.search(p, low):
            return "AI/LLM"
    for p in BOT_KEYWORDS:
        if re.search(p, low):
            return "Bot"
    return "Other"


# ============================================================
# ENTRY START REGEX
# ============================================================

START_RE = re.compile(
    r'^(?:(?P<file>[^:\s]+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s'
)


def appears_new_entry(line: str) -> bool:
    if START_RE.match(line):
        return True
    if line.startswith("[") and re.search(r"\d{2}/[A-Za-z]{3}/\d{4}", line):
        return True
    return False


# ============================================================
# PARSE ONE LOG ENTRY
# ============================================================

def extract_request(entry: str):
    m = re.search(r'"(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+([^"]+)"', entry)
    if m:
        return m.group(1), m.group(2).split()[0]
    fallback = re.search(r'(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+(/[^\s"]+)', entry)
    if fallback:
        return fallback.group(1), fallback.group(2)
    return "-", "-"


def parse_time(entry: str):
    m = re.search(r'\[([^\]]+)\]', entry)
    if not m:
        return None
    token = m.group(1)
    try:
        return dtparser.parse(token)
    except Exception:
        try:
            return datetime.strptime(token, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            return None


def parse_single(entry: str):
    start = START_RE.match(entry)
    file_src = start.group("file") if start and start.group("file") else "-"
    lineno = start.group("lineno") if start and start.group("lineno") else "-"
    ip = start.group("ip") if start else "-"

    method, path = extract_request(entry)

    dt = parse_time(entry)

    m_status = re.search(r'"\s*(\d{3})\s+(-|\d+)', entry)
    status = m_status.group(1) if m_status else "-"
    bytes_sent = m_status.group(2) if m_status else "-"

    quoted = re.findall(r'"([^"]*)"', entry)
    referer = quoted[1].strip() if len(quoted) >= 2 else "-"
    ua = quoted[-1].strip() if quoted else "-"

    ua_clean = clean_ua(ua)
    ua_canon = canonicalize(ua_clean)
    group = detect_group(ua_clean)

    path_clean, query, query_params = "-", "", {}
    if path and path != "-":
        try:
            p = urlparse(unquote(path))
            path_clean = p.path or "-"
            query = p.query
            query_params = dict(parse_qs(p.query))
        except Exception:
            path_clean = path

    is_static = bool(re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ico|ttf)$', path_clean, re.I))
    section = path_clean.split('/')[1] if path_clean.startswith('/') and len(path_clean.split('/')) > 1 else "-"

    hour = dt.replace(minute=0, second=0, microsecond=0) if dt else None
    session = hashlib.sha1(f"{ip}|{ua_clean}|{hour}".encode()).hexdigest()[:10]

    return {
        "File": file_src,
        "Line": lineno,
        "IP": ip,
        "Time": dt,
        "Method": method,
        "Path": path,
        "PathClean": path_clean,
        "Query": query,
        "Status": status,
        "Bytes": bytes_sent,
        "Referer": referer,
        "UA": ua_canon,
        "UA-Raw": ua_clean,
        "Group": group,
        "IsStatic": is_static,
        "Section": section,
        "SessionID": session,
        "Raw": entry,
    }


# ============================================================
# PARSE LOG STREAM
# ============================================================

def parse_log(lines_with_enc):
    rows, buf = [], []
    diag = {"total": 0, "parsed": 0, "failed": 0, "samples": []}
    enc_used = None

    for line, enc in lines_with_enc:
        enc_used = enc
        diag["total"] += 1

        if appears_new_entry(line):
            if buf:
                entry = " ".join(buf).strip()
                try:
                    rows.append(parse_single(entry))
                    diag["parsed"] += 1
                except Exception:
                    diag["failed"] += 1
                    if len(diag["samples"]) < 5:
                        diag["samples"].append(entry)
                buf = [line]
            else:
                buf = [line]
        else:
            buf.append(line)

    if buf:
        entry = " ".join(buf).strip()
        try:
            rows.append(parse_single(entry))
            diag["parsed"] += 1
        except Exception:
            diag["failed"] += 1
            if len(diag["samples"]) < 5:
                diag["samples"].append(entry)

    return pd.DataFrame(rows), diag, enc_used


# ============================================================
# UI
# ============================================================

uploaded = st.file_uploader("Upload a per-bot log file", type=None)

if not uploaded:
    st.stop()

with st.spinner("Parsing…"):
    df, diag, enc_used = parse_log(stream_lines(uploaded))

st.subheader("Parsing Diagnostics")
c1, c2, c3 = st.columns(3)
c1.metric("Lines Read", diag["total"])
c2.metric("Parsed", diag["parsed"])
c3.metric("Failed", diag["failed"])
st.write(f"**Detected Encoding:** `{enc_used}`")

if diag["samples"]:
    st.write("Failed samples:")
    for s in diag["samples"]:
        st.code(s)


# ============================================================
# CLEAN DATAFRAME
# ============================================================

df["Time"] = pd.to_datetime(df["Time"], errors="coerce")

# ============================================================
# KPIs — Screaming Frog Style
# ============================================================

st.subheader("Executive Summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Hits", len(df))
c2.metric("Unique Paths", df["PathClean"].nunique())
c3.metric("Unique IPs", df["IP"].nunique())
success_rate = round(
    (df["Status"].astype(str).str.startswith(("2", "3")).mean()) * 100, 1
)
c4.metric("% 2xx/3xx", f"{success_rate}%")


# ============================================================
# GROUPS (Dynamic Bot Detection)
# ============================================================

st.subheader("Groups (Dynamic Bot Detection)")
group_counts = df["Group"].value_counts().reset_index()
group_counts.columns = ["Group", "Hits"]
st.dataframe(group_counts, use_container_width=True)


# ============================================================
# TOP PATHS (Safe)
# ============================================================

st.subheader("Top Paths")
paths = (
    df["PathClean"]
    .fillna("-")
    .value_counts()
    .reset_index()
    .iloc[:50]
)
paths.columns = ["Path", "Hits"]
st.dataframe(paths, use_container_width=True)


# ============================================================
# TOP UAs
# ============================================================

st.subheader("Top User-Agents (Canonical)")
ua_tab = df["UA"].value_counts().reset_index()
ua_tab.columns = ["User-Agent", "Count"]
st.dataframe(ua_tab.head(50), use_container_width=True)


# ============================================================
# SECTION DISTRIBUTION
# ============================================================

st.subheader("Section Distribution")
sec = df["Section"].replace("", "-").value_counts().reset_index()
sec.columns = ["Section", "Hits"]
st.dataframe(sec, use_container_width=True)


# ============================================================
# DEPTH DISTRIBUTION (No KeyError)
# Safe version: name columns explicitly
# ============================================================

st.subheader("Crawl Depth Distribution")
df["Depth"] = df["PathClean"].fillna("-").apply(
    lambda p: len([seg for seg in str(p).split('/') if seg])
)
depth = df["Depth"].value_counts().reset_index()
depth.columns = ["Depth", "Count"]
depth = depth.sort_values("Depth")
st.dataframe(depth, use_container_width=True)


# ============================================================
# HOURLY DISTRIBUTION
# ============================================================

st.subheader("Hourly Distribution")
df_valid_time = df[df["Time"].notna()]
if not df_valid_time.empty:
    df_valid_time["Hour"] = df_valid_time["Time"].dt.floor("H")
    hourly = df_valid_time.groupby("Hour").size().reset_index(name="Count")

    fig = px.bar(hourly, x="Hour", y="Count", title="Crawl Hits Per Hour")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No timestamp data available.")


# ============================================================
# EXPORT
# ============================================================

st.subheader("Export")
csv = df.to_csv(index=False).encode("utf-8")
st.download_button("Download Parsed CSV", data=csv, file_name="parsed_log.csv")
