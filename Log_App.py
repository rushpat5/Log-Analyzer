import streamlit as st
import pandas as pd
import re
import io
import codecs
import hashlib
from datetime import datetime
from dateutil import parser as dtparser
from urllib.parse import urlparse, parse_qs, unquote
import plotly.express as px

# ============================================================================
# PAGE CONFIG
# ============================================================================
st.set_page_config(page_title="Bot-Focused Log Analyzer — Corrected", layout="wide")
st.title("Bot-Focused Log Analyzer — Corrected & Normalized")

# ============================================================================
# BOT NAME NORMALIZATION
# ============================================================================
BOT_MAP = {
    # --- AI/LLM Bots ---
    r"chatgpt-user": "ChatGPT-User/1.0",
    r"gptbot": "GPTBot/1.0",
    r"perplexitybot": "PerplexityBot/1.0",
    r"claude-user": "Claude-User/1.0",
    r"claudebot": "ClaudeBot/1.0",

    # --- Search Engines ---
    r"googlebot": "Googlebot/2.1",
    r"bingbot": "Bingbot/2.0",
    r"bingpreview": "BingPreview/1.0",

    # --- Others ---
    r"ahrefsbot": "AhrefsBot/1.0",
    r"semrushbot": "SemrushBot/1.0",
    r"mj12bot": "MJ12Bot/1.0"
}

def normalize_ua(raw):
    if not raw:
        return "UnknownBot/1.0"

    ua = raw.lower().strip()

    # Remove appended garbage
    ua = re.sub(r",?\s*(gzip|gfe|gzip\(gfe\)|bot\.html|bot\.htm)", "", ua)

    # Match canonical patterns
    for pat, norm in BOT_MAP.items():
        if re.search(pat, ua):
            return norm

    return raw.strip()[:80]


def classify_group(norm):
    norm_low = norm.lower()
    if "googlebot" in norm_low:
        return "Google"
    if "bing" in norm_low:
        return "Bing"
    if any(x in norm_low for x in ["chatgpt", "gptbot", "claude", "perplexity"]):
        return "AI/LLM"
    return "Other"


# ============================================================================
# REQUEST PARSING FIX (CRITICAL)
# ============================================================================
REQUEST_FALLBACK = re.compile(
    r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s"]+)(?:\s+HTTP/\d\.\d)?"',
    re.I
)

def parse_request(entry):
    m = REQUEST_FALLBACK.search(entry)
    if not m:
        return "-", "-"
    method = m.group(1)
    path = m.group(2)
    return method, path


# ============================================================================
# TIME PARSER
# ============================================================================
def parse_timestamp(ts):
    try:
        return dtparser.parse(ts)
    except:
        return None


# ============================================================================
# STREAM LINES (NO FULL FILE READ)
# ============================================================================
def stream_lines(uploaded):
    uploaded.seek(0)
    sample = uploaded.read(65536)
    enc = "utf-8"
    for e in ["utf-8", "latin-1", "utf-16"]:
        try:
            sample.decode(e)
            enc = e
            break
        except:
            pass

    uploaded.seek(0)
    wrapper = io.TextIOWrapper(uploaded, encoding=enc, errors="replace")
    for line in wrapper:
        yield line.rstrip("\n").rstrip("\r")


# ============================================================================
# ENTRY START DETECTOR
# ============================================================================
START_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}\s")

def is_start(line):
    return bool(START_RE.match(line))


# ============================================================================
# MAIN PARSER (BUFFER + FIXES)
# ============================================================================
def parse_lines(lines):
    buf = []
    parsed = []

    for ln in lines:
        if is_start(ln):
            if buf:
                parsed.append(parse_entry(" ".join(buf)))
            buf = [ln]
        else:
            buf.append(ln)

    if buf:
        parsed.append(parse_entry(" ".join(buf)))

    return [p for p in parsed if p]


def parse_entry(entry):
    # Extract timestamp
    time_match = re.search(r"\[([^\]]+)\]", entry)
    ts = time_match.group(1) if time_match else "-"
    dt = parse_timestamp(ts)

    # Extract IP
    ip_match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", entry)
    ip = ip_match.group(1) if ip_match else "-"

    # Extract request (fixed)
    method, path = parse_request(entry)

    # Clean path
    try:
        p = urlparse(unquote(path))
        path_clean = p.path if p.path else "-"
    except:
        path_clean = "-"

    # Extract UA (last quoted string)
    ua_list = re.findall(r'"([^"]*)"', entry)
    ua = ua_list[-1] if ua_list else "-"

    ua_norm = normalize_ua(ua)
    group = classify_group(ua_norm)

    # Extract status
    st_match = re.search(r'\s(\d{3})\s', entry)
    status = st_match.group(1) if st_match else "-"

    return {
        "Time": dt,
        "IP": ip,
        "Method": method,
        "Path": path,
        "PathClean": path_clean,
        "UserAgentRaw": ua,
        "UserAgent": ua_norm,
        "BotGroup": group,
        "Status": status,
        "Raw": entry
    }


# ============================================================================
# UI
# ============================================================================
uploaded = st.file_uploader("Upload log file", type=None)

if uploaded:
    lines = stream_lines(uploaded)
    entries = parse_lines(lines)
    df = pd.DataFrame(entries)

    # ===================== FIX: Remove "-" paths from top URLs ========================
    df = df[df["PathClean"] != "-"]

    st.subheader("Executive Summary")

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Hits", len(df))
    c2.metric("Unique Pages", df["PathClean"].nunique())
    c3.metric("Unique IPs", df["IP"].nunique())

    st.subheader("Bot Groups")
    st.dataframe(df["BotGroup"].value_counts().reset_index())

    # ===================== TIME SERIES ============================
    st.subheader("Hourly Distribution")
    df["Hour"] = df["Time"].dt.floor("H")
    h = df.groupby(["Hour", "BotGroup"]).size().reset_index(name="Count")
    fig = px.area(h, x="Hour", y="Count", color="BotGroup")
    st.plotly_chart(fig, use_container_width=True)

    # ===================== TOP URLS ===============================
    st.subheader("Top URLs")
    top = df["PathClean"].value_counts().reset_index()
    top.columns = ["Path", "Hits"]
    st.dataframe(top)

    # ===================== RAW DIAGNOSTICS ========================
    st.subheader("Raw Log Diagnostics (first 10)")
    st.code("\n".join(df["Raw"].head(10).tolist()))

else:
    st.info("Upload a log file to begin.")
