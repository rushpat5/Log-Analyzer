import streamlit as st
import pandas as pd
import re
import io
from datetime import datetime
from dateutil import parser as dtparser
from urllib.parse import urlparse, unquote
import plotly.express as px

st.set_page_config(page_title="Bot-Focused Log Analyzer — Corrected", layout="wide")
st.title("Bot-Focused Log Analyzer — Corrected & Normalized")

# =====================================================================
# BOT NORMALIZATION
# =====================================================================
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
    if not raw:
        return "UnknownBot/1.0"
    ua = raw.lower().strip()
    ua = re.sub(r",?\s*(gzip|gfe|gzip\(gfe\)|bot\.html|bot\.htm)", "", ua)
    for pat, norm in BOT_MAP.items():
        if re.search(pat, ua):
            return norm
    return raw.strip()[:80]

def classify_group(norm):
    n = norm.lower()
    if "googlebot" in n:
        return "Google"
    if "bing" in n:
        return "Bing"
    if any(x in n for x in ["chatgpt", "gptbot", "claude", "perplexity"]):
        return "AI/LLM"
    return "Other"

# =====================================================================
# REQUEST PARSER
# =====================================================================
REQUEST_FALLBACK = re.compile(
    r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s"]+)',
    re.I
)

def parse_request(entry):
    m = REQUEST_FALLBACK.search(entry)
    if not m:
        return "-", "-"
    return m.group(1), m.group(2)

# =====================================================================
# TIME PARSER
# =====================================================================
def parse_timestamp(ts):
    try:
        return dtparser.parse(ts)
    except:
        return None

# =====================================================================
# STREAM LINES
# =====================================================================
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

# =====================================================================
# ENTRY START DETECTION
# =====================================================================
START_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}\s")

def is_start(line):
    return bool(START_RE.match(line))

# =====================================================================
# ENTRY PARSER
# =====================================================================
def parse_entry(entry):
    tm = re.search(r"\[([^\]]+)\]", entry)
    ts = tm.group(1) if tm else ""
    dt = parse_timestamp(ts)

    im = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", entry)
    ip = im.group(1) if im else "-"

    method, path = parse_request(entry)

    try:
        p = urlparse(unquote(path))
        path_clean = p.path if p.path else "-"
    except:
        path_clean = "-"

    ua_list = re.findall(r'"([^"]*)"', entry)
    ua_raw = ua_list[-1] if ua_list else "-"
    ua_norm = normalize_ua(ua_raw)
    group = classify_group(ua_norm)

    sm = re.search(r"\s(\d{3})\s", entry)
    status = sm.group(1) if sm else "-"

    return {
        "Time": dt if isinstance(dt, datetime) else None,
        "IP": ip,
        "Method": method,
        "Path": path,
        "PathClean": path_clean,
        "UserAgent": ua_norm,
        "BotGroup": group,
        "Status": status,
        "Raw": entry,
    }

# =====================================================================
# MULTI-LINE PARSER
# =====================================================================
def parse_lines(lines):
    buf = []
    out = []
    for ln in lines:
        if is_start(ln):
            if buf:
                out.append(parse_entry(" ".join(buf)))
            buf = [ln]
        else:
            buf.append(ln)
    if buf:
        out.append(parse_entry(" ".join(buf)))
    return [x for x in out if x]

# =====================================================================
# UI
# =====================================================================
uploaded = st.file_uploader("Upload log file", type=None)

if uploaded:
    entries = parse_lines(stream_lines(uploaded))
    df = pd.DataFrame(entries)

    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df = df[df["Time"].notna()]
    df = df[df["PathClean"] != "-"]

    st.subheader("Executive Summary")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Hits", len(df))
    c2.metric("Unique Pages", df["PathClean"].nunique())
    c3.metric("Unique IPs", df["IP"].nunique())

    st.subheader("Bot Groups")
    st.dataframe(df["BotGroup"].value_counts().reset_index(), use_container_width=True)

    st.subheader("Hourly Distribution")
    df["Hour"] = df["Time"].dt.floor("H")
    h = df.groupby(["Hour", "BotGroup"]).size().reset_index(name="Count")
    fig = px.area(h, x="Hour", y="Count", color="BotGroup")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top URLs")
    top = df["PathClean"].value_counts().reset_index()
    top.columns = ["Path", "Hits"]
    st.dataframe(top, use_container_width=True)

    st.subheader("Sample Raw Entries")
    st.code("\n".join(df["Raw"].head(10).tolist()))

else:
    st.info("Upload a log file to begin.")
