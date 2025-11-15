# app.py
import streamlit as st
import pandas as pd
import re
import io
import codecs
import hashlib
from datetime import datetime, timedelta, timezone
from dateutil import parser as dtparser
from urllib.parse import urlparse, parse_qs, unquote
import plotly.express as px
from typing import Iterator, Tuple, Optional, Dict, Any, Iterable
import base64

# =====================================================================
# Page
# =====================================================================
st.set_page_config(page_title="Bot-Focused Log Analyzer — Client Ready", layout="wide")
st.title("Bot-Focused Log Analyzer — Client Ready")

# =====================================================================
# Config: patterns and canonical mapping
# =====================================================================
VERIFIED_TOP_BOTS = [
    r'\bGooglebot\b', r'\bGooglebot-Image\b', r'\bGooglebot-News\b', r'\bGooglebot-Video\b',
    r'\bGooglebot-Mobile\b', r'\bBingbot\b', r'\bBingPreview\b', r'\bDuckDuckBot\b',
    r'\bBaiduspider\b', r'\bYandexBot\b', r'\bSemrushBot\b', r'\bPerplexityBot\b',
    r'\bGPTBot\b', r'\bChatGPT-User\b', r'\bClaude-User\b', r'\bClaudeBot\b',
    r'\bGPTBot\b', r'\bBytespider\b', r'\bCCBot\b', r'\bDiffbot\b',
    r'\bAhrefsBot\b', r'\bMJ12bot\b', r'\bfacebookexternalhit\b', r'\bSlackbot\b',
    r'\bTwitterbot\b',
]
AI_LLM_BOT_PATTERNS = [
    r'\bGPTBot\b', r'\bChatGPT-User\b', r'\bPerplexityBot\b', r'\bClaude-User\b', r'\bClaudeBot\b'
]
AI_LLM_BOT_RE = re.compile("|".join(AI_LLM_BOT_PATTERNS), re.I)
GENERIC_BOT_RE = re.compile("|".join([p for p in VERIFIED_TOP_BOTS if p not in AI_LLM_BOT_PATTERNS]), re.I)

BOT_CANONICAL = [
    (r'\bGooglebot\b', "Googlebot"),
    (r'\bGooglebot-Image\b', "Googlebot-Image"),
    (r'\bBingbot\b', "Bingbot"),
    (r'\bGPTBot\b', "GPTBot (OpenAI)"),
    (r'\bChatGPT-User\b', "ChatGPT-User (OpenAI)"),
    (r'\bPerplexityBot\b', "PerplexityBot"),
    (r'\bClaude-User\b', "Claude-User"),
    (r'\bAhrefsBot\b', "AhrefsBot"),
    (r'\bSlackbot\b', "Slackbot"),
    (r'\bTwitterbot\b', "Twitterbot"),
]

# =====================================================================
# Regex constants
# =====================================================================
START_INFO_RE = re.compile(r'^(?:(?P<file>[^:\s]+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s')
COMBINED_LOG_RE = re.compile(
    r'(?P<remote>\S+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"',
    flags=re.DOTALL,
)
COMMON_LOG_RE = re.compile(
    r'(?P<remote>\S+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)',
    flags=re.DOTALL,
)
STATIC_RE = re.compile(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)($|\?)', re.I)

# =====================================================================
# Utilities
# =====================================================================
def compute_sha256_of_bytes(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def detect_encoding_from_sample(b: bytes, sample_size: int = 65536) -> str:
    sample = b[:sample_size]
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            sample.decode(enc)
            return enc
        except Exception:
            continue
    return "utf-8"

def parse_time_preserve_tz(ts: str) -> Optional[datetime]:
    if not ts or ts.strip() == "-":
        return None
    try:
        return dtparser.parse(ts, fuzzy=False)
    except Exception:
        pass
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        pass
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return None

def parse_request_field(request: str):
    if not request or request == "-":
        return "-", "-", "-"
    m = re.match(r'([A-Z]+)\s+(\S+)(?:\s+HTTP/(\d\.\d))?', request)
    if m:
        return m.group(1), m.group(2), m.group(3) if m.group(3) else "-"
    return "-", request, "-"

def safe_urlparse(path: str):
    if not path or path == "-":
        return path, "", {}
    try:
        p = urlparse(unquote(path))
        return p.path, p.query, parse_qs(p.query)
    except Exception:
        return path, "", {}

def identify_bot_from_ua(ua: str) -> Optional[str]:
    if not ua or ua.strip() == "-":
        return None
    if AI_LLM_BOT_RE.search(ua):
        return "AI/LLM"
    if GENERIC_BOT_RE.search(ua):
        return "GenericBot"
    return None

def canonicalize_ua(ua: str) -> Tuple[str,str]:
    """
    Return (canonical_name, group) where group one of: Google, Bing, AI/LLM, Generic, Others
    """
    if not ua or ua.strip() == "-":
        return ("-", "Others")
    for pat, name in BOT_CANONICAL:
        if re.search(pat, ua, re.I):
            if "Google" in name:
                return (name, "Google")
            if "Bing" in name:
                return (name, "Bing")
            if re.search("|".join([p for p,_ in BOT_CANONICAL]), name, re.I) and AI_LLM_BOT_RE.search(ua):
                return (name, "AI/LLM")
            # fallback mapping
            if AI_LLM_BOT_RE.search(ua):
                return (name, "AI/LLM")
            return (name, "Generic")
    # heuristics
    if re.search(r'google', ua, re.I):
        return ("Unknown Google UA", "Google")
    if re.search(r'bing', ua, re.I):
        return ("Unknown Bing UA", "Bing")
    if AI_LLM_BOT_RE.search(ua):
        return ("Unknown AI/LLM", "AI/LLM")
    if GENERIC_BOT_RE.search(ua):
        return ("Unknown Generic", "Generic")
    return (ua[:80], "Others")

# =====================================================================
# Parsing (streaming-friendly)
# =====================================================================
def parse_single_entry(entry: str) -> Optional[dict]:
    try:
        m_start = START_INFO_RE.match(entry)
        file_src = m_start.group("file") if m_start and m_start.group("file") else "-"
        lineno = m_start.group("lineno") if m_start and m_start.group("lineno") else ""
        client_ip = m_start.group("ip") if m_start else "-"

        m = COMBINED_LOG_RE.search(entry)
        if m:
            time_str = m.group("time")
            request = m.group("request").strip() if m.group("request") else "-"
            referer = m.group("referer").strip()
            ua = re.sub(r'\s+', ' ', m.group("ua").strip())
            status = m.group("status")
            bytes_sent = m.group("bytes")
        else:
            m2 = COMMON_LOG_RE.search(entry)
            if m2:
                time_str = m2.group("time")
                request = m2.group("request").strip()
                referer = "-"
                ua = "-"
                status = m2.group("status")
                bytes_sent = m2.group("bytes")
            else:
                quoted = re.findall(r'"([^"]*)"', entry, flags=re.DOTALL)
                request = quoted[0].strip() if len(quoted) >= 1 else "-"
                referer = quoted[1].strip() if len(quoted) >= 2 else "-"
                ua = quoted[-1].strip() if len(quoted) >= 1 else "-"
                m_status_bytes = re.search(r'\s(\d{3})\s+(-|\d+)', entry)
                status = m_status_bytes.group(1) if m_status_bytes else "-"
                bytes_sent = m_status_bytes.group(2) if m_status_bytes else "-"
                m_time = re.search(r'\[([^\]]+)\]', entry)
                time_str = m_time.group(1) if m_time else "-"

        dt = parse_time_preserve_tz(time_str)
        time_iso = dt.isoformat() if dt else "-"
        method, path, http_ver = parse_request_field(request)
        path_clean, query_str, query_params = safe_urlparse(path)
        is_static = bool(STATIC_RE.search(path or ""))
        status_class = f"{status[0]}xx" if status.isdigit() else "-"
        section = path_clean.split('/')[1] if path_clean.startswith('/') and len(path_clean.split('/')) > 1 else ""
        canonical_name, bot_group = canonicalize_ua(ua)

        return {
            "File": file_src,
            "LineNo": lineno,
            "ClientIP": client_ip,
            "Time": time_iso,
            "Time_parsed": dt,
            "Method": method,
            "Path": path,
            "PathClean": path_clean,
            "Query": query_str,
            "QueryParams": query_params,
            "Status": status,
            "StatusClass": status_class,
            "Bytes": bytes_sent,
            "Referer": referer,
            "User-Agent": ua,
            "BotCanonical": canonical_name,
            "BotGroup": bot_group,
            "IsStatic": is_static,
            "Section": section,
            "HTTP_Version": http_ver,
            "RawEntry": entry,
        }
    except Exception:
        return None

def stream_lines_from_uploaded(uploaded_file) -> Iterator[str]:
    """
    Read small sample to detect encoding, then yield lines without loading entire file.
    """
    # uploaded_file: stream-like. read small sample
    pos = uploaded_file.tell() if hasattr(uploaded_file, "tell") else None
    sample = uploaded_file.read(65536)
    enc = detect_encoding_from_sample(sample if isinstance(sample, bytes) else sample.encode('utf-8', errors='replace'))
    # rewind
    try:
        uploaded_file.seek(0)
    except Exception:
        pass
    # wrap with TextIOWrapper
    textio = io.TextIOWrapper(uploaded_file, encoding=enc, errors='replace', newline=None)
    for line in textio:
        yield line.rstrip("\n").rstrip("\r")

def parse_streaming_to_dfs(lines: Iterable[str], batch_size: int = 5000):
    """
    Parse incoming lines into DataFrame batches; yields DataFrames.
    Handles multi-line log entries using start_of_entry heuristic.
    """
    def start_of_entry(ln):
        if not ln:
            return False
        if START_INFO_RE.match(ln):
            return True
        if ln.startswith("[") and re.search(r'\d{1,2}/[A-Za-z]{3}/\d{4}', ln):
            return True
        if re.match(r'^\d', ln):
            return True
        return False

    buf = []
    parsed_batch = []
    for ln in lines:
        if start_of_entry(ln):
            if buf:
                entry = " ".join(buf).strip()
                r = parse_single_entry(entry)
                if r:
                    parsed_batch.append(r)
                    if len(parsed_batch) >= batch_size:
                        yield pd.DataFrame.from_records(parsed_batch)
                        parsed_batch = []
                buf = [ln]
            else:
                buf = [ln]
        else:
            if buf:
                buf.append(ln)
            else:
                entry = ln.strip()
                r = parse_single_entry(entry)
                if r:
                    parsed_batch.append(r)
                    if len(parsed_batch) >= batch_size:
                        yield pd.DataFrame.from_records(parsed_batch)
                        parsed_batch = []
    if buf:
        entry = " ".join(buf).strip()
        r = parse_single_entry(entry)
        if r:
            parsed_batch.append(r)
    if parsed_batch:
        yield pd.DataFrame.from_records(parsed_batch)

# =====================================================================
# UI: upload and parsing controls
# =====================================================================
st.sidebar.header("Upload / Controls")
uploaded_file = st.sidebar.file_uploader("Upload per-bot log file (one bot per file recommended)", type=None, help="Large per-bot files supported via streaming.")
sample_rows = st.sidebar.number_input("Preview rows in table", min_value=5, max_value=1000, value=25)

if uploaded_file:
    # use streaming parse and incremental aggregation
    placeholder = st.empty()
    progress = st.sidebar.progress(0)
    status_text = st.sidebar.empty()

    # compute SHA from a small sample to use caching key
    try:
        # some stream objects support getbuffer()/read; for robust, read small sample as bytes
        uploaded_file.seek(0)
        sample_bytes = uploaded_file.read(65536)
        file_hash = compute_sha256_of_bytes(sample_bytes)
        uploaded_file.seek(0)
    except Exception:
        file_hash = str(hash(uploaded_file))

    # parse in batches
    dfs = []
    total_rows = 0
    batch_count = 0
    try:
        lines = stream_lines_from_uploaded(uploaded_file)
        for i, df_batch in enumerate(parse_streaming_to_dfs(lines, batch_size=4000)):
            batch_count += 1
            total_rows += len(df_batch)
            dfs.append(df_batch)
            progress.progress(min(100, int((i+1) % 100)))
            status_text.write(f"Parsed batches: {batch_count}, rows so far: {total_rows}")
        progress.progress(100)
    except Exception as e:
        st.error(f"Parsing failed: {e}")
        raise

    if not dfs:
        st.warning("No parseable entries found.")
        st.stop()

    # concat with memory-sensible dtypes
    df = pd.concat(dfs, ignore_index=True)
    # basic normalization
    df['Time_parsed'] = pd.to_datetime(df['Time_parsed'], errors='coerce')
    # reduce memory
    for col in ['BotGroup','StatusClass','Section']:
        if col in df.columns:
            df[col] = df[col].astype('category')
    st.sidebar.success(f"Parsed {len(df)} rows; batches: {len(dfs)}")

    # =================================================================
    # Executive summary cards
    # =================================================================
    st.subheader("Executive summary")
    total_hits = len(df)
    unique_pages = df['PathClean'].nunique()
    unique_ips = df['ClientIP'].nunique()
    pct_success = round(((df['Status'].astype(str).str.startswith('2') | df['Status'].astype(str).str.startswith('3')).sum() / total_hits) * 100, 1) if total_hits else 0.0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total bot hits", total_hits)
    c2.metric("Unique pages crawled", unique_pages)
    c3.metric("Unique bot IPs", unique_ips)
    c4.metric("% 2xx/3xx responses", f"{pct_success}%")

    # top bot groups
    st.markdown("**Bot groups**")
    bot_group_counts = df['BotGroup'].value_counts().reset_index()
    bot_group_counts.columns = ['BotGroup', 'Hits']
    st.dataframe(bot_group_counts, use_container_width=True, height=200)

    # =================================================================
    # Filters (left pane)
    # =================================================================
    st.sidebar.header("Filters")
    bot_choice = st.sidebar.multiselect("Bot group", options=df['BotGroup'].cat.categories.tolist() if 'BotGroup' in df.columns else df['BotGroup'].unique().tolist(), default=None)
    status_filter = st.sidebar.multiselect("Status class", options=df['StatusClass'].dropna().unique().tolist(), default=None)
    section_filter = st.sidebar.text_input("Include section (regex)", value="")
    only_dynamic = st.sidebar.checkbox("Only dynamic content (exclude static assets)", value=True)

    dff = df.copy()
    if bot_choice:
        dff = dff[dff['BotGroup'].isin(bot_choice)]
    if status_filter:
        dff = dff[dff['StatusClass'].isin(status_filter)]
    if section_filter:
        try:
            dff = dff[dff['Section'].str.contains(section_filter, na=False, regex=True)]
        except Exception:
            pass
    if only_dynamic:
        dff = dff[~dff['IsStatic']]

    if dff.empty:
        st.warning("No rows match filters.")
        st.stop()

    # =================================================================
    # Chart 1: hourly time series by BotCanonical or BotGroup
    # =================================================================
    st.subheader("Hourly distribution (time series)")
    # choose grouping: BotGroup or BotCanonical if multiple
    group_by = st.selectbox("Group by", ["BotGroup", "BotCanonical"])
    tmp = dff.copy()
    tmp['DateHour'] = tmp['Time_parsed'].dt.floor('H')
    agg = tmp.groupby(['DateHour', group_by]).size().reset_index(name='Count')
    if agg.empty:
        st.info("No time-series data available for selected filters.")
    else:
        fig = px.area(agg, x='DateHour', y='Count', color=group_by, line_group=group_by, title="Bot hits over time")
        st.plotly_chart(fig, use_container_width=True)
        # Export PNG if kaleido available
        try:
            img_bytes = fig.to_image(format="png")
            st.download_button("Download time series PNG", img_bytes, file_name="time_series.png", mime="image/png")
        except Exception:
            st.info("PNG export not available in this environment (kaleido). Chart download suppressed.")

    # =================================================================
    # Chart 2: Top URLs for selected bot/filter
    # =================================================================
    st.subheader("Top URLs (by hits)")
    top_n = st.slider("Top N", min_value=5, max_value=200, value=20)
    top_urls = dff['PathClean'].value_counts().reset_index().head(top_n)
    top_urls.columns = ["Path", "Hits"]
    st.dataframe(top_urls, use_container_width=True)

    # small bar chart
    if not top_urls.empty:
        fig2 = px.bar(top_urls.sort_values("Hits"), x="Hits", y="Path", orientation='h', title=f"Top {top_n} URLs")
        st.plotly_chart(fig2, use_container_width=True)
        try:
            img_bytes2 = fig2.to_image(format="png")
            st.download_button("Download top URLs PNG", img_bytes2, file_name="top_urls.png", mime="image/png")
        except Exception:
            pass

    # =================================================================
    # UA variants and IP table
    # =================================================================
    st.subheader("UA variants (top)")
    ua_tab = dff['User-Agent'].value_counts().reset_index().head(50)
    ua_tab.columns = ["User-Agent", "Count"]
    st.dataframe(ua_tab, use_container_width=True)

    st.subheader("Bot IPs (top)")
    ip_tab = dff['ClientIP'].value_counts().reset_index().head(200)
    ip_tab.columns = ["IP", "Count"]
    st.dataframe(ip_tab, use_container_width=True)

    # =================================================================
    # Export CSV / data
    # =================================================================
    st.subheader("Export")
    csv_bytes = dff.to_csv(index=False).encode('utf-8')
    st.download_button("Download filtered CSV", csv_bytes, file_name="bot_filtered.csv", mime="text/csv")

    # small report text
    findings = f"""Findings:
Total hits: {total_hits}
Unique pages: {unique_pages}
Unique IPs: {unique_ips}
% success (2xx/3xx): {pct_success}%
Top bot groups:\n{bot_group_counts.head(10).to_string(index=False)}
"""
    st.text_area("Auto-generated findings (editable)", value=findings, height=160)

else:
    st.info("Upload a per-bot log file in the sidebar to begin parsing. App parses in-stream and provides batch outputs without loading the entire file into memory.")
