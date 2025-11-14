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
from typing import Iterator, Tuple, Optional, Dict, Any

# =====================================================================
# PAGE CONFIG
# =====================================================================
st.set_page_config(page_title="Bot-Focused Log Analyzer", layout="wide")

# =====================================================================
# VERIFIED TOP BOT UA PATTERNS (no invention, no speculation)
# =====================================================================
VERIFIED_TOP_BOTS = [

    # Search engine crawlers
    r'\bGooglebot\b',
    r'\bGooglebot-Image\b',
    r'\bGooglebot-News\b',
    r'\bGooglebot-Video\b',
    r'\bGooglebot-Mobile\b',
    r'\bGoogle-Extended\b',
    r'\bBingbot\b',
    r'\bBingPreview\b',
    r'\bDuckDuckBot\b',
    r'\bBaiduspider\b',
    r'\bYandexBot\b',
    r'\bYandexImages\b',
    r'\bYisouSpider\b',
    r'\bMojeekBot\b',
    r'\bSogou web spider\b',
    r'\b360Spider\b',
    r'\bCoccocbot\b',
    r'\bCoccocbot-web\b',
    r'\bSemrushBot\b',

    # AI search crawlers
    r'\bPerplexityBot\b',
    r'\bOAI-SearchBot\b',
    r'\bClaude-SearchBot\b',
    r'\bYouBot\b',
    r'\bAddSearchBot\b',
    r'\bAmazonbot\b',
    r'\bPetalBot\b',

    # AI data scrapers
    r'\bGPTBot\b',
    r'\bBytespider\b',
    r'\bCCBot\b',
    r'\bDiffbot\b',
    r'\bomgili\b',
    r'\bApplebot-Extended\b',
    r'\bmeta-externalfetcher\b',
    r'\bmeta-externalagent\b',
    r'\bwebzio-extended\b',

    # AI/LLM user-driven fetchers
    r'\bChatGPT-User\b',
    r'\bClaude-User\b',
    r'\bClaudeBot\b',
    r'\bPerplexity-User\b',
    r'\bMistralAI-User\b',

    # Enterprise / misc
    r'\bAhrefsBot\b',
    r'\bMJ12bot\b',
    r'\bfacebookexternalhit\b',
    r'\bSlackbot\b',
    r'\bTwitterbot\b',
]

# Placeholders for extension
CUSTOM_TOP50_EXTENSIONS = [
    # Add additional UA tokens exactly as they appear in real logs.
]

ALL_BOT_PATTERNS = VERIFIED_TOP_BOTS + CUSTOM_TOP50_EXTENSIONS

AI_LLM_BOT_PATTERNS = [
    r'\bGPTBot\b',
    r'\bChatGPT-User\b',
    r'\bOAI-SearchBot\b',
    r'\bClaude-User\b',
    r'\bClaudeBot\b',
    r'\bClaude-SearchBot\b',
    r'\bPerplexityBot\b',
    r'\bPerplexity-User\b',
    r'\bMistralAI-User\b',
    r'\bBytespider\b',
    r'\bCCBot\b',
    r'\bDiffbot\b',
    r'\bomgili\b',
    r'\bApplebot-Extended\b',
    r'\bmeta-externalagent\b',
    r'\bmeta-externalfetcher\b',
]

GENERIC_BOT_PATTERNS = [p for p in ALL_BOT_PATTERNS if p not in AI_LLM_BOT_PATTERNS]

AI_LLM_BOT_RE = re.compile("|".join(AI_LLM_BOT_PATTERNS), re.I)
GENERIC_BOT_RE = re.compile("|".join(GENERIC_BOT_PATTERNS), re.I)

# =====================================================================
# REGEXES AND CONSTANTS
# =====================================================================
START_INFO_RE = re.compile(
    r'^(?:(?P<file>[^:\s]+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s'
)

COMBINED_LOG_RE = re.compile(
    r'(?P<remote>\S+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"',
    flags=re.DOTALL,
)

COMMON_LOG_RE = re.compile(
    r'(?P<remote>\S+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)',
    flags=re.DOTALL,
)

STATIC_RE = re.compile(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)($|\?)', re.I)

SESSION_TIMEOUT_MINUTES = 30

# =====================================================================
# UTILITY FUNCTIONS
# =====================================================================
def compute_sha256_of_bytes(b: bytes) -> str:
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

def text_line_iterator_from_bytes(b: bytes, encoding: Optional[str] = None) -> Iterator[str]:
    if encoding is None:
        encoding = detect_encoding_from_sample(b)
    bio = io.BytesIO(b)
    reader = codecs.getreader(encoding)(bio, errors="replace")
    for line in reader:
        yield line.rstrip("\n").rstrip("\r")

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

def anonymize_ip(ip: str, salt: str):
    if not ip or ip == "-":
        return ip
    h = hashlib.sha256((salt + "|" + ip).encode()).hexdigest()
    return h[:16]

# =====================================================================
# BOT IDENTIFICATION
# =====================================================================
def identify_bot_from_ua(ua: str) -> Optional[str]:
    if not ua or ua.strip() == "-":
        return None
    if AI_LLM_BOT_RE.search(ua):
        return "AI/LLM"
    if GENERIC_BOT_RE.search(ua):
        return "GenericBot"
    return None

# =====================================================================
# PARSING
# =====================================================================
def parse_single_entry(entry: str) -> Optional[dict]:
    try:
        m_start = START_INFO_RE.match(entry)
        file_src = m_start.group("file") if m_start and m_start.group("file") else "-"
        lineno = m_start.group("lineno") if m_start and m_start.group("lineno") else "-"
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
        section = path_clean.split('/')[1] if path_clean.startswith('/') and len(path_clean.split('/')) > 1 else "-"
        bot_label = identify_bot_from_ua(ua) or "Others"

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
            "BotType": bot_label,
            "IsStatic": is_static,
            "Section": section,
            "HTTP_Version": http_ver,
            "RawEntry": entry,
        }
    except Exception:
        return None

def parse_log_stream(lines: Iterator[str]):
    rows = []
    diag = {"total": 0, "parsed": 0, "failed": 0, "samples": []}
    buf = []

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

# =====================================================================
# CACHED PARSE
# =====================================================================
@st.cache_data(show_spinner=False)
def cached_parse(file_hash, b):
    enc = detect_encoding_from_sample(b)
    lines = text_line_iterator_from_bytes(b, encoding=enc)
    rows, diag = parse_log_stream(lines)
    df = pd.DataFrame(rows) if rows else pd.DataFrame()
    return df, diag, enc

# =====================================================================
# UI
# =====================================================================
st.title("Bot-Focused Log Analyzer")
uploaded_file = st.file_uploader("Upload log file (<=200 MB)", type=None)

if uploaded_file:
    b = uploaded_file.read()
    h = compute_sha256_of_bytes(b)
    df, diag, enc = cached_parse(h, b)

    st.subheader("Parsing diagnostics")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total lines", diag.get("total", 0))
    c2.metric("Parsed", diag.get("parsed", 0))
    c3.metric("Failed", diag.get("failed", 0))
    if diag.get("samples"):
        for s in diag["samples"]:
            st.code(s)

    if df.empty:
        st.warning("No parsed entries.")
    else:
        st.subheader("Bot Overview")
        df["Time_parsed"] = pd.to_datetime(df["Time_parsed"], errors="coerce")
        df["Hour"] = df["Time_parsed"].dt.hour.fillna(-1).astype(int)

        bot_summary = df.groupby("BotType").agg(
            Hits=("BotType", "size"),
            UniqueIPs=("ClientIP", "nunique"),
            FirstSeen=("Time_parsed", "min"),
            LastSeen=("Time_parsed", "max"),
        ).sort_values("Hits", ascending=False).reset_index()

        st.dataframe(bot_summary, use_container_width=True)

        st.subheader("Hourly distribution")
        bot_sel = st.selectbox("Bot", bot_summary["BotType"].unique())
        dfb = df[df["BotType"] == bot_sel]
        hdist = dfb.groupby("Hour").size().reset_index(name="Count")
        hdist = hdist.sort_values("Hour")
        fig = px.bar(hdist, x="Hour", y="Count")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Status distribution")
        sb = df.groupby(["BotType", "StatusClass"]).size().reset_index(name="Count")
        fig2 = px.bar(sb, x="BotType", y="Count", color="StatusClass", barmode="stack")
        st.plotly_chart(fig2, use_container_width=True)

        st.subheader("Top URLs for bot")
        top_urls = dfb["PathClean"].value_counts().reset_index().head(20)
        top_urls.columns = ["Path", "Hits"]
        st.dataframe(top_urls, use_container_width=True)

        st.subheader("User-Agent variants")
        ua_var = dfb["User-Agent"].value_counts().reset_index().head(20)
        ua_var.columns = ["User-Agent", "Count"]
        st.dataframe(ua_var, use_container_width=True)

        st.subheader("Bot IPs")
        iptab = dfb["ClientIP"].value_counts().reset_index().head(50)
        iptab.columns = ["IP", "Count"]
        st.dataframe(iptab, use_container_width=True)

        st.subheader("Bot Hit Log")
        cols = ["Time", "ClientIP", "Method", "PathClean", "Status", "User-Agent"]
        st.dataframe(dfb[cols].reset_index(drop=True), use_container_width=True)

        st.subheader("Export")
        csv = dfb.to_csv(index=False).encode()
        st.download_button("Download bot CSV", csv, file_name=f"{bot_sel}.csv")

else:
    st.info("Upload a log file to begin.")
