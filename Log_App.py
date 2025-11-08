import streamlit as st
import pandas as pd
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
import hashlib
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", layout="wide")

# Minimal styling
st.markdown(
    """
    <style>
      body {background-color: #0f1117; color: #e8e8e8;}
      .stMetric {background: #1c1f2b; border-radius:12px; padding:10px;}
      div[data-testid="stDataFrame"] table {border-radius:10px; overflow:hidden;}
      .block-container {padding-top:2rem;}
    </style>
    """,
    unsafe_allow_html=True
)

st.title("Log Analyzer — Time-bucket fix")
uploaded_file = st.file_uploader("Upload log file (~3 GB max)", type=None)

# Bot patterns
generic_bot_patterns = [
    r'googlebot', r'bingbot', r'ahrefsbot', r'semrushbot', r'yandexbot',
    r'duckduckbot', r'crawler', r'spider', r'applebot'
]
ai_llm_bot_patterns = [
    r'gptbot', r'oai-searchbot', r'chatgpt-user', r'claudebot', r'claude-web',
    r'anthropic-ai', r'perplexitybot', r'perplexity-user', r'google-extended',
    r'applebot-extended', r'cohere-ai', r"ai2bot", r'ccbot', r'duckassistbot',
    r'youbot', r'mistralai-user'
]

def identify_bot(ua: str):
    if not ua:
        return None
    ua_l = ua.lower()
    for p in ai_llm_bot_patterns:
        if re.search(p, ua_l, flags=re.IGNORECASE):
            return "LLM/AI"
    for p in generic_bot_patterns:
        if re.search(p, ua_l, flags=re.IGNORECASE):
            return "Generic"
    return None

def extract_time_from_entry(entry: str):
    """Return a datetime or None. Accepts timezone offset if present."""
    m = re.search(r'\[([^\]]+)\]', entry)
    if not m:
        return None
    ts = m.group(1).strip()
    # try parse with timezone, then without
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except Exception:
            continue
    return None

# detect start of new logical entry (optional file:lineno:IP prefix)
start_re = re.compile(r'^(?:\S+:\d+:)?\d{1,3}(?:\.\d{1,3}){3}\s')
start_info_re = re.compile(r'^(?:(?P<file>\S+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s')

if uploaded_file is not None:
    raw_bytes = uploaded_file.read()
    text = None
    for enc_try in ("utf-8", "utf-16", "latin-1"):
        try:
            text = raw_bytes.decode(enc_try)
            break
        except Exception:
            text = None
    if text is None:
        text = raw_bytes.decode("utf-8", errors="ignore")

    # join wrapped lines into logical entries
    raw_lines = text.splitlines()
    entries = []
    buf = []
    for ln in raw_lines:
        ln = ln.rstrip("\r\n")
        if start_re.match(ln):
            if buf:
                entries.append(" ".join(buf).strip())
                buf = []
            buf.append(ln)
        else:
            if buf:
                buf.append(ln)
            else:
                entries.append(ln)
    if buf:
        entries.append(" ".join(buf).strip())

    # containers
    hits = []
    total_requests = 0
    generic_bot_requests = llm_bot_requests = others_requests = 0
    generic_bot_uas = {}
    llm_bot_uas = {}
    others_uas = {}

    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        total_requests += 1

        # file/line/ip
        m_start = start_info_re.match(entry)
        file_src = m_start.group("file") if m_start and m_start.group("file") else "-"
        lineno = m_start.group("lineno") if m_start and m_start.group("lineno") else "-"
        client_ip = m_start.group("ip") if m_start else "-"

        # quoted groups: request, referer, ua (tolerant)
        quoted = re.findall(r'"([^"]*)"', entry, flags=re.DOTALL)
        if len(quoted) >= 3:
            request = quoted[0].replace("\n", " ").strip()
            referer = quoted[1].replace("\n", " ").strip()
            ua = quoted[-1].replace("\n", " ").strip()
        elif len(quoted) == 2:
            request = quoted[0].replace("\n", " ").strip()
            referer = "-"
            ua = quoted[1].replace("\n", " ").strip()
        elif len(quoted) == 1:
            request = quoted[0].replace("\n", " ").strip()
            referer = "-"
            ua = "-"
        else:
            request = referer = ua = "-"

        ua = re.sub(r'\s+', ' ', ua).strip()

        # request parsing
        m_req = re.search(r'([A-Z]+)\s+(\S+)(?:\s+HTTP/(\d\.\d))?', request)
        method = m_req.group(1) if m_req else "-"
        path = m_req.group(2) if m_req else "-"
        http_ver = m_req.group(3) if (m_req and m_req.group(3)) else "-"

        # status and bytes
        m_status_bytes = re.search(r'"\s*(\d{3})\s+(-|\d+)', entry)
        if not m_status_bytes:
            m_status_bytes = re.search(r'\s(\d{3})\s+(-|\d+)', entry)
        status = m_status_bytes.group(1) if m_status_bytes else "-"
        bytes_sent = m_status_bytes.group(2) if m_status_bytes else "-"

        # TIME handling (fix): produce three things
        #  - Time         : original ISO string (keeps offset if present)
        #  - HourBucketLocal : ISO string rounded to hour, preserving original timezone offset (for display)
        #  - Time_parsed_utc : naive UTC datetime used for sorting/aggregation
        dt = extract_time_from_entry(entry)
        if dt:
            # original ISO (may include offset)
            time_iso = dt.isoformat()
            # Hour bucket in original timezone (preserve offset if present)
            try:
                hb_local = dt.replace(minute=0, second=0, microsecond=0).isoformat()
            except Exception:
                hb_local = dt.isoformat()
            # canonical UTC datetime (naive) for sorting
            if dt.tzinfo is not None:
                dt_utc = dt.astimezone(timezone.utc).replace(tzinfo=None)
            else:
                dt_utc = dt  # naive; treat as already UTC-like
            time_parsed_utc = dt_utc
            # hour bucket UTC (naive) if needed
            hb_utc = dt_utc.replace(minute=0, second=0, microsecond=0).isoformat()
        else:
            time_iso = "-"
            hb_local = "-"
            time_parsed_utc = None
            hb_utc = "-"

        # derived and meta fields
        status_class = f"{status[0]}xx" if status and status.isdigit() else "-"
        parsed_url = urlparse(path) if path and path != "-" else None
        path_clean = parsed_url.path if parsed_url and parsed_url.path else path
        query_string = parsed_url.query if parsed_url else ""
        query_params = dict(parse_qs(parsed_url.query)) if parsed_url and parsed_url.query else {}
        is_static = bool(re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)($|\?)', path, re.IGNORECASE))
        is_mobile = bool(re.search(r'\b(Mobile|iPhone|Android)\b', ua, re.I))
        section = path_clean.split('/')[1] if path_clean and path_clean.startswith('/') and len(path_clean.split('/')) > 1 else "-"

        sid_base = f"{client_ip}|{ua}|{hb_local}"
        session_id = hashlib.sha1(sid_base.encode('utf-8')).hexdigest()[:10]

        bot_type = identify_bot(ua)
        if bot_type == "Generic":
            generic_bot_requests += 1
            generic_bot_uas[ua] = generic_bot_uas.get(ua, 0) + 1
        elif bot_type == "LLM/AI":
            llm_bot_requests += 1
            llm_bot_uas[ua] = llm_bot_uas.get(ua, 0) + 1
        else:
            others_requests += 1
            others_uas[ua] = others_uas.get(ua, 0) + 1

        hits.append({
            "File": file_src,
            "LineNo": lineno,
            "ClientIP": client_ip,
            "Time": time_iso,
            "HourBucketLocal": hb_local,   # display-friendly, preserves original timezone offset if any
            "HourBucketUTC": hb_utc,       # canonical UTC hour (naive string)
            "Time_parsed": time_parsed_utc, # naive UTC datetime for sorting
            "Date": str(time_parsed_utc.date()) if time_parsed_utc is not None else "-",
            "Method": method,
            "Path": path,
            "PathClean": path_clean,
            "Query": query_string,
            "QueryParams": query_params,
            "Status": status,
            "StatusClass": status_class,
            "Bytes": bytes_sent,
            "Referer": referer,
            "User-Agent": ua,
            "Bot Type": bot_type or "Others",
            "IsStatic": is_static,
            "IsMobile": is_mobile,
            "Section": section,
            "SessionID": session_id,
            "HTTP_Version": http_ver
        })

        if total_requests % 200000 == 0:
            st.write(f"Processed {total_requests:,} lines…")

    # DataFrame
    df_hits = pd.DataFrame(hits)

    # Ensure Time_parsed is datetime dtype for sorting (coerce None -> NaT)
    if "Time_parsed" in df_hits.columns:
        df_hits["Time_parsed"] = pd.to_datetime(df_hits["Time_parsed"], errors="coerce")

    # Basic metrics + small views
    st.subheader("Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{len(df_hits):,}")
    c2.metric("Bot (Generic)", f"{generic_bot_requests:,}")
    c3.metric("Bot (LLM/AI)", f"{llm_bot_requests:,}")
    c4.metric("Others", f"{others_requests:,}")

    st.subheader("Detailed Hits")
    if not df_hits.empty:
        # sort by canonical UTC time when available
        if "Time_parsed" in df_hits.columns and df_hits["Time_parsed"].notna().any():
            df_hits = df_hits.sort_values(by=["Time_parsed", "Bot Type"], ascending=[True, True], na_position="last")
        else:
            df_hits = df_hits.sort_values(by=["Bot Type", "ClientIP"], ascending=[True, True])

        # display HourBucketLocal to show the hour in the log's original timezone
        display_cols = [
            "Bot Type", "Time", "HourBucketLocal", "ClientIP", "Method", "PathClean",
            "Status", "Bytes", "Referer", "User-Agent", "IsStatic", "IsMobile", "SessionID",
            "File", "LineNo", "HTTP_Version"
        ]
        display_cols = [c for c in display_cols if c in df_hits.columns]
        df_display = df_hits[display_cols].reset_index(drop=True)
        st.dataframe(df_display, use_container_width=True)
        csv_bytes = df_display.to_csv(index=False).encode("utf-8")
        st.download_button("Download CSV", csv_bytes, "hits.csv", "text/csv")
    else:
        st.info("No hits parsed.")
else:
    st.info("Please upload a log file.")
