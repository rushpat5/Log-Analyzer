import streamlit as st
import pandas as pd
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import hashlib
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

# Styling retained
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

st.title("🧠 Log Analyzer – Web Traffic & Bot Insights")
st.caption("Upload a server access log. Extracts time, client IP, referer, bytes, method, path, status class, UA-derived flags and session heuristics.")

uploaded_file = st.file_uploader("Upload log file (~3 GB max)", type=None)

# Bot patterns
generic_bot_patterns = [
    r'googlebot', r'bingbot', r'ahrefsbot', r'semrushbot', r'yandexbot',
    r'duckduckbot', r'crawler', r'spider', r'applebot'
]
ai_llm_bot_patterns = [
    r'gptbot', r'oai-searchbot', r'chatgpt-user', r'claudebot', r'claude-web',
    r'anthropic-ai', r'perplexitybot', r'perplexity-user', r'google-extended',
    r'applebot-extended', r'cohere-ai', r'ai2bot', r'ccbot', r'duckassistbot',
    r'youbot', r'mistralai-user'
]

def identify_bot(ua: str):
    if not ua:
        return None
    ua_l = ua.lower()
    for p in ai_llm_bot_patterns:
        if re.search(p, ua_l):
            return "LLM/AI"
    for p in generic_bot_patterns:
        if re.search(p, ua_l):
            return "Generic"
    return None

def extract_time_from_entry(entry: str):
    m = re.search(r'\[([^\]]+)\]', entry)
    if not m:
        return None
    ts = m.group(1).strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except Exception:
            continue
    return None

start_re = re.compile(r'^(?:\S+:\d+:)?\d{1,3}(?:\.\d{1,3}){3}\s')
start_info_re = re.compile(r'^(?:(?P<file>\S+):(?P<lineno>\d+):)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s')

if uploaded_file is not None:
    st.info("Processing file…")

    raw_bytes = uploaded_file.read()
    text = None
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            text = raw_bytes.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        text = raw_bytes.decode("utf-8", errors="ignore")

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

        m_start = start_info_re.match(entry)
        file_src = m_start.group("file") if m_start and m_start.group("file") else "-"
        lineno = m_start.group("lineno") if m_start and m_start.group("lineno") else "-"
        client_ip = m_start.group("ip") if m_start else "-"

        quoted = re.findall(r'"([^"]*)"', entry, flags=re.DOTALL)
        if len(quoted) >= 3:
            request = quoted[0].strip()
            referer = quoted[1].strip()
            ua = quoted[-1].strip()
        elif len(quoted) == 2:
            request = quoted[0].strip()
            referer = "-"
            ua = quoted[1].strip()
        elif len(quoted) == 1:
            request = quoted[0].strip()
            referer = "-"
            ua = "-"
        else:
            request = referer = ua = "-"

        ua = re.sub(r'\s+', ' ', ua).strip()

        m_req = re.search(r'([A-Z]+)\s+(\S+)(?:\s+HTTP/(\d\.\d))?', request)
        method = m_req.group(1) if m_req else "-"
        path = m_req.group(2) if m_req else "-"
        http_ver = m_req.group(3) if (m_req and m_req.group(3)) else "-"

        m_status_bytes = re.search(r'"\s*(\d{3})\s+(-|\d+)', entry)
        if not m_status_bytes:
            m_status_bytes = re.search(r'\s(\d{3})\s+(-|\d+)', entry)
        status = m_status_bytes.group(1) if m_status_bytes else "-"
        bytes_sent = m_status_bytes.group(2) if m_status_bytes else "-"

        # === Fixed time parsing logic ===
        dt = extract_time_from_entry(entry)
        if dt:
            time_iso = dt.isoformat()  # Keep full timezone
            # Keep local (log) time — do not convert to UTC — keep minutes and seconds
            if dt.tzinfo is not None:
                dt_local = dt.replace(tzinfo=None)
            else:
                dt_local = dt
            time_parsed = dt_local
            hour_bucket = dt_local.replace(microsecond=0)  # keep hh:mm:ss
            date_bucket = dt_local.date()
        else:
            time_iso = "-"
            time_parsed = None
            hour_bucket = None
            date_bucket = None
        # ================================

        status_class = f"{status[0]}xx" if status and status.isdigit() else "-"
        parsed_url = urlparse(path) if path and path != "-" else None
        path_clean = parsed_url.path if parsed_url and parsed_url.path else path
        query_string = parsed_url.query if parsed_url else ""
        query_params = dict(parse_qs(parsed_url.query)) if parsed_url and parsed_url.query else {}
        is_static = bool(re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)($|\?)', path, re.IGNORECASE))
        is_mobile = bool(re.search(r'\b(Mobile|iPhone|Android)\b', ua, re.I))
        section = path_clean.split('/')[1] if path_clean and path_clean.startswith('/') and len(path_clean.split('/')) > 1 else "-"

        sid_base = f"{client_ip}|{ua}|{hour_bucket.isoformat() if hour_bucket else time_iso}"
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
            "Time_parsed": time_parsed,
            "Date": str(date_bucket) if date_bucket else "-",
            "HourBucket": hour_bucket.isoformat() if hour_bucket else "-",
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

    df_hits = pd.DataFrame(hits)
    if "Time_parsed" in df_hits.columns:
        df_hits["Time_parsed"] = pd.to_datetime(df_hits["Time_parsed"], errors="coerce")

    st.subheader("Key Metrics")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Requests", f"{total_requests:,}")
    c2.metric("Bot (Generic)", f"{generic_bot_requests:,}")
    c3.metric("Bot (LLM/AI)", f"{llm_bot_requests:,}")
    c4.metric("Others", f"{others_requests:,}")
    c5.metric("Unique IPs", f"{df_hits['ClientIP'].nunique():,}" if not df_hits.empty else "0")

    st.subheader("Traffic Composition")
    df_comp = pd.DataFrame({
        "Category": ["Bots (Generic)", "Bots (LLM/AI)", "Others"],
        "Count": [generic_bot_requests, llm_bot_requests, others_requests]
    })
    fig = px.pie(df_comp, names="Category", values="Count", title="Requests by Category")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top Referers")
    top_ref = df_hits["Referer"].replace("-", pd.NA).value_counts().reset_index().head(10)
    top_ref.columns = ["Referer", "Count"]
    st.dataframe(top_ref, use_container_width=True)

    st.subheader("Top IPs")
    top_ips = df_hits["ClientIP"].replace("-", pd.NA).value_counts().reset_index().head(10)
    top_ips.columns = ["ClientIP", "Count"]
    st.dataframe(top_ips, use_container_width=True)

    st.subheader("Static vs Dynamic Requests")
    static_counts = df_hits["IsStatic"].value_counts().rename_axis("IsStatic").reset_index(name="Count")
    static_counts["Label"] = static_counts["IsStatic"].apply(lambda v: "Static" if v else "Dynamic")
    fig2 = px.pie(static_counts, names="Label", values="Count", title="Static vs Dynamic")
    st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Detailed Hits (filtered view)")
    if not df_hits.empty:
        if df_hits["Time_parsed"].notna().any():
            df_hits = df_hits.sort_values(by=["Time_parsed"], ascending=True)
        df_display = df_hits.reset_index(drop=True)
        st.dataframe(df_display, use_container_width=True)
        csv_bytes = df_display.to_csv(index=False).encode("utf-8")
        st.download_button("Download Detailed CSV", csv_bytes, "detailed_hits.csv", "text/csv")
    else:
        st.info("No parsed hits.")
else:
    st.warning("Please upload a log file to begin analysis.")
