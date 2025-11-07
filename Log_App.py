import streamlit as st
import pandas as pd
import io
import re
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

# Minimal styling kept similar to original app
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
st.caption("Upload a web server log file. Detects bots (including Applebot) and lists URLs + status codes. Parser is conservative and intends minimal change to original behavior.")

uploaded_file = st.file_uploader(
    "Upload log file (~3 GB max)",
    type=None,
    help="Upload any web server log file (e.g. access.log, access.log.2025.09.18, .txt, .gz(not supported here))."
)

# Keep original bot lists and add Applebot
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
bot_regex = re.compile("|".join(generic_bot_patterns + ai_llm_bot_patterns), flags=re.IGNORECASE)

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

if uploaded_file is not None:
    st.info("⏳ Processing file — please wait…")

    raw_bytes = uploaded_file.read()
    # decode fallback without external deps
    for enc_try in ("utf-8", "utf-16", "latin-1"):
        try:
            text = raw_bytes.decode(enc_try)
            break
        except Exception:
            text = None
    if text is None:
        text = raw_bytes.decode("utf-8", errors="ignore")

    # --- Conservative assembly of logical entries (minimal change) ---
    # Approach:
    # 1) Treat lines starting with IP (optionally prefixed by file:lineno:) as new entry starts.
    # 2) Accumulate subsequent continuation lines until we have at least 3 quoted groups
    #    (combined log format normally contains 3 quoted fields: request, referer, user-agent).
    # This preserves behavior for standard logs while correctly joining wrapped UAs/referrers.
    raw_lines = text.splitlines()
    entries = []
    buf = []
    # regex that detects a new line starting with optional filename:lineno: then IP
    start_re = re.compile(r'^(?:\S+:\d+:)?\d{1,3}(?:\.\d{1,3}){3}\s')
    for ln in raw_lines:
        ln = ln.rstrip("\r\n")
        if start_re.match(ln):
            # new record
            if buf:
                merged = " ".join(buf).strip()
                # ensure the merged entry has at least three quoted fields; if not, keep merging (defensive)
                if len(re.findall(r'"', merged)) >= 6 or True:
                    entries.append(merged)
                else:
                    entries.append(merged)  # still append but it's rare
                buf = []
            buf.append(ln)
        else:
            # continuation line (likely wrapped UA or referrer), append to current buffer if exists
            if buf:
                buf.append(ln)
            else:
                # no active buffer — treat as its own entry to avoid dropping data
                entries.append(ln)
    if buf:
        entries.append(" ".join(buf).strip())

    # --- Parsing each logical entry with tolerant extraction ---
    total_requests = 0
    generic_bot_requests = 0
    llm_bot_requests = 0
    others_requests = 0

    generic_bot_uas = {}
    llm_bot_uas = {}
    others_uas = {}
    bot_hits = []

    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        total_requests += 1

        # Extract all quoted groups conservatively (handles wrapped quotes because we joined lines)
        quoted = re.findall(r'"([^"]*)"', entry, flags=re.DOTALL)
        # Request typically first quoted, user-agent typically last quoted
        request = quoted[0] if len(quoted) >= 1 else ""
        ua = quoted[-1] if len(quoted) >= 1 else ""

        # Clean UA: collapse whitespace/newlines
        ua = re.sub(r'\s+', ' ', ua).strip()

        # Extract method and path from the request string
        m_req = re.search(r'([A-Z]+)\s+(\S+)', request)
        path = m_req.group(2) if m_req else "-"

        # Extract status code: look for the 3-digit code after the request or anywhere in entry
        status_match = re.search(r'"\s*(\d{3})\s', entry)
        if not status_match:
            status_match = re.search(r'\s(\d{3})\s', entry)
        status = status_match.group(1) if status_match else "-"

        bot_type = identify_bot(ua)
        if bot_type == "Generic":
            generic_bot_requests += 1
            generic_bot_uas[ua] = generic_bot_uas.get(ua, 0) + 1
            bot_hits.append({"Bot Type": "Generic", "User-Agent": ua, "URL": path, "Status": status})
        elif bot_type == "LLM/AI":
            llm_bot_requests += 1
            llm_bot_uas[ua] = llm_bot_uas.get(ua, 0) + 1
            bot_hits.append({"Bot Type": "LLM/AI", "User-Agent": ua, "URL": path, "Status": status})
        else:
            others_requests += 1
            others_uas[ua] = others_uas.get(ua, 0) + 1
            bot_hits.append({"Bot Type": "Others", "User-Agent": ua, "URL": path, "Status": status})

        # light progress message for big files
        if total_requests % 200000 == 0:
            st.write(f"Processed {total_requests:,} lines…")

    # --- Output / Dashboard ---
    st.subheader("📌 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{total_requests:,}")
    c2.metric("Bot Requests (Generic)", f"{generic_bot_requests:,}")
    c3.metric("Bot Requests (LLM/AI)", f"{llm_bot_requests:,}")
    c4.metric("Others (non-matched)", f"{others_requests:,}")

    st.subheader("📊 Traffic Composition")
    df_comp = pd.DataFrame({
        "Category": ["Bots (Generic)", "Bots (LLM/AI)", "Others"],
        "Count": [generic_bot_requests, llm_bot_requests, others_requests]
    })
    fig = px.pie(
        df_comp,
        names="Category",
        values="Count",
        color_discrete_sequence=["#3498db", "#9b59b6", "#2ecc71"],
        title="Requests by Category"
    )
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("🤖 All Generic Bot User-Agents")
    df_generic = pd.DataFrame(list(generic_bot_uas.items()), columns=["User-Agent","Count"]) \
        .sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_generic, use_container_width=True)

    st.subheader("🧩 All LLM/AI Bot User-Agents")
    df_llm = pd.DataFrame(list(llm_bot_uas.items()), columns=["User-Agent","Count"]) \
        .sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_llm, use_container_width=True)

    st.subheader("🌀 All Others (non-matched) User-Agents")
    df_others = pd.DataFrame(list(others_uas.items()), columns=["User-Agent","Count"]) \
        .sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_others, use_container_width=True)

    st.subheader("🔍 Detailed Bot Activity (Bot Type · User-Agent · URL · Status)")
    df_hits = pd.DataFrame(bot_hits)
    if not df_hits.empty:
        df_hits = df_hits.sort_values(by=["Bot Type","User-Agent","URL","Status"], ascending=[True,True,True,True]).reset_index(drop=True)
        st.dataframe(df_hits, use_container_width=True)
        csv_hits = df_hits.to_csv(index=False).encode('utf-8')
        st.download_button("Download Detailed Bot Hits CSV", csv_hits, "bot_hits.csv", "text/csv")
    else:
        st.info("No bot hits detected in this log file.")

    st.success("✅ Analysis complete.")
else:
    st.warning("Please upload a log file to begin analysis.")
