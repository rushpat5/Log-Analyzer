import streamlit as st
import pandas as pd
import io
import re
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

# --- minimal styling (keeps original look & layout) ---
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
st.caption("Upload a web server log file. Detects bots and lists URLs + status codes. Minimal changes to parser; preserves behavior for other files.")

uploaded_file = st.file_uploader(
    "Upload log file (~3 GB max)",
    type=None,
    help="Upload any web server log file (access.log, *.log, *.txt)."
)

# --- bot lists (added Applebot + kept original patterns) ---
generic_bot_patterns = [
    r"googlebot", r"bingbot", r"ahrefsbot", r"semrushbot", r"yandexbot",
    r"duckduckbot", r"crawler", r"spider", r"applebot"
]
ai_llm_bot_patterns = [
    r"gptbot", r"oai-searchbot", r"chatgpt-user", r"claudebot", r"claude-web",
    r"anthropic-ai", r"perplexitybot", r"perplexity-user", r"google-extended",
    r"applebot-extended", r"cohere-ai", r"ai2bot", r"ccbot", r"duckassistbot",
    r"youbot", r"mistralai-user"
]

def identify_bot(ua: str):
    s = (ua or "").lower()
    for p in ai_llm_bot_patterns:
        if re.search(p, s, flags=re.IGNORECASE):
            return "LLM/AI"
    for p in generic_bot_patterns:
        if re.search(p, s, flags=re.IGNORECASE):
            return "Generic"
    return None

if uploaded_file is not None:
    st.info("⏳ Processing file — please wait…")

    # --- robust decode without extra deps (try utf-8 then latin-1) ---
    raw = uploaded_file.read()
    try:
        text = raw.decode("utf-8")
    except Exception:
        try:
            text = raw.decode("latin-1")
        except Exception:
            text = raw.decode("utf-8", errors="ignore")

    # --- MINIMAL CHANGE: merge continuation/wrapped lines into logical log entries ---
    # We only change how we assemble lines. The parsing logic below remains simple and tolerant.
    lines = text.splitlines()

    entries = []
    current = []
    # detect start of a new log entry: common prefixes used in your files
    start_re = re.compile(r'^(?:\S+\.log:\d+:)?\d{1,3}(?:\.\d{1,3}){3}\s')  # optional fileprefix then IP
    for ln in lines:
        ln_stripped = ln.rstrip("\r\n")
        if start_re.match(ln_stripped):
            # start of a new logical entry
            if current:
                entries.append(" ".join(current))
                current = []
            current.append(ln_stripped)
        else:
            # continuation line (likely wrapped UA/referrer). Append to previous entry if present,
            # otherwise keep as a standalone line (to avoid dropping lines).
            if current:
                current.append(ln_stripped)
            else:
                # no prior start detected -> treat as own entry (defensive)
                entries.append(ln_stripped)
    if current:
        entries.append(" ".join(current))

    # --- Parse each logical entry conservatively ---
    total_requests = 0
    generic_bot_requests = 0
    llm_bot_requests = 0
    others_requests = 0

    generic_bot_uas = {}
    llm_bot_uas = {}
    others_uas = {}

    bot_hits = []  # will store dicts: Bot Type, User-Agent, URL, Status

    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        total_requests += 1

        # Extract quoted substrings. Combined log format puts request, referer, agent as quoted groups.
        quoted = re.findall(r'"(.*?)"', entry, flags=re.DOTALL)
        # Heuristic:
        # - request line is usually the first quoted group ("GET /path HTTP/1.1")
        # - user-agent is usually the last quoted group (but may be wrapped into multiple lines)
        request = quoted[0] if len(quoted) >= 1 else ""
        ua = quoted[-1] if len(quoted) >= 1 else ""

        # extract method/path from request
        m = re.search(r'^([A-Z]+)\s+(\S+)', request)
        path = m.group(2) if m else "-"
        # extract status code (first 3-digit number after request)
        status_m = re.search(r'"\s*(\d{3})\s', entry) or re.search(r'\s(\d{3})\s', entry)
        status = status_m.group(1) if status_m else "-"

        # normalize UA (strip excessive whitespace/newlines)
        ua = re.sub(r'\s+', ' ', ua).strip()

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
            # also record Others' URLs so they are visible
            bot_hits.append({"Bot Type": "Others", "User-Agent": ua, "URL": path, "Status": status})

        # light progress indicator for very large files (no heavy UI churn)
        if total_requests % 200000 == 0:
            st.write(f"Processed {total_requests:,} lines…")

    # --- Metrics / Dashboard (keeps original layout) ---
    st.subheader("📌 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{total_requests:,}")
    c2.metric("Bot Requests (Generic)", f"{generic_bot_requests:,}")
    c3.metric("Bot Requests (LLM/AI)", f"{llm_bot_requests:,}")
    c4.metric("Others (non-matched)", f"{others_requests:,}")

    # Pie chart
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

    # Generic bots table
    st.subheader("🤖 All Generic Bot User-Agents")
    df_generic = pd.DataFrame(list(generic_bot_uas.items()), columns=["User-Agent","Count"]) \
        .sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_generic, use_container_width=True)

    # LLM bots table
    st.subheader("🧩 All LLM/AI Bot User-Agents")
    df_llm = pd.DataFrame(list(llm_bot_uas.items()), columns=["User-Agent","Count"]) \
        .sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_llm, use_container_width=True)

    # Others table (now includes UA -> Count and we list their URLs separately)
    st.subheader("🌀 All Others (non-matched) User-Agents")
    df_others = pd.DataFrame(list(others_uas.items()), columns=["User-Agent","Count"]) \
        .sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_others, use_container_width=True)

    # Detailed bot hits (includes Others with URLs and status codes)
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
