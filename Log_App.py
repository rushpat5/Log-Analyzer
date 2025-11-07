import streamlit as st
import pandas as pd
import io
import re
import unicodedata
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

st.markdown("""
<style>
body {background-color:#0f1117;color:#e8e8e8;}
.stMetric {background:#1c1f2b;border-radius:12px;padding:10px;}
div[data-testid="stDataFrame"] table {border-radius:10px;overflow:hidden;}
.block-container {padding-top:2rem;}
</style>
""", unsafe_allow_html=True)

st.title("🧠 Log Analyzer – Web Traffic & Bot Insights")
st.caption("Detects bots, lists URLs and status codes from real logs (Googlebot/2.1 supported).")

uploaded_file = st.file_uploader("Upload log file (~3 GB max)", type=None)

generic_bot_patterns = [
    "googlebot", "bingbot", "ahrefsbot", "semrushbot", "yandexbot",
    "duckduckbot", "crawler", "spider"
]
ai_llm_bot_patterns = [
    "gptbot", "oai-searchbot", "chatgpt-user", "claudebot", "claude-web",
    "anthropic-ai", "perplexitybot", "perplexity-user", "google-extended",
    "applebot-extended", "cohere-ai", "ai2bot", "ccbot", "duckassistbot",
    "youbot", "mistralai-user"
]

def normalize(s):
    # clean to plain ascii
    s = s.strip()
    s = unicodedata.normalize("NFKD", s)
    return re.sub(r"[^\x00-\x7F]", "", s).lower()

def identify_bot(ua: str):
    ua_norm = normalize(ua)
    for p in ai_llm_bot_patterns:
        if p in ua_norm:
            return "LLM/AI"
    for p in generic_bot_patterns:
        if p in ua_norm:
            return "Generic"
    return None

if uploaded_file:
    st.info("⏳ Processing file — please wait…")

    text_stream = io.TextIOWrapper(uploaded_file, encoding="latin-1", errors="ignore")

    total = generic = llm = others = 0
    generic_uas, llm_uas, others_uas = {}, {}, {}
    bot_hits = []

    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})[^"]*"(?:[^"]*)"\s+"(?P<agent>[^"]*)"'
    )

    for raw in text_stream:
        total += 1
        line = raw.strip()
        if not line:
            continue

        if ":" in line and line.split(":")[0].endswith(".log"):
            parts = line.split(":", 2)
            if len(parts) == 3:
                line = parts[2].strip()

        m = log_pattern.search(line)
        if not m:
            others += 1
            continue

        ua = m.group("agent").strip()
        ua_norm = normalize(ua)
        path = m.group("path")
        status = m.group("status")

        bot_type = identify_bot(ua)
        if bot_type == "Generic":
            generic += 1
            generic_uas[ua] = generic_uas.get(ua, 0) + 1
            bot_hits.append({"Bot Type": "Generic", "User-Agent": ua, "URL": path, "Status": status})
        elif bot_type == "LLM/AI":
            llm += 1
            llm_uas[ua] = llm_uas.get(ua, 0) + 1
            bot_hits.append({"Bot Type": "LLM/AI", "User-Agent": ua, "URL": path, "Status": status})
        else:
            others += 1
            others_uas[ua] = others_uas.get(ua, 0) + 1

        if total % 200000 == 0:
            st.write(f"Processed {total:,} lines…")

    # metrics
    st.subheader("📌 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{total:,}")
    c2.metric("Bot Requests (Generic)", f"{generic:,}")
    c3.metric("Bot Requests (LLM/AI)", f"{llm:,}")
    c4.metric("Others (non-matched)", f"{others:,}")

    df_comp = pd.DataFrame({
        "Category": ["Bots (Generic)", "Bots (LLM/AI)", "Others"],
        "Count": [generic, llm, others]
    })
    fig = px.pie(df_comp, names="Category", values="Count",
                 color_discrete_sequence=["#3498db", "#9b59b6", "#2ecc71"],
                 title="Requests by Category")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("🔍 Detailed Bot Activity")
    df_hits = pd.DataFrame(bot_hits)
    if not df_hits.empty:
        df_hits = df_hits.sort_values(by=["Bot Type", "User-Agent", "URL"]).reset_index(drop=True)
        st.dataframe(df_hits, use_container_width=True)
        st.download_button("Download Bot Hits CSV",
                           df_hits.to_csv(index=False).encode("utf-8"),
                           "bot_hits.csv", "text/csv")
    else:
        st.info("No bot hits detected in this log file.")
else:
    st.warning("Please upload a log file to begin analysis.")
