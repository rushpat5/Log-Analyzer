import streamlit as st
import pandas as pd
import io
import re
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

st.title("🧠 Log Analyzer – Web Traffic & Bot Insights")
st.caption("Detects bots (e.g. Googlebot, GPTBot) and lists URLs + status codes, even with multiline logs.")

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

def identify_bot(ua: str):
    ua_lower = ua.lower()
    for p in ai_llm_bot_patterns:
        if p in ua_lower:
            return "LLM/AI"
    for p in generic_bot_patterns:
        if p in ua_lower:
            return "Generic"
    return None

if uploaded_file:
    st.info("⏳ Processing file — please wait…")
    text_stream = io.TextIOWrapper(uploaded_file, encoding="latin-1", errors="ignore")

    # combine physical lines into complete log entries
    buffer = []
    entries = []
    for line in text_stream:
        line = line.rstrip("\n")
        if line.startswith("access.log") or re.match(r'^\d+\.\d+\.\d+\.\d+', line):
            # start of a new log entry
            if buffer:
                entries.append(" ".join(buffer))
                buffer = []
            buffer.append(line)
        else:
            # continuation line (likely user-agent)
            buffer.append(line)
    if buffer:
        entries.append(" ".join(buffer))

    total = generic = llm = others = 0
    bot_hits = []

    pattern = re.compile(r'"([A-Z]+)\s+(\S+)\s+HTTP[^"]*"\s+(\d{3})[^"]*"(?:[^"]*)"\s*"([^"]+)"')

    for entry in entries:
        total += 1
        # strip prefix like access.log:####
        if ":" in entry and entry.split(":")[0].endswith(".log"):
            entry = entry.split(":", 2)[-1].strip()

        m = pattern.search(entry)
        if not m:
            others += 1
            continue

        method, path, status, ua = m.groups()
        ua = ua.strip()

        bot_type = identify_bot(ua)
        if bot_type == "Generic":
            generic += 1
            bot_hits.append({"Bot Type": "Generic", "User-Agent": ua, "URL": path, "Status": status})
        elif bot_type == "LLM/AI":
            llm += 1
            bot_hits.append({"Bot Type": "LLM/AI", "User-Agent": ua, "URL": path, "Status": status})
        else:
            others += 1

    # display
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
        st.dataframe(df_hits, use_container_width=True)
        csv_hits = df_hits.to_csv(index=False).encode("utf-8")
        st.download_button("Download Bot Hits CSV", csv_hits, "bot_hits.csv", "text/csv")
    else:
        st.info("No bot hits detected in this log file.")
else:
    st.warning("Please upload a log file to begin analysis.")
