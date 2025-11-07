import streamlit as st
import pandas as pd
import re

# -----------------------------
# Load and normalize file
# -----------------------------
def load_log_file(uploaded_file):
    try:
        text = uploaded_file.read().decode("utf-8", errors="ignore")
    except Exception:
        uploaded_file.seek(0)
        text = uploaded_file.read().decode("latin-1", errors="ignore")
    # Merge broken multi-line log entries
    text = re.sub(r"\n(?=\S+- - \[)", "\n", text)  # keep new records intact
    text = text.replace("\n", " ")  # flatten wrapped lines
    text = re.sub(r'(?<=HTTP/1\.[01]")\s*', "\n", text)  # separate distinct requests
    return text.splitlines()

# -----------------------------
# Bot detection patterns
# -----------------------------
bot_patterns = {
    "Googlebot": r"googlebot",
    "Bingbot": r"bingbot",
    "Applebot": r"applebot",
    "GPTBot": r"gptbot",
    "ClaudeBot": r"claudebot",
    "CCBot": r"ccbot",
    "DuckDuckBot": r"duckduckbot",
    "YandexBot": r"yandexbot",
    "Baiduspider": r"baiduspider",
}

def classify_bot(user_agent):
    for bot, pattern in bot_patterns.items():
        if re.search(pattern, user_agent, re.IGNORECASE):
            return bot
    return "Others"

# -----------------------------
# Flexible Log Parser
# -----------------------------
def parse_log(lines):
    data = []
    log_pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+- - \[(?P<datetime>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>HTTP/[0-9.]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<useragent>[^"]*)"'
    )

    for line in lines:
        m = re.search(log_pattern, line)
        if m:
            data.append(m.groupdict())
    return pd.DataFrame(data)

# -----------------------------
# Streamlit layout
# -----------------------------
st.set_page_config(page_title="Bot Log Analyzer", layout="wide")
st.title("📊 Advanced Bot Log Analyzer (Robust for Applebot Logs)")

uploaded_file = st.file_uploader("Upload access log file", type=["log", "txt"])

if uploaded_file:
    with st.spinner("Processing log file..."):
        lines = load_log_file(uploaded_file)
        df = parse_log(lines)

    if not df.empty:
        df["Bot Type"] = df["useragent"].apply(classify_bot)

        total_requests = len(df)
        others_count = (df["Bot Type"] == "Others").sum()
        ai_count = df["Bot Type"].str.contains("GPT|Claude|CCBot", case=False).sum()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Requests", total_requests)
        col2.metric("Bot Requests (Known)", total_requests - others_count)
        col3.metric("Bot Requests (LLM/AI)", ai_count)
        col4.metric("Others (Non-matched)", others_count)

        st.subheader("Requests by Category")
        summary_data = (
            df["Bot Type"].value_counts().reset_index()
            .rename(columns={"index": "Bot Type", "Bot Type": "Count"})
        )
        st.bar_chart(summary_data.set_index("Bot Type"))

        st.subheader("🔍 Detailed Bot Activity (All Bots + Others)")
        detailed = (
            df.groupby(["Bot Type", "useragent", "url", "status"])
            .size()
            .reset_index(name="Hit Count")
            .sort_values(["Bot Type", "Hit Count"], ascending=[True, False])
        )
        st.dataframe(detailed, use_container_width=True)

        st.subheader("🌀 All 'Others' User-Agents and URLs")
        others_df = (
            df[df["Bot Type"] == "Others"]
            .groupby(["useragent", "url", "status"])
            .size()
            .reset_index(name="Count")
            .sort_values("Count", ascending=False)
        )
        if others_df.empty:
            st.info("No 'Others' entries found — all user-agents matched known bot patterns.")
        else:
            st.dataframe(others_df, use_container_width=True)

        st.subheader("📈 HTTP Status Code Breakdown")
        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        st.dataframe(status_counts)
    else:
        st.error("No valid log entries found — your file may contain wrapped or malformed log lines not matching standard access log patterns.")
