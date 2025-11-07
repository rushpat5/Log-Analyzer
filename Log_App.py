import streamlit as st
import pandas as pd
import re
import chardet

# -----------------------------
# Detect encoding and load file
# -----------------------------
def load_log_file(uploaded_file):
    raw_data = uploaded_file.read()
    encoding = chardet.detect(raw_data)['encoding']
    text = raw_data.decode(encoding or 'utf-8', errors='ignore')
    lines = text.splitlines()
    return lines

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
# Parse log lines
# -----------------------------
def parse_log(lines):
    data = []
    log_pattern = (
        r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<useragent>[^"]*)"'
    )

    for line in lines:
        match = re.search(log_pattern, line)
        if match:
            data.append(match.groupdict())

    return pd.DataFrame(data)

# -----------------------------
# Streamlit App Layout
# -----------------------------
st.set_page_config(page_title="Bot Log Analyzer", layout="wide")
st.title("📊 Advanced Bot Log Analyzer (with 'Others' URLs)")

uploaded_file = st.file_uploader("Upload access log file", type=["log", "txt"])

if uploaded_file:
    with st.spinner("Processing log file..."):
        lines = load_log_file(uploaded_file)
        df = parse_log(lines)

    if not df.empty:
        df["Bot Type"] = df["useragent"].apply(classify_bot)

        total_requests = len(df)
        bot_counts = df["Bot Type"].value_counts().to_dict()
        status_counts = df["status"].value_counts().to_dict()
        others_count = len(df[df["Bot Type"] == "Others"])

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Requests", total_requests)
        col2.metric("Bot Requests (Known)", total_requests - others_count)
        col3.metric("Bot Requests (LLM/AI)", df["Bot Type"].str.contains("GPT|Claude|CCBot", case=False).sum())
        col4.metric("Others (Non-matched)", others_count)

        st.subheader("Requests by Category")
        summary_data = (
            df["Bot Type"]
            .value_counts()
            .reset_index()
            .rename(columns={"index": "Bot Type", "Bot Type": "Count"})
        )
        st.bar_chart(summary_data.set_index("Bot Type"))

        # Detailed Bot Activity
        st.subheader("🔍 Detailed Bot Activity (All Bots + Others)")
        detailed_data = (
            df.groupby(["Bot Type", "useragent", "url", "status"])
            .size()
            .reset_index(name="Hit Count")
            .sort_values(["Bot Type", "Hit Count"], ascending=[True, False])
        )
        st.dataframe(detailed_data, use_container_width=True)

        # Separate section for "Others"
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

        # Status summary
        st.subheader("📈 HTTP Status Code Breakdown")
        st.dataframe(pd.DataFrame(list(status_counts.items()), columns=["Status", "Count"]))
    else:
        st.error("No valid log entries found in the uploaded file.")
