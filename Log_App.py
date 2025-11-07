import streamlit as st
import pandas as pd
import io
import re
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
st.caption("Detects bots, LLM crawlers, and URLs accessed (with status codes).")

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

if uploaded_file is not None:
    st.info("⏳ Processing file — please wait…")
    text_stream = io.TextIOWrapper(uploaded_file, encoding="utf-8", errors="ignore")

    total_requests = 0
    generic_bot_requests = 0
    llm_bot_requests = 0
    others_requests = 0
    generic_bot_uas = {}
    llm_bot_uas = {}
    others_uas = {}
    bot_hits = []

    for raw_line in text_stream:
        total_requests += 1
        line = raw_line.strip()
        if not line:
            continue

        # remove "access.log:####:" prefix
        if ":" in line and line.split(":")[0].endswith(".log"):
            parts = line.split(":", 2)
            if len(parts) == 3:
                line = parts[2].strip()

        # extract quoted segments (method/URL/referer/agent)
        quoted_parts = re.findall(r'"(.*?)"', line)
        if not quoted_parts:
            others_requests += 1
            continue

        # guess main request
        request = quoted_parts[0] if len(quoted_parts) >= 1 else ""
        user_agent = quoted_parts[-1] if len(quoted_parts) >= 1 else ""

        # extract path from request
        path_match = re.search(r'([A-Z]+)\s+(\S+)', request)
        path = path_match.group(2) if path_match else "-"
        # extract status code (3 digits)
        status_match = re.search(r'\s(\d{3})\s', line)
        status = status_match.group(1) if status_match else "-"

        bot_type = identify_bot(user_agent)
        if bot_type == "Generic":
            generic_bot_requests += 1
            generic_bot_uas[user_agent] = generic_bot_uas.get(user_agent, 0) + 1
            bot_hits.append({"Bot Type": "Generic", "User-Agent": user_agent, "URL": path, "Status": status})
        elif bot_type == "LLM/AI":
            llm_bot_requests += 1
            llm_bot_uas[user_agent] = llm_bot_uas.get(user_agent, 0) + 1
            bot_hits.append({"Bot Type": "LLM/AI", "User-Agent": user_agent, "URL": path, "Status": status})
        else:
            others_requests += 1
            others_uas[user_agent] = others_uas.get(user_agent, 0) + 1

        if total_requests % 200000 == 0:
            st.write(f"Processed {total_requests:,} lines…")

    # Metrics
    st.subheader("📌 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{total_requests:,}")
    c2.metric("Bot Requests (Generic)", f"{generic_bot_requests:,}")
    c3.metric("Bot Requests (LLM/AI)", f"{llm_bot_requests:,}")
    c4.metric("Others (non-matched)", f"{others_requests:,}")

    # Composition Chart
    df_comp = pd.DataFrame({
        "Category": ["Bots (Generic)", "Bots (LLM/AI)", "Others"],
        "Count": [generic_bot_requests, llm_bot_requests, others_requests]
    })
    fig = px.pie(df_comp, names="Category", values="Count",
                 color_discrete_sequence=["#3498db", "#9b59b6", "#2ecc71"],
                 title="Requests by Category")
    st.plotly_chart(fig, use_container_width=True)

    # Bot hits
    st.subheader("🔍 Detailed Bot Activity")
    df_hits = pd.DataFrame(bot_hits)
    if not df_hits.empty:
        df_hits = df_hits.sort_values(by=["Bot Type", "User-Agent", "URL"]).reset_index(drop=True)
        st.dataframe(df_hits, use_container_width=True)
        csv_hits = df_hits.to_csv(index=False).encode("utf-8")
        st.download_button("Download Detailed Bot Hits CSV", csv_hits, "bot_hits.csv", "text/csv")
    else:
        st.info("No bot hits detected in this log file.")

    # Summary tables
    st.subheader("🤖 All Generic Bot User-Agents")
    df_generic = pd.DataFrame(list(generic_bot_uas.items()), columns=["User-Agent", "Count"]).sort_values(by="Count", ascending=False)
    st.dataframe(df_generic, use_container_width=True)

    st.subheader("🧩 All LLM/AI Bot User-Agents")
    df_llm = pd.DataFrame(list(llm_bot_uas.items()), columns=["User-Agent", "Count"]).sort_values(by="Count", ascending=False)
    st.dataframe(df_llm, use_container_width=True)

    st.subheader("🌀 All Others (non-matched) User-Agents")
    df_others = pd.DataFrame(list(others_uas.items()), columns=["User-Agent", "Count"]).sort_values(by="Count", ascending=False)
    st.dataframe(df_others, use_container_width=True)

    # Exports
    st.subheader("📥 Export Results")
    st.download_button("Download Generic Bot CSV", df_generic.to_csv(index=False).encode("utf-8"), "generic_bots.csv", "text/csv")
    st.download_button("Download LLM Bot CSV", df_llm.to_csv(index=False).encode("utf-8"), "llm_bots.csv", "text/csv")
    st.download_button("Download Others CSV", df_others.to_csv(index=False).encode("utf-8"), "others.csv", "text/csv")

    st.success("✅ Analysis complete.")
else:
    st.warning("Please upload a log file to begin analysis.")
