import streamlit as st
import pandas as pd
import io
import re
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

# --- Styling ---
st.markdown(
    """
    <style>
      body {background-color: #0f1117; color: #e8e8e8;}
      .stMetric {background: #1c1f2b; border-radius: 12px; padding: 10px;}
      div[data-testid="stDataFrame"] table {border-radius: 10px; overflow: hidden;}
      .block-container {padding-top: 2rem;}
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🧠 Log Analyzer – Web Traffic & Bot Insights")
st.caption("Upload a web server log file to detect bots (generic & LLM) and Others (non-matched).")

uploaded_file = st.file_uploader("Upload log file (~3 GB max)", type=["log","txt","gz","bz2"])

# Bot pattern definitions
generic_bot_patterns = [
    r'Googlebot', r'Bingbot', r'AhrefsBot', r'SemrushBot', r'YandexBot',
    r'DuckDuckBot', r'crawler', r'spider'
]
ai_llm_bot_patterns = [
    r'GPTBot', r'OAI-SearchBot', r'ChatGPT-User', r'ClaudeBot', r'claude-web',
    r'anthropic-ai', r'PerplexityBot', r'Perplexity-User', r'Google-Extended',
    r'Applebot-Extended', r'cohere-ai', r'AI2Bot', r'CCBot', r'DuckAssistBot',
    r'YouBot', r'MistralAI-User'
]
bot_regex = re.compile("|".join(generic_bot_patterns + ai_llm_bot_patterns), flags=re.IGNORECASE)

if uploaded_file is not None:
    st.info("⏳ Processing file — please wait…")
    text_stream = io.TextIOWrapper(uploaded_file, encoding='utf-8', errors='ignore')

    total_requests = 0
    generic_bot_requests = 0
    llm_bot_requests = 0
    others_requests = 0

    generic_bot_uas = {}
    llm_bot_uas = {}

    # Improved log line parsing pattern
    log_pattern = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+" '
        r'(?P<status>\d{3}) \S+ '
        r'"(?P<referer>[^"]*)" '
        r'"(?P<agent>[^"]*)"'
    )

    for line in text_stream:
        line = line.strip()
        if not line:
            continue
        total_requests += 1

        m = log_pattern.match(line)
        if not m:
            others_requests += 1
            continue

        ua = m.group("agent").strip()

        # Extract simplified bot name
        bot_name_match = re.search(r'\b([A-Za-z0-9\-_]+(?:Bot|User))\b', ua, flags=re.IGNORECASE)
        if bot_name_match:
            bot_name = bot_name_match.group(1)
        else:
            bot_name = ua  # fallback when no bot name matched

        if bot_regex.search(ua):
            if any(re.search(p, ua, flags=re.IGNORECASE) for p in ai_llm_bot_patterns):
                llm_bot_requests += 1
                llm_bot_uas[bot_name] = llm_bot_uas.get(bot_name, 0) + 1
            else:
                generic_bot_requests += 1
                generic_bot_uas[bot_name] = generic_bot_uas.get(bot_name, 0) + 1
        else:
            others_requests += 1

        if total_requests % 200000 == 0:
            st.write(f"Processed {total_requests} lines…")

    # Metrics display
    st.subheader("📌 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{total_requests:,}")
    c2.metric("Bot Requests (Generic)", f"{generic_bot_requests:,}")
    c3.metric("Bot Requests (LLM/AI)", f"{llm_bot_requests:,}")
    c4.metric("Others (non-matched)", f"{others_requests:,}")

    # Composition chart
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

    # Data tables
    st.subheader("🤖 All Generic Bot Names")
    df_generic = pd.DataFrame(list(generic_bot_uas.items()), columns=["Bot Name","Count"]) \
        .sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_generic, use_container_width=True)

    st.subheader("🧩 All LLM/AI Bot Names")
    df_llm = pd.DataFrame(list(llm_bot_uas.items()), columns=["Bot Name","Count"]) \
        .sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_llm, use_container_width=True)

    # Export results
    st.subheader("📥 Export Results")
    csv_generic = df_generic.to_csv(index=False).encode('utf-8')
    csv_llm = df_llm.to_csv(index=False).encode('utf-8')
    st.download_button("Download Generic Bot Names CSV", csv_generic, "generic_bot_names.csv", "text/csv", key="download-generic")
    st.download_button("Download LLM Bot Names CSV", csv_llm, "llm_bot_names.csv", "text/csv", key="download-llm")

    st.success("✅ Analysis complete.")
else:
    st.warning("Please upload a log file to begin analysis.")
