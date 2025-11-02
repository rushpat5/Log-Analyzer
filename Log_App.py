import streamlit as st
import pandas as pd
import io
import re
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

# --- Header ---
st.markdown(
    """
    <style>
    .main {background-color: #0f1117; color: #e8e8e8;}
    h1, h2, h3, h4 {color: #f5f5f5;}
    .stMetric {background: #1c1f2b; border-radius: 12px; padding: 10px;}
    .block-container {padding-top: 2rem;}
    div[data-testid="stDataFrame"] div[data-testid="StyledTable"] {
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🧠 Log Analyzer – Web Traffic & Bot Insights")
st.caption("Upload a webserver log file to analyze traffic, detect crawlers, and identify AI/LLM bots.")

uploaded_file = st.file_uploader("Upload log file (~3 GB max)", type=["log", "txt", "gz", "bz2"])

# --- Bot definitions ---
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
    st.info("⏳ Processing file — this may take some time...")
    buffer = io.TextIOWrapper(uploaded_file, encoding='utf-8', errors='ignore')

    total, bot_total, llm_total = 0, 0, 0
    bot_uas, llm_uas = {}, {}
    timeline = []

    for line in buffer:
        total += 1
        parts = line.split('"')
        if len(parts) < 6:
            continue
        ua = parts[-2]
        if bot_regex.search(ua):
            bot_total += 1
            if any(re.search(p, ua, flags=re.IGNORECASE) for p in ai_llm_bot_patterns):
                llm_total += 1
                llm_uas[ua] = llm_uas.get(ua, 0) + 1
            else:
                bot_uas[ua] = bot_uas.get(ua, 0) + 1
        if total % 200000 == 0:
            st.write(f"Processed {total} lines...")

    human_total = total - bot_total

    # --- KPIs ---
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", f"{total:,}")
    col2.metric("Bot Requests", f"{bot_total:,}")
    col3.metric("AI/LLM Bot Requests", f"{llm_total:,}")
    col4.metric("Human Requests", f"{human_total:,}")

    # --- Charts ---
    st.subheader("📊 Bot Traffic Breakdown")

    data = {
        "Category": ["Humans", "Generic Bots", "LLM/AI Bots"],
        "Requests": [human_total, bot_total - llm_total, llm_total],
    }
    df_pie = pd.DataFrame(data)
    fig_pie = px.pie(df_pie, names="Category", values="Requests", color="Category",
                     color_discrete_sequence=["#2ecc71", "#3498db", "#9b59b6"],
                     title="Overall Traffic Composition")
    st.plotly_chart(fig_pie, use_container_width=True)

    # --- Tables ---
    st.subheader("🤖 Top Generic Bot User-Agents")
    df_bots = pd.DataFrame(list(bot_uas.items()), columns=["User-Agent", "Count"]).sort_values(
        by="Count", ascending=False
    )
    st.dataframe(df_bots.head(20), use_container_width=True)

    st.subheader("🧩 Top AI / LLM Bot User-Agents")
    df_llm = pd.DataFrame(list(llm_uas.items()), columns=["User-Agent", "Count"]).sort_values(
        by="Count", ascending=False
    )
    st.dataframe(df_llm.head(20), use_container_width=True)

    st.success("✅ Processing complete.")
else:
    st.warning("Please upload a log file to begin analysis.")
