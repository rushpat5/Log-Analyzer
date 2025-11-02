import streamlit as st
import pandas as pd
import io
import re
import datetime
import plotly.express as px

st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

# --- Styling ---
st.markdown(
    """
    <style>
      body {background-color: #0f1117; color: #c9d1d9;}
      .stMetric {background: #161b22; border-radius:12px; padding:12px; box-shadow:0px 3px 6px rgba(0,0,0,0.3);}
      h1, h2, h3, h4 {color:#f0f6fc;}
      div[data-testid="stDataFrame"] table {border-radius:10px; overflow:hidden;}
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🧠 Log Analyzer – Web Traffic & Bot Insights")
st.caption("Upload your web-server log (combined format) to detect bots (generic & LLM) and Others (non-matched).")

uploaded_file = st.file_uploader("Upload log file (~3 GB max)", type=["log","txt","gz","bz2"])

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

    ts_records = []

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
        try:
            dt = datetime.datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            dt = None

        if bot_regex.search(ua):
            if any(re.search(p, ua, flags=re.IGNORECASE) for p in ai_llm_bot_patterns):
                llm_bot_requests += 1
                llm_bot_uas[ua] = llm_bot_uas.get(ua, 0) + 1
                cat = "LLM/AI Bot"
            else:
                generic_bot_requests += 1
                generic_bot_uas[ua] = generic_bot_uas.get(ua, 0) + 1
                cat = "Generic Bot"
        else:
            others_requests += 1
            cat = "Others"

        if dt is not None:
            ts_records.append({"timestamp": dt, "category": cat})

        if total_requests % 200000 == 0:
            st.write(f"Processed {total_requests} lines…")

    st.subheader("📌 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{total_requests:,}")
    c2.metric("Bot Requests (Generic)", f"{generic_bot_requests:,}")
    c3.metric("Bot Requests (LLM/AI)", f"{llm_bot_requests:,}")
    c4.metric("Others (non-matched)", f"{others_requests:,}")

    st.subheader("📊 Traffic Composition")
    df_comp = pd.DataFrame({
        "Category": ["Generic Bots", "LLM/AI Bots", "Others"],
        "Count": [generic_bot_requests, llm_bot_requests, others_requests]
    })
    fig_pie = px.pie(
        df_comp, names="Category", values="Count",
        color_discrete_sequence=["#1f78b4","#6a3d9a","#33a02c"],
        title="Request Composition by Category"
    )
    st.plotly_chart(fig_pie, use_container_width=True)

    if ts_records:
        st.subheader("📈 Requests Timeline")
        df_ts = pd.DataFrame(ts_records)
        df_ts["minute"] = df_ts["timestamp"].dt.floor("T")
        df_counts = df_ts.groupby(["minute","category"]).size().reset_index(name="count")

        min_time = df_counts["minute"].min()
        max_time = df_counts["minute"].max()

        # slider supports datetime directly as min_value and max_value
        time_range = st.slider(
            "Select Time Window",
            min_value=min_time,
            max_value=max_time,
            value=(min_time, max_time),
            step=datetime.timedelta(minutes=1),
            format="MM/DD/Y HH:mm"
        )

        filtered = df_counts[(df_counts["minute"] >= time_range[0]) & (df_counts["minute"] <= time_range[1])]
        fig_line = px.line(
            filtered, x="minute", y="count", color="category",
            title="Requests Timeline by Category", markers=True
        )
        st.plotly_chart(fig_line, use_container_width=True)

    st.subheader("🔍 Search/Filter User-Agents")
    search_input = st.text_input("Search term (case-insensitive substring):", "")
    if search_input:
        generic_filtered = {k:v for k,v in generic_bot_uas.items() if search_input.lower() in k.lower()}
        llm_filtered     = {k:v for k,v in llm_bot_uas.items()     if search_input.lower() in k.lower()}
    else:
        generic_filtered = generic_bot_uas
        llm_filtered     = llm_bot_uas

    df_gen_f = pd.DataFrame(list(generic_filtered.items()), columns=["User-Agent","Count"]).sort_values(by="Count", ascending=False).reset_index(drop=True)
    df_llm_f = pd.DataFrame(list(llm_filtered.items()), columns=["User-Agent","Count"]).sort_values(by="Count", ascending=False).reset_index(drop=True)

    st.write("Generic Bots matching search:")
    st.dataframe(df_gen_f, use_container_width=True)
    st.write("LLM/AI Bots matching search:")
    st.dataframe(df_llm_f, use_container_width=True)

    st.subheader("🤖 All Generic Bot User-Agents")
    df_generic = pd.DataFrame(list(generic_bot_uas.items()), columns=["User-Agent","Count"]).sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_generic, use_container_width=True)

    st.subheader("🧩 All LLM/AI Bot User-Agents")
    df_llm = pd.DataFrame(list(llm_bot_uas.items()), columns=["User-Agent","Count"]).sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_llm, use_container_width=True)

    st.subheader("📥 Download Results")
    csv_generic = df_generic.to_csv(index=False).encode('utf-8')
    csv_llm     = df_llm.to_csv(index=False).encode('utf-8')
    st.download_button("Download Generic Bots CSV", csv_generic, "generic_bots.csv", "text/csv", key="dl-generic")
    st.download_button("Download LLM/AI Bots CSV", csv_llm,     "llm_bots.csv",     "text/csv",     key="dl-llm")

    st.success("✅ Analysis complete.")
else:
    st.warning("Please upload a log file to begin analysis.")
