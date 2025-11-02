import streamlit as st
import pandas as pd
import io
import re
import datetime
import plotly.express as px

# Page config
st.set_page_config(page_title="Log Analyzer", page_icon="🧠", layout="wide")

# Theme selector
theme = st.sidebar.selectbox("Choose UI theme", ["Dark", "Light", "Ocean"])
if theme == "Dark":
    bg = "#0d1117"; fg = "#c9d1d9"; accent = "#1f78b4"
elif theme == "Light":
    bg = "#ffffff"; fg = "#111111"; accent = "#0066cc"
else:
    bg = "#002b36"; fg = "#839496"; accent = "#268bd2"

st.markdown(f"""
<style>
  html, body, [class*="css"] {{
    background-color: {bg};
    color: {fg};
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  }}
  .stMetric {{
    background: {accent};
    border-radius: 12px;
    padding: 12px;
    color: #ffffff;
    box-shadow: 0px 4px 8px rgba(0,0,0,0.2);
  }}
  h1, h2, h3, h4 {{
    color: {accent};
  }}
  div[data-testid="stDataFrame"] table {{
    border-radius: 10px;
    overflow: hidden;
  }}
</style>
""", unsafe_allow_html=True)

st.title("🧠 Log Analyzer – Traffic & Bot Insights")
st.caption("Upload your log to analyze bots, patterns and get alerts.")

uploaded_file = st.file_uploader("Upload log file (~3 GB max)", type=["log","txt","gz","bz2"])

generic_bot_patterns = [r'Googlebot', r'Bingbot', r'AhrefsBot', r'SemrushBot',
                        r'YandexBot', r'DuckDuckBot', r'crawler', r'spider']
ai_llm_bot_patterns = [r'GPTBot', r'OAI-SearchBot', r'ChatGPT-User',
                        r'ClaudeBot', r'claude-web', r'anthropic-ai', r'PerplexityBot',
                        r'Perplexity-User', r'Google-Extended', r'Applebot-Extended',
                        r'cohere-ai', r'AI2Bot', r'CCBot', r'DuckAssistBot',
                        r'YouBot', r'MistralAI-User']
bot_regex = re.compile("|".join(generic_bot_patterns + ai_llm_bot_patterns), flags=re.IGNORECASE)

if uploaded_file:
    st.info("⏳ Processing…")
    text_stream = io.TextIOWrapper(uploaded_file, encoding='utf-8', errors='ignore')
    total_requests = 0
    generic_requests = 0
    llm_requests = 0
    others_requests = 0
    generic_uas = {}
    llm_uas = {}
    ts_records = []
    ua_path_ip = {}  # dictionary mapping ua -> list of (path, ip)

    log_pattern = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
                             r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+" '
                             r'(?P<status>\d{3}) \S+ '
                             r'"(?P<referer>[^"]*)" '
                             r'"(?P<agent>[^"]*)"')

    progress_bar = st.progress(0)
    for line in text_stream:
        total_requests += 1
        if total_requests % 1000 == 0:
            progress_bar.progress(min(1.0, total_requests/100000))  # adjust denominator as needed

        m = log_pattern.match(line.strip())
        if not m:
            others_requests += 1
            continue

        ua = m.group("agent").strip()
        ip = m.group("ip")
        path = m.group("path")
        try:
            dt = datetime.datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
        except:
            dt = None

        if bot_regex.search(ua):
            if any(re.search(p, ua, flags=re.IGNORECASE) for p in ai_llm_bot_patterns):
                llm_requests += 1
                llm_uas[ua] = llm_uas.get(ua, 0) + 1
                cat = "LLM/AI Bot"
            else:
                generic_requests += 1
                generic_uas[ua] = generic_uas.get(ua, 0) + 1
                cat = "Generic Bot"
        else:
            others_requests += 1
            cat = "Others"

        if dt:
            ts_records.append({"timestamp": dt, "category": cat})

        ua_path_ip.setdefault(ua, []).append((path, ip))

    st.subheader("📌 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{total_requests:,}")
    c2.metric("Generic Bot Requests", f"{generic_requests:,}")
    c3.metric("LLM Bot Requests", f"{llm_requests:,}")
    c4.metric("Others", f"{others_requests:,}")

    st.subheader("📊 Traffic Composition")
    df_comp = pd.DataFrame({
        "Category": ["Generic Bot", "LLM Bot", "Others"],
        "Count": [generic_requests, llm_requests, others_requests]
    })
    fig_pie = px.pie(df_comp, names="Category", values="Count",
                     color_discrete_sequence=[accent, "#6a3d9a", "#33a02c"],
                     title="Composition")
    st.plotly_chart(fig_pie, use_container_width=True)

    # Heat-map feature: hour of day vs category counts
    if ts_records:
        st.subheader("🌡️ Bot Traffic Heat-Map (Hour vs Category)")
        df_ts = pd.DataFrame(ts_records)
        df_ts["hour"] = df_ts["timestamp"].dt.hour
        counts_heat = df_ts.groupby(["hour","category"]).size().reset_index(name="count")
        fig_heat = px.density_heatmap(counts_heat, x="hour", y="category", z="count",
                                      color_continuous_scale="Viridis",
                                      title="Hourly Traffic Heat Map")
        st.plotly_chart(fig_heat, use_container_width=True)

    # Alerts
    alert_threshold = st.sidebar.number_input("Alert threshold (requests)", min_value=10, max_value=10000, value=500)
    st.subheader("🚨 Alerts")
    for ua, count in {**generic_uas, **llm_uas}.items():
        if count > alert_threshold:
            st.warning(f"High volume detected 👉 {ua}: {count} requests")

    # Drill-down tables
    st.subheader("🔍 User-Agent Drill-Down")
    selected_ua = st.selectbox("Select a User-Agent to investigate", sorted(list(set(list(generic_uas.keys())+list(llm_uas.keys())))))
    if selected_ua:
        st.write(f"Paths & IPs visited by **{selected_ua}**")
        df_detail = pd.DataFrame(ua_path_ip[selected_ua], columns=["Path","IP"])
        st.dataframe(df_detail, use_container_width=True)

    # Export
    st.subheader("📥 Download Data")
    df_gen = pd.DataFrame(list(generic_uas.items()), columns=["User-Agent","Count"])
    df_ll  = pd.DataFrame(list(llm_uas.items()),   columns=["User-Agent","Count"])
    st.download_button("Download Generic Bot CSV", df_gen.to_csv(index=False).encode('utf-8'), "generic_bots.csv", "text/csv")
    st.download_button("Download LLM Bot CSV",     df_ll.to_csv(index=False).encode('utf-utf-8'),     "llm_bots.csv",     "text/csv")

    st.success("✅ Done.")
else:
    st.info("Upload a log file above to start.")
