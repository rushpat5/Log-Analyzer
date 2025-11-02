# app.py
import streamlit as st
import pandas as pd
import io
import re
import datetime
import plotly.express as px
import numpy as np

st.set_page_config(page_title="Log Analyzer + Anomaly Detection", page_icon="🧠", layout="wide")

# --------------------
# Styling (clean, pleasing)
# --------------------
st.markdown(
    """
    <style>
      html, body, [class*="css"] {
        font-family: 'Inter', system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
        background-color: #0f1724;
        color: #e6eef8;
      }
      .kpi-card {
        background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
        border-radius: 12px;
        padding: 12px;
        box-shadow: 0 6px 18px rgba(2,6,23,0.6);
      }
      h1,h2,h3 { color: #f4f8fb; }
      .small-muted { color: #9fb0c5; font-size: 0.9em; }
      .alert-card {
        background: #2b1a2f;
        border-left: 4px solid #ff6b6b;
        padding: 8px;
        border-radius: 6px;
        margin-bottom: 8px;
      }
      div[data-testid="stDataFrame"] table { border-radius: 8px; overflow:hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Log Analyzer — Bot Insights + Anomaly Detection")
st.caption("Upload combined-format webserver logs. Detect bots, pinpoint spikes, export results.")

# --------------------
# File upload
# --------------------
uploaded_file = st.file_uploader("Upload log file (text; ~3GB max if your host supports it)", type=["log","txt","gz","bz2"])

# --------------------
# Bot detection lists (tweak as needed)
# --------------------
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

# --------------------
# Sidebar controls
# --------------------
st.sidebar.header("Anomaly settings")
std_multiplier = st.sidebar.slider("Anomaly threshold (k × std)", min_value=1.0, max_value=6.0, value=3.0, step=0.5)
min_samples_for_ua = st.sidebar.number_input("Minimum minutes of history to consider UA anomaly", min_value=3, max_value=1000, value=10)
time_agg = st.sidebar.selectbox("Time aggregation for timeline", ["minute", "5min", "hour"], index=0)

# --------------------
# Log parsing pattern (Combined Log Format)
# --------------------
log_pattern = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+" '
    r'(?P<status>\d{3}) \S+ '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<agent>[^"]*)"'
)

# Helper: floor to aggregation
def floor_timestamp(dt: datetime.datetime, agg: str):
    if agg == "minute":
        return dt.replace(second=0, microsecond=0)
    if agg == "5min":
        minute = (dt.minute // 5) * 5
        return dt.replace(minute=minute, second=0, microsecond=0)
    if agg == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    return dt

# --------------------
# Main processing
# --------------------
if uploaded_file is not None:
    st.info("Parsing file and computing metrics. This may take time for large logs.")
    text_stream = io.TextIOWrapper(uploaded_file, encoding='utf-8', errors='ignore')

    # Counters and collections
    total = 0
    generic_count = 0
    llm_count = 0
    others_count = 0

    ua_counts = {}          # {ua: total_count}
    ua_minute_counts = {}   # {(ua, minute): count}
    cat_minute_counts = {}  # {(category, minute): count}
    rows_for_table = []     # store parsed rows for drill-down if needed

    progress_bar = st.progress(0)
    lines_processed_text = st.empty()

    # iterate lines
    for i, raw_line in enumerate(text_stream, start=1):
        line = raw_line.strip()
        if not line:
            continue
        total += 1

        # update progress UI (approximate)
        if i % 500 == 0:
            progress_bar.progress(min(1.0, i / 200000))  # progress heuristic
            lines_processed_text.text(f"Processed ~{i:,} lines")

        m = log_pattern.match(line)
        if not m:
            # count as Others if unparsable
            others_count += 1
            continue

        ua = m.group("agent").strip()
        ip = m.group("ip")
        path = m.group("path")
        time_str = m.group("time")
        try:
            dt = datetime.datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            # unparsable time - skip time-based metrics but track counts
            dt = None

        # classify category
        if bot_regex.search(ua):
            if any(re.search(p, ua, flags=re.IGNORECASE) for p in ai_llm_bot_patterns):
                category = "LLM/AI Bot"
                llm_count += 1
            else:
                category = "Generic Bot"
                generic_count += 1
        else:
            category = "Others"
            others_count += 1

        # update UA totals
        ua_counts[ua] = ua_counts.get(ua, 0) + 1

        # update minute buckets
        if dt is not None:
            bucket = floor_timestamp(dt, time_agg)
            ua_minute_counts[(ua, bucket)] = ua_minute_counts.get((ua, bucket), 0) + 1
            cat_minute_counts[(category, bucket)] = cat_minute_counts.get((category, bucket), 0) + 1

        # small store for drilldown
        rows_for_table.append({"time": dt, "ip": ip, "path": path, "ua": ua, "category": category})

    progress_bar.empty()
    lines_processed_text.empty()

    # Summary KPIs
    st.subheader("Key Metrics")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total requests", f"{total:,}")
    col2.metric("Generic bots", f"{generic_count:,}")
    col3.metric("LLM/AI bots", f"{llm_count:,}")
    col4.metric("Others (non-matched)", f"{others_count:,}")

    # Build dataframes for tables and time series
    df_ua = pd.DataFrame(list(ua_counts.items()), columns=["User-Agent", "Total"])
    df_ua = df_ua.sort_values("Total", ascending=False).reset_index(drop=True)

    # category timeline dataframe
    cat_ts = []
    for (cat, minute), cnt in cat_minute_counts.items():
        cat_ts.append({"minute": minute, "category": cat, "count": cnt})
    if cat_ts:
        df_cat_ts = pd.DataFrame(cat_ts)
        # ensure minute column is datetime
        df_cat_ts["minute"] = pd.to_datetime(df_cat_ts["minute"])
    else:
        df_cat_ts = pd.DataFrame(columns=["minute", "category", "count"])

    # UA-minute dataframe
    ua_ts = []
    for (ua, minute), cnt in ua_minute_counts.items():
        ua_ts.append({"minute": minute, "ua": ua, "count": cnt})
    if ua_ts:
        df_ua_ts = pd.DataFrame(ua_ts)
        df_ua_ts["minute"] = pd.to_datetime(df_ua_ts["minute"])
    else:
        df_ua_ts = pd.DataFrame(columns=["minute", "ua", "count"])

    # --------------------
    # Anomaly detection: category level
    # --------------------
    st.subheader("Anomaly Detection — Category level")

    if df_cat_ts.empty:
        st.info("No timestamped entries found; cannot compute timeline anomalies.")
    else:
        # pivot to timeseries per category
        pivot = df_cat_ts.pivot_table(index="minute", columns="category", values="count", aggfunc="sum", fill_value=0)
        pivot = pivot.sort_index()

        # compute rolling mean/std or overall mean/std per category
        cat_alerts = []
        for cat in pivot.columns:
            series = pivot[cat].astype(float)
            mean = series.mean()
            std = series.std(ddof=0)
            threshold = mean + std_multiplier * std
            # find minutes above threshold
            spikes = series[series > threshold]
            for minute, val in spikes.items():
                cat_alerts.append({"category": cat, "minute": minute.to_pydatetime(), "count": int(val), "threshold": float(threshold)})

        # show pie chart of composition
        comp_df = pd.DataFrame({
            "Category": ["Generic Bot", "LLM/AI Bot", "Others"],
            "Count": [generic_count, llm_count, others_count]
        })
        fig_pie = px.pie(comp_df, names="Category", values="Count", title="Overall composition")
        st.plotly_chart(fig_pie, use_container_width=True)

        # show timeline with anomalies marked
        fig_ts = px.line(pivot.reset_index(), x="minute", y=pivot.columns, title="Category timeline (per selected aggregation)")
        # annotate anomalies on chart
        for a in cat_alerts:
            fig_ts.add_scatter(x=[a["minute"]], y=[a["count"]], mode="markers",
                               marker=dict(color="red", size=10),
                               name=f"Anomaly: {a['category']}")
        st.plotly_chart(fig_ts, use_container_width=True)

        # alert list
        if cat_alerts:
            st.markdown("### Category anomalies detected")
            df_cat_alerts = pd.DataFrame(cat_alerts).sort_values(["minute", "category"], ascending=[False, True])
            df_cat_alerts["minute"] = pd.to_datetime(df_cat_alerts["minute"])
            st.dataframe(df_cat_alerts, use_container_width=True)
        else:
            st.success("No category-level anomalies detected with current threshold.")

    # --------------------
    # Anomaly detection: per-User-Agent spikes
    # --------------------
    st.subheader("Anomaly Detection — Per User-Agent spikes")

    if df_ua_ts.empty:
        st.info("No UA timestamps to analyze for UA-level anomalies.")
    else:
        # compute per-UA series and detect anomalies for UA that have enough samples
        ua_alerts = []
        grouped = df_ua_ts.groupby("ua")
        for ua, g in grouped:
            minutes = g.groupby("minute")["count"].sum().sort_index()
            if len(minutes) < min_samples_for_ua:
                continue
            mean = minutes.mean()
            std = minutes.std(ddof=0)
            threshold = mean + std_multiplier * std
            spikes = minutes[minutes > threshold]
            for minute, val in spikes.items():
                ua_alerts.append({"ua": ua, "minute": minute.to_pydatetime(), "count": int(val), "threshold": float(threshold)})

        # show top UA table and anomalies
        st.markdown("Top User-Agents by total requests")
        st.dataframe(df_ua.head(50), use_container_width=True)

        if ua_alerts:
            st.markdown("### UA anomalies detected")
            df_ua_alerts = pd.DataFrame(ua_alerts).sort_values(["minute", "ua"], ascending=[False, True])
            df_ua_alerts["minute"] = pd.to_datetime(df_ua_alerts["minute"])
            st.dataframe(df_ua_alerts, use_container_width=True)
        else:
            st.success("No UA-level anomalies detected with current settings.")

    # --------------------
    # Drill-down and exports
    # --------------------
    st.subheader("Drill-down & Exports")
    df_rows = pd.DataFrame(rows_for_table)
    if not df_rows.empty:
        # show simple drill-down: select UA and show top paths and IPs
        ua_list = sorted(df_rows["ua"].unique())
        sel_ua = st.selectbox("Select User-Agent for drill-down (or leave empty)", options=[""] + ua_list)
        if sel_ua:
            sel_rows = df_rows[df_rows["ua"] == sel_ua]
            st.markdown("Top paths visited by selection")
            st.dataframe(sel_rows["path"].value_counts().reset_index().rename(columns={"index":"path","path":"count"}).head(50), use_container_width=True)
            st.markdown("Top IPs used by selection")
            st.dataframe(sel_rows["ip"].value_counts().reset_index().rename(columns={"index":"ip","ip":"count"}).head(50), use_container_width=True)

        # export CSVs
        st.download_button("Download UA summary CSV", df_ua.to_csv(index=False).encode("utf-8"), "ua_summary.csv")
        st.download_button("Download raw parsed rows CSV (limited)", df_rows.head(50000).to_csv(index=False).encode("utf-8"), "parsed_rows_sample.csv")
    else:
        st.info("No rows available for drill-down/export.")

    # final note
    st.markdown("<div class='small-muted'>Anomaly rule: value &gt; mean + k×std for category/UA timeseries. Adjust k and min samples in the sidebar.</div>", unsafe_allow_html=True)

else:
    st.info("Upload a log file to begin analysis.")
