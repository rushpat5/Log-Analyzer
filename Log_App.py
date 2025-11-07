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
st.caption("Detects bots (e.g., Googlebot, GPTBot) and lists all URLs hit with status codes. Handles multiline and mixed-encoding logs.")

uploaded_file = st.file_uploader("Upload log file (~3 GB max)", type=None)

# --- Bot detection patterns ---
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

    # --- Robust decoding without external dependencies ---
    raw_bytes = uploaded_file.read()
    text_stream = None
    for enc_try in ("utf-8", "utf-16", "latin-1"):
        try:
            text_stream = io.StringIO(raw_bytes.decode(enc_try))
            break
        except Exception:
            continue
    if text_stream is None:
        st.error("❌ Could not decode the log file. Please upload as UTF-8, UTF-16, or Latin-1 text.")
        st.stop()

    # --- Merge multiline log entries ---
    buffer, entries = [], []
    for line in text_stream:
        line = line.rstrip("\n")
        if line.startswith("access.log") or re.match(r"^\d{1,3}(\.\d{1,3}){3}", line):
            if buffer:
                entries.append(" ".join(buffer))
                buffer = []
            buffer.append(line)
        else:
            buffer.append(line)
    if buffer:
        entries.append(" ".join(buffer))

    total = generic = llm = others = 0
    bot_hits = []

    # --- Flexible regex for common log formats ---
    pattern = re.compile(
        r'"([A-Z]+)\s+(\S+)\s+HTTP[^"]*"\s+(\d{3})[^"]*"(?:[^"]*)"\s*"([^"]+)"'
    )

    for entry in entries:
        total += 1
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

    # --- Key Metrics ---
    st.subheader("📌 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", f"{total:,}")
    c2.metric("Bot Requests (Generic)", f"{generic:,}")
    c3.metric("Bot Requests (LLM/AI)", f"{llm:,}")
    c4.metric("Others (non-matched)", f"{others:,}")

    # --- Pie Chart ---
    df_comp = pd.DataFrame({
        "Category": ["Bots (Generic)", "Bots (LLM/AI)", "Others"],
        "Count": [generic, llm, others]
    })
    fig = px.pie(df_comp, names="Category", values="Count",
                 color_discrete_sequence=["#3498db", "#9b59b6", "#2ecc71"],
                 title="Requests by Category")
    st.plotly_chart(fig, use_container_width=True)

    # --- Detailed Bot Activity ---
    st.subheader("🔍 Detailed Bot Activity")
    df_hits = pd.DataFrame(bot_hits)
    if not df_hits.empty:
        df_hits = df_hits.sort_values(by=["Bot Type", "User-Agent", "URL"]).reset_index(drop=True)
        st.dataframe(df_hits, use_container_width=True)
        csv_hits = df_hits.to_csv(index=False).encode("utf-8")
        st.download_button("Download Bot Hits CSV", csv_hits, "bot_hits.csv", "text/csv")
    else:
        st.info("No bot hits detected in this log file.")

    st.success("✅ Analysis complete.")
else:
    st.warning("Please upload a log file to begin analysis.")
