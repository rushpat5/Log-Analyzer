import streamlit as st
import pandas as pd
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import hashlib
import plotly.express as px

# -----------------------------------------------------------------------------
# 1. VISUAL CONFIGURATION (Dejan Style - Light Mode Forced)
# -----------------------------------------------------------------------------
st.set_page_config(page_title="Server Log Forensics", layout="wide", page_icon="🔎")

st.markdown("""
<style>
    /* --- FORCE LIGHT MODE --- */
    :root {
        --primary-color: #1a7f37;
        --background-color: #ffffff;
        --secondary-background-color: #f6f8fa;
        --text-color: #24292e;
        --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    }

    .stApp {
        background-color: #ffffff;
        color: #24292e;
    }
    
    /* --- TYPOGRAPHY --- */
    h1, h2, h3, h4, .markdown-text-container {
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
        color: #000000 !important;
        letter-spacing: -0.3px;
    }
    
    p, li, span, div {
        color: #24292e;
    }

    /* --- SIDEBAR --- */
    section[data-testid="stSidebar"] {
        background-color: #f6f8fa;
        border-right: 1px solid #d0d7de;
    }
    section[data-testid="stSidebar"] * {
        color: #24292e !important;
    }
    
    /* --- FILE UPLOADER --- */
    [data-testid="stFileUploader"] {
        background-color: #f6f8fa;
        border: 1px dashed #d0d7de;
        border-radius: 6px;
        padding: 20px;
    }
    
    /* --- METRIC CARDS --- */
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem !important;
        color: #1a7f37 !important; /* Green Accent */
        font-weight: 700;
    }
    div[data-testid="stMetricLabel"] {
        font-size: 0.9rem !important;
        color: #586069 !important;
    }
    
    /* --- TECH NOTE CALLOUTS --- */
    .tech-note {
        font-size: 0.85rem;
        color: #57606a;
        background-color: #f3f4f6;
        border-left: 3px solid #0969da;
        padding: 12px;
        margin-top: 8px;
        margin-bottom: 15px;
        border-radius: 0 4px 4px 0;
        line-height: 1.5;
    }
    
    /* Remove Streamlit Bloat */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 2. PARSING LOGIC & CONFIGURATION
# -----------------------------------------------------------------------------

# Bot patterns
GENERIC_BOTS = [
    r'googlebot', r'bingbot', r'ahrefsbot', r'semrushbot', r'yandexbot',
    r'duckduckbot', r'crawler', r'spider', r'applebot'
]
AI_BOTS = [
    r'gptbot', r'oai-searchbot', r'chatgpt-user', r'claudebot', r'claude-web',
    r'anthropic-ai', r'perplexitybot', r'perplexity-user', r'google-extended',
    r'applebot-extended', r'cohere-ai', r'ai2bot', r'ccbot', r'duckassistbot',
    r'youbot', r'mistralai-user'
]

def identify_bot(ua: str):
    if not ua: return "Unknown"
    ua_l = ua.lower()
    for p in AI_BOTS:
        if re.search(p, ua_l): return "LLM / AI Agent"
    for p in GENERIC_BOTS:
        if re.search(p, ua_l): return "Standard Crawler"
    return "Human / Other"

def extract_time_from_entry(entry: str):
    # Standard NCSA time format: [19/Sep/2025:00:00:39 +0530]
    m = re.search(r'\[([^\]]+)\]', entry)
    if not m: return None
    ts = m.group(1).strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try: return datetime.strptime(ts, fmt)
        except: continue
    return None

# -----------------------------------------------------------------------------
# 3. SIDEBAR
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Parser Config")
    st.markdown("""
    **Format:** Auto-Detect (Supports Standard & Grep Prefixes)
    <div class="tech-note">
    <b>Heuristics:</b>
    <br>• <b>User-Agent Sniffing:</b> Classifies traffic into AI Agents (e.g., GPTBot) vs Standard Crawlers (e.g., Googlebot).
    <br>• <b>Regex Cleaning:</b> Automatically strips filename prefixes (e.g., <code>access.log:123:</code>) to find valid log data.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### 🛡️ Bot Definitions")
    with st.expander("View AI Bot Signatures"):
        st.code("\n".join(AI_BOTS), language="text")

# -----------------------------------------------------------------------------
# 4. MAIN INTERFACE
# -----------------------------------------------------------------------------

st.title("Server Log Forensics")
st.markdown("### Traffic pattern analysis & Bot detection")

# Abstract
with st.expander("Technical Methodology (How it works)", expanded=False):
    st.markdown("""
    **Log File Analysis**
    
    1.  **Ingestion:** Reads raw server logs. Supports standard NCSA format even if prefixed with filenames/line numbers.
    2.  **Extraction:** Uses Regular Expressions (Regex) to parse `IP`, `Timestamp`, `Request`, `Status`, `Referer`, and `User-Agent`.
    3.  **Classification:**
        *   **Standard Crawlers:** Search engine bots indexing your content.
        *   **LLM Agents:** AI models (ChatGPT, Claude, Perplexity) scraping for training data or RAG.
        *   **Human/Other:** Regular browser traffic.
    """)

st.write("")

# --- INPUT SECTION ---
st.markdown("#### 1. Upload Access Log")
uploaded_file = st.file_uploader("Upload .log or .txt file (Max 200MB recommended for browser performance)", type=None)

if uploaded_file is not None:
    # -------------------------------------------------------------------------
    # 5. PROCESSING
    # -------------------------------------------------------------------------
    with st.spinner("Parsing log lines & identifying signatures..."):
        
        # Safe decoding
        raw_bytes = uploaded_file.read()
        try:
            text = raw_bytes.decode("utf-8")
        except:
            text = raw_bytes.decode("latin-1", errors="ignore")

        raw_lines = text.splitlines()
        
        hits = []
        
        # Regex to find the start of a Standard Log Entry (IP - - [Date)
        # This ignores any garbage prefix like "file.log:123:"
        log_pattern = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[')

        for entry in raw_lines:
            entry = entry.strip()
            if not entry: continue

            # Robust Match: Search for the IP pattern anywhere in the line
            match = log_pattern.search(entry)
            
            if match:
                # We found a valid log entry inside the line.
                # Slice the string to start from the IP, effectively removing prefixes
                clean_entry = entry[match.start():]
                client_ip = match.group("ip")
            else:
                # Skip lines that don't look like NCSA logs
                continue

            # Extract quoted fields (Request, Referer, UA)
            quoted = re.findall(r'"([^"]*)"', clean_entry)
            if len(quoted) >= 3:
                request, referer, ua = quoted[0], quoted[1], quoted[2]
            else:
                continue # Skip malformed lines

            # Parse Request
            m_req = re.search(r'([A-Z]+)\s+(\S+)', request)
            method = m_req.group(1) if m_req else "-"
            path = m_req.group(2) if m_req else "-"

            # Parse Status
            m_status = re.search(r'"\s*(\d{3})\s', clean_entry)
            status = m_status.group(1) if m_status else "000"

            # Parse Time
            dt = extract_time_from_entry(clean_entry)
            
            # Bot Classification
            bot_type = identify_bot(ua)
            
            hits.append({
                "IP": client_ip,
                "Time": dt,
                "Method": method,
                "Path": path,
                "Status": status,
                "Referer": referer if referer != "-" else None,
                "User Agent": ua,
                "Category": bot_type
            })

        df = pd.DataFrame(hits)

    if not df.empty:
        # ---------------------------------------------------------------------
        # 6. RESULTS DASHBOARD
        # ---------------------------------------------------------------------
        st.markdown("---")
        st.markdown("### Traffic Intelligence")
        
        # --- METRICS ROW ---
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Hits", f"{len(df):,}")
        c2.metric("AI Agents", f"{len(df[df['Category']=='LLM / AI Agent']):,}")
        c3.metric("Search Bots", f"{len(df[df['Category']=='Standard Crawler']):,}")
        c4.metric("Unique IPs", f"{df['IP'].nunique():,}")
        
        st.write("")

        # --- CHARTS ROW ---
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.markdown("#### Bot Composition")
            counts = df['Category'].value_counts().reset_index()
            counts.columns = ['Category', 'Hits']
            
            # Dejan-style clean colors
            fig_pie = px.pie(
                counts, 
                names='Category', 
                values='Hits', 
                color_discrete_sequence=['#1a7f37', '#0969da', '#d0d7de'], # Green, Blue, Gray
                hole=0.4
            )
            fig_pie.update_layout(showlegend=True, margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with col_chart2:
            st.markdown("#### Status Codes")
            status_counts = df['Status'].value_counts().head(5).reset_index()
            status_counts.columns = ['Status Code', 'Count']
            
            fig_bar = px.bar(
                status_counts, 
                x='Status Code', 
                y='Count',
                color_discrete_sequence=['#24292e'] # Dark gray bars
            )
            fig_bar.update_layout(
                plot_bgcolor='white', 
                paper_bgcolor='white',
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=True, gridcolor='#f0f0f0'),
                margin=dict(t=0, b=0, l=0, r=0)
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # --- DATA TABLES ---
        st.markdown("#### Top Referers")
        st.markdown("""<div class="tech-note">External domains driving traffic to the server.</div>""", unsafe_allow_html=True)
        
        if df['Referer'].notna().any():
            top_ref = df['Referer'].value_counts().head(10).reset_index()
            top_ref.columns = ['Referer URL', 'Hits']
            st.dataframe(top_ref, use_container_width=True, hide_index=True)
        else:
            st.info("No referer data found in logs.")

        st.markdown("#### Raw Log Data (Filtered)")
        
        # Interactive Filter
        filter_opt = st.selectbox("Filter View:", ["All Traffic", "LLM / AI Agents Only", "Standard Crawlers Only", "Errors (4xx/5xx)"])
        
        df_view = df.copy()
        if filter_opt == "LLM / AI Agents Only":
            df_view = df[df['Category'] == "LLM / AI Agent"]
        elif filter_opt == "Standard Crawlers Only":
            df_view = df[df['Category'] == "Standard Crawler"]
        elif filter_opt == "Errors (4xx/5xx)":
            df_view = df[df['Status'].str.startswith(('4', '5'))]
            
        st.dataframe(
            df_view.sort_values(by="Time", ascending=False), 
            use_container_width=True,
            column_config={
                "Time": st.column_config.DatetimeColumn("Timestamp", format="D MMM YYYY, HH:mm:ss"),
            }
        )
        
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Processed CSV", csv, "log_forensics_report.csv", "text/csv")

    else:
        st.warning("No valid log entries found. Please check if the file format matches standard Apache/Nginx logs.")
