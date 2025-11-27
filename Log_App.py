import streamlit as st
import pandas as pd
import re
from datetime import datetime
import plotly.express as px

# -----------------------------------------------------------------------------
# 1. VISUAL CONFIGURATION (Dejan Style)
# -----------------------------------------------------------------------------
st.set_page_config(page_title="Server Log Forensics", layout="wide", page_icon="🔎")

st.markdown("""
<style>
    :root { --primary-color: #1a7f37; --background-color: #ffffff; --secondary-background-color: #f6f8fa; --text-color: #24292e; --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
    .stApp { background-color: #ffffff; color: #24292e; }
    h1, h2, h3, h4, .markdown-text-container { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #000000 !important; letter-spacing: -0.3px; }
    p, li, span, div { color: #24292e; }
    section[data-testid="stSidebar"] { background-color: #f6f8fa; border-right: 1px solid #d0d7de; }
    section[data-testid="stSidebar"] * { color: #24292e !important; }
    [data-testid="stFileUploader"] { background-color: #f6f8fa; border: 1px dashed #d0d7de; border-radius: 6px; padding: 20px; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem !important; color: #1a7f37 !important; font-weight: 700; }
    div[data-testid="stMetricLabel"] { font-size: 0.9rem !important; color: #586069 !important; }
    .tech-note { font-size: 0.85rem; color: #57606a; background-color: #f3f4f6; border-left: 3px solid #0969da; padding: 12px; margin-top: 8px; margin-bottom: 15px; border-radius: 0 4px 4px 0; line-height: 1.5; }
    #MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 2. BOT DATABASE & LOGIC
# -----------------------------------------------------------------------------

# CATEGORY 1: LLM / AI (Data Scrapers, Chatbots)
BOTS_AI = [
    r'gptbot', r'chatgpt-user', r'oai-searchbot', r'openai',  # OpenAI
    r'claudebot', r'claude-web', r'anthropic',               # Anthropic
    r'perplexitybot', r'perplexity',                         # Perplexity
    r'applebot-extended',                                    # Apple AI
    r'google-extended', r'googleother', r'vertexai',         # Google AI
    r'ccbot', r'commoncrawl',                                # Common Crawl (Training Data)
    r'cohere-ai', r'cohere',                                 # Cohere
    r'diffbot', r'bytespider', r'imagesiftbot',              # Scrapers
    r'facebookbot', r'meta-externalagent', r'omgilibot',     # Meta / Social AI
    r'amazonbot',                                            # Amazon (Alexa/Training)
    r'youbot', r'msnbot-media', r'bingbot-media',            # Other AI Search
    r'ai2bot', r'mistral', r'dataminr'
]

# CATEGORY 2: TRADITIONAL (Search Engines, SEO Tools)
BOTS_TRADITIONAL = [
    r'googlebot', r'bingbot', r'yandex', r'baiduspider', r'duckduckbot', r'sogou', r'exabot', r'slurp', # Search Engines
    r'ahrefsbot', r'semrushbot', r'dotbot', r'mj12bot', r'rogerbot', r'moz', r'serpstat',                # SEO Tools
    r'petalbot', r'aspiegel',                                                                            # Huawei
    r'pinterest', r'linkedinbot', r'slackbot', r'twitterbot', r'facebookexternalhit', r'discordbot',     # Social Previews
    r'telegrambot', r'whatsapp', r'skypeuripreview',
    r'uptime', r'pingdom', r'gtmetrix'                                                                   # Monitoring
]

def identify_bot(ua: str):
    if not ua or ua == "-": return "Human / Other"
    ua_l = ua.lower()
    
    # Check AI first (Priority)
    for p in BOTS_AI:
        if re.search(p, ua_l): return "LLM / AI Agent"
        
    # Check Standard
    for p in BOTS_TRADITIONAL:
        if re.search(p, ua_l): return "Traditional Bot"
        
    return "Human / Other"

def extract_time_from_entry(ts_string: str):
    # Try parsing common formats
    ts = ts_string.strip()
    # Format: 19/Sep/2025:00:00:39 +0530
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try: return datetime.strptime(ts, fmt)
        except: continue
    return None

# -----------------------------------------------------------------------------
# 3. SIDEBAR
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Engine Config")
    st.markdown("""
    **Parser:** Multi-Line Reassembler
    <div class="tech-note">
    <b>Smart Merging:</b> Detects when log lines are split (e.g. wrapped by text editors or grep) and re-assembles them before analysis.
    <br><b>Prefix Stripping:</b> Automatically ignores <code>filename:line:</code> prefixes.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### 🛡️ Detection Capabilities")
    with st.expander("Show AI Agent Signatures"):
        st.code("\n".join(BOTS_AI), language="text")
    with st.expander("Show Traditional Bot Signatures"):
        st.code("\n".join(BOTS_TRADITIONAL), language="text")

# -----------------------------------------------------------------------------
# 4. MAIN INTERFACE
# -----------------------------------------------------------------------------

st.title("Server Log Forensics")
st.markdown("### Traffic pattern analysis & Bot detection")

with st.expander("Technical Methodology", expanded=False):
    st.markdown("""
    1.  **Re-assembly:** Reads the raw file and merges split lines based on IP address patterns.
    2.  **Extraction:** regex parses `IP`, `Timestamp`, `Request`, `Status`, `Bytes`, `Referer`, `User-Agent`.
    3.  **Classification:** Segments traffic into **LLM/AI**, **Traditional Bots**, and **Humans**.
    """)

st.write("")
st.markdown("#### 1. Upload Access Log")
uploaded_file = st.file_uploader("Upload .log or .txt file (Supports Grep output)", type=None)

if uploaded_file is not None:
    # -------------------------------------------------------------------------
    # 5. PRE-PROCESSING (LINE MERGING)
    # -------------------------------------------------------------------------
    with st.spinner("Re-assembling log lines..."):
        raw_bytes = uploaded_file.read()
        try: text = raw_bytes.decode("utf-8")
        except: text = raw_bytes.decode("latin-1", errors="ignore")
        
        raw_lines = text.splitlines()
        clean_lines = []
        
        # Regex to detect the START of a log line (Any Prefix + IP Address)
        # Matches: "access.log:123:127.0.0.1" OR just "127.0.0.1"
        start_pattern = re.compile(r'.*?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        
        current_buffer = ""
        
        for line in raw_lines:
            line = line.strip()
            if not line: continue
            
            # Does this line look like the start of a new entry?
            # It must contain an IP address sequence
            if start_pattern.match(line):
                # If we have a previous buffer, save it
                if current_buffer:
                    clean_lines.append(current_buffer)
                current_buffer = line
            else:
                # It's a continuation of the previous line (e.g. wrapped UA)
                current_buffer += " " + line
                
        # Append last buffer
        if current_buffer:
            clean_lines.append(current_buffer)

    # -------------------------------------------------------------------------
    # 6. PARSING
    # -------------------------------------------------------------------------
    with st.spinner(f"Parsing {len(clean_lines)} entries..."):
        hits = []
        
        # Greedy Regex to extract data regardless of prefix
        # 1. IP
        # 2. Timestamp [...]
        # 3. Request "..."
        # 4. Status 
        # 5. Bytes
        # 6. Referer "..."
        # 7. UA "..."
        log_regex = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?\[(?P<time>[^\]]+)\].*?"(?P<req>[^"]*)".*?\s(?P<status>\d{3})\s+(?P<bytes>\d+|-).*?"(?P<ref>[^"]*)".*?"(?P<ua>[^"]*)"')

        for entry in clean_lines:
            match = log_regex.search(entry)
            if match:
                d = match.groupdict()
                
                # Parse Request (Method + Path)
                req_parts = d['req'].split()
                method = req_parts[0] if len(req_parts) > 0 else "-"
                path = req_parts[1] if len(req_parts) > 1 else "-"
                
                # Bot ID
                bot_type = identify_bot(d['ua'])
                
                hits.append({
                    "IP": d['ip'],
                    "Time": extract_time_from_entry(d['time']),
                    "Method": method,
                    "Path": path,
                    "Status": d['status'],
                    "Referer": d['ref'] if d['ref'] != "-" else None,
                    "User Agent": d['ua'],
                    "Category": bot_type
                })
        
        df = pd.DataFrame(hits)

    if not df.empty:
        # ---------------------------------------------------------------------
        # 7. RESULTS
        # ---------------------------------------------------------------------
        st.markdown("---")
        st.markdown("### Traffic Intelligence")
        
        # Metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Hits", f"{len(df):,}")
        c2.metric("LLM / AI Bots", f"{len(df[df['Category']=='LLM / AI Agent']):,}")
        c3.metric("Traditional Bots", f"{len(df[df['Category']=='Traditional Bot']):,}")
        c4.metric("Human / Other", f"{len(df[df['Category']=='Human / Other']):,}")
        
        st.write("")

        # Charts
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.markdown("#### Agent Composition")
            counts = df['Category'].value_counts().reset_index()
            counts.columns = ['Category', 'Hits']
            # Specific Colors: Red for AI, Blue for Trad, Gray for Human
            fig_pie = px.pie(counts, names='Category', values='Hits', 
                             color='Category',
                             color_discrete_map={
                                 "LLM / AI Agent": "#d93025", 
                                 "Traditional Bot": "#1a73e8", 
                                 "Human / Other": "#eeeeee"
                             },
                             hole=0.4)
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with col_chart2:
            st.markdown("#### Status Codes")
            status_counts = df['Status'].value_counts().head(5).reset_index()
            status_counts.columns = ['Status Code', 'Count']
            fig_bar = px.bar(status_counts, x='Status Code', y='Count', color_discrete_sequence=['#24292e'])
            fig_bar.update_layout(plot_bgcolor='white', yaxis=dict(gridcolor='#f0f0f0'))
            st.plotly_chart(fig_bar, use_container_width=True)

        # Detail Tables
        st.markdown("#### Top User Agents (AI Only)")
        ai_df = df[df['Category'] == "LLM / AI Agent"]
        if not ai_df.empty:
            top_ai = ai_df['User Agent'].value_counts().head(10).reset_index()
            top_ai.columns = ['User Agent String', 'Hits']
            st.dataframe(top_ai, use_container_width=True)
        else:
            st.info("No AI Agents detected in this log.")

        st.markdown("#### Raw Log Data")
        
        # Filter
        filter_opt = st.selectbox("View:", ["All", "LLM / AI Agents", "Traditional Bots", "Humans"])
        df_view = df.copy()
        if filter_opt == "LLM / AI Agents": df_view = df[df['Category'] == "LLM / AI Agent"]
        elif filter_opt == "Traditional Bots": df_view = df[df['Category'] == "Traditional Bot"]
        elif filter_opt == "Humans": df_view = df[df['Category'] == "Human / Other"]
        
        st.dataframe(
            df_view.sort_values(by="Time", ascending=False),
            use_container_width=True,
            column_config={"Time": st.column_config.DatetimeColumn("Timestamp", format="D MMM YYYY, HH:mm:ss")}
        )
        
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Report CSV", csv, "forensics_report.csv", "text/csv")

    else:
        st.error("Parsing failed. 0 valid entries found. Please ensure the file contains NCSA formatted logs (IP, Date, Request).")
