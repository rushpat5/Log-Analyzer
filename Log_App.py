import streamlit as st
import pandas as pd
import re
from datetime import datetime
import plotly.express as px

# -----------------------------------------------------------------------------
# 1. VISUAL CONFIGURATION (Dejan Style - Light Mode Forced)
# -----------------------------------------------------------------------------
st.set_page_config(page_title="Server Log Forensics", layout="wide", page_icon="🔎")

st.markdown("""
<style>
    /* --- FORCE LIGHT MODE --- */
    :root { --primary-color: #1a7f37; --background-color: #ffffff; --secondary-background-color: #f6f8fa; --text-color: #24292e; --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
    .stApp { background-color: #ffffff; color: #24292e; }
    
    /* Typography */
    h1, h2, h3, h4, .markdown-text-container { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #000000 !important; letter-spacing: -0.3px; }
    p, li, span, div { color: #24292e; }
    a { color: #0969da; text-decoration: none; }
    a:hover { text-decoration: underline; }
    
    /* Sidebar */
    section[data-testid="stSidebar"] { background-color: #f6f8fa; border-right: 1px solid #d0d7de; }
    section[data-testid="stSidebar"] * { color: #24292e !important; }
    
    /* Components */
    [data-testid="stFileUploader"] { background-color: #f6f8fa; border: 1px dashed #d0d7de; border-radius: 6px; padding: 20px; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem !important; color: #1a7f37 !important; font-weight: 700; }
    div[data-testid="stMetricLabel"] { font-size: 0.9rem !important; color: #586069 !important; }
    
    /* Tech Note */
    .tech-note { font-size: 0.85rem; color: #57606a; background-color: #f3f4f6; border-left: 3px solid #0969da; padding: 12px; margin-top: 8px; margin-bottom: 15px; border-radius: 0 4px 4px 0; line-height: 1.5; }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] { border-bottom: 1px solid #e1e4e8; }
    .stTabs [data-baseweb="tab"] { font-weight: 600; color: #586069; }
    .stTabs [aria-selected="true"] { color: #1a7f37 !important; border-bottom-color: #1a7f37 !important; }

    /* Clean UI */
    #MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 2. BOT DATABASE
# -----------------------------------------------------------------------------
# Comprehensive list of AI Agents (Scrapers/LLMs)
BOTS_AI = [
    r'gptbot', r'chatgpt-user', r'oai-searchbot', r'openai',  # OpenAI
    r'claudebot', r'claude-web', r'anthropic',               # Anthropic
    r'perplexitybot', r'perplexity',                         # Perplexity
    r'applebot-extended',                                    # Apple AI
    r'google-extended', r'googleother', r'vertexai',         # Google AI
    r'ccbot', r'commoncrawl',                                # Common Crawl
    r'cohere-ai', r'cohere',                                 # Cohere
    r'diffbot', r'bytespider', r'imagesiftbot',              # ByteDance/Scrapers
    r'facebookbot', r'meta-externalagent', r'omgilibot',     # Meta
    r'amazonbot', r'amazon-q',                               # Amazon
    r'youbot', r'msnbot-media', r'bingbot-media',            # Other AI Search
    r'ai2bot', r'mistral', r'dataminr', r'seekr',
    r'meltwater', r'turnitin', r'sidetrade', r'semrushbot-si', 
    r'chatgpt' # Fallback
]

# Comprehensive list of Standard SEO Crawlers
BOTS_TRADITIONAL = [
    r'googlebot', r'bingbot', r'yandex', r'baiduspider', r'duckduckbot', r'sogou', r'exabot', r'slurp', # Engines
    r'ahrefsbot', r'semrushbot', r'dotbot', r'mj12bot', r'rogerbot', r'moz', r'serpstat',                # SEO Tools
    r'petalbot', r'aspiegel', r'aspiegelbot',                                                            # Huawei
    r'pinterest', r'linkedinbot', r'slackbot', r'twitterbot', r'facebookexternalhit', r'discordbot',     # Social
    r'telegrambot', r'whatsapp', r'skypeuripreview',
    r'uptime', r'pingdom', r'gtmetrix', r'screaming frog',
    r'adsbot-google', r'mediapartners-google', r'feedfetcher-google' # Google specific services
]

def identify_bot(ua: str):
    if not ua or ua == "-": return "Human / Other"
    ua_l = ua.lower()
    
    # Check AI First (They are the priority for blocking/analysis)
    for p in BOTS_AI:
        if p in ua_l: return "LLM / AI Agent"
        
    # Check Standard
    for p in BOTS_TRADITIONAL:
        if p in ua_l: return "Standard Bot"
        
    return "Human / Other"

def extract_time(ts_string: str):
    # Standard NCSA format: 19/Sep/2025:00:00:39 +0530
    if not ts_string: return None
    ts = ts_string.strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try: return datetime.strptime(ts, fmt)
        except: continue
    return None

# -----------------------------------------------------------------------------
# 3. SIDEBAR
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Parser Engine")
    st.markdown("""
    **Core:** Multi-Line Fault Tolerant
    <div class="tech-note">
    <b>Normalization:</b> Handles UTF-16/UTF-8 encoding and strips <code>grep</code> prefixes.
    <br><b>Re-assembly:</b> Stitches broken log lines together to ensure User-Agents aren't truncated.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### 🛡️ Detection Database")
    
    with st.expander("Category: AI & LLM Agents"):
        st.markdown("Bots used for model training or RAG (Retrieval Augmented Generation).")
        st.code("\n".join(BOTS_AI), language="text")
        
    with st.expander("Category: Standard Crawlers"):
        st.markdown("Bots used for search indexing and SEO analysis.")
        st.code("\n".join(BOTS_TRADITIONAL), language="text")

# -----------------------------------------------------------------------------
# 4. MAIN INTERFACE
# -----------------------------------------------------------------------------

st.title("Server Log Forensics")
st.markdown("### Bot Classification & Traffic Inspector")

with st.expander("Methodology & Technical Context (Read First)", expanded=False):
    st.markdown("""
    **Why analyze raw logs?**
    Server logs provide the only unfiltered view of who is accessing your infrastructure. JavaScript-based analytics (like GA4) often fail to capture bot traffic.
    
    **Classification Logic:**
    1.  **LLM / AI Agents:** Scrapers like [GPTBot](https://platform.openai.com/docs/gptbot) and [ClaudeBot](https://docs.anthropic.com/en/docs/claude-bot) that consume content to train AI models. Identifying these allows you to decide whether to block them via `robots.txt`.
    2.  **Standard Bots:** Essential crawlers like [Googlebot](https://developers.google.com/search/docs/crawling-indexing/googlebot) and Ahrefs. These are vital for SEO visibility.
    3.  **Human/Other:** Regular users or unidentified scripts.
    """)

st.write("")
st.markdown("#### 1. Upload Access Log")
uploaded_file = st.file_uploader("Upload .log or .txt file", type=None)

if uploaded_file is not None:
    # -------------------------------------------------------------------------
    # 5. PARSING LOGIC
    # -------------------------------------------------------------------------
    with st.spinner("Processing log structure..."):
        
        # 1. ENCODING DETECTION
        raw_bytes = uploaded_file.read()
        text = ""
        # Check for null bytes indicative of UTF-16
        if b'\x00' in raw_bytes:
            try: text = raw_bytes.decode("utf-16")
            except: text = raw_bytes.decode("utf-16-be", errors="ignore")
        else:
            try: text = raw_bytes.decode("utf-8")
            except: text = raw_bytes.decode("latin-1", errors="ignore")
        
        text = text.replace('\x00', '')
        raw_lines = text.splitlines()
        clean_entries = []
        
        # 2. LOG RE-ASSEMBLY
        # Locate Valid IP + Timestamp to identify start of a line
        ip_finder = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        date_finder = re.compile(r'\[\d{2}/[A-Z][a-z]{2}/\d{4}')

        current_buffer = ""
        
        for line in raw_lines:
            line = line.strip()
            if not line: continue
            
            # Start of new entry?
            if date_finder.search(line):
                if current_buffer:
                    clean_entries.append(current_buffer)
                
                # Strip Prefix (grep output)
                ip_match = ip_finder.search(line)
                if ip_match:
                    current_buffer = line[ip_match.start():]
                else:
                    current_buffer = line
            else:
                # Continuation of previous entry
                current_buffer += " " + line
        
        if current_buffer:
            clean_entries.append(current_buffer)

    # 3. EXTRACTION
    with st.spinner(f"Classifying {len(clean_entries)} events..."):
        hits = []
        for entry in clean_entries:
            try:
                # Regex Extraction
                ip_m = ip_finder.search(entry)
                ip = ip_m.group(1) if ip_m else "-"
                
                time_m = re.search(r'\[([^\]]+)\]', entry)
                dt_str = time_m.group(1) if time_m else ""
                dt = extract_time(dt_str)
                
                # Extract quoted strings
                quotes = re.findall(r'"([^"]*)"', entry)
                request = quotes[0] if len(quotes) > 0 else "-"
                referer = quotes[1] if len(quotes) > 1 else "-"
                ua = quotes[-1] if len(quotes) > 2 else "-"
                
                # Parse Request
                req_parts = request.split()
                method = req_parts[0] if len(req_parts) > 0 else "-"
                path = req_parts[1] if len(req_parts) > 1 else "-"
                
                # Parse Status
                clean_for_status = re.sub(r'"[^"]*"', '', entry) 
                status_m = re.search(r'\s(\d{3})\s', clean_for_status)
                status = status_m.group(1) if status_m else "000"

                # Identify Bot
                bot_type = identify_bot(ua)
                
                hits.append({
                    "IP": ip, "Time": dt, "Method": method, "Path": path,
                    "Status": status, "Referer": referer, "User Agent": ua,
                    "Category": bot_type
                })
            except: continue

        df = pd.DataFrame(hits)

    if not df.empty:
        # ---------------------------------------------------------------------
        # 7. RESULTS DASHBOARD
        # ---------------------------------------------------------------------
        st.markdown("---")
        st.markdown("### Analysis Report")
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Events", f"{len(df):,}")
        c2.metric("LLM / AI Bots", f"{len(df[df['Category']=='LLM / AI Agent']):,}")
        c3.metric("Standard Bots", f"{len(df[df['Category']=='Standard Bot']):,}")
        c4.metric("Human/Other", f"{len(df[df['Category']=='Human / Other']):,}")
        
        st.write("")
        
        # Charts
        col_pie, col_bar = st.columns(2)
        with col_pie:
            st.markdown("#### Agent Distribution")
            counts = df['Category'].value_counts().reset_index()
            counts.columns = ['Category', 'Hits']
            fig = px.pie(counts, names='Category', values='Hits', hole=0.4,
                         color='Category',
                         color_discrete_map={
                             "LLM / AI Agent": "#d93025", 
                             "Standard Bot": "#1a73e8", 
                             "Human / Other": "#eeeeee"
                         })
            st.plotly_chart(fig, use_container_width=True)
            
        with col_bar:
            st.markdown("#### HTTP Status Codes")
            s_counts = df['Status'].value_counts().head(5).reset_index()
            s_counts.columns = ['Code', 'Count']
            s_counts['Code'] = s_counts['Code'].astype(str) # Force Category
            fig2 = px.bar(s_counts, x='Code', y='Count', color_discrete_sequence=['#24292e'])
            fig2.update_layout(plot_bgcolor='white', yaxis=dict(gridcolor='#f0f0f0'), xaxis=dict(type='category'))
            st.plotly_chart(fig2, use_container_width=True)

        # --- DETAILED BREAKDOWN TABS ---
        st.markdown("### Bot Activity Explorer")
        st.markdown("""<div class="tech-note">Explore the specific User-Agents identified in your logs.</div>""", unsafe_allow_html=True)
        
        tab_ai, tab_std, tab_all = st.tabs(["🔴 AI Agents", "🔵 Standard Bots", "📋 All Data"])
        
        with tab_ai:
            ai_df = df[df['Category'] == "LLM / AI Agent"]
            if not ai_df.empty:
                st.dataframe(ai_df['User Agent'].value_counts().reset_index(name='Hits'), use_container_width=True)
                with st.expander("View Full AI Logs"):
                    st.dataframe(ai_df, use_container_width=True)
            else:
                st.success("No AI Agents detected.")

        with tab_std:
            std_df = df[df['Category'] == "Standard Bot"]
            if not std_df.empty:
                st.dataframe(std_df['User Agent'].value_counts().reset_index(name='Hits'), use_container_width=True)
                with st.expander("View Full Standard Bot Logs"):
                    st.dataframe(std_df, use_container_width=True)
            else:
                st.info("No Standard Bots (Google/Bing) detected.")

        with tab_all:
            st.dataframe(
                df.sort_values(by="Time", ascending=False),
                use_container_width=True,
                column_config={"Time": st.column_config.DatetimeColumn("Timestamp", format="D MMM, HH:mm:ss")}
            )
            st.download_button("Download Full CSV", df.to_csv(index=False).encode('utf-8'), "log_analysis.csv", "text/csv")

    else:
        st.error("Parsing Failure. Please ensure the file is a standard Access Log (UTF-8 or UTF-16).")
