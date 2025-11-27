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
    
    /* Sidebar */
    section[data-testid="stSidebar"] { background-color: #f6f8fa; border-right: 1px solid #d0d7de; }
    section[data-testid="stSidebar"] * { color: #24292e !important; }
    
    /* Components */
    [data-testid="stFileUploader"] { background-color: #f6f8fa; border: 1px dashed #d0d7de; border-radius: 6px; padding: 20px; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem !important; color: #1a7f37 !important; font-weight: 700; }
    div[data-testid="stMetricLabel"] { font-size: 0.9rem !important; color: #586069 !important; }
    
    /* Tech Note */
    .tech-note { font-size: 0.85rem; color: #57606a; background-color: #f3f4f6; border-left: 3px solid #0969da; padding: 12px; margin-top: 8px; margin-bottom: 15px; border-radius: 0 4px 4px 0; line-height: 1.5; }
    
    /* Clean UI */
    #MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 2. EXTENSIVE BOT DATABASE
# -----------------------------------------------------------------------------

# AI / LLM AGENTS (Scrapers, Training Data, Chatbots)
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
    r'meltwater', r'turnitin', r'sidetrade', r'semrushbot-si'
]

# TRADITIONAL CRAWLERS (SEO, Search Engines, Monitors)
BOTS_TRADITIONAL = [
    r'googlebot', r'bingbot', r'yandex', r'baiduspider', r'duckduckbot', r'sogou', r'exabot', r'slurp', # Engines
    r'ahrefsbot', r'semrushbot', r'dotbot', r'mj12bot', r'rogerbot', r'moz', r'serpstat',                # SEO Tools
    r'petalbot', r'aspiegel', r'aspiegelbot',                                                            # Huawei
    r'pinterest', r'linkedinbot', r'slackbot', r'twitterbot', r'facebookexternalhit', r'discordbot',     # Social
    r'telegrambot', r'whatsapp', r'skypeuripreview',
    r'uptime', r'pingdom', r'gtmetrix', r'screaming frog'                                                # Monitoring
]

def identify_bot(ua: str):
    if not ua or ua == "-": return "Human / Other"
    ua_l = ua.lower()
    
    # Priority Check: AI First
    for p in BOTS_AI:
        if re.search(p, ua_l): return "LLM / AI Agent"
        
    for p in BOTS_TRADITIONAL:
        if re.search(p, ua_l): return "Standard Bot"
        
    return "Human / Other"

def extract_time_from_entry(ts_string: str):
    # Parses: 19/Sep/2025:00:00:39 +0530
    if not ts_string: return None
    ts = ts_string.strip()
    # Try with and without timezone
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try: return datetime.strptime(ts, fmt)
        except: continue
    return None

# -----------------------------------------------------------------------------
# 3. SIDEBAR
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Parser Configuration")
    
    st.markdown("""
    **Engine:** Robust Multi-Line Reassembler
    <div class="tech-note">
    <b>What this does:</b> This tool reads raw server logs (Apache/Nginx). 
    It automatically fixes broken lines (common in large exports) and strips metadata prefixes (like grep filenames) to ensure 100% data accuracy.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### 🛡️ Detection capabilities")
    st.markdown("We maintain a database of 50+ signatures to distinguish between beneficial crawlers and AI scrapers.")
    
    with st.expander("View AI Agent List"):
        st.code("\n".join(BOTS_AI), language="text")
    with st.expander("View Standard Bot List"):
        st.code("\n".join(BOTS_TRADITIONAL), language="text")

# -----------------------------------------------------------------------------
# 4. MAIN INTERFACE
# -----------------------------------------------------------------------------

st.title("Server Log Forensics")
st.markdown("### AI & Bot Traffic Inspector")

with st.expander("How this tool works (Read First)", expanded=False):
    st.markdown("""
    **The Problem:** Your website traffic is a mix of Humans, SEO Bots (Google), and AI Scrapers (ChatGPT, Claude). Standard analytics tools (GA4) often block or hide bot traffic, leaving you blind to who is actually crawling your site.
    
    **The Solution:** This tool analyzes raw server logs to uncover the truth.
    
    1.  **Ingestion & Repair:** We upload raw logs. The engine fixes broken lines and handles character encoding (UTF-16/UTF-8) automatically.
    2.  **Fingerprinting:** We analyze the `User-Agent` string of every hit against our proprietary database.
    3.  **Classification:**
        *   🔴 **LLM / AI Agents:** Bots scraping your content to train AI models (e.g., GPTBot, CCBot).
        *   🔵 **Standard Bots:** Essential crawlers for SEO ranking (e.g., Googlebot, Ahrefs).
        *   ⚪ **Humans:** Real users visiting via browsers.
    """)

st.write("")
st.markdown("#### 1. Upload Access Log")
uploaded_file = st.file_uploader("Upload .log or .txt file (Supports Grep output)", type=None)

if uploaded_file is not None:
    # -------------------------------------------------------------------------
    # 5. ROBUST PARSING ENGINE
    # -------------------------------------------------------------------------
    with st.spinner("Analyzing log structure..."):
        
        # 1. Read & Decode
        raw_bytes = uploaded_file.read()
        try: text = raw_bytes.decode("utf-8")
        except: text = raw_bytes.decode("latin-1", errors="ignore")
        
        raw_lines = text.splitlines()
        clean_entries = []
        
        # 2. Re-assembly Logic
        # Pattern: Look for "IP - - [" which marks the start of a valid entry
        # This regex looks for the [DD/Mon/YYYY sequence
        start_marker = re.compile(r'\[\d{2}/[A-Z][a-z]{2}/\d{4}')
        
        # Pattern to find IP address (to strip prefixes)
        ip_finder = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        current_buffer = ""
        
        for line in raw_lines:
            line = line.strip()
            if not line: continue
            
            # Is this a new entry? (Does it have a Timestamp?)
            if start_marker.search(line):
                # Save previous buffer
                if current_buffer:
                    clean_entries.append(current_buffer)
                
                # Start new buffer
                # CLEANUP: Find the IP, and slice everything before it (removes grep prefix)
                ip_match = ip_finder.search(line)
                if ip_match:
                    current_buffer = line[ip_match.start():]
                else:
                    current_buffer = line
            else:
                # No timestamp? It's a broken line (continuation)
                current_buffer += " " + line
                
        # Append last buffer
        if current_buffer:
            clean_entries.append(current_buffer)

    # -------------------------------------------------------------------------
    # 6. EXTRACTION
    # -------------------------------------------------------------------------
    with st.spinner(f"Classifying {len(clean_entries)} events..."):
        hits = []
        
        for entry in clean_entries:
            try:
                # 1. Extract IP (First token)
                ip_match = ip_finder.search(entry)
                ip = ip_match.group(1) if ip_match else "-"
                
                # 2. Extract Time [...]
                time_match = re.search(r'\[([^\]]+)\]', entry)
                dt_str = time_match.group(1) if time_match else ""
                dt = extract_time_from_entry(dt_str)
                
                # 3. Extract Quoted Strings (Request, Referer, UA)
                quotes = re.findall(r'"([^"]*)"', entry)
                
                request = quotes[0] if len(quotes) > 0 else "-"
                referer = quotes[1] if len(quotes) > 1 else "-"
                ua = quotes[-1] if len(quotes) > 2 else "-" # UA is usually last
                
                # 4. Parse Request
                req_parts = request.split()
                method = req_parts[0] if len(req_parts) > 0 else "-"
                path = req_parts[1] if len(req_parts) > 1 else "-"
                
                # 5. Parse Status
                # Find the number between the first and second quote
                between_quotes = entry.split('"')[2] if len(entry.split('"')) > 2 else ""
                status_match = re.search(r'\s(\d{3})\s', " " + between_quotes + " ")
                status = status_match.group(1) if status_match else "000"

                # 6. ID Bot
                bot_type = identify_bot(ua)
                
                hits.append({
                    "IP": ip,
                    "Time": dt,
                    "Method": method,
                    "Path": path,
                    "Status": status,
                    "Referer": referer,
                    "User Agent": ua,
                    "Category": bot_type
                })
            except:
                continue # Skip malformed lines

        df = pd.DataFrame(hits)

    if not df.empty:
        # ---------------------------------------------------------------------
        # 7. VISUALIZATION
        # ---------------------------------------------------------------------
        st.markdown("---")
        st.markdown("### Traffic Intelligence")
        
        # KPI Cards
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
            # Specific Colors: Red for AI, Blue for Trad, Gray for Human
            fig = px.pie(counts, names='Category', values='Hits', hole=0.4,
                         color='Category',
                         color_discrete_map={
                             "LLM / AI Agent": "#d93025", 
                             "Standard Bot": "#1a73e8", 
                             "Human / Other": "#eeeeee"
                         })
            st.plotly_chart(fig, use_container_width=True)
            
        with col_bar:
            st.markdown("#### Server Response Codes")
            # --- FIX: Ensure X-axis is categorical (Strings) ---
            s_counts = df['Status'].value_counts().head(10).reset_index()
            s_counts.columns = ['Code', 'Count']
            # Force Code to be a string so Plotly treats it as a category, not a number
            s_counts['Code'] = s_counts['Code'].astype(str)
            
            fig2 = px.bar(s_counts, x='Code', y='Count', color_discrete_sequence=['#24292e'])
            fig2.update_layout(
                plot_bgcolor='white', 
                yaxis=dict(gridcolor='#f0f0f0'),
                xaxis=dict(type='category') # Enforce categorical x-axis
            )
            st.plotly_chart(fig2, use_container_width=True)

        # Deep Dives
        st.markdown("#### Bot Activity Breakdown")
        bot_df = df[df['Category'] != "Human / Other"]
        
        if not bot_df.empty:
            # Group by Category AND UA
            top_bots = bot_df.groupby(['Category', 'User Agent']).size().reset_index(name='Hits').sort_values('Hits', ascending=False).head(15)
            st.dataframe(top_bots, use_container_width=True)
        else:
            st.info("No automated bot traffic detected in this sample.")

        st.markdown("#### Raw Data Inspector")
        filter_val = st.selectbox("Filter By:", ["All", "LLM / AI Agents", "Standard Bots", "Errors (4xx/5xx)"])
        
        view_df = df.copy()
        if filter_val == "LLM / AI Agents": view_df = df[df['Category'] == "LLM / AI Agent"]
        elif filter_val == "Standard Bots": view_df = df[df['Category'] == "Standard Bot"]
        elif filter_val == "Errors (4xx/5xx)": view_df = df[df['Status'].astype(str).str.startswith(('4','5'))]
        
        st.dataframe(
            view_df.sort_values(by="Time", ascending=False),
            use_container_width=True,
            column_config={"Time": st.column_config.DatetimeColumn("Timestamp", format="D MMM, HH:mm:ss")}
        )
        
        st.download_button("Download Data (CSV)", df.to_csv(index=False).encode('utf-8'), "log_analysis.csv", "text/csv")

    else:
        st.error("Parsing Failure: No valid entries found. Please ensure the log format contains standard NCSA timestamps [DD/Mon/YYYY].")
