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
    /* --- FORCE LIGHT MODE --- */
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
# 2. BOT DATABASE
# -----------------------------------------------------------------------------
BOTS_AI = [
    r'gptbot', r'chatgpt-user', r'oai-searchbot', r'openai', r'claudebot', r'claude-web', 
    r'anthropic', r'perplexitybot', r'perplexity', r'applebot-extended', r'google-extended', 
    r'googleother', r'vertexai', r'ccbot', r'commoncrawl', r'cohere-ai', r'cohere', 
    r'diffbot', r'bytespider', r'imagesiftbot', r'facebookbot', r'meta-externalagent', 
    r'omgilibot', r'amazonbot', r'amazon-q', r'youbot', r'msnbot-media', r'bingbot-media', 
    r'ai2bot', r'mistral', r'dataminr', r'seekr', r'meltwater', r'turnitin', r'sidetrade', r'semrushbot-si'
]

BOTS_TRADITIONAL = [
    r'googlebot', r'bingbot', r'yandex', r'baiduspider', r'duckduckbot', r'sogou', r'exabot', 
    r'slurp', r'ahrefsbot', r'semrushbot', r'dotbot', r'mj12bot', r'rogerbot', r'moz', 
    r'serpstat', r'petalbot', r'aspiegel', r'aspiegelbot', r'pinterest', r'linkedinbot', 
    r'slackbot', r'twitterbot', r'facebookexternalhit', r'discordbot', r'telegrambot', 
    r'whatsapp', r'skypeuripreview', r'uptime', r'pingdom', r'gtmetrix', r'screaming frog'
]

def identify_bot(ua: str):
    if not ua or ua == "-": return "Human / Other"
    ua_l = ua.lower()
    
    # Priority 1: AI Agents
    for p in BOTS_AI:
        if re.search(p, ua_l): return "LLM / AI Agent"
        
    # Priority 2: Traditional Bots
    for p in BOTS_TRADITIONAL:
        if re.search(p, ua_l): return "Traditional Bot" # Fixed Naming Mismatch
        
    return "Human / Other"

def extract_time(ts_string: str):
    ts = ts_string.strip()
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
    **Parser:** Multi-Encoding Reassembler
    <div class="tech-note">
    <b>Smart Decoding:</b> Auto-detects UTF-16/UTF-8.
    <br><b>Fault Tolerance:</b> Re-assembles multi-line log entries.
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("### 🛡️ Signatures")
    with st.expander("AI Agents"):
        st.code("\n".join(BOTS_AI), language="text")
    with st.expander("Traditional Bots"):
        st.code("\n".join(BOTS_TRADITIONAL), language="text")

# -----------------------------------------------------------------------------
# 4. MAIN INTERFACE
# -----------------------------------------------------------------------------
st.title("Server Log Forensics")
st.markdown("### Traffic pattern analysis & Bot detection")

with st.expander("Technical Methodology", expanded=False):
    st.markdown("1. **Decoding:** Heuristic detection of file encoding.\n2. **Re-assembly:** Merges multi-line log entries.\n3. **Classification:** Segments traffic into AI, Search, and Human buckets.")

st.write("")
st.markdown("#### 1. Upload Access Log")
uploaded_file = st.file_uploader("Upload .log or .txt file", type=None)

if uploaded_file is not None:
    with st.spinner("Processing logs..."):
        # 1. READ & DETECT ENCODING
        raw_bytes = uploaded_file.read()
        text = ""
        try:
            text = raw_bytes.decode("utf-16")
            if "HTTP" not in text: raise ValueError()
        except:
            try: text = raw_bytes.decode("utf-8")
            except: text = raw_bytes.decode("latin-1", errors="ignore")
        
        raw_lines = text.splitlines()
        clean_entries = []
        
        # 2. ANCHOR LOGIC
        ip_finder = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        date_finder = re.compile(r'\[\d{2}/[A-Z][a-z]{2}/\d{4}')

        current_buffer = ""
        for line in raw_lines:
            line = line.strip()
            if not line: continue
            
            if date_finder.search(line):
                if current_buffer: clean_entries.append(current_buffer)
                
                # Cleanup Prefix
                ip_match = ip_finder.search(line)
                if ip_match: current_buffer = line[ip_match.start():]
                else: current_buffer = line
            else:
                current_buffer += " " + line
        
        if current_buffer: clean_entries.append(current_buffer)

    # 3. CLASSIFY
    with st.spinner(f"Classifying {len(clean_entries)} events..."):
        hits = []
        for entry in clean_entries:
            try:
                ip_m = ip_finder.search(entry)
                ip = ip_m.group(1) if ip_m else "-"
                
                time_m = re.search(r'\[([^\]]+)\]', entry)
                dt_str = time_m.group(1) if time_m else ""
                dt = extract_time(dt_str)
                
                quotes = re.findall(r'"([^"]*)"', entry)
                request = quotes[0] if len(quotes) > 0 else "-"
                referer = quotes[1] if len(quotes) > 1 else "-"
                ua = quotes[-1] if len(quotes) > 2 else "-"
                
                req_parts = request.split()
                method = req_parts[0] if len(req_parts) > 0 else "-"
                path = req_parts[1] if len(req_parts) > 1 else "-"
                
                clean_for_status = re.sub(r'"[^"]*"', '', entry) 
                status_m = re.search(r'\s(\d{3})\s', clean_for_status)
                status = status_m.group(1) if status_m else "000"

                bot_type = identify_bot(ua)
                
                hits.append({
                    "IP": ip, "Time": dt, "Method": method, "Path": path,
                    "Status": status, "Referer": referer, "User Agent": ua,
                    "Category": bot_type
                })
            except: continue

        df = pd.DataFrame(hits)

    if not df.empty:
        st.markdown("---")
        st.markdown("### Traffic Intelligence")
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Events", f"{len(df):,}")
        c2.metric("LLM / AI Bots", f"{len(df[df['Category']=='LLM / AI Agent']):,}")
        c3.metric("Standard Bots", f"{len(df[df['Category']=='Traditional Bot']):,}")
        c4.metric("Human/Other", f"{len(df[df['Category']=='Human / Other']):,}")
        
        st.write("")
        
        col_pie, col_bar = st.columns(2)
        with col_pie:
            st.markdown("#### Agent Distribution")
            counts = df['Category'].value_counts().reset_index()
            counts.columns = ['Category', 'Hits']
            # Fixed Colors matching Categories
            fig = px.pie(counts, names='Category', values='Hits', hole=0.4,
                         color='Category',
                         color_discrete_map={
                             "LLM / AI Agent": "#d93025", 
                             "Traditional Bot": "#1a73e8", 
                             "Human / Other": "#eeeeee"
                         })
            st.plotly_chart(fig, use_container_width=True)
            
        with col_bar:
            st.markdown("#### Response Codes")
            s_counts = df['Status'].value_counts().head(5).reset_index()
            s_counts.columns = ['Code', 'Count']
            fig2 = px.bar(s_counts, x='Code', y='Count', color_discrete_sequence=['#24292e'])
            fig2.update_layout(plot_bgcolor='white', yaxis=dict(gridcolor='#f0f0f0'))
            st.plotly_chart(fig2, use_container_width=True)

        st.markdown("#### Top Bots Detected")
        bot_df = df[df['Category'] != "Human / Other"]
        if not bot_df.empty:
            top_bots = bot_df.groupby(['Category', 'User Agent']).size().reset_index(name='Hits').sort_values('Hits', ascending=False).head(10)
            st.dataframe(top_bots, use_container_width=True)
        else:
            st.info("No Bots found.")

        st.markdown("#### Data Inspector")
        filter_val = st.selectbox("Filter By:", ["All", "LLM / AI Agents", "Standard Bots", "Errors"])
        
        view_df = df.copy()
        if filter_val == "LLM / AI Agents": view_df = df[df['Category'] == "LLM / AI Agent"]
        elif filter_val == "Standard Bots": view_df = df[df['Category'] == "Traditional Bot"]
        elif filter_val == "Errors": view_df = df[df['Status'].astype(str).str.startswith(('4','5'))]
        
        st.dataframe(view_df.sort_values(by="Time", ascending=False), use_container_width=True)
        st.download_button("Download CSV", df.to_csv(index=False).encode('utf-8'), "log_analysis.csv", "text/csv")

    else:
        st.error("No valid entries found.")
