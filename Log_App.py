import streamlit as st
import pandas as pd
import io
import re

st.title("Log File Bot-Analyzer")

uploaded_file = st.file_uploader("Upload your log file (text format)", type=["log","txt","gz","bz2"])
if uploaded_file is not None:
    st.write("Processing file … this may take a while for large files")
    buffer = io.TextIOWrapper(uploaded_file, encoding='utf-8', errors='ignore')

    generic_bot_patterns = [
        r'Googlebot',
        r'Bingbot',
        r'AhrefsBot',
        r'SemrushBot',
        r'YandexBot',
        r'DuckDuckBot',
        r'crawler',
        r'spider',
    ]
    ai_llm_bot_patterns = [
        r'GPTBot',
        r'OAI-SearchBot',
        r'ChatGPT-User',
        r'ClaudeBot',
        r'claude-web',
        r'anthropic-ai',
        r'PerplexityBot',
        r'Perplexity-User',
        r'Google-Extended',
        r'Applebot-Extended',
        r'cohere-ai',
        r'AI2Bot',
        r'CCBot',
        r'DuckAssistBot',
        r'YouBot',
        r'MistralAI-User'
    ]
    bot_regex = re.compile("|".join(generic_bot_patterns + ai_llm_bot_patterns), flags=re.IGNORECASE)

    total_requests = 0
    bot_requests = 0
    llm_bot_requests = 0
    bot_useragents = {}
    llm_bot_useragents = {}

    for line in buffer:
        total_requests += 1
        parts = line.split('"')
        if len(parts) < 6:
            continue
        ua = parts[-2]
        if bot_regex.search(ua):
            bot_requests += 1
            if any(re.search(p, ua, flags=re.IGNORECASE) for p in ai_llm_bot_patterns):
                llm_bot_requests += 1
                llm_bot_useragents[ua] = llm_bot_useragents.get(ua, 0) + 1
            else:
                bot_useragents[ua] = bot_useragents.get(ua, 0) + 1
        if total_requests % 100000 == 0:
            st.write(f"Processed {total_requests} lines …")

    st.write("Total requests:", total_requests)
    st.write("Bot requests:", bot_requests)
    st.write("LLM/AI-bot requests:", llm_bot_requests)
    human_requests = total_requests - bot_requests
    st.write("Human/Non-bot requests:", human_requests)

    st.write("Top generic bot user-agents:")
    df_bots = pd.DataFrame(list(bot_useragents.items()), columns=["User-Agent","Count"]).sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_bots.head(20))

    st.write("Top LLM/AI bot user-agents:")
    df_llm = pd.DataFrame(list(llm_bot_useragents.items()), columns=["User-Agent","Count"]).sort_values(by="Count", ascending=False).reset_index(drop=True)
    st.dataframe(df_llm.head(20))