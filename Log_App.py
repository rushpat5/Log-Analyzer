import streamlit as st
import pandas as pd
import re
from datetime import datetime
from io import BytesIO

st.set_page_config(page_title="Bot Log Parser (Full DateTime)", page_icon="🧠", layout="wide")

st.title("🧠 Advanced Bot Log Parser (Full Timestamp Version)")
st.caption("Upload raw .log or .txt files — auto-detects timestamp, URL, status, and user-agent.")

uploaded = st.file_uploader("Upload log file", type=["log", "txt"])

# Define month mapping
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5,
    "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10,
    "Nov": 11, "Dec": 12
}

# Regex patterns
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<date>\d{2})/(?P<month>\w{3})/(?P<year>\d{4}):(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) [+\-]\d{4}\] "(?:GET|POST) (?P<url>\S+) [^"]+" (?P<status>\d{3}) [^"]* "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)
ALT_PATTERN = re.compile(
    r'(?P<ua>Mozilla[^"]+) (?P<status>\d{3}) (?P<url>/\S*)'
)

if uploaded:
    lines = uploaded.read().decode("utf-8", errors="ignore").splitlines()
    parsed = []

    for line in lines:
        match = LOG_PATTERN.search(line)
        if match:
            g = match.groupdict()
            try:
                dt = datetime(
                    int(g["year"]), MONTHS[g["month"]], int(g["date"]),
                    int(g["hour"]), int(g["minute"]), int(g["second"])
                )
            except Exception:
                dt = None
            parsed.append({
                "IP": g["ip"],
                "datetime": dt,
                "url": g["url"],
                "status": int(g["status"]),
                "User-Agent": g["ua"]
            })
        else:
            # Try Applebot-style or truncated formats
            alt = ALT_PATTERN.search(line)
            if alt:
                g = alt.groupdict()
                parsed.append({
                    "IP": None,
                    "datetime": None,
                    "url": g.get("url", ""),
                    "status": int(g.get("status", 0)),
                    "User-Agent": g.get("ua", "")
                })

    df = pd.DataFrame(parsed)
    if df.empty:
        st.error("❌ No valid log entries found — check format or upload a different log file.")
    else:
        st.success(f"✅ Parsed {len(df):,} entries successfully.")
        st.dataframe(df.head(50), use_container_width=True)

        # Save Excel
        buffer = BytesIO()
        df.to_excel(buffer, index=False, engine="openpyxl")
        buffer.seek(0)
        st.download_button(
            "⬇ Download Structured Log (Excel)",
            data=buffer,
            file_name="parsed_logs.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
else:
    st.info("Upload a log file to begin.")
