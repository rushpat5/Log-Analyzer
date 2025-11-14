# Bot-Focused Log Analyzer

Parses server access logs and extracts bot traffic patterns. 
Supports search crawlers, AI crawlers, AI assistants, and LLM-driven user-agent fetchers.
Generates summaries, hourly histograms, status distributions, top URLs, and full per-bot CSV exports.

## Features
- Large-file streaming parser (≤200 MB on Streamlit Cloud)
- Verified UA pattern set (search engines, AI crawlers, AI model-trainers)
- Per-bot analytics
- Hourly traffic histogram
- Status-class distribution
- Top paths, top IPs, UA variants
- CSV export

## How to run on Streamlit Cloud
1. Upload this repo.
2. Add `app.py` as the main app.
3. Ensure `requirements.txt` is present.

## Custom Bot Patterns
Edit the block in `app.py`:
`CUSTOM_TOP50_EXTENSIONS = [ r'\bYourBotHere\b', ... ]`

## Supported Log Formats
- Apache Combined Log
- Apache Common Log
- Nginx access logs
- Multi-line wrapped entries
