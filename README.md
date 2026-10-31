# CyberGuard AI

A local-first cybersecurity dashboard built with Streamlit and SQLite.

## Run locally

```powershell
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

The dashboard creates `cyberguard.db` locally when first opened. Its cards,
security overview, and recent activity are populated from saved scan records.
Scanner pages are navigation placeholders until their individual scanning
features are implemented.