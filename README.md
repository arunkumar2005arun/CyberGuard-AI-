# CyberGuard AI

CyberGuard AI is a Streamlit application for explainable, local-first checks of
URLs, messages, email content, and selected files. Detection is based on
explicit heuristic rules; this project does not include a trained model or
claim to provide machine-learning predictions.

## Features

- **URL scanner:** validates and parses HTTP(S) URLs without visiting them,
	then explains indicators such as IP hosts, embedded credentials, suspicious
	terms, long URLs, and unusual hostname patterns.
- **Message scanner:** identifies configured phishing, urgency, threat, prize,
	sensitive-information, and suspicious-link patterns.
- **Email scanner:** validates the sender address, compares selected brand
	mentions with configured domains, reuses message-content analysis, and can
	statically inspect up to five supported attachments (20 MB combined).
- **File scanner:** performs bounded static checks on TXT, PDF, DOCX, and common
	image formats. It does not execute files or macros and does not upload them.
- **Dashboard and history:** shows saved scan counts, recent activity, and
	filterable scan records using SQLite.

All scores are heuristic indicators, not proof that content is safe or
malicious. File inspection is intentionally limited: PDF text extraction is
basic, and image analysis checks file signatures and selected raw markers; the
application is not an antivirus engine.

## Run locally

```powershell
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Run the automated suite with:

```powershell
python -m unittest discover -s tests -v
```

The application creates `cyberguard.db` in the project root when history is
first used. New history rows retain scan type, a redacted target label, risk
level, category summary, and timestamp; message and email content, file names,
file hashes, and URL paths or queries are not stored in new rows. Existing rows
from earlier versions are not automatically rewritten.

## Streamlit Community Cloud

Deploy from the repository root with `app.py` as the main file. Keep the
project's directory structure intact and commit `requirements.txt` at the
repository root. In particular, `components/dashboard.py` and the other
first-party modules must remain inside their package folders; do not flatten
them into the root. The `.streamlit/config.toml`, `assets/`, and `pages/`
directories must also remain at the root level.

SQLite on Streamlit Community Cloud uses the app's local filesystem. That
filesystem may be ephemeral and is shared by sessions of the deployed app, so
this project is not a multi-user, privacy-isolated service. Do not submit
sensitive production data to a public deployment. The local database is
excluded from version control.

## Project layout

```text
app.py
requirements.txt
.streamlit/config.toml
ai/                    # no model-backed AI implementation is included
assets/
components/
config/
core/
database/
pages/
scanners/
services/
tests/
```