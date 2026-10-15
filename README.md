# OSINT-X

A Python-based OSINT investigation dashboard and API for authorized investigations using publicly accessible sources.

## Features

- Domain reconnaissance (DNS, RDAP, certificate transparency, public website metadata and security headers)
- Username checks across public platforms
- Evidence-oriented findings with source references and confidence labels
- Investigation reports in JSON, Markdown and HTML
- FastAPI dashboard and interactive API documentation

## Requirements

- Python 3.10 or newer (recommended)
- Internet access for public-source collectors

## Local setup (Windows)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install python-multipart
python -m uvicorn app:app --reload
```

Open http://127.0.0.1:8000/ for the dashboard and http://127.0.0.1:8000/docs for API documentation.

If PowerShell blocks activation, use Command Prompt instead:

```cmd
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pip install python-multipart
python -m uvicorn app:app --reload
```

## Configuration

Review `.env.example` and configure only the API keys needed for optional integrations. Never commit real `.env` files, API keys, access tokens, private investigation reports, or local databases.

## Responsible use

Use OSINT-X only for lawful, authorized investigations. Public-source matches are leads, not proof of identity; independently verify findings. Do not bypass authentication, access controls, or CAPTCHAs, and respect the terms and rate limits of third-party services.

## Status

This is a learning/portfolio project. External data sources may be unavailable or rate-limited; not every collector or integration is guaranteed to work in every environment.
