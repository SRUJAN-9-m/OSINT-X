# OSINT-X

OSINT-X is a modular, source-attributed OSINT (Open Source Intelligence)
correlation platform intended for **authorized, legal investigations** —
security research, brand/fraud protection, due-diligence, journalism, and
defensive threat intelligence.

> ⚠️ **Read the [Legal & Ethical Use](#legal--ethical-use) section before running this.**

## What this actually does (and doesn't do)

This project ships with a real, working core: data models, a source/evidence
ledger, a confidence-scoring correlation engine, DNS/WHOIS/certificate-
transparency domain reconnaissance, a GitHub public-API collector, simple
"does this username exist" checks (the same technique tools like Sherlock
use — a plain HTTP GET/HEAD against a known profile URL, nothing more), a
report generator (JSON/Markdown/HTML), a CLI, and a minimal FastAPI
dashboard/API.

It **deliberately does not** ship scrapers for platforms whose Terms of
Service prohibit automated scraping (e.g. LinkedIn, Instagram, TikTok
content/profile scraping), breach-database lookups, or paid search-engine
APIs. Those are wired up as clean **adapter stubs** in `collectors/social.py`
and `collectors/search.py` — if you have a legitimate contract/API key for a
service (e.g. HaveIBeenPwned API, a licensed search API, a licensed people-
data API), you plug your own key in and implement the adapter's `collect()`
method. The engine will treat any adapter that isn't configured as
"unavailable" rather than fabricating data or silently skipping it.

**No component in this project bypasses login walls, CAPTCHAs, paywalls, or
rate limits, or attempts to access non-public data.**

## Legal & Ethical Use

- Only use this tool on targets you are **authorized** to investigate (your
  own organization's assets, a client under signed engagement, your own
  accounts, or otherwise with clear legal basis/consent).
- Do not use this to stalk, harass, dox, or build dossiers on private
  individuals without their consent or a lawful basis.
- Respect every site's Terms of Service and robots.txt. This tool will not
  do it for you if you point it at something it shouldn't.
- Findings are labeled `CONFIRMED` / `SUPPORTED` / `POSSIBLE` / `UNVERIFIED`.
  Treat anything below `CONFIRMED` as a lead to verify manually, not a fact.
- Matching usernames/emails/names across platforms is *correlation*, not
  *proof of identity*. The engine never auto-merges identities without
  supporting evidence, and confidence scores are attached to source
  correlation only — never to inferred personal traits.
- You are responsible for complying with local law (e.g. GDPR/CCPA if you
  operate on EU/CA residents' data), and for your own organization's policies.

## Install

```bash
cd osint_x
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in any API keys you legitimately hold
```

## CLI usage

```bash
python osint.py domain example.com --format md
python osint.py username example_user --format json
python osint.py github example_user
python osint.py email person@example.com   # domain-level analysis only by default
```

Run `python osint.py --help` for all options.

## Dashboard / API

```bash
uvicorn app:app --reload
```

Then open `http://127.0.0.1:8000/` for the dashboard and
`http://127.0.0.1:8000/docs` for the interactive API.

## Tests

```bash
pytest
```

## Architecture

See `collectors/`, `analyzers/`, `database/`, `reports/`, `ui/`, `utils/`.
Every external source is its own adapter under `collectors/`, implementing a
common `BaseCollector` interface (`collectors/base.py`), so new sources can
be added without touching the correlation engine. Every collector that
cannot run (missing API key, network failure, source down) reports itself
as `unavailable` rather than being silently skipped or fabricated.

## Adding a new source

1. Subclass `BaseCollector` in `collectors/base.py`.
2. Implement `async def collect(self, target: str) -> CollectionResult`.
3. Wrap every fact you emit in a `Finding` with a `Source` (see
   `database/models.py`) — findings without a source are rejected by the
   correlation engine.
4. Register the collector in the relevant `collectors/*.py` module's
   `COLLECTORS` list.
