<p align="center">
  <img src="https://seedbuster.xyz/assets/seedbuster-social.png" alt="SeedBuster" width="840" />
</p>

# SeedBuster

Community-powered scam defense for the crypto community.
Automated detection and response pipeline for phishing and scam sites.

## Highlights

- Public/admin dashboard is the primary interface for triage, reporting, and submissions.
- Monitors Certificate Transparency logs with optional search discovery.
- Scores domains with fuzzy matching, IDN/homograph checks, and heuristics.
- Uses Playwright to analyze targets and collect evidence.
- Stores evidence in SQLite plus screenshots and HTML; reporting helpers included.
- Telegram bot for alerts and shortcuts (optional).

## Flow

CT logs + search + community reports -> scoring -> browser analysis -> detection -> evidence -> dashboard triage -> reporting

## Quick start

1) Configure

```bash
cp .env.example .env
# Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID only if you want bot alerts (use @userinfobot to get your chat ID)
```

2) Capture the legitimate wallet fingerprint (one time)

```bash
# Local
pip install -e .
playwright install chromium
python scripts/capture_fingerprint.py

# Docker
docker-compose run --rm seedbuster python scripts/capture_fingerprint.py
```

3) Run the stack (dashboard + pipeline)

```bash
docker-compose up -d
docker-compose logs -f
```

Dashboard runs on `http://localhost:8080` (admin at `/admin`).

Or run locally (two terminals):

```bash
python -m src.main
seedbuster-dashboard
```

4) Frontend dev server (UI work)

```bash
cd src/dashboard/frontend
npm install
VITE_ADMIN_AUTH=admin:password npm run dev -- --host
```

## Telegram (optional)

`/status`, `/recent [n]`, `/submit <url>`, `/ack <id>`, `/fp <id>`, `/evidence <id>`, `/report <id>`, `/help`

## Configuration

- `.env.example` lists all options, including search discovery and reporting providers.
- `REPORT_PLATFORMS` controls auto-reporting; providers that require manual steps emit instructions into evidence folders.
- `config/allowlist.txt`, `config/denylist.txt`, `config/keywords.txt` tune discovery.
- `config/heuristics.yaml` overrides scoring and detection without code changes.
- Data and evidence live under `data/` (do not commit).

## Repository layout

- `src/` pipeline, services, and dashboard server
- `src/dashboard/frontend/` React/Vite UI
- `config/` heuristics and lists
- `tests/` pytest suite
- `scripts/` one-off tooling

## License

MIT
