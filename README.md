# SeedBuster

Automated detection pipeline for Kaspa wallet phishing sites that steal seed phrases.

## Features

- **Real-time monitoring** of Certificate Transparency logs for suspicious domains
- **Smart detection** using fuzzy matching, IDN/homograph detection, and visual fingerprinting
- **Headless browser analysis** with Playwright for evidence collection
- **Telegram bot** for alerts, manual submissions, and control
- **Evidence storage** with screenshots, HTML snapshots, and analysis results

## Quick Start

### 1. Get your Telegram Chat ID

Message [@userinfobot](https://t.me/userinfobot) on Telegram to get your chat ID.

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
```

### 3. Capture fingerprint (one-time setup)

Before running, capture the legitimate wallet fingerprint for clone detection:

```bash
# Local (requires Python 3.11+)
pip install -e .
playwright install chromium
python scripts/capture_fingerprint.py

# Or via Docker
docker-compose run --rm seedbuster python scripts/capture_fingerprint.py
```

### 4. Run

**Docker (recommended):**
```bash
docker-compose up -d
docker-compose logs -f
```

**Local:**
```bash
pip install -e .
playwright install chromium
python -m src.main
```

## Telegram Commands

| Command | Description |
|---------|-------------|
| `/status` | System health and stats |
| `/recent [n]` | Show last N domains |
| `/submit <url>` | Manually submit domain |
| `/ack <id>` | Acknowledge alert |
| `/fp <id>` | Mark false positive |
| `/evidence <id>` | Get evidence files |
| `/report <id>` | Submit to blocklists |
| `/help` | Show all commands |

## How It Works

```
CT Logs → Domain Filter → Scorer → Browser Analysis → Detection → Telegram Alert
                                        ↓
                              Evidence Storage (SQLite + files)
```

1. **Discovery**: Monitors Certificate Transparency logs for new Kaspa-related domains
2. **Scoring**: Fuzzy matching, IDN detection, suspicious TLD/keyword scoring
3. **Analysis**: Playwright visits suspicious sites, collects screenshots/HTML
4. **Detection**: Checks for seed phrase forms, visual similarity to wallet.kaspanet.io
5. **Alerting**: Sends Telegram alerts with evidence for human review

## Configuration

See `.env.example` for all options.

Required:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Detection:
- `DOMAIN_SCORE_THRESHOLD` - Minimum domain score to analyze (default: 30)
- `ANALYSIS_SCORE_THRESHOLD` - Minimum analysis score to alert (default: 70)
- `MAX_CONCURRENT_ANALYSES` - Parallel browser sessions (default: 3)
- `ANALYSIS_TIMEOUT` - Browser timeout in seconds (default: 30)

External intelligence (optional):
- `VIRUSTOTAL_API_KEY`
- `URLSCAN_API_KEY`

Reporting:
- `REPORT_PLATFORMS` - Comma-separated list (default: `google,cloudflare,netcraft,resend`)
- `REPORT_MIN_SCORE` - Minimum score required to report (default: 80)
- `REPORT_REQUIRE_APPROVAL` - If `false`, auto-submit reports on initial scans when score ≥ `REPORT_MIN_SCORE`
- `RESEND_API_KEY`, `RESEND_FROM_EMAIL` - Email reporting via Resend
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL` - Email reporting via SMTP
- `PHISHTANK_API_KEY` - Optional (PhishTank API access required)

Paths:
- `DATA_DIR` (default: `./data`)
- `EVIDENCE_DIR` (default: `./data/evidence`)
- `CONFIG_DIR` (default: `./config`)

## File Structure

```
seedbuster/
├── src/
│   ├── discovery/      # CT log listener, domain scoring
│   ├── analyzer/       # Playwright browser, phishing detection
│   ├── storage/        # SQLite database, evidence files
│   ├── bot/            # Telegram bot handlers
│   └── reporter/       # Blocklist reporting (Phase 3)
├── config/
│   ├── allowlist.txt   # Known good domains
│   ├── denylist.txt    # Known bad domains
│   └── keywords.txt    # Detection keywords
├── data/
│   ├── seedbuster.db   # SQLite database
│   ├── evidence/       # Collected evidence
│   └── fingerprints/   # Visual fingerprints
└── tests/
```

## Roadmap

- [x] **Phase 1**: Core pipeline with CT monitoring and Telegram alerts
- [ ] **Phase 2**: Visual fingerprinting and smart clone detection
- [ ] **Phase 3**: Automated reporting to Google Safe Browsing, PhishTank
- [ ] **Phase 4**: Hardening, monitoring, cleanup policies

## License

MIT
