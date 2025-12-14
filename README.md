# SeedBuster

Automated detection pipeline for Kaspa wallet phishing sites that steal seed phrases.

## Features

- **Real-time monitoring** of Certificate Transparency logs for suspicious domains
- **Optional search discovery** via official APIs (Google CSE / Bing) to find already-issued/older kits
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
CT Logs + Search APIs → Domain Filter → Scorer → Browser Analysis → Detection → Telegram Alert
                                        ↓
                              Evidence Storage (SQLite + files)
```

1. **Discovery**: Monitors Certificate Transparency logs (and optionally search APIs) for Kaspa-related sites
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

Search discovery (optional):
- `SEARCH_DISCOVERY_ENABLED` - If `true`, periodically queries search APIs for phishing results
- `SEARCH_DISCOVERY_PROVIDER` - `google` or `bing`
- `SEARCH_DISCOVERY_QUERIES` - `;`-separated list of search queries
- `SEARCH_DISCOVERY_INTERVAL_MINUTES`, `SEARCH_DISCOVERY_RESULTS_PER_QUERY`
- `SEARCH_DISCOVERY_ROTATE_PAGES` - If `true`, rotates through result pages to discover new results over time
- `SEARCH_DISCOVERY_FORCE_ANALYZE` - If `true`, bypasses `DOMAIN_SCORE_THRESHOLD` for search hits
- `SEARCH_DISCOVERY_EXCLUDE_DOMAINS` - Comma-separated domains to ignore (e.g. `reddit.com,youtube.com`)
- `GOOGLE_CSE_API_KEY`, `GOOGLE_CSE_ID` - For provider `google`
- `BING_SEARCH_API_KEY` - For provider `bing`

Reporting:
- `REPORT_PLATFORMS` - Comma-separated list (default: `google,cloudflare,netcraft,resend`)
- `REPORT_MIN_SCORE` - Minimum score required to report (default: 80)
- `REPORT_REQUIRE_APPROVAL` - If `false`, auto-submit reports on initial scans when score ≥ `REPORT_MIN_SCORE`
- `RESEND_API_KEY`, `RESEND_FROM_EMAIL` - Email reporting via Resend
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL` - Email reporting via SMTP
- `PHISHTANK_API_KEY` - Optional (PhishTank API access required)
- `hosting_provider` platform - Optional helper that generates provider-specific manual abuse destinations + copy/paste blocks (useful if you don't have Resend/SMTP)
- `registrar` platform - Optional helper that does an RDAP lookup for registrar abuse contacts and generates a copy/paste email template
- `apwg` platform - Optional helper that generates instructions for reporting to `reportphishing@apwg.org` (APWG)

Manual reporting:
- When a platform returns `manual_required`, SeedBuster writes `report_instructions_<platform>.txt` into the domain evidence folder and sends it after `/report` or "Approve & Report" (you can also use `/evidence <id>`).

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
