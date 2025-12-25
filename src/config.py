"""Configuration management for SeedBuster."""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set

import yaml
from dotenv import load_dotenv
from .utils.domains import canonicalize_domain

logger = logging.getLogger(__name__)


DEFAULT_SEARCH_EXCLUDE_DOMAINS: set[str] = {
    # Social/discussion platforms (common false positives for wallet/seed queries)
    "reddit.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "quora.com",
    "discord.com",
    "discord.gg",
    "t.me",
    "telegram.me",
    # Code/blog/video platforms (often educational results, rarely the phishing kit itself)
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "medium.com",
    "youtube.com",
    "youtu.be",
    "stackoverflow.com",
    "stackexchange.com",
    "wikipedia.org",
    # Major portals (reduce noise)
    "google.com",
    "microsoft.com",
    "apple.com",
}

# Default heuristics for scoring/detection/exploration. These can be overridden
# via config/heuristics.yaml without touching code.
DEFAULT_DOMAIN_KEYWORDS: list[tuple[str, int]] = [
    ("wallet", 10),
    ("recover", 15),
    ("seed", 15),
    ("restore", 10),
    ("login", 5),
    ("secure", 5),
    ("official", 10),
    ("verify", 10),
    ("claim", 10),
    ("airdrop", 10),
]

DEFAULT_TITLE_KEYWORDS: list[tuple[str, int, str]] = [
    ("kaspa", 10, "Kaspa-related title"),
    ("wallet", 5, "Wallet-related title"),
    ("recovery", 10, "Recovery-related title"),
    ("restore", 10, "Restore-related title"),
    ("seed", 10, "Seed-related title"),
    ("claim", 5, "Claim-related title"),
    ("airdrop", 5, "Airdrop-related title"),
]

DEFAULT_SEED_KEYWORDS: list[str] = [
    r"recovery\s*phrase",
    r"seed\s*phrase",
    r"mnemonic",
    r"secret\s*phrase",
    r"backup\s*phrase",
    r"12\s*words?",
    r"24\s*words?",
    r"enter\s*(your\s*)?seed",
    r"restore\s*wallet",
    r"import\s*wallet",
    r"recover\s*wallet",
    r"enter\s*mnemonic",
    r"word\s*#?\d+",
    r"recovery\s*words?",
]

DEFAULT_EXPLORATION_TARGETS: list[dict] = [
    {"text": "legacy wallet", "priority": 1},
    {"text": "continue on legacy", "priority": 1},
    {"text": "recover from seed", "priority": 1},
    {"text": "kaspa ng", "priority": 1},
    {"text": "go to", "priority": 2},
    {"text": "continue", "priority": 2},
    {"text": "wallet", "priority": 1},
    {"text": "open wallet", "priority": 1},
    {"text": "access wallet", "priority": 1},
    {"text": "my wallet", "priority": 1},
    {"text": "recover", "priority": 1},
    {"text": "restore", "priority": 1},
    {"text": "import", "priority": 1},
    {"text": "recovery", "priority": 1},
    {"text": "import existing", "priority": 1},
    {"text": "create wallet", "priority": 2},
    {"text": "new wallet", "priority": 2},
    {"text": "create new wallet", "priority": 2},
    {"text": "create", "priority": 3},
    {"text": "12-word", "priority": 1},
    {"text": "24-word", "priority": 1},
    {"text": "12 word", "priority": 1},
    {"text": "24 word", "priority": 1},
    {"text": "12 words", "priority": 1},
    {"text": "24 words", "priority": 1},
    {"text": "mnemonic", "priority": 1},
    {"text": "import mnemonic", "priority": 1},
    {"text": "enter mnemonic", "priority": 1},
    {"text": "seed phrase", "priority": 1},
    {"text": "secret phrase", "priority": 1},
    {"text": "continue", "priority": 2},
    {"text": "next", "priority": 2},
    {"text": "proceed", "priority": 2},
    {"text": "connect", "priority": 2},
    {"text": "connect wallet", "priority": 1},
    {"text": "settings", "priority": 3},
]

DEFAULT_SUBSTITUTIONS: dict[str, str] = {
    "4": "a",
    "3": "e",
    "1": "i",
    "0": "o",
    "5": "s",
    "@": "a",
    "$": "s",
}


@dataclass
class Config:
    """Application configuration loaded from environment."""

    # Telegram
    telegram_bot_token: str
    telegram_chat_id: str

    # Dashboard (optional)
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8080
    dashboard_admin_user: str = "admin"
    dashboard_admin_password: str = ""
    health_host: str = "0.0.0.0"
    health_port: int = 8081
    health_enabled: bool = True

    # Detection thresholds
    domain_score_threshold: int = 30
    analysis_score_threshold: int = 70

    # Reporting API keys
    resend_api_key: str = ""
    resend_from_email: str = "SeedBuster <onboarding@resend.dev>"

    # External intelligence API keys (optional, improves detection)
    virustotal_api_key: str = ""  # Free tier: 4 req/min, 500/day
    urlscan_api_key: str = ""  # Free tier: 50 scans/day (optional for search)
    urlscan_submit_enabled: bool = False  # Requires URLSCAN_API_KEY and explicit opt-in
    urlscan_submit_visibility: str = "unlisted"  # public | unlisted | private (depends on plan)

    # Optional: search-engine discovery (uses official APIs; avoids scraping SERPs)
    search_discovery_enabled: bool = False
    search_discovery_provider: str = "google"  # google | bing
    search_discovery_queries: list[str] = field(
        default_factory=lambda: [
            "kaspa wallet",
            "kaspa recover wallet",
            "kaspa seed phrase",
            "kaspanet wallet",
            "kaspawallet",
        ]
    )
    search_discovery_interval_minutes: int = 60
    search_discovery_results_per_query: int = 20
    search_discovery_force_analyze: bool = False  # bypass DOMAIN_SCORE_THRESHOLD for search hits
    search_discovery_rotate_pages: bool = True
    search_discovery_exclude_domains: Set[str] = field(
        default_factory=lambda: set(DEFAULT_SEARCH_EXCLUDE_DOMAINS)
    )

    # Google Programmable Search Engine (Custom Search JSON API)
    google_cse_api_key: str = ""
    google_cse_id: str = ""  # cx
    google_cse_gl: str = ""  # country code, e.g. AU (optional)
    google_cse_hl: str = "en"  # UI language (optional)

    # Bing Web Search API (Azure Cognitive Services)
    bing_search_api_key: str = ""
    bing_search_endpoint: str = "https://api.bing.microsoft.com/v7.0/search"
    bing_search_market: str = "en-US"

    # SMTP configuration for email reports (alternative to Resend)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""

    # Reporting options
    report_require_approval: bool = True
    report_min_score: int = 80
    report_platforms: list[str] | None = field(
        default_factory=lambda: ["google", "cloudflare", "netcraft", "resend"]
    )

    # Operational limits
    analysis_timeout: int = 30
    max_concurrent_analyses: int = 3

    # Paths
    data_dir: Path = field(default_factory=lambda: Path("./data"))
    evidence_dir: Path = field(default_factory=lambda: Path("./data/evidence"))
    config_dir: Path = field(default_factory=lambda: Path("./config"))

    # Loaded lists
    allowlist: Set[str] = field(default_factory=set)
    denylist: Set[str] = field(default_factory=set)
    keywords: list[str] = field(default_factory=list)

    # Heuristics (override via config/heuristics.yaml)
    domain_keyword_weights: list[tuple[str, int]] = field(
        default_factory=lambda: list(DEFAULT_DOMAIN_KEYWORDS)
    )
    substitutions: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SUBSTITUTIONS))
    seed_keywords: list[str] = field(default_factory=lambda: list(DEFAULT_SEED_KEYWORDS))
    title_keywords: list[tuple[str, int, str]] = field(
        default_factory=lambda: list(DEFAULT_TITLE_KEYWORDS)
    )
    exploration_targets: list[dict] = field(
        default_factory=lambda: list(DEFAULT_EXPLORATION_TARGETS)
    )
    # Flexible pattern categories for content detection (loaded from heuristics.yaml)
    pattern_categories: list[dict] = field(default_factory=list)

    # Target patterns for domain matching
    target_patterns: list[str] = field(
        default_factory=lambda: [
            "kaspa",
            "kaspanet",
            "kaspawallet",
            "kasware",
            "kaspapay",
        ]
    )

    # Suspicious TLDs (common in phishing)
    suspicious_tlds: Set[str] = field(
        default_factory=lambda: {
            "xyz",
            "top",
            "click",
            "online",
            "site",
            "website",
            "link",
            "club",
            "fun",
            "icu",
            "buzz",
            "quest",
        }
    )

    def __post_init__(self):
        """Ensure paths exist and load lists."""
        self.data_dir = Path(self.data_dir)
        self.evidence_dir = Path(self.evidence_dir)
        self.config_dir = Path(self.config_dir)

        # Create directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Load lists from config files
        self._load_lists()

    def _load_lists(self):
        """Load allowlist, denylist, and keywords from config files."""
        allowlist_path = self.config_dir / "allowlist.txt"
        denylist_path = self.config_dir / "denylist.txt"
        keywords_path = self.config_dir / "keywords.txt"

        if allowlist_path.exists():
            raw_allowlist = self._load_list_file(allowlist_path)
            self.allowlist = {
                canonicalize_domain(item) or item for item in raw_allowlist
            }
        if denylist_path.exists():
            raw_denylist = self._load_list_file(denylist_path)
            self.denylist = {
                canonicalize_domain(item) or item for item in raw_denylist
            }
        if keywords_path.exists():
            self.keywords = list(self._load_list_file(keywords_path))

    @staticmethod
    def _load_list_file(path: Path) -> Set[str]:
        """Load a list file, ignoring comments and empty lines."""
        items = set()
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.add(line.lower())
        return items


def _load_heuristics(config_dir: Path) -> dict:
    """Load heuristic overrides from config/heuristics.yaml (optional)."""
    path = Path(config_dir or ".") / "heuristics.yaml"
    if not path.exists():
        return {}

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        logger.warning("Failed to parse heuristics.yaml: %s", exc)
        return {}

    def _coerce_keyword_weights(raw, default):
        items: list[tuple[str, int]] = []
        for entry in raw or []:
            if not isinstance(entry, dict):
                continue
            keyword = str(entry.get("keyword") or "").strip()
            try:
                points = int(entry.get("points"))
            except Exception:
                continue
            if keyword:
                items.append((keyword, points))
        return items or default

    def _coerce_title_keywords(raw, default):
        items: list[tuple[str, int, str]] = []
        for entry in raw or []:
            if not isinstance(entry, dict):
                continue
            keyword = str(entry.get("keyword") or "").strip()
            try:
                points = int(entry.get("points"))
            except Exception:
                continue
            reason = str(entry.get("reason") or "").strip() or f"{keyword} match"
            if keyword:
                items.append((keyword, points, reason))
        return items or default

    def _coerce_exploration_targets(raw, default):
        items: list[dict] = []
        for entry in raw or []:
            if not isinstance(entry, dict):
                continue
            text = str(entry.get("text") or "").strip()
            if not text:
                continue
            try:
                priority = int(entry.get("priority", 1))
            except Exception:
                priority = 1
            items.append({"text": text, "priority": priority})
        return items or default

    def _coerce_pattern_categories(raw):
        """Parse flexible pattern categories from config."""
        categories: list[dict] = []
        for cat in raw or []:
            if not isinstance(cat, dict):
                continue
            name = str(cat.get("name") or "").strip()
            if not name:
                continue
            label = str(cat.get("label") or name.upper()).strip()
            try:
                threshold = int(cat.get("threshold", 2))
            except Exception:
                threshold = 2

            patterns: list[dict] = []
            for p in cat.get("patterns") or []:
                if not isinstance(p, dict):
                    continue
                pattern = str(p.get("pattern") or "").strip()
                if not pattern:
                    continue
                try:
                    points = int(p.get("points", 10))
                except Exception:
                    points = 10
                reason = str(p.get("reason") or "").strip() or f"{label} pattern match"
                patterns.append({"pattern": pattern, "points": points, "reason": reason})

            if patterns:
                categories.append({
                    "name": name,
                    "label": label,
                    "threshold": threshold,
                    "patterns": patterns,
                })
        return categories

    domain_cfg = data.get("domain", {}) if isinstance(data, dict) else {}
    detection_cfg = data.get("detection", {}) if isinstance(data, dict) else {}
    browser_cfg = data.get("browser", {}) if isinstance(data, dict) else {}

    return {
        "target_patterns": domain_cfg.get("target_patterns"),
        "suspicious_tlds": domain_cfg.get("suspicious_tlds"),
        "domain_keyword_weights": _coerce_keyword_weights(
            domain_cfg.get("keywords"), list(DEFAULT_DOMAIN_KEYWORDS)
        ),
        "substitutions": domain_cfg.get("substitutions"),
        "seed_keywords": detection_cfg.get("seed_keywords"),
        "title_keywords": _coerce_title_keywords(
            detection_cfg.get("title_keywords"), list(DEFAULT_TITLE_KEYWORDS)
        ),
        "exploration_targets": _coerce_exploration_targets(
            browser_cfg.get("exploration_targets"), list(DEFAULT_EXPLORATION_TARGETS)
        ),
        "pattern_categories": _coerce_pattern_categories(
            detection_cfg.get("pattern_categories")
        ),
    }


def load_config() -> Config:
    """Load configuration from environment variables."""
    load_dotenv()

    # Parse report platforms from comma-separated string
    report_platforms_str = os.getenv("REPORT_PLATFORMS", "google,cloudflare,netcraft,resend")
    report_platforms_raw = report_platforms_str.strip().lower()
    report_platforms = [p.strip() for p in report_platforms_str.split(",") if p.strip()]
    if not report_platforms or report_platforms_raw in {"all", "*"}:
        report_platforms = None

    queries_str = os.getenv("SEARCH_DISCOVERY_QUERIES", "")
    search_kwargs: dict[str, object] = {}
    if queries_str.strip():
        search_kwargs["search_discovery_queries"] = [q.strip() for q in queries_str.split(";") if q.strip()]

    exclude_str = os.getenv("SEARCH_DISCOVERY_EXCLUDE_DOMAINS", "")
    if exclude_str.strip():
        exclude = {d.strip().lower() for d in exclude_str.split(",") if d.strip()}
        search_kwargs["search_discovery_exclude_domains"] = set(DEFAULT_SEARCH_EXCLUDE_DOMAINS) | exclude

    heuristics = _load_heuristics(Path(os.getenv("CONFIG_DIR", "./config")))
    target_patterns = (
        heuristics.get("target_patterns")
        if isinstance(heuristics.get("target_patterns"), list)
        else None
    )
    suspicious_tlds = (
        heuristics.get("suspicious_tlds")
        if isinstance(heuristics.get("suspicious_tlds"), (list, set, tuple))
        else None
    )

    return Config(
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", ""),
        dashboard_host=os.getenv("DASHBOARD_HOST", "127.0.0.1"),
        dashboard_port=int(os.getenv("DASHBOARD_PORT", "8080")),
        dashboard_admin_user=os.getenv("DASHBOARD_ADMIN_USER", "admin"),
        dashboard_admin_password=os.getenv("DASHBOARD_ADMIN_PASSWORD", ""),
        health_host=os.getenv("HEALTH_HOST", "0.0.0.0"),
        health_port=int(os.getenv("HEALTH_PORT", "8081")),
        health_enabled=os.getenv("HEALTH_ENABLED", "true").lower() == "true",
        domain_score_threshold=int(os.getenv("DOMAIN_SCORE_THRESHOLD", "30")),
        analysis_score_threshold=int(os.getenv("ANALYSIS_SCORE_THRESHOLD", "70")),
        resend_api_key=os.getenv("RESEND_API_KEY", ""),
        resend_from_email=os.getenv("RESEND_FROM_EMAIL", "SeedBuster <onboarding@resend.dev>"),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
        urlscan_api_key=os.getenv("URLSCAN_API_KEY", ""),
        urlscan_submit_enabled=os.getenv("URLSCAN_SUBMIT_ENABLED", "false").lower() == "true",
        urlscan_submit_visibility=os.getenv("URLSCAN_SUBMIT_VISIBILITY", "unlisted"),
        search_discovery_enabled=os.getenv("SEARCH_DISCOVERY_ENABLED", "false").lower() == "true",
        search_discovery_provider=os.getenv("SEARCH_DISCOVERY_PROVIDER", "google").strip().lower() or "google",
        search_discovery_interval_minutes=int(os.getenv("SEARCH_DISCOVERY_INTERVAL_MINUTES", "60")),
        search_discovery_results_per_query=int(os.getenv("SEARCH_DISCOVERY_RESULTS_PER_QUERY", "20")),
        search_discovery_force_analyze=os.getenv("SEARCH_DISCOVERY_FORCE_ANALYZE", "false").lower() == "true",
        search_discovery_rotate_pages=os.getenv("SEARCH_DISCOVERY_ROTATE_PAGES", "true").lower() == "true",
        google_cse_api_key=os.getenv("GOOGLE_CSE_API_KEY", ""),
        google_cse_id=os.getenv("GOOGLE_CSE_ID", ""),
        google_cse_gl=os.getenv("GOOGLE_CSE_GL", ""),
        google_cse_hl=os.getenv("GOOGLE_CSE_HL", "en"),
        bing_search_api_key=os.getenv("BING_SEARCH_API_KEY", ""),
        bing_search_endpoint=os.getenv("BING_SEARCH_ENDPOINT", "https://api.bing.microsoft.com/v7.0/search"),
        bing_search_market=os.getenv("BING_SEARCH_MARKET", "en-US"),
        **search_kwargs,
        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_username=os.getenv("SMTP_USERNAME", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_from_email=os.getenv("SMTP_FROM_EMAIL", ""),
        report_require_approval=os.getenv("REPORT_REQUIRE_APPROVAL", "true").lower() == "true",
        report_min_score=int(os.getenv("REPORT_MIN_SCORE", "80")),
        report_platforms=report_platforms,
        analysis_timeout=int(os.getenv("ANALYSIS_TIMEOUT", "30")),
        max_concurrent_analyses=int(os.getenv("MAX_CONCURRENT_ANALYSES", "3")),
        data_dir=Path(os.getenv("DATA_DIR", "./data")),
        evidence_dir=Path(os.getenv("EVIDENCE_DIR", "./data/evidence")),
        config_dir=Path(os.getenv("CONFIG_DIR", "./config")),
        target_patterns=target_patterns or [
            "kaspa",
            "kaspanet",
            "kaspawallet",
            "kasware",
            "kaspapay",
        ],
        suspicious_tlds=set(suspicious_tlds) if suspicious_tlds else {
            "xyz",
            "top",
            "click",
            "online",
            "site",
            "website",
            "link",
            "club",
            "fun",
            "icu",
            "buzz",
            "quest",
        },
        domain_keyword_weights=heuristics.get("domain_keyword_weights", list(DEFAULT_DOMAIN_KEYWORDS)),
        substitutions=heuristics.get("substitutions", dict(DEFAULT_SUBSTITUTIONS)) or dict(DEFAULT_SUBSTITUTIONS),
        seed_keywords=heuristics.get("seed_keywords", list(DEFAULT_SEED_KEYWORDS)) or list(DEFAULT_SEED_KEYWORDS),
        title_keywords=heuristics.get("title_keywords", list(DEFAULT_TITLE_KEYWORDS)),
        exploration_targets=heuristics.get("exploration_targets", list(DEFAULT_EXPLORATION_TARGETS)),
        pattern_categories=heuristics.get("pattern_categories", []),
    )


def validate_config(config: Config) -> list[str]:
    """Validate required configuration and return list of error messages."""
    errors: list[str] = []
    if not (config.telegram_bot_token or "").strip():
        errors.append("TELEGRAM_BOT_TOKEN is required")
    if not (config.telegram_chat_id or "").strip():
        errors.append("TELEGRAM_CHAT_ID is required")

    if config.search_discovery_enabled:
        provider = (config.search_discovery_provider or "").lower()
        if provider == "google" and (not config.google_cse_api_key or not config.google_cse_id):
            errors.append("Search discovery enabled but GOOGLE_CSE_API_KEY/GOOGLE_CSE_ID missing")
        if provider == "bing" and not config.bing_search_api_key:
            errors.append("Search discovery enabled but BING_SEARCH_API_KEY missing")

    if not (config.resend_api_key or config.smtp_host):
        # Reporting will still run in manual/preview mode, but automatic email submissions will fail.
        logger.info("No RESEND_API_KEY or SMTP_HOST configured; email reporting will be disabled")

    return errors
