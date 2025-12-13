"""Configuration management for SeedBuster."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set

from dotenv import load_dotenv


@dataclass
class Config:
    """Application configuration loaded from environment."""

    # Telegram
    telegram_bot_token: str
    telegram_chat_id: str

    # Detection thresholds
    domain_score_threshold: int = 30
    analysis_score_threshold: int = 70

    # Reporting API keys
    phishtank_api_key: str = ""
    resend_api_key: str = ""
    resend_from_email: str = "SeedBuster <onboarding@resend.dev>"

    # External intelligence API keys (optional, improves detection)
    virustotal_api_key: str = ""  # Free tier: 4 req/min, 500/day
    urlscan_api_key: str = ""  # Free tier: 50 scans/day (optional for search)
    urlscan_submit_enabled: bool = False  # Requires URLSCAN_API_KEY and explicit opt-in
    urlscan_submit_visibility: str = "unlisted"  # public | unlisted | private (depends on plan)

    # SMTP configuration for email reports (alternative to Resend)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""

    # Reporting options
    report_require_approval: bool = True
    report_min_score: int = 80
    report_platforms: list[str] = field(
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
            self.allowlist = self._load_list_file(allowlist_path)
        if denylist_path.exists():
            self.denylist = self._load_list_file(denylist_path)
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


def load_config() -> Config:
    """Load configuration from environment variables."""
    load_dotenv()

    # Parse report platforms from comma-separated string
    report_platforms_str = os.getenv("REPORT_PLATFORMS", "google,cloudflare,netcraft,resend")
    report_platforms = [p.strip() for p in report_platforms_str.split(",") if p.strip()]

    return Config(
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", ""),
        domain_score_threshold=int(os.getenv("DOMAIN_SCORE_THRESHOLD", "30")),
        analysis_score_threshold=int(os.getenv("ANALYSIS_SCORE_THRESHOLD", "70")),
        phishtank_api_key=os.getenv("PHISHTANK_API_KEY", ""),
        resend_api_key=os.getenv("RESEND_API_KEY", ""),
        resend_from_email=os.getenv("RESEND_FROM_EMAIL", "SeedBuster <onboarding@resend.dev>"),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
        urlscan_api_key=os.getenv("URLSCAN_API_KEY", ""),
        urlscan_submit_enabled=os.getenv("URLSCAN_SUBMIT_ENABLED", "false").lower() == "true",
        urlscan_submit_visibility=os.getenv("URLSCAN_SUBMIT_VISIBILITY", "unlisted"),
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
    )
