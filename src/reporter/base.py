"""Base classes for abuse reporting in SeedBuster."""

import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class ReportStatus(str, Enum):
    """Status of an abuse report submission."""

    PENDING = "pending"  # Awaiting human approval
    MANUAL_REQUIRED = "manual_required"  # Automation blocked; manual submission needed
    APPROVED = "approved"  # Approved, ready to send
    SUBMITTED = "submitted"  # Successfully submitted
    CONFIRMED = "confirmed"  # Platform confirmed receipt
    REJECTED = "rejected"  # Human rejected / false positive
    FAILED = "failed"  # Submission failed
    SKIPPED = "skipped"  # Not applicable / intentionally skipped
    RATE_LIMITED = "rate_limited"  # Hit rate limit, retry later
    DUPLICATE = "duplicate"  # Already reported


@dataclass
class ReportEvidence:
    """Evidence package for an abuse report."""

    domain: str
    url: str
    detected_at: datetime
    confidence_score: int
    domain_id: Optional[int] = None
    detection_reasons: list[str] = field(default_factory=list)
    suspicious_endpoints: list[str] = field(default_factory=list)

    # File paths (optional)
    screenshot_path: Optional[Path] = None
    html_path: Optional[Path] = None
    analysis_path: Optional[Path] = None

    # Analysis data
    analysis_json: dict = field(default_factory=dict)

    # Infrastructure intel (for email reports)
    backend_domains: list[str] = field(default_factory=list)
    api_keys_found: list[str] = field(default_factory=list)
    hosting_provider: Optional[str] = None

    # Scam type classification
    scam_type: Optional[str] = None  # "seed_phishing", "crypto_doubler", "fake_airdrop"

    # Crypto doubler specific (wallet addresses for advance-fee fraud)
    scammer_wallets: list[str] = field(default_factory=list)

    def to_summary(self) -> str:
        """Generate a human-readable summary for reports with context."""
        scam_type = self.resolve_scam_type()
        # Choose summary based on scam type
        if scam_type == "crypto_doubler":
            return self._crypto_doubler_summary()
        if scam_type == "fake_airdrop":
            return self._fake_airdrop_summary()
        if scam_type == "seed_phishing":
            return self._seed_phishing_summary()
        return self._generic_summary()

    def _action_request_line(self) -> str:
        """Return a consistent action request line for report summaries."""
        scam_type = self.resolve_scam_type()
        if scam_type == "seed_phishing":
            return "ACTION REQUESTED: Please remove/block this phishing site (seed phrase theft)."
        if scam_type == "fake_airdrop":
            return "ACTION REQUESTED: Please remove/block this fraudulent airdrop/claim site."
        if scam_type == "crypto_doubler":
            return "ACTION REQUESTED: Please remove/block this fraudulent giveaway site."
        return "ACTION REQUESTED: Please remove/block this fraudulent site."

    def _seed_phishing_summary(self) -> str:
        """Generate summary for seed phrase phishing scams."""
        lines = [
            self._action_request_line(),
            "",
            "PHISHING REPORT - Cryptocurrency Seed Phrase Theft",
            "",
            "This site impersonates a cryptocurrency wallet to steal seed phrases.",
            "A seed phrase is the master key to a wallet - theft enables immediate,",
            "irreversible loss of all funds.",
            "",
            "SITE DETAILS:",
            f"  Domain: {self.domain}",
            f"  URL: {self.url}",
            f"  Detected: {self.detected_at.strftime('%Y-%m-%d %H:%M UTC') if self.detected_at else 'Unknown'}",
        ]

        impersonation = self.get_impersonation_lines()
        if impersonation:
            lines.append("")
            lines.append("IMPERSONATION INDICATORS:")
            lines.extend(f"  - {line}" for line in impersonation)

        self._append_review_notes(lines)

        lines.append("")
        lines.append("WHAT A VISITOR SEES:")
        lines.extend([
            "  - A wallet restore/import form requesting a 12 or 24-word seed phrase.",
            "  - A page designed to look like a legitimate wallet recovery flow.",
        ])

        lines.append("")
        lines.append("KEY EVIDENCE:")
        for reason in self.get_filtered_reasons(max_items=5):
            lines.append(f"  - {reason}")

        if self.backend_domains:
            lines.append("")
            lines.append("STOLEN DATA SENT TO:")
            for backend in self.backend_domains[:3]:
                lines.append(f"  - {backend}")

        if self.suspicious_endpoints and not self.backend_domains:
            lines.append("")
            lines.append("SUSPICIOUS ENDPOINTS:")
            for endpoint in self.suspicious_endpoints[:3]:
                lines.append(f"  - {endpoint}")

        if self.screenshot_path or self.html_path:
            lines.append("")
            lines.append("Captured evidence (screenshot + HTML) available on request.")

        return "\n".join(lines)

    def _fake_airdrop_summary(self) -> str:
        """Generate summary for fake airdrop / claim scams."""
        lines = [
            self._action_request_line(),
            "",
            "FRAUD REPORT - Cryptocurrency Fake Airdrop/Claim",
            "",
            "This site impersonates a cryptocurrency project and promotes a",
            "fake airdrop/claim flow. It is designed to trick users into unsafe",
            "actions that can result in loss of funds or account compromise.",
            "",
            "SITE DETAILS:",
            f"  Domain: {self.domain}",
            f"  URL: {self.url}",
            f"  Detected: {self.detected_at.strftime('%Y-%m-%d %H:%M UTC') if self.detected_at else 'Unknown'}",
        ]
        impersonation = self.get_impersonation_lines()
        if impersonation:
            lines.append("")
            lines.append("IMPERSONATION INDICATORS:")
            lines.extend(f"  - {line}" for line in impersonation)

        self._append_review_notes(lines)

        lines.append("")
        lines.append("WHAT A VISITOR SEES:")
        lines.extend([
            "  - A page advertising a crypto airdrop/claim.",
            "  - Prompts to connect a wallet or claim tokens.",
        ])

        lines.append("")
        lines.append("KEY EVIDENCE:")
        for reason in self.get_filtered_reasons(max_items=5):
            lines.append(f"  - {reason}")

        if self.backend_domains:
            lines.append("")
            lines.append("DATA SENT TO:")
            for backend in self.backend_domains[:3]:
                lines.append(f"  - {backend}")

        if self.suspicious_endpoints and not self.backend_domains:
            lines.append("")
            lines.append("SUSPICIOUS ENDPOINTS:")
            for endpoint in self.suspicious_endpoints[:3]:
                lines.append(f"  - {endpoint}")

        if self.screenshot_path or self.html_path:
            lines.append("")
            lines.append("Captured evidence (screenshot + HTML) available on request.")

        return "\n".join(lines)

    def _generic_summary(self) -> str:
        """Generate a generic summary for crypto fraud/phishing."""
        lines = [
            self._action_request_line(),
            "",
            "FRAUD REPORT - Cryptocurrency Phishing/Fraud",
            "",
            "This site hosts cryptocurrency-related fraud/phishing content intended",
            "to trick users into unsafe actions.",
            "",
            "SITE DETAILS:",
            f"  Domain: {self.domain}",
            f"  URL: {self.url}",
            f"  Detected: {self.detected_at.strftime('%Y-%m-%d %H:%M UTC') if self.detected_at else 'Unknown'}",
        ]
        impersonation = self.get_impersonation_lines()
        if impersonation:
            lines.append("")
            lines.append("IMPERSONATION INDICATORS:")
            lines.extend(f"  - {line}" for line in impersonation)

        self._append_review_notes(lines)

        lines.append("")
        lines.append("WHAT A VISITOR SEES:")
        lines.extend([
            "  - A crypto-themed page with misleading claims and calls-to-action.",
            "  - Prompts users to proceed with unsafe actions (connect wallet, submit info, or send funds).",
        ])

        lines.append("")
        lines.append("KEY EVIDENCE:")
        for reason in self.get_filtered_reasons(max_items=5):
            lines.append(f"  - {reason}")

        if self.backend_domains:
            lines.append("")
            lines.append("DATA SENT TO:")
            for backend in self.backend_domains[:3]:
                lines.append(f"  - {backend}")

        if self.suspicious_endpoints and not self.backend_domains:
            lines.append("")
            lines.append("SUSPICIOUS ENDPOINTS:")
            for endpoint in self.suspicious_endpoints[:3]:
                lines.append(f"  - {endpoint}")

        if self.screenshot_path or self.html_path:
            lines.append("")
            lines.append("Captured evidence (screenshot + HTML) available on request.")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Utility Methods for Template Generation (reduce duplication in reporters)
    # -------------------------------------------------------------------------

    def extract_seed_phrase_indicator(self) -> Optional[str]:
        """Extract seed phrase field name from detection reasons (e.g., 'mnemonic')."""
        for reason in self.detection_reasons or []:
            text = (reason or "").strip()
            if not text:
                continue
            lower = text.lower()
            if "seed phrase" not in lower and "mnemonic" not in lower:
                continue
            match = re.search(r"'([^']+)'", text)
            if match:
                return match.group(1).strip() or None
        return None

    @staticmethod
    def humanize_reason(text: str) -> str:
        """Convert detection reasons into plain-language statements."""
        out = (text or "").strip()
        if not out:
            return out

        lower = out.lower()
        if lower.startswith("temporal:"):
            out = out.split(":", 1)[1].strip()

        out = out.replace("Seed phrase form found via exploration:", "Seed phrase form detected:")
        out = out.replace("Seed phrase form found:", "Seed phrase form detected:")
        out = out.replace(" via exploration", "")
        out = out.replace("Cloaking detected", "Cloaking detected (content varied across scans)")

        if lower == "kaspa-related title":
            return "Page title references Kaspa branding."
        if lower == "airdrop-related title":
            return "Page title references an airdrop/claim."
        if lower == "wallet-related title":
            return "Page title references a cryptocurrency wallet."
        if "stolen kaspa branding asset" in lower:
            return "Uses Kaspa branding assets (logo/styles)."

        match = re.search(r"visual match to ([^:]+):\s*(\d+)%", out, re.I)
        if match:
            target = match.group(1).strip()
            score = match.group(2).strip()
            return f"Visual similarity to {target} (~{score}% match), indicating a clone."

        prefix_match = re.match(r"([A-Z_]+):\s*(.+)", out)
        if prefix_match:
            label = prefix_match.group(1).strip().upper()
            reason = prefix_match.group(2).strip()
            prefix_map = {
                "AIRDROP": "Fake airdrop/claim flow detected",
                "DOUBLER": "Giveaway/doubler scam behavior detected",
                "SUPPORT": "Fake support/social engineering detected",
                "SEED": "Seed phrase theft indicator detected",
                "MALWARE": "Malware/download lure detected",
            }
            if label in prefix_map:
                return f"{prefix_map[label]} — {reason}"

        return out

    def _reasons_contain(self, needles: tuple[str, ...]) -> bool:
        for reason in self.detection_reasons or []:
            text = (reason or "").lower()
            if not text:
                continue
            if any(needle in text for needle in needles):
                return True
        return False

    def resolve_scam_type(self) -> str:
        scam_type = (self.scam_type or "").strip().lower()
        seed_form = False
        if isinstance(self.analysis_json, dict):
            seed_form = bool(self.analysis_json.get("seed_form"))
        has_seed_evidence = seed_form or self._reasons_contain(("seed phrase", "mnemonic", "recovery phrase"))
        looks_like_airdrop = self._reasons_contain(("airdrop", "claim"))

        if scam_type == "seed_phishing" and not has_seed_evidence:
            if looks_like_airdrop:
                return "fake_airdrop"
            return "unknown"

        if not scam_type or scam_type == "unknown":
            if has_seed_evidence:
                return "seed_phishing"
            if looks_like_airdrop:
                return "fake_airdrop"
            return "unknown"

        return scam_type

    def get_public_entry_url(self) -> Optional[str]:
        """Return public SeedBuster URL for this domain entry, if configured."""
        base_url = os.getenv("DASHBOARD_PUBLIC_URL", "").strip()
        if not base_url or not self.domain_id:
            return None
        base_url = base_url.rstrip("/")
        return f"{base_url}/#/domains/{self.domain_id}"

    def get_public_entry_line(self) -> Optional[str]:
        url = self.get_public_entry_url()
        if not url:
            return None
        return f"More information: {url}"

    @staticmethod
    def _extract_urls(text: str) -> list[str]:
        if not text:
            return []
        urls = []
        for match in re.findall(r"https?://\\S+", text):
            cleaned = match.rstrip(").,]\"'")
            if cleaned:
                urls.append(cleaned)
        return urls

    def _get_urlscan_links(self) -> list[str]:
        links: list[str] = []
        if isinstance(self.analysis_json, dict):
            external = self.analysis_json.get("external_intel")
            if isinstance(external, dict):
                urlscan = external.get("urlscan")
                if isinstance(urlscan, dict):
                    result_url = (urlscan.get("result_url") or "").strip()
                    if result_url:
                        links.append(result_url)
            submission = self.analysis_json.get("urlscan_submission")
            if isinstance(submission, dict):
                result_url = (submission.get("result_url") or "").strip()
                if result_url:
                    links.append(result_url)

        for reason in self.detection_reasons or []:
            for link in self._extract_urls(reason):
                if "urlscan.io" in link:
                    links.append(link)

        deduped: list[str] = []
        seen = set()
        for link in links:
            if link in seen:
                continue
            deduped.append(link)
            seen.add(link)
        return deduped

    def _get_review_notes(self) -> list[str]:
        notes: list[str] = []
        reasons = [(r or "").lower() for r in (self.detection_reasons or [])]

        cloaking = any("cloaking" in r for r in reasons)
        if isinstance(self.analysis_json, dict):
            temporal = self.analysis_json.get("temporal")
            if isinstance(temporal, dict) and temporal.get("cloaking_detected"):
                cloaking = True

        anti_bot = any(
            token in r
            for r in reasons
            for token in ("anti-bot", "bot detection", "turnstile", "recaptcha", "access denied")
        )

        if cloaking:
            notes.append("Content appears cloaked or inconsistent across visits.")
        if anti_bot:
            notes.append("Anti-bot measures may show a decoy page to reviewers.")

        if cloaking or anti_bot:
            for link in self._get_urlscan_links()[:2]:
                notes.append(f"External capture (may show hidden content): {link}")

        return notes

    def _append_review_notes(self, lines: list[str]) -> None:
        notes = self._get_review_notes()
        if not notes:
            return
        lines.append("")
        lines.append("REVIEWER NOTES:")
        lines.extend(f"  - {note}" for note in notes)

    def get_filtered_reasons(self, max_items: int = 5) -> list[str]:
        """Get detection reasons with low-signal items filtered out."""
        skip_terms = (
            "suspicion score",
            "domain suspicion",
            "keyword",
            "tld",
        )

        keep_terms = (
            "seed phrase",
            "mnemonic",
            "recovery phrase",
            "private key",
            "cloaking detected",
            "ondigitalocean.app",
            "workers.dev",
            "kaspa",
            "airdrop",
            "giveaway",
            "claim",
            "support",
            "doubler",
        )

        high_signal = []
        other = []

        for reason in self.detection_reasons or []:
            text = (reason or "").strip()
            if not text:
                continue
            lower = text.lower()

            # Skip temporal noise except cloaking
            if lower.startswith("temporal:") and "cloaking" not in lower:
                continue

            # Skip low-signal
            if any(s in lower for s in skip_terms):
                continue

            # Classify
            if any(s in lower for s in keep_terms):
                high_signal.append(self.humanize_reason(text))
            else:
                other.append(self.humanize_reason(text))

        # Return high-signal first, then fill with others
        result = high_signal[:max_items]
        if len(result) < max_items:
            result.extend(other[: max_items - len(result)])

        if result:
            return result
        return [
            self.humanize_reason(r)
            for r in (self.detection_reasons or [])[:max_items]
            if r
        ]

    def get_impersonation_lines(self) -> list[str]:
        """Return plain-language impersonation indicators."""
        reasons = self.detection_reasons or []
        lines: list[str] = []
        brand = None
        official_site = None
        has_brand_reason = False
        hint_sources = []
        hint_sources.extend(reasons)
        hint_sources.extend(self.suspicious_endpoints or [])
        hint_sources.extend(self.backend_domains or [])
        hint_text = " ".join(str(item) for item in hint_sources if item).lower()

        domain_lower = (self.domain or "").lower()
        url_lower = (self.url or "").lower()
        kaspa_ng_hint = any(
            token in domain_lower or token in url_lower
            for token in ("kaspa_ng", "kaspa-ng", "kaspa ng", "app-kaspa-ng")
        )
        kaspa_wallet_hint = any(
            token in hint_text
            for token in (
                "walletkaspanet",
                "wallet-kaspanet",
                "wallet.kaspanet",
                "kaspanet-wallet",
                "kaspanet wallet",
            )
        )
        kaspa_seed_phish = "kaspa" in domain_lower and (
            (self.scam_type or "").lower() == "seed_phishing"
            or self._reasons_contain(("seed phrase", "mnemonic", "recovery phrase"))
        )

        for reason in reasons:
            text = (reason or "").strip()
            if not text:
                continue
            lower = text.lower()
            match = re.search(r"visual match to ([^:]+):\s*(\d+)%", text, re.I)
            if match:
                target = match.group(1).strip()
                score = match.group(2).strip()
                lines.append(f"Visual similarity to {target} (~{score}% match).")
                has_brand_reason = True
                if "." in target:
                    official_site = target
                    brand = target.split(".", 1)[0].title()
                else:
                    brand = target.title()
            if "stolen kaspa branding asset" in lower:
                lines.append("Uses Kaspa branding assets (logo/styles).")
                brand = brand or "Kaspa"
                has_brand_reason = True
            if "kaspa-related title" in lower:
                lines.append("Page title references Kaspa branding.")
                brand = brand or "Kaspa"
                has_brand_reason = True
            if "fake kaspa support" in lower:
                lines.append("Claims to be Kaspa support.")
                brand = brand or "Kaspa"
                has_brand_reason = True
            if "wallet-related title" in lower:
                lines.append("Page title references a cryptocurrency wallet.")
        if kaspa_ng_hint and (brand is None or brand.lower().startswith("kaspa")):
            brand = "Kaspa NG"
            official_site = "kaspa-ng.org"
            has_brand_reason = True
        elif kaspa_wallet_hint and (brand is None or brand.lower().startswith("kaspa")):
            brand = "Kaspa Wallet"
            official_site = "wallet.kaspanet.io"
            has_brand_reason = True
        elif kaspa_seed_phish and (brand is None or brand.lower().startswith("kaspa")):
            brand = "Kaspa Wallet"
            official_site = "wallet.kaspanet.io"
            has_brand_reason = True

        if "kaspa" in domain_lower and domain_lower not in ("kaspa.org", "www.kaspa.org"):
            if not has_brand_reason:
                lines.append("Domain name includes 'kaspa'.")
            brand = brand or "Kaspa"

        if brand:
            if brand.lower() == "kaspa":
                official_site = official_site or "kaspa.org"
            if official_site:
                official_url = official_site
                if not official_url.startswith("http"):
                    official_url = f"https://{official_url}"
                lines.insert(0, f"Appears to impersonate {brand} (official site: {official_url}).")
            else:
                lines.insert(0, f"Appears to impersonate {brand}.")

        deduped = []
        seen = set()
        for line in lines:
            if line in seen:
                continue
            deduped.append(line)
            seen.add(line)
        return deduped

    def get_seed_observation(self) -> str:
        """Get a human-readable observation about seed phrase detection."""
        seed_hint = self.extract_seed_phrase_indicator()
        if seed_hint:
            return f"Observed seed phrase field: '{seed_hint}'"
        return "Observed seed phrase theft flow"

    def get_backend_hosts(self) -> list[str]:
        """Get unique backend domain hosts from suspicious endpoints."""
        from urllib.parse import urlparse

        hosts = set()
        for domain in self.backend_domains or []:
            hosts.add(domain.lower().strip())

        for endpoint in self.suspicious_endpoints or []:
            if not isinstance(endpoint, str):
                continue
            try:
                parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
                host = (parsed.hostname or "").lower().strip()
                if host:
                    hosts.add(host)
            except Exception:
                pass

        return sorted(hosts)

    def _crypto_doubler_summary(self) -> str:
        """Generate summary for crypto doubler / fake giveaway scams."""
        lines = [
            self._action_request_line(),
            "",
            "FRAUD REPORT - Cryptocurrency Doubler/Giveaway Scam",
            "",
            "This site runs an advance-fee fraud scheme (\"crypto doubler\"/giveaway).",
            "It promises to multiply deposits (e.g., 2X/3X), but victims receive nothing back.",
            "",
            "SITE DETAILS:",
            f"  Domain: {self.domain}",
            f"  URL: {self.url}",
            f"  Detected: {self.detected_at.strftime('%Y-%m-%d %H:%M UTC') if self.detected_at else 'Unknown'}",
            "",
        ]

        impersonation = self.get_impersonation_lines()
        if impersonation:
            lines.append("IMPERSONATION INDICATORS:")
            lines.extend(f"  - {line}" for line in impersonation)
            lines.append("")

        self._append_review_notes(lines)

        if self.scammer_wallets:
            lines.append("SCAMMER WALLET ADDRESSES:")
            for wallet in self.scammer_wallets[:5]:
                lines.append(f"  - {wallet}")
            lines.append("")

        lines.append("KEY EVIDENCE:")
        for reason in self.get_filtered_reasons(max_items=5):
            lines.append(f"  - {reason}")

        lines.extend([
            "",
            "HOW THE SCAM WORKS:",
            "  1. Site advertises a fake giveaway promising 2X/3X returns",
            "  2. Displays a deposit address and urgency cues (e.g., countdown)",
            "  3. Victim sends cryptocurrency to the scammer's address",
            "  4. Scammer keeps funds; victim receives nothing",
        ])

        if self.screenshot_path or self.html_path:
            lines.append("")
            lines.append("Captured evidence (screenshot + HTML) available on request.")

        return "\n".join(lines)


@dataclass
class ManualSubmissionField:
    """A single field for manual form submission."""

    name: str  # Internal field name (e.g., "email")
    label: str  # Display label (e.g., "Your email address")
    value: str  # The value to copy
    multiline: bool = False  # Whether this is a multiline text field


@dataclass
class ManualSubmissionData:
    """Structured data for manual form submission."""

    form_url: str  # URL of the form to submit
    reason: str  # Why manual submission is required (e.g., "Turnstile/CAPTCHA")
    fields: list[ManualSubmissionField] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # Additional instructions

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "form_url": self.form_url,
            "reason": self.reason,
            "fields": [
                {
                    "name": f.name,
                    "label": f.label,
                    "value": f.value,
                    "multiline": f.multiline,
                }
                for f in self.fields
            ],
            "notes": self.notes,
        }


@dataclass
class ReportResult:
    """Result of a report submission attempt."""

    platform: str
    status: ReportStatus
    report_id: Optional[str] = None
    message: Optional[str] = None
    response_data: Optional[dict] = None
    retry_after: Optional[int] = None  # Seconds to wait before retry
    submitted_at: Optional[datetime] = None

    def __post_init__(self):
        if self.status == ReportStatus.SUBMITTED and not self.submitted_at:
            self.submitted_at = datetime.now()


class BaseReporter(ABC):
    """Abstract base class for all abuse reporters."""

    platform_name: str = "unknown"
    platform_url: str = ""
    supports_evidence: bool = False
    requires_api_key: bool = False
    rate_limit_per_minute: int = 60
    manual_only: bool = False  # If True, always returns MANUAL_REQUIRED (no automation)

    def __init__(self):
        self._configured = False

    @abstractmethod
    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Submit a phishing report to this platform.

        Args:
            evidence: The evidence package to submit

        Returns:
            ReportResult with status and any response data
        """
        pass

    async def check_status(self, report_id: str) -> ReportResult:
        """
        Check status of a previously submitted report.

        Not all platforms support this - returns SUBMITTED by default.
        """
        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.SUBMITTED,
            report_id=report_id,
            message="Status check not supported for this platform",
        )

    async def check_duplicate(self, url: str) -> bool:
        """
        Check if URL has already been reported to this platform.

        Not all platforms support this - returns False by default.
        """
        return False

    def is_configured(self) -> bool:
        """Check if this reporter is properly configured."""
        return self._configured

    def validate_evidence(self, evidence: ReportEvidence) -> tuple[bool, str]:
        """
        Validate evidence before submission.

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not evidence.domain:
            return False, "Domain is required"
        if not evidence.url:
            return False, "URL is required"
        if evidence.confidence_score < 0 or evidence.confidence_score > 100:
            return False, "Confidence score must be 0-100"
        return True, ""

    def is_applicable(self, evidence: ReportEvidence) -> tuple[bool, str]:
        """
        Return whether this reporter is applicable for this evidence.

        This is used by the manager to avoid noisy failures (e.g., provider-specific
        reporters when no matching infrastructure is present).
        """
        return True, ""

    def generate_manual_submission(self, evidence: ReportEvidence) -> "ManualSubmissionData":
        """
        Build structured manual submission data for this platform.

        Subclasses can override to provide richer, platform-specific instructions.
        """
        form_url = getattr(self, "platform_url", "") or ""
        summary = evidence.to_summary()
        return ManualSubmissionData(
            form_url=form_url,
            reason="Manual submission required",
            fields=[
                ManualSubmissionField(
                    name="url",
                    label="URL to report",
                    value=evidence.url,
                ),
                ManualSubmissionField(
                    name="details",
                    label="Evidence summary",
                    value=summary,
                    multiline=True,
                ),
            ],
            notes=[],
        )


class ReporterError(Exception):
    """Base exception for reporter errors."""

    pass


class RateLimitError(ReporterError):
    """Rate limit exceeded."""

    def __init__(self, retry_after: int, message: str = "Rate limit exceeded"):
        self.retry_after = retry_after
        self.message = message
        super().__init__(f"{message}. Retry after {retry_after} seconds.")


class APIError(ReporterError):
    """API returned an error."""

    def __init__(self, status_code: int, message: str, response_body: str = ""):
        self.status_code = status_code
        self.message = message
        self.response_body = response_body
        super().__init__(f"API error {status_code}: {message}")


class ConfigurationError(ReporterError):
    """Reporter not properly configured."""

    pass


class BaseHTTPReporter(BaseReporter):
    """
    Base class for reporters that use HTTP APIs.

    Provides:
    - Shared httpx client with sensible defaults
    - Standard error handling (rate limits, timeouts, API errors)
    - Retry logic for transient failures

    Subclasses implement `_do_submit()` instead of `submit()`.
    """

    # HTTP client defaults
    timeout_seconds: float = 30.0
    user_agent: str = "SeedBuster/1.0 (https://github.com/elldeeone/seedbuster)"
    max_retries: int = 2

    def __init__(self):
        super().__init__()
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout_seconds),
                headers={"User-Agent": self.user_agent},
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Submit with automatic error handling.

        Subclasses should override `_do_submit()` instead.
        """
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        try:
            return await self._do_submit(evidence)

        except httpx.TimeoutException:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message="Request timed out",
            )

        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code

            # Rate limiting
            if status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 60))
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.RATE_LIMITED,
                    message=f"Rate limited (retry after {retry_after}s)",
                    retry_after=retry_after,
                )

            # Client errors
            if 400 <= status_code < 500:
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message=f"API error: {status_code}",
                    response_data={"status_code": status_code},
                )

            # Server errors (may retry)
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=f"Server error: {status_code}",
                response_data={"status_code": status_code},
            )

        except Exception as e:
            logger.exception(f"Unexpected error in {self.platform_name}: {e}")
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=f"Unexpected error: {str(e)}",
            )

    async def _do_submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Perform the actual submission.

        Subclasses must implement this method. The base `submit()` wraps this
        with standard error handling.
        """
        raise NotImplementedError("Subclasses must implement _do_submit()")

    async def _post_json(
        self,
        url: str,
        data: dict[str, Any],
        headers: Optional[dict[str, str]] = None,
    ) -> httpx.Response:
        """Helper for JSON POST requests."""
        client = await self._get_client()
        return await client.post(url, json=data, headers=headers)

    async def _post_form(
        self,
        url: str,
        data: dict[str, Any],
        headers: Optional[dict[str, str]] = None,
    ) -> httpx.Response:
        """Helper for form POST requests."""
        client = await self._get_client()
        return await client.post(url, data=data, headers=headers)

    async def _get(
        self,
        url: str,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> httpx.Response:
        """Helper for GET requests."""
        client = await self._get_client()
        return await client.get(url, params=params, headers=headers)


def build_manual_submission(
    form_url: str,
    reason: str,
    evidence: ReportEvidence,
    *,
    include_wallets: bool = False,
    extra_fields: Optional[list[ManualSubmissionField]] = None,
    notes: Optional[list[str]] = None,
) -> ManualSubmissionData:
    """
    Factory function to build ManualSubmissionData with common patterns.

    Reduces boilerplate in manual-only reporters.
    """
    fields = [
        ManualSubmissionField(
            name="url",
            label="URL to report",
            value=evidence.url,
        ),
    ]

    # Build details based on scam type
    scam_type = evidence.resolve_scam_type()
    seed_hint = evidence.extract_seed_phrase_indicator()
    if scam_type == "crypto_doubler":
        details = [
            "Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam)",
            "",
            f"Domain: {evidence.domain}",
        ]
        if include_wallets and evidence.scammer_wallets:
            details.append("")
            details.append("Scammer wallet addresses:")
            for wallet in evidence.scammer_wallets[:3]:
                details.append(f"  - {wallet}")
    elif scam_type == "fake_airdrop":
        details = [
            "Cryptocurrency fraud (fake airdrop/claim)",
            "",
            f"Domain: {evidence.domain}",
            "",
            "Observed fake airdrop/claim flow",
        ]
    elif scam_type == "seed_phishing" or seed_hint:
        seed_obs = evidence.get_seed_observation()
        details = [
            "Cryptocurrency phishing (seed phrase theft)",
            "",
            f"Domain: {evidence.domain}",
            "",
            seed_obs,
        ]
    else:
        details = [
            "Cryptocurrency fraud / phishing",
            "",
            f"Domain: {evidence.domain}",
            "",
            "Observed cryptocurrency fraud/phishing content",
        ]

    # Add filtered reasons
    details.append("")
    details.append("Key evidence:")
    for reason_text in evidence.get_filtered_reasons(max_items=4):
        details.append(f"  - {reason_text}")

    fields.append(
        ManualSubmissionField(
            name="details",
            label="Evidence summary",
            value="\n".join(details),
            multiline=True,
        )
    )

    if extra_fields:
        fields.extend(extra_fields)

    return ManualSubmissionData(
        form_url=form_url,
        reason=reason,
        fields=fields,
        notes=notes or [],
    )
