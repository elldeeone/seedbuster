"""Base classes for abuse reporting in SeedBuster."""

import logging
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
        # Choose summary based on scam type
        if self.scam_type == "crypto_doubler":
            return self._crypto_doubler_summary()
        # Default to seed phishing summary
        return self._seed_phishing_summary()

    def _seed_phishing_summary(self) -> str:
        """Generate summary for seed phrase phishing scams."""
        lines = [
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
            f"  Confidence: {self.confidence_score}%",
            "",
            "KEY EVIDENCE:",
        ]
        # Filter out low-signal reasons
        skip_terms = ("suspicion score", "domain suspicion", "tld", "keyword")
        for reason in self.detection_reasons[:5]:
            if not any(s in (reason or "").lower() for s in skip_terms):
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

        lines.extend([
            "",
            "Reported by: SeedBuster (automated phishing detection)",
            "Source: https://github.com/elldeeone/seedbuster",
        ])

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

    def get_filtered_reasons(self, max_items: int = 5) -> list[str]:
        """Get detection reasons with low-signal items filtered out."""
        skip_terms = (
            "suspicion score",
            "domain suspicion",
            "keyword",
            "tld",
            "kaspa-related title",
            "wallet-related title",
        )

        keep_terms = (
            "seed phrase",
            "mnemonic",
            "recovery phrase",
            "private key",
            "cloaking detected",
            "ondigitalocean.app",
            "workers.dev",
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
                high_signal.append(text)
            else:
                other.append(text)

        # Return high-signal first, then fill with others
        result = high_signal[:max_items]
        if len(result) < max_items:
            result.extend(other[: max_items - len(result)])

        return result or self.detection_reasons[:max_items]

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
            "FRAUD REPORT - Cryptocurrency Doubler/Giveaway Scam",
            "",
            "This site impersonates the official Kaspa project to run an advance-fee",
            "fraud scheme. It promises to multiply (e.g., 3X) any cryptocurrency sent",
            "to their address, but victims receive nothing back.",
            "",
            "SITE DETAILS:",
            f"  Domain: {self.domain}",
            f"  URL: {self.url}",
            f"  Detected: {self.detected_at.strftime('%Y-%m-%d %H:%M UTC') if self.detected_at else 'Unknown'}",
            f"  Confidence: {self.confidence_score}%",
            "",
        ]

        if self.scammer_wallets:
            lines.append("SCAMMER WALLET ADDRESSES:")
            for wallet in self.scammer_wallets[:5]:
                lines.append(f"  - {wallet}")
            lines.append("")

        lines.append("KEY EVIDENCE:")
        skip_terms = ("suspicion score", "domain suspicion", "tld", "keyword")
        for reason in self.detection_reasons[:5]:
            if not any(s in (reason or "").lower() for s in skip_terms):
                lines.append(f"  - {reason}")

        lines.extend([
            "",
            "HOW THE SCAM WORKS:",
            "  1. Site clones official project branding (kaspa.org)",
            "  2. Claims users will receive 3X back if they send crypto",
            "  3. Shows fake transaction history and countdown timers",
            "  4. Victim sends crypto to scammer's wallet address",
            "  5. Scammer keeps funds; victim receives nothing",
            "",
            "Reported by: SeedBuster (automated phishing detection)",
            "Source: https://github.com/elldeeone/seedbuster",
        ])

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
    if evidence.scam_type == "crypto_doubler":
        details = [
            "Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam)",
            "",
            f"Domain: {evidence.domain}",
            f"Confidence: {evidence.confidence_score}%",
        ]
        if include_wallets and evidence.scammer_wallets:
            details.append("")
            details.append("Scammer wallet addresses:")
            for wallet in evidence.scammer_wallets[:3]:
                details.append(f"  - {wallet}")
    else:
        seed_obs = evidence.get_seed_observation()
        details = [
            "Cryptocurrency phishing (seed phrase theft)",
            "",
            f"Domain: {evidence.domain}",
            f"Confidence: {evidence.confidence_score}%",
            "",
            seed_obs,
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
