"""Base classes for abuse reporting in SeedBuster."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


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

    def to_summary(self) -> str:
        """Generate a human-readable summary for reports."""
        lines = [
            f"Domain: {self.domain}",
            f"URL: {self.url}",
            f"Detected: {self.detected_at.isoformat()}",
            f"Confidence: {self.confidence_score}%",
            "",
            "Detection Reasons:",
        ]
        for reason in self.detection_reasons:
            lines.append(f"  - {reason}")

        if self.suspicious_endpoints:
            lines.append("")
            lines.append("Suspicious Endpoints:")
            for endpoint in self.suspicious_endpoints[:5]:
                lines.append(f"  - {endpoint}")

        if self.backend_domains:
            lines.append("")
            lines.append("Backend Infrastructure:")
            for backend in self.backend_domains:
                lines.append(f"  - {backend}")

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
