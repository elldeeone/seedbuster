"""Reporter modules for SeedBuster abuse reporting."""

from .base import (
    BaseReporter,
    ReportEvidence,
    ReportResult,
    ReportStatus,
    ReporterError,
    RateLimitError,
    APIError,
    ConfigurationError,
)
from .manager import ReportManager
from .rate_limiter import RateLimiter, get_rate_limiter
from .templates import ReportTemplates

# Platform reporters
from .phishtank import PhishTankReporter
from .cloudflare import CloudflareReporter
from .google_form import GoogleFormReporter
from .smtp_reporter import SMTPReporter
from .netcraft import NetcraftReporter
from .resend_reporter import ResendReporter

__all__ = [
    # Base classes
    "BaseReporter",
    "ReportEvidence",
    "ReportResult",
    "ReportStatus",
    "ReporterError",
    "RateLimitError",
    "APIError",
    "ConfigurationError",
    # Manager
    "ReportManager",
    # Utilities
    "RateLimiter",
    "get_rate_limiter",
    "ReportTemplates",
    # Reporters
    "PhishTankReporter",
    "CloudflareReporter",
    "GoogleFormReporter",
    "SMTPReporter",
    "NetcraftReporter",
    "ResendReporter",
]
