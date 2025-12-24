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
from .cloudflare import CloudflareReporter
from .google_form import GoogleFormReporter
from .smtp_reporter import SMTPReporter
from .netcraft import NetcraftReporter
from .resend_reporter import ResendReporter
from .digitalocean import DigitalOceanReporter
from .google_safebrowsing import GoogleSafeBrowsingReporter
from .hosting_provider import HostingProviderReporter
from .registrar import RegistrarReporter
from .apwg import APWGReporter
from .microsoft import MicrosoftReporter
from .manual_platforms import (
    AWSReporter,
    AzureReporter,
    DiscordReporter,
    FlyReporter,
    GCPReporter,
    GoogleDomainsReporter,
    GoDaddyReporter,
    NamecheapReporter,
    NetlifyReporter,
    OpenDNSReporter,
    PorkbunReporter,
    Quad9Reporter,
    RailwayReporter,
    RenderReporter,
    TelegramReporter,
    TucowsReporter,
    VercelReporter,
)

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
    "CloudflareReporter",
    "GoogleFormReporter",
    "SMTPReporter",
    "NetcraftReporter",
    "ResendReporter",
    "DigitalOceanReporter",
    "GoogleSafeBrowsingReporter",
    "HostingProviderReporter",
    "RegistrarReporter",
    "APWGReporter",
    "MicrosoftReporter",
    "AWSReporter",
    "AzureReporter",
    "DiscordReporter",
    "FlyReporter",
    "GCPReporter",
    "GoogleDomainsReporter",
    "GoDaddyReporter",
    "NamecheapReporter",
    "NetlifyReporter",
    "OpenDNSReporter",
    "PorkbunReporter",
    "Quad9Reporter",
    "RailwayReporter",
    "RenderReporter",
    "TelegramReporter",
    "TucowsReporter",
    "VercelReporter",
]
