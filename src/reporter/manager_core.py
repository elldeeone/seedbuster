"""Report manager core setup."""

from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

from .base import BaseReporter

if TYPE_CHECKING:
    from ..storage.database import Database
    from ..storage.evidence import EvidenceStore

logger = logging.getLogger(__name__)


class ReportManagerCoreMixin:
    """Reporter initialization and metadata helpers."""

    def __init__(
        self,
        database: "Database",
        evidence_store: "EvidenceStore",
        smtp_config: Optional[dict] = None,
        resend_api_key: Optional[str] = None,
        resend_from_email: Optional[str] = None,
        reporter_email: str = "",
        enabled_platforms: Optional[list[str]] = None,
    ):
        self.database = database
        self.evidence_store = evidence_store
        self.smtp_config = smtp_config or {}
        self.resend_api_key = resend_api_key
        self.resend_from_email = resend_from_email
        self.reporter_email = reporter_email
        if enabled_platforms in (None, [], set(), ()):  # type: ignore[comparison-overlap]
            self.enabled_platforms = None
        else:
            self.enabled_platforms = {p for p in enabled_platforms}

        self.reporters: dict[str, BaseReporter] = {}
        self._init_reporters()

    @staticmethod
    def _get_rate_limiter(platform: str, rate_limit_per_minute: int):
        from . import manager as manager_module

        return manager_module.get_rate_limiter(platform, rate_limit_per_minute)

    def _init_reporters(self) -> None:
        """Initialize available reporters based on configuration."""
        from .smtp_reporter import SMTPReporter
        from .cloudflare import CloudflareReporter
        from .google_form import GoogleFormReporter
        from .netcraft import NetcraftReporter
        from .hosting_provider import HostingProviderReporter
        from .registrar import RegistrarReporter
        from .microsoft import MicrosoftReporter
        from .resend_reporter import ResendReporter
        from .digitalocean import DigitalOceanReporter
        from .shortlink_provider import ShortlinkProviderReporter
        from .manual_platforms import (
            AWSReporter,
            AzureReporter,
            DiscordReporter,
            GCPReporter,
            GoDaddyReporter,
            NamecheapReporter,
            NetlifyReporter,
            PorkbunReporter,
            TelegramReporter,
            VercelReporter,
            GoogleDomainsReporter,
            TucowsReporter,
            NjallaReporter,
            RenderReporter,
            FlyReporter,
            RailwayReporter,
        )

        self.reporters["google"] = GoogleFormReporter()
        logger.info("Initialized Google Safe Browsing reporter")

        reporter_identity = self.resend_from_email or self.reporter_email or ""
        self.reporters["cloudflare"] = CloudflareReporter(reporter_email=reporter_identity)
        logger.info("Initialized Cloudflare reporter")

        self.reporters["netcraft"] = NetcraftReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized Netcraft reporter")

        self.reporters["shortlink_provider"] = ShortlinkProviderReporter()
        logger.info("Initialized shortlink provider manual reporter")

        self.reporters["microsoft"] = MicrosoftReporter()
        logger.info("Initialized Microsoft manual reporter")

        self.reporters["hosting_provider"] = HostingProviderReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized hosting provider manual reporter")

        self.reporters["edge_provider"] = HostingProviderReporter(
            reporter_email=self.resend_from_email or self.reporter_email or "",
            provider_source="edge",
            provider_label="Edge/CDN provider",
            platform_name="edge_provider",
            display_name="Edge/CDN Provider",
        )
        logger.info("Initialized edge/CDN provider manual reporter")

        self.reporters["dns_provider"] = HostingProviderReporter(
            reporter_email=self.resend_from_email or self.reporter_email or "",
            provider_source="dns",
            provider_label="Nameserver/DNS provider",
            platform_name="dns_provider",
            display_name="DNS Provider",
        )
        logger.info("Initialized DNS provider manual reporter")

        self.reporters["registrar"] = RegistrarReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized registrar manual reporter")

        self.reporters["resend"] = ResendReporter(
            api_key=self.resend_api_key or "",
            from_email=self.resend_from_email or self.reporter_email or "SeedBuster <onboarding@resend.dev>",
        )
        if self.resend_api_key:
            logger.info(
                "Initialized Resend email reporter (from: %s)",
                self.resend_from_email or self.reporter_email,
            )
        else:
            logger.info("Resend email reporter not configured (missing RESEND_API_KEY)")

        reporter_email = self.resend_from_email or self.reporter_email or ""
        self.reporters["digitalocean"] = DigitalOceanReporter(
            reporter_email=reporter_email.split("<")[-1].rstrip(">") if "<" in reporter_email else reporter_email,
            reporter_name="Kaspa Security",
        )
        if reporter_email:
            logger.info("Initialized DigitalOcean form reporter (Playwright)")
        else:
            logger.info("DigitalOcean form reporter not configured (missing reporter email)")

        self.reporters["aws"] = AWSReporter()
        self.reporters["gcp"] = GCPReporter()
        self.reporters["azure"] = AzureReporter()
        self.reporters["vercel"] = VercelReporter()
        self.reporters["netlify"] = NetlifyReporter()
        self.reporters["godaddy"] = GoDaddyReporter()
        self.reporters["namecheap"] = NamecheapReporter()
        self.reporters["porkbun"] = PorkbunReporter()
        self.reporters["telegram"] = TelegramReporter()
        self.reporters["discord"] = DiscordReporter()
        self.reporters["google_domains"] = GoogleDomainsReporter()
        self.reporters["tucows"] = TucowsReporter()
        self.reporters["njalla"] = NjallaReporter()
        self.reporters["render"] = RenderReporter()
        self.reporters["fly_io"] = FlyReporter()
        self.reporters["railway"] = RailwayReporter()
        logger.info("Initialized manual-only reporters for providers/registrars/messaging")

        self.reporters["smtp"] = SMTPReporter(
            host=self.smtp_config.get("host", ""),
            port=self.smtp_config.get("port", 587),
            username=self.smtp_config.get("username", ""),
            password=self.smtp_config.get("password", ""),
            from_email=self.smtp_config.get("from_email", self.reporter_email),
        )
        if self.smtp_config.get("host"):
            logger.info("Initialized SMTP reporter")
        else:
            logger.info("SMTP reporter not configured (missing SMTP_HOST)")

        if self.enabled_platforms is not None:
            unknown = sorted(p for p in self.enabled_platforms if p not in self.reporters)
            if unknown:
                logger.warning(
                    "Unknown report platforms in REPORT_PLATFORMS: %s",
                    ", ".join(unknown),
                )

    def get_available_platforms(self) -> list[str]:
        """Get list of available/configured platforms."""
        platforms = [
            name
            for name, reporter in self.reporters.items()
            if reporter.is_configured()
        ]
        if self.enabled_platforms is not None:
            platforms = [p for p in platforms if p in self.enabled_platforms]
        return platforms

    def get_platform_info(self) -> dict[str, dict]:
        """Get metadata about each available platform."""
        platforms = self.get_available_platforms()
        info = {}
        for name in platforms:
            reporter = self.reporters.get(name)
            if reporter:
                display = (
                    getattr(reporter, "display_name", None)
                    or getattr(reporter, "platform_display_name", None)
                    or " ".join(part.capitalize() for part in name.split("_"))
                )
                info[name] = {
                    "manual_only": getattr(reporter, "manual_only", False),
                    "url": getattr(reporter, "platform_url", ""),
                    "name": display,
                }
        return info
