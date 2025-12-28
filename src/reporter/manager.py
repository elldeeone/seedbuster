"""Report manager for coordinating abuse reports across platforms."""

import asyncio
import json
import logging
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

import httpx

from .base import (
    BaseReporter,
    ConfigurationError,
    ReportEvidence,
    ReportResult,
    ReportStatus,
    ReporterError,
)
from .rate_limiter import get_rate_limiter

if TYPE_CHECKING:
    from ..analyzer.campaigns import ThreatCampaign, ThreatCampaignManager
    from ..storage.database import Database
    from ..storage.evidence import EvidenceStore

logger = logging.getLogger(__name__)


class ReportManager:
    """
    Manages multi-platform abuse reporting.

    Coordinates reporters, handles rate limiting, tracks report status
    in database, and provides evidence packaging.
    """

    # Guardrails for repeated rate limiting to avoid endless churn.
    MAX_RATE_LIMIT_ATTEMPTS: int = 6
    MAX_RATE_LIMIT_BACKOFF_SECONDS: int = 6 * 60 * 60  # 6 hours

    @classmethod
    def _compute_rate_limit_backoff(cls, base_seconds: int, attempts: int) -> int:
        """
        Compute an exponential backoff (capped) for rate-limited retries.

        attempts should be the *next* attempts count after the status update.
        """
        base = max(30, int(base_seconds or 60))
        exponent = min(max(0, int(attempts) - 1), 6)
        return min(base * (2**exponent), cls.MAX_RATE_LIMIT_BACKOFF_SECONDS)

    @staticmethod
    def _preview_only_enabled() -> bool:
        """Return True when reporting should run in preview-only mode."""
        return os.environ.get("REPORT_PREVIEW_ONLY", "false").lower() == "true"

    @staticmethod
    def _dry_run_save_only_enabled() -> bool:
        """Return True when dry-run previews should only be saved locally."""
        return os.environ.get("DRY_RUN_SAVE_ONLY", "false").lower() == "true"

    @staticmethod
    def _ensure_url(target: str) -> str:
        """Ensure a scheme is present so urlparse works predictably."""
        value = (target or "").strip()
        if not value:
            return ""
        if value.startswith(("http://", "https://")):
            return value
        return f"https://{value}"

    @staticmethod
    def _safe_filename_component(value: str) -> str:
        raw = (value or "").strip()
        if not raw:
            return "unknown"
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in raw)[:80]

    @staticmethod
    def _dry_run_email_dir() -> Path:
        data_dir = Path(os.environ.get("DATA_DIR", "./data"))
        return data_dir / "packages" / "dry_run_emails"

    @classmethod
    def _extract_hostname(cls, target: str) -> str:
        """Extract hostname from a target that may include path/query/fragment."""
        parsed = urlparse(cls._ensure_url(target))
        return (parsed.hostname or "").strip().lower()

    @classmethod
    def _extract_hostnames_from_endpoints(cls, endpoints: list[object]) -> list[str]:
        """Extract unique hostnames from a list of URL-ish strings."""
        seen: set[str] = set()
        hosts: list[str] = []
        for item in endpoints or []:
            if not isinstance(item, str):
                continue
            raw = item.strip()
            if not raw:
                continue
            host = cls._extract_hostname(raw)
            if not host:
                continue
            if host in seen:
                continue
            seen.add(host)
            hosts.append(host)
        return hosts

    @staticmethod
    def _extract_api_key_indicators(reasons: list[object]) -> list[str]:
        """Extract API-key related indicators from reasons for reporting context."""
        found: list[str] = []
        seen: set[str] = set()
        for reason in reasons or []:
            if not isinstance(reason, str):
                continue
            lower = reason.lower()
            if "api key" not in lower and "apikey" not in lower:
                continue
            entry = reason.strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            found.append(entry)
        return found

    @staticmethod
    def _is_timestamp_due(timestamp: str | None) -> bool:
        """Return True if a timestamp is missing or not in the future."""
        if not timestamp:
            return True
        value = timestamp.strip()
        if not value:
            return True
        try:
            # SQLite may store either "YYYY-MM-DD HH:MM:SS" or ISO strings.
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return True
        # Compare naive timestamps in UTC-ish space (best-effort).
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt <= datetime.now(timezone.utc)

    @staticmethod
    def _build_manual_instructions_text(
        platform: str, evidence: ReportEvidence, result: ReportResult
    ) -> str:
        """Build a text file containing manual reporting instructions."""
        message = (result.message or "").strip()
        lines = [
            "SeedBuster Manual Report Instructions",
            f"Platform: {platform}",
            "",
        ]
        if message:
            lines.extend(["Platform Notes:", message, ""])
        lines.extend(["Evidence Summary:", evidence.to_summary().strip(), ""])
        return "\n".join(lines).strip() + "\n"

    @staticmethod
    def _public_placeholder_for_field(name: str, label: str) -> Optional[str]:
        """Return placeholder text for identity fields in public mode."""
        key = f"{name} {label}".lower()
        if "email" in key:
            return "(your email)"
        if "name" in key:
            return "(your name)"
        if "company" in key or "organization" in key or "organisation" in key:
            return "(your organization)"
        if "title" in key:
            return "(your title)"
        if "telephone" in key or "phone" in key or "tele" in key:
            return "(your phone)"
        if "country" in key:
            return "(your country)"
        return None

    @staticmethod
    def _identity_tokens_from(value: str) -> set[str]:
        tokens: set[str] = set()
        raw = (value or "").strip()
        if not raw:
            return tokens
        tokens.add(raw)
        if "<" in raw and ">" in raw:
            name = raw.split("<", 1)[0].strip().strip('"')
            email = raw.split("<", 1)[1].split(">", 1)[0].strip()
            if name:
                tokens.add(name)
            if email:
                tokens.add(email)
        return tokens

    def _public_identity_tokens(self) -> list[str]:
        tokens: set[str] = set()
        tokens.update(self._identity_tokens_from(self.reporter_email))
        tokens.update(self._identity_tokens_from(self.resend_from_email or ""))
        tokens.update(self._identity_tokens_from(self.smtp_config.get("from_email", "")))
        return [t for t in tokens if t]

    def _scrub_public_identity(self, data: dict) -> dict:
        """Replace operator identity with placeholders for public manual instructions."""
        if not isinstance(data, dict):
            return data
        fields = data.get("fields")
        if not isinstance(fields, list):
            return data

        tokens = self._public_identity_tokens()
        scrubbed_fields: list[dict] = []
        for field in fields:
            if not isinstance(field, dict):
                continue
            name = str(field.get("name") or "")
            label = str(field.get("label") or "")
            value = field.get("value")

            placeholder = self._public_placeholder_for_field(name, label)
            if placeholder is not None:
                field["value"] = placeholder
            elif isinstance(value, str) and tokens:
                updated = value
                for token in tokens:
                    if token and token in updated:
                        replacement = "(your email)" if "@" in token else "(your details)"
                        updated = updated.replace(token, replacement)
                field["value"] = updated

            scrubbed_fields.append(field)

        data["fields"] = scrubbed_fields
        return data

    async def retry_due_reports(self, *, limit: int = 20) -> list[ReportResult]:
        """
        Retry rate-limited reports that are due.

        This only retries reports in `rate_limited` status whose `next_attempt_at`
        is due (or missing). Pending/manual-required reports are not retried.
        """
        if self._preview_only_enabled():
            logger.info("REPORT_PREVIEW_ONLY enabled; skipping retry_due_reports")
            return []

        due = await self.database.get_due_retry_reports(limit=limit)
        if not due:
            return []

        attempted: list[ReportResult] = []

        for row in due:
            try:
                report_id = int(row["id"])
                domain_id = int(row["domain_id"])
                platform = str(row.get("platform") or "").strip().lower()
                domain = str(row.get("domain") or "").strip()

                reporter = self.reporters.get(platform)
                if not reporter or not reporter.is_configured():
                    result = ReportResult(
                        platform=platform or "unknown",
                        status=ReportStatus.FAILED,
                        report_id=str(report_id),
                        message="Reporter not configured",
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                # Respect enabled_platforms selection.
                if self.enabled_platforms is not None and platform not in self.enabled_platforms:
                    continue

                evidence = await self.build_evidence(domain_id=domain_id, domain=domain)
                if not evidence:
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.FAILED,
                        report_id=str(report_id),
                        message="Could not build evidence",
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                applicable, skip_reason = reporter.is_applicable(evidence)
                if not applicable:
                    msg = skip_reason or "Not applicable"
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.SKIPPED,
                        report_id=str(report_id),
                        message=msg,
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                limiter = get_rate_limiter(platform, reporter.rate_limit_per_minute)
                if not await limiter.acquire(timeout=5):
                    current_attempts = int(row.get("attempts") or 0)
                    next_attempts = current_attempts + 1
                    base_retry_after = max(30, int(limiter.wait_time() or 60))

                    if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                        platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                        url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                        msg = (
                            f"Rate limit persisted after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                            f"URL: {evidence.url}"
                        )
                        result = ReportResult(
                            platform=platform,
                            status=ReportStatus.MANUAL_REQUIRED,
                            report_id=str(report_id),
                            message=msg,
                            response_data={"domain_id": domain_id, "domain": domain},
                        )
                        attempted.append(result)
                        try:
                            content = self._build_manual_instructions_text(platform, evidence, result)
                            await self.evidence_store.save_report_instructions(domain, platform, content)
                        except Exception as e:
                            logger.warning(f"Failed to save manual report instructions for {domain} ({platform}): {e}")
                        await self.database.update_report(
                            report_id=report_id,
                            status=result.status.value,
                            response=result.message,
                        )
                        continue

                    retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                    msg = (
                        f"Rate limit exceeded; retry scheduled in {retry_after}s "
                        f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                    )
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.RATE_LIMITED,
                        report_id=str(report_id),
                        message=msg,
                        retry_after=retry_after,
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                        retry_after=retry_after,
                    )
                    continue

                result = await reporter.submit(evidence)
                if result.status == ReportStatus.RATE_LIMITED:
                    current_attempts = int(row.get("attempts") or 0)
                    next_attempts = current_attempts + 1
                    base_retry_after = int(result.retry_after or 60)

                    if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                        platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                        url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                        msg = (
                            f"Rate limited by platform after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                            f"URL: {evidence.url}"
                        )
                        result = ReportResult(
                            platform=platform,
                            status=ReportStatus.MANUAL_REQUIRED,
                            report_id=str(report_id),
                            message=msg,
                            response_data={"domain_id": domain_id, "domain": domain},
                        )
                    else:
                        retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                        result.retry_after = retry_after
                        base_msg = (result.message or "Rate limited").strip()
                        result.message = (
                            f"{base_msg}; retry scheduled in {retry_after}s "
                            f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                        )

                result.report_id = str(report_id)
                metadata = {"domain_id": domain_id, "domain": domain}
                if result.response_data is None:
                    result.response_data = metadata
                else:
                    try:
                        result.response_data = {**result.response_data, **metadata}
                    except Exception:
                        result.response_data = metadata
                attempted.append(result)

                if result.status == ReportStatus.MANUAL_REQUIRED:
                    try:
                        content = self._build_manual_instructions_text(platform, evidence, result)
                        await self.evidence_store.save_report_instructions(domain, platform, content)
                    except Exception as e:
                        logger.warning(f"Failed to save manual report instructions for {domain} ({platform}): {e}")

                # Serialize response_data to JSON for storage
                response_data_json = None
                if result.response_data:
                    try:
                        response_data_json = json.dumps(result.response_data)
                    except Exception:
                        pass

                await self.database.update_report(
                    report_id=report_id,
                    status=result.status.value,
                    response=result.message,
                    response_data=response_data_json,
                    retry_after=result.retry_after,
                )

                await self._mark_domain_reported_if_needed(domain_id, {platform: result})

            except Exception as e:
                logger.exception("Retry reporting failed")
                # Best-effort: keep report in rate_limited so it can be retried.
                try:
                    report_id = int(row.get("id") or 0)
                    if report_id:
                        await self.database.update_report(
                            report_id=report_id,
                            status=ReportStatus.RATE_LIMITED.value,
                            response=f"Retry worker error: {e}",
                            retry_after=300,
                        )
                except Exception:
                    pass

        return attempted

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
        if enabled_platforms in (None, [], set(), ()):
            self.enabled_platforms = None
        else:
            self.enabled_platforms = {p for p in enabled_platforms}

        self.reporters: dict[str, BaseReporter] = {}
        self._init_reporters()

    def _init_reporters(self):
        """Initialize available reporters based on configuration."""
        # Import here to avoid circular imports
        from .smtp_reporter import SMTPReporter
        from .cloudflare import CloudflareReporter
        from .google_form import GoogleFormReporter
        from .netcraft import NetcraftReporter
        from .hosting_provider import HostingProviderReporter
        from .registrar import RegistrarReporter
        from .apwg import APWGReporter
        from .microsoft import MicrosoftReporter
        from .resend_reporter import ResendReporter
        from .digitalocean import DigitalOceanReporter
        from .manual_platforms import (
            AWSReporter,
            AzureReporter,
            DiscordReporter,
            GCPReporter,
            GoDaddyReporter,
            NamecheapReporter,
            NetlifyReporter,
            PorkbunReporter,
            Quad9Reporter,
            TelegramReporter,
            VercelReporter,
            OpenDNSReporter,
            GoogleDomainsReporter,
            TucowsReporter,
            NjallaReporter,
            RenderReporter,
            FlyReporter,
            RailwayReporter,
        )

        # Google Safe Browsing form (always available, free)
        self.reporters["google"] = GoogleFormReporter()
        logger.info("Initialized Google Safe Browsing reporter")

        # Cloudflare abuse form (always available)
        reporter_identity = self.resend_from_email or self.reporter_email or ""
        self.reporters["cloudflare"] = CloudflareReporter(reporter_email=reporter_identity)
        logger.info("Initialized Cloudflare reporter")

        # Netcraft (always available, no account needed)
        self.reporters["netcraft"] = NetcraftReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized Netcraft reporter")

        # APWG manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["apwg"] = APWGReporter()
        logger.info("Initialized APWG manual reporter")

        # Microsoft manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["microsoft"] = MicrosoftReporter()
        logger.info("Initialized Microsoft manual reporter")

        # Hosting provider manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["hosting_provider"] = HostingProviderReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized hosting provider manual reporter")

        # Registrar manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["registrar"] = RegistrarReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized registrar manual reporter")

        # Resend email reporter (configured when API key is present)
        self.reporters["resend"] = ResendReporter(
            api_key=self.resend_api_key or "",
            from_email=self.resend_from_email or self.reporter_email or "SeedBuster <onboarding@resend.dev>",
        )
        if self.resend_api_key:
            logger.info(f"Initialized Resend email reporter (from: {self.resend_from_email or self.reporter_email})")
        else:
            logger.info("Resend email reporter not configured (missing RESEND_API_KEY)")

        # DigitalOcean form reporter (configured when reporter email is present)
        reporter_email = self.resend_from_email or self.reporter_email or ""
        self.reporters["digitalocean"] = DigitalOceanReporter(
            reporter_email=reporter_email.split("<")[-1].rstrip(">") if "<" in reporter_email else reporter_email,
            reporter_name="Kaspa Security",
        )
        if reporter_email:
            logger.info("Initialized DigitalOcean form reporter (Playwright)")
        else:
            logger.info("DigitalOcean form reporter not configured (missing reporter email)")

        # Manual-only provider/reporting helpers
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
        self.reporters["quad9"] = Quad9Reporter()
        self.reporters["opendns"] = OpenDNSReporter()
        self.reporters["google_domains"] = GoogleDomainsReporter()
        self.reporters["tucows"] = TucowsReporter()
        self.reporters["njalla"] = NjallaReporter()
        self.reporters["render"] = RenderReporter()
        self.reporters["fly_io"] = FlyReporter()
        self.reporters["railway"] = RailwayReporter()
        logger.info("Initialized manual-only reporters for providers/registrars/messaging")

        # SMTP reporter (configured when SMTP host and from_email are present)
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

        # Warn if enabled_platforms includes unknown/uninitialized reporters.
        if self.enabled_platforms is not None:
            unknown = sorted(p for p in self.enabled_platforms if p not in self.reporters)
            if unknown:
                logger.warning(f"Unknown report platforms in REPORT_PLATFORMS: {', '.join(unknown)}")

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
        """Get metadata about each available platform.

        Returns dict mapping platform name to info dict:
        {
            "cloudflare": {"manual_only": False, "url": "https://...", "name": "Cloudflare"},
            "microsoft": {"manual_only": True, "url": "https://..."},
            ...
        }
        """
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

    @staticmethod
    def _normalize_hint(value: Optional[str]) -> str:
        """Normalize provider/registrar strings for comparison."""
        return (value or "").strip().lower()

    def _canonical_provider(self, value: str) -> str:
        """Map provider aliases to platform keys used by reporters."""
        key = self._normalize_hint(value)
        if not key:
            return ""
        aliases = {
            "amazon": "aws",
            "amazon web services": "aws",
            "aws": "aws",
            "google cloud": "gcp",
            "google cloud platform": "gcp",
            "google": "gcp",
            "gcp": "gcp",
            "microsoft": "azure",
            "azure": "azure",
            "msft": "azure",
            "fly.io": "fly_io",
            "flyio": "fly_io",
            "fly": "fly_io",
            "fastly": "fastly",
            "akamai": "akamai",
            "sucuri": "sucuri",
            "wix": "wix",
            "squarespace": "squarespace",
            "shopify": "shopify",
            "vercel": "vercel",
            "netlify": "netlify",
            "railway": "railway",
            "render": "render",
        }
        return aliases.get(key, key)

    def _provider_host_candidates(self, evidence: ReportEvidence) -> list[str]:
        """Collect hostnames worth probing for provider signals (preserve priority)."""
        hosts: list[str] = []
        seen: set[str] = set()

        def _add_host(raw: Optional[str]) -> None:
            if not raw:
                return
            parsed = urlparse(raw if "://" in raw else f"https://{raw}")
            host = (parsed.hostname or "").strip().lower()
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)

        _add_host(evidence.url)
        _add_host((evidence.analysis_json or {}).get("final_url"))

        for endpoint in evidence.suspicious_endpoints or []:
            _add_host(endpoint)
        for backend in evidence.backend_domains or []:
            _add_host(backend)

        return hosts

    def _detect_vercel_from_hosts(self, hosts: list[str]) -> set[str]:
        """Lightweight Vercel detection using DNS/IP ranges and headers."""
        hints: set[str] = set()
        if not hosts:
            return hints

        # Known Vercel edge ranges (documented for alias.vercel-dns.com)
        vercel_ip_prefixes = ("76.76.21.", "76.76.22.", "76.223.126.", "76.223.127.")
        header_keys = ("server", "x-vercel-id", "x-vercel-cache", "x-powered-by")

        for host in hosts[:5]:  # cap to avoid long probes
            if "vercel" in host:
                hints.add("vercel")
                continue

            try:
                infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                ips = {info[4][0] for info in infos if info and info[4]}
            except Exception:
                ips = set()

            if any(ip.startswith(prefix) for prefix in vercel_ip_prefixes for ip in ips):
                hints.add("vercel")
                continue

            # As a fallback, probe headers for explicit Vercel markers
            try:
                resp = httpx.get(
                    f"https://{host}",
                    timeout=3.0,
                    follow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "SeedBuster/abuse-helper"},
                )
                header_values = " ".join(resp.headers.get(k, "") for k in header_keys).lower()
                if "vercel" in header_values:
                    hints.add("vercel")
            except Exception:
                continue

        return hints

    def _collect_hosting_hints(self, evidence: ReportEvidence) -> set[str]:
        """Collect hosting/provider hints from analysis outputs and endpoints."""
        hints: set[str] = set()

        candidates = [
            evidence.hosting_provider,
            (evidence.analysis_json or {}).get("hosting_provider"),
        ]
        try:
            infra = (evidence.analysis_json or {}).get("infrastructure") or {}
            candidates.append(infra.get("hosting_provider"))
            ns = infra.get("nameservers") or []
            ns_combined = " ".join(ns).lower() if isinstance(ns, list) else ""
            if ns_combined:
                if "cloudflare.com" in ns_combined:
                    candidates.append("cloudflare")
                if "awsdns-" in ns_combined:
                    candidates.append("aws")
                if "azure-dns" in ns_combined:
                    candidates.append("azure")
                if "google" in ns_combined or "googledomains" in ns_combined:
                    candidates.append("gcp")
                if "vercel-dns.com" in ns_combined:
                    candidates.append("vercel")
                if "netlifydns.net" in ns_combined:
                    candidates.append("netlify")
                if "shopifydns" in ns_combined:
                    candidates.append("shopify")
                if "render.com" in ns_combined:
                    candidates.append("render")
                if "njalla" in ns_combined:
                    candidates.append("njalla")
        except Exception:
            pass

        for candidate in candidates:
            canon = self._canonical_provider(candidate or "")
            if canon:
                hints.add(canon)

        haystack_parts: list[str] = []
        for item in [evidence.url] + (evidence.backend_domains or []) + (evidence.suspicious_endpoints or []):
            if isinstance(item, str):
                haystack_parts.append(item.lower())

        haystack = " ".join(haystack_parts)
        patterns: dict[str, list[str]] = {
            "digitalocean": ["ondigitalocean.app", "digitaloceanspaces.com", "digitalocean"],
            "vercel": ["vercel.app", ".vercel.com", "vercel"],
            "netlify": ["netlify.app", ".netlify.com", "netlify"],
            "render": ["onrender.com", ".render.com", "render.com"],
            "fly_io": [".fly.dev", "fly.dev"],
            "railway": ["railway.app", ".railway.app"],
            "aws": ["amazonaws.com", "cloudfront.net", ".awsstatic", "aws"],
            "gcp": ["appspot.com", "cloudfunctions.net", "googleusercontent.com", "firebaseapp.com", ".web.app", "gcp"],
            "azure": ["azurewebsites.net", "azureedge.net", "cloudapp.azure.com", "azure"],
            "cloudflare": ["workers.dev", "pages.dev", "cloudflare"],
            "fastly": ["fastly.net", ".fastly"],
            "akamai": ["akamai.net", ".akamai", "akadns.net"],
            "sucuri": ["sucuri.net", "sucuri"],
            "wix": ["wixsite.com", ".wixdns.net", "wix"],
            "squarespace": ["squarespace.com", "squarespace-cdn.com"],
            "shopify": ["myshopify.com", "shopify"],
            "digitalocean": ["digitaloceanspaces.com", "ondigitalocean.app"],
            "railway": ["railway.app"],
            "render": ["onrender.com", "render.com"],
        }
        for provider, needles in patterns.items():
            if any(needle in haystack for needle in needles):
                hints.add(provider)

        return {h for h in hints if h}

    def _collect_service_hints(self, evidence: ReportEvidence) -> set[str]:
        """Detect platform-specific service usage (e.g., Telegram bots, Discord webhooks)."""
        hints: set[str] = set()
        haystack_parts: list[str] = []
        for item in [evidence.url] + (evidence.backend_domains or []) + (evidence.suspicious_endpoints or []):
            if isinstance(item, str):
                haystack_parts.append(item.lower())
        haystack = " ".join(haystack_parts)

        if any(token in haystack for token in ["t.me/", "telegram.me", "telegram.org", "telegram"]):
            hints.add("telegram")
        if any(token in haystack for token in ["discord.gg", "discord.com", "discordapp.com", "discordapp.net", "discordapp.io"]):
            hints.add("discord")
        return hints

    async def _collect_hosting_hints_async(self, evidence: ReportEvidence) -> set[str]:
        """
        Async wrapper to enrich hosting hints with lightweight live probes.

        This keeps the base heuristic fast while adding selective checks
        (e.g., Vercel headers/CNAME IPs) without blocking the event loop.
        """
        hints = self._collect_hosting_hints(evidence)
        if "vercel" in hints:
            return hints

        candidates = self._provider_host_candidates(evidence)
        if not candidates:
            return hints

        try:
            extra = await asyncio.to_thread(self._detect_vercel_from_hosts, candidates)
            hints.update(extra)
        except Exception as e:
            logger.debug("Provider host probe failed for %s: %s", evidence.domain, e)

        return hints

    async def _detect_registrar_hint(self, evidence: ReportEvidence) -> tuple[Optional[str], Optional[str]]:
        """Best-effort registrar lookup using cached analysis or RDAP."""
        registrar = None
        abuse_email = None
        try:
            registrar = (evidence.analysis_json or {}).get("registrar")
            infra = (evidence.analysis_json or {}).get("infrastructure") or {}
            registrar = registrar or infra.get("registrar")
            abuse_email = infra.get("registrar_abuse_email")
        except Exception:
            pass

        if not registrar and not abuse_email:
            try:
                from .rdap import lookup_registrar_via_rdap

                lookup = await lookup_registrar_via_rdap(evidence.domain)
                registrar = lookup.registrar_name
                abuse_email = lookup.abuse_email
            except Exception as e:
                logger.debug(f"RDAP lookup failed for {evidence.domain}: {e}")

        return self._normalize_hint(registrar), abuse_email

    @staticmethod
    def _registrar_platforms_for(registrar_name: Optional[str]) -> set[str]:
        """Map registrar names to specific platform reporters."""
        name = (registrar_name or "").lower()
        if not name:
            return set()
        mapping = {
            "godaddy": "godaddy",
            "namecheap": "namecheap",
            "porkbun": "porkbun",
            "tucows": "tucows",
            "hover": "tucows",
            "google": "google_domains",
            "njalla": "njalla",
        }
        return {platform for needle, platform in mapping.items() if needle in name}

    def _platform_applicable(
        self,
        platform: str,
        reporter: BaseReporter,
        evidence: ReportEvidence,
        hosting_hints: set[str],
        registrar_name: Optional[str],
        registrar_matches: set[str],
        service_hints: set[str],
        registrar_abuse_email: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Determine whether a reporter is relevant for the given evidence."""
        is_applicable, reason = reporter.is_applicable(evidence)
        if not is_applicable:
            return False, reason

        hosting_specific = {
            "digitalocean",
            "aws",
            "gcp",
            "azure",
            "vercel",
            "netlify",
            "render",
            "fly_io",
            "railway",
            "cloudflare",
            "fastly",
            "akamai",
            "sucuri",
            "wix",
            "squarespace",
            "shopify",
            "njalla",
            "hosting_provider",
        }
        registrar_specific = {
            "registrar",
            "godaddy",
            "namecheap",
            "porkbun",
            "google_domains",
            "tucows",
        }
        service_specific = {"telegram", "discord"}

        if platform in hosting_specific:
            if platform == "hosting_provider":
                return (is_applicable, reason or "No hosting provider identified")
            if platform == "digitalocean":
                if is_applicable or platform in hosting_hints:
                    return True, ""
                return False, "No DigitalOcean infrastructure detected"
            return (platform in hosting_hints, f"Not hosted on {platform}")

        if platform in registrar_specific:
            has_registrar_signal = bool(registrar_name or registrar_abuse_email)
            if platform == "registrar":
                return (has_registrar_signal, "Registrar not identified")
            return (platform in registrar_matches, f"Registrar not matched: {registrar_name or 'unknown'}")

        if platform in service_specific:
            return (platform in service_hints, f"No {platform} endpoints detected")

        return True, ""

    async def get_manual_report_options(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        *,
        public: bool = False,
    ) -> dict[str, dict]:
        """
        Build manual submission instructions for the given domain/platforms.

        Does not touch the database or submit reports; returns a mapping of
        platform -> ManualSubmissionData dict.
        """
        if platforms is None:
            platforms = self.get_available_platforms()
        if not platforms:
            return {}

        evidence = await self.build_evidence(domain_id, domain)
        if not evidence:
            return {}

        hosting_hints: set[str] = set()
        service_hints: set[str] = set()
        registrar_name: Optional[str] = None
        registrar_abuse_email: Optional[str] = None
        registrar_matches: set[str] = set()

        hosting_specific = {
            "digitalocean",
            "aws",
            "gcp",
            "azure",
            "vercel",
            "netlify",
            "render",
            "fly_io",
            "railway",
            "cloudflare",
            "hosting_provider",
        }
        registrar_specific = {
            "registrar",
            "godaddy",
            "namecheap",
            "porkbun",
            "google_domains",
            "tucows",
        }
        service_specific = {"telegram", "discord"}

        if any(p in hosting_specific for p in platforms):
            hosting_hints = await self._collect_hosting_hints_async(evidence)
        if any(p in registrar_specific for p in platforms):
            registrar_name, registrar_abuse_email = await self._detect_registrar_hint(evidence)
            registrar_matches = self._registrar_platforms_for(registrar_name)
        if any(p in service_specific for p in platforms):
            service_hints = self._collect_service_hints(evidence)

        results: dict[str, dict] = {}
        for platform in platforms:
            reporter = self.reporters.get(platform)
            if not reporter or not reporter.is_configured():
                continue
            if getattr(reporter, "public_exclude", False):
                logger.debug(f"Skipping {platform} for manual instructions (public_exclude)")
                continue
            applicable, reason = self._platform_applicable(
                platform=platform,
                reporter=reporter,
                evidence=evidence,
                hosting_hints=hosting_hints,
                registrar_name=registrar_name,
                registrar_matches=registrar_matches,
                service_hints=service_hints,
                registrar_abuse_email=registrar_abuse_email,
            )
            if not applicable:
                logger.debug(f"Skipping {platform} for {domain}: {reason}")
                continue
            try:
                manual = None
                if (
                    platform == "registrar"
                    and hasattr(reporter, "generate_manual_submission_with_hints")
                ):
                    manual = reporter.generate_manual_submission_with_hints(
                        evidence,
                        registrar_name=registrar_name,
                        registrar_abuse_email=registrar_abuse_email,
                    )
                else:
                    manual = reporter.generate_manual_submission(evidence)
                data = manual.to_dict() if hasattr(manual, "to_dict") else dict(manual)

                # Add quick context so public users know why a platform is shown.
                if isinstance(data, dict):
                    notes = data.get("notes")
                    if not isinstance(notes, list):
                        notes = []
                        data["notes"] = notes
                    if platform in hosting_hints:
                        context = f"Hosting detected: {platform.replace('_', ' ').title()}"
                        if context not in notes:
                            notes.insert(0, context)
                    if platform in registrar_specific or platform == "registrar":
                        if registrar_name:
                            context = f"Registrar detected: {registrar_name.title()}"
                            if context not in notes:
                                notes.insert(0, context)
                        elif registrar_abuse_email:
                            context = f"Registrar abuse contact found: {registrar_abuse_email}"
                            if context not in notes:
                                notes.insert(0, context)
                    if public:
                        data = self._scrub_public_identity(data)
                        notes = data.get("notes")
                        if not isinstance(notes, list):
                            notes = []
                            data["notes"] = notes
                        if "Use your own contact details" not in notes:
                            notes.append("Use your own contact details (do not use SeedBuster details).")
                    form_url = str(data.get("form_url") or "").strip() if isinstance(data, dict) else ""
                    if not form_url:
                        missing = "Destination missing; research needed."
                        if isinstance(notes, list) and missing not in notes:
                            notes.insert(0, missing)

                results[platform] = data
            except Exception as e:
                results[platform] = {"error": str(e)}
        return results

    async def ensure_pending_reports(self, domain_id: int, platforms: Optional[list[str]] = None) -> None:
        """
        Ensure there is a pending (awaiting approval) report row per platform.

        This is used when reporting requires manual approval so `/report <id> status`
        can show per-platform pending status before any submissions are attempted.
        """
        if platforms is None:
            platforms = self.get_available_platforms()
        if not platforms:
            return

        existing = await self.database.get_reports_for_domain(domain_id)
        existing_platforms = {str(r.get("platform") or "").strip().lower() for r in existing}

        for platform in platforms:
            key = (platform or "").strip().lower()
            if not key or key in existing_platforms:
                continue
            await self.database.add_report(
                domain_id=domain_id,
                platform=key,
                status=ReportStatus.PENDING.value,
            )

    async def build_evidence(
        self,
        domain_id: int,
        domain: str,
    ) -> Optional[ReportEvidence]:
        """
        Build evidence package from stored analysis data.

        Args:
            domain_id: Database ID of the domain
            domain: Domain name

        Returns:
            ReportEvidence or None if domain not found
        """
        # Get domain data from database
        domain_data = await self.database.get_domain_by_id(domain_id)
        if not domain_data:
            logger.warning(f"Domain not found: {domain_id}")
            return None

        # Get evidence paths
        evidence_dir = self.evidence_store.get_evidence_path(domain)

        # Load analysis JSON if available
        analysis_json = {}
        analysis_path = self.evidence_store.get_analysis_path(domain)
        if analysis_path and analysis_path.exists():
            analysis_json = self.evidence_store.load_analysis(domain) or {}

        # Extract detection reasons from analysis
        detection_reasons = analysis_json.get("reasons") or []
        if not detection_reasons:
            verdict_reasons = domain_data.get("verdict_reasons") or ""
            detection_reasons = [r.strip() for r in verdict_reasons.splitlines() if r.strip()]

        # Build evidence
        target = (domain or "").strip()
        hostname = self._extract_hostname(target) or target.lower()

        # Prefer the final URL from analysis if available (may include redirects to kit path).
        final_url = (analysis_json.get("final_url") or "").strip()
        report_url = final_url or self._ensure_url(target)

        suspicious_endpoints = analysis_json.get("suspicious_endpoints", []) or []

        backend_domains = analysis_json.get("backend_domains")
        if not backend_domains:
            backend_domains = self._extract_hostnames_from_endpoints(suspicious_endpoints)

        api_keys_found = analysis_json.get("api_keys_found")
        if not api_keys_found:
            api_keys_found = self._extract_api_key_indicators(detection_reasons)

        hosting_provider = analysis_json.get("hosting_provider")
        if not hosting_provider:
            hosting_provider = (analysis_json.get("infrastructure") or {}).get("hosting_provider")

        scam_type = (analysis_json.get("scam_type") or domain_data.get("scam_type") or "").strip() or None
        scammer_wallets = analysis_json.get("scammer_wallets") or []
        if isinstance(scammer_wallets, str):
            scammer_wallets = [scammer_wallets]
        if not isinstance(scammer_wallets, list):
            scammer_wallets = []

        # Choose the best available screenshot for reports (seed form > suspicious exploration > early > main).
        screenshot_path = None
        try:
            shots = self.evidence_store.get_all_screenshot_paths(domain)
            screenshot_path = shots[0] if shots else None
        except Exception:
            screenshot_path = None
        if not screenshot_path:
            screenshot_path = self.evidence_store.get_screenshot_path(domain)

        evidence = ReportEvidence(
            domain=hostname,
            url=report_url,
            detected_at=datetime.fromisoformat(
                domain_data.get("first_seen", datetime.now().isoformat())
            ),
            confidence_score=domain_data.get("analysis_score", 0),
            domain_id=domain_id,
            detection_reasons=detection_reasons,
            suspicious_endpoints=suspicious_endpoints,
            screenshot_path=screenshot_path,
            html_path=evidence_dir / "page.html" if evidence_dir else None,
            analysis_path=analysis_path,
            analysis_json=analysis_json,
            backend_domains=backend_domains,
            api_keys_found=api_keys_found,
            hosting_provider=hosting_provider,
            scam_type=scam_type,
            scammer_wallets=[str(w).strip() for w in scammer_wallets if str(w).strip()],
        )

        return evidence

    async def report_domain(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        *,
        force: bool = False,
        dry_run: bool = False,
        dry_run_email: Optional[str] = None,
    ) -> dict[str, ReportResult]:
        """
        Submit reports to multiple platforms.

        Args:
            domain_id: Database ID of the domain
            domain: Domain name
            platforms: List of platforms to report to (None = all configured)
            force: When True, bypass rate-limited schedules and attempt submission immediately
            dry_run: When True, send reports to dry_run_email instead of real platforms
            dry_run_email: Email address to receive dry-run reports

        Returns:
            Dict mapping platform name to ReportResult
        """
        if self._preview_only_enabled():
            dry_run = True
            if dry_run_email is None:
                dry_run_email = os.environ.get("DRY_RUN_EMAIL", "")

        # Handle dry-run mode
        if dry_run:
            return await self._dry_run_domain_report(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms,
                dry_run_email=dry_run_email or os.environ.get("DRY_RUN_EMAIL", ""),
            )
        # Build evidence package
        evidence = await self.build_evidence(domain_id, domain)
        if not evidence:
            return {
                "error": ReportResult(
                    platform="manager",
                    status=ReportStatus.FAILED,
                    message=f"Could not build evidence for domain {domain}",
                )
            }

        # Determine platforms to report to
        if platforms is None:
            platforms = self.get_available_platforms()
        else:
            # Filter to only available platforms
            platforms = [p for p in platforms if p in self.reporters]
            if self.enabled_platforms is not None:
                platforms = [p for p in platforms if p in self.enabled_platforms]

        if not platforms:
            return {
                "error": ReportResult(
                    platform="manager",
                    status=ReportStatus.FAILED,
                    message="No platforms available for reporting",
                )
            }

        # Submit to each platform
        results: dict[str, ReportResult] = {}

        for platform in platforms:
            reporter = self.reporters[platform]

            # Skip if not configured (should not happen if get_available_platforms is used).
            if not reporter.is_configured():
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message="Reporter not configured",
                )
                continue

            latest = await self.database.get_latest_report(domain_id=domain_id, platform=platform)
            latest_status = (latest.get("status") if latest else "") or ""
            latest_status_lower = str(latest_status).strip().lower()
            next_attempt_at = (latest.get("next_attempt_at") if latest else None)

            # Dedupe: don't re-submit if we already have a successful record.
            if latest_status_lower in {"submitted", "confirmed", "duplicate"}:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.DUPLICATE,
                    report_id=str(latest.get("id")) if latest else None,
                    message=f"Already reported ({latest_status_lower})",
                )
                continue

            # Manual-required reports shouldn't be re-attempted automatically; keep the last instructions.
            if latest_status_lower == ReportStatus.MANUAL_REQUIRED.value:
                # Parse response_data from database to include structured fields
                response_data = None
                if latest:
                    raw_response_data = latest.get("response_data")
                    if raw_response_data:
                        try:
                            response_data = json.loads(raw_response_data) if isinstance(raw_response_data, str) else raw_response_data
                        except (json.JSONDecodeError, TypeError):
                            pass
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.MANUAL_REQUIRED,
                    report_id=str(latest.get("id")) if latest else None,
                    message=(latest.get("response") if latest else None) or "Manual submission required",
                    response_data=response_data,
                )
                continue

            # Respect retry schedule for rate-limited reports unless explicitly forced.
            if not force and latest_status_lower == "rate_limited" and not self._is_timestamp_due(next_attempt_at):
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.RATE_LIMITED,
                    report_id=str(latest.get("id")) if latest else None,
                    message=f"Retry scheduled at {next_attempt_at}",
                )
                continue

            applicable, skip_reason = reporter.is_applicable(evidence)
            if not applicable:
                msg = skip_reason or "Not applicable"
                report_row_id = int(latest["id"]) if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"} else 0
                if not report_row_id:
                    report_row_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status=ReportStatus.SKIPPED.value,
                    )
                await self.database.update_report(
                    report_id=report_row_id,
                    status=ReportStatus.SKIPPED.value,
                    response=msg,
                )
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    report_id=str(report_row_id),
                    message=msg,
                )
                continue

            # Check rate limit
            limiter = get_rate_limiter(
                platform,
                reporter.rate_limit_per_minute,
            )

            if not await limiter.acquire(timeout=30):
                base_retry_after = max(30, int(limiter.wait_time() or 60))

                # Create or reuse a report record so the retry worker can pick it up.
                report_row_id = int(latest["id"]) if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"} else 0
                current_attempts = int(latest.get("attempts") or 0) if report_row_id and latest and int(latest["id"]) == report_row_id else 0
                if not report_row_id:
                    report_row_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status=ReportStatus.RATE_LIMITED.value,
                    )
                    current_attempts = 0

                next_attempts = current_attempts + 1
                if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                    platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                    url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                    msg = (
                        f"Rate limit persisted after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                        f"URL: {evidence.url}"
                    )
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.MANUAL_REQUIRED,
                        report_id=str(report_row_id),
                        message=msg,
                    )
                    results[platform] = result
                    try:
                        content = self._build_manual_instructions_text(platform, evidence, result)
                        await self.evidence_store.save_report_instructions(domain, platform, content)
                    except Exception as e:
                        logger.warning(f"Failed to save manual report instructions for {domain} ({platform}): {e}")
                    await self.database.update_report(
                        report_id=report_row_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                msg = (
                    f"Rate limit exceeded; retry scheduled in {retry_after}s "
                    f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                )

                await self.database.update_report(
                    report_id=report_row_id,
                    status=ReportStatus.RATE_LIMITED.value,
                    response=msg,
                    retry_after=retry_after,
                )

                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.RATE_LIMITED,
                    report_id=str(report_row_id),
                    message=msg,
                    retry_after=retry_after,
                )
                continue

            try:
                # Create or reuse a report row for this platform.
                report_id = int(latest["id"]) if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"} else 0
                if not report_id:
                    report_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status="pending",
                    )
                    current_attempts = 0
                else:
                    current_attempts = int(latest.get("attempts") or 0) if latest and int(latest["id"]) == report_id else 0

                # Submit report
                result = await reporter.submit(evidence)

                if result.status == ReportStatus.RATE_LIMITED:
                    next_attempts = current_attempts + 1
                    base_retry_after = int(result.retry_after or 60)
                    if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                        platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                        url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                        msg = (
                            f"Rate limited by platform after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                            f"URL: {evidence.url}"
                        )
                        result = ReportResult(
                            platform=platform,
                            status=ReportStatus.MANUAL_REQUIRED,
                            message=msg,
                        )
                    else:
                        retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                        result.retry_after = retry_after
                        base_msg = (result.message or "Rate limited").strip()
                        result.message = (
                            f"{base_msg}; retry scheduled in {retry_after}s "
                            f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                        )

                result.report_id = str(report_id)
                results[platform] = result

                if result.status == ReportStatus.MANUAL_REQUIRED:
                    try:
                        content = self._build_manual_instructions_text(platform, evidence, result)
                        await self.evidence_store.save_report_instructions(domain, platform, content)
                    except Exception as e:
                        logger.warning(f"Failed to save manual report instructions for {domain} ({platform}): {e}")

                # Serialize response_data to JSON for storage
                response_data_json = None
                if result.response_data:
                    try:
                        response_data_json = json.dumps(result.response_data)
                    except Exception:
                        pass

                # Update database
                await self.database.update_report(
                    report_id=report_id,
                    status=result.status.value,
                    response=result.message,
                    response_data=response_data_json,
                    retry_after=result.retry_after,
                )

                logger.info(
                    f"Report submitted to {platform}: {result.status.value}"
                )

            except ReporterError as e:
                logger.error(f"Reporter error for {platform}: {e}")
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=str(e),
                )

            except Exception as e:
                logger.exception(f"Unexpected error reporting to {platform}")
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=f"Unexpected error: {e}",
                )

        await self._mark_domain_reported_if_needed(domain_id, results)
        return results

    async def _mark_domain_reported_if_needed(
        self, domain_id: int, results: dict[str, ReportResult]
    ) -> None:
        """Update domain status to REPORTED when at least one platform succeeded."""
        from ..storage.database import DomainStatus

        success_statuses = {ReportStatus.SUBMITTED, ReportStatus.CONFIRMED, ReportStatus.DUPLICATE}
        if any(r.status in success_statuses for r in results.values()):
            await self.database.update_domain_status(domain_id, DomainStatus.REPORTED)

    async def get_report_status(self, domain_id: int) -> list[dict]:
        """
        Get all report statuses for a domain.

        Returns list of report records from database.
        """
        return await self.database.get_reports_for_domain(domain_id)

    async def get_pending_approvals(self) -> list[dict]:
        """Get domains awaiting report approval."""
        return await self.database.get_pending_reports()

    async def approve_report(self, domain_id: int, domain: str) -> dict[str, ReportResult]:
        """
        Approve and submit reports for a domain.

        Called when user clicks "Approve" in Telegram.
        """
        return await self.report_domain(domain_id, domain)

    async def reject_report(self, domain_id: int, reason: str = "false_positive"):
        """
        Reject a report (mark as false positive).

        Updates domain status in database.
        """
        await self.database.update_domain_status(
            domain_id,
            status="false_positive",
            verdict="benign",
        )
        logger.info(f"Report rejected for domain {domain_id}: {reason}")

    async def mark_manual_done(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        *,
        note: str = "Manual submission marked complete",
    ) -> dict[str, ReportResult]:
        """
        Mark MANUAL_REQUIRED reports as completed (SUBMITTED).

        This is used after an operator submits reports manually so they don't linger
        in the manual queue indefinitely.
        """
        # Determine platforms present for this domain if none were provided.
        target_platforms: list[str] = []
        if platforms is None:
            rows = await self.database.get_reports_for_domain(domain_id)
            seen: set[str] = set()
            for row in rows:
                p = str(row.get("platform") or "").strip().lower()
                if not p or p in seen:
                    continue
                seen.add(p)
                target_platforms.append(p)
        else:
            seen: set[str] = set()
            for p in platforms:
                value = str(p or "").strip().lower()
                if not value or value in seen:
                    continue
                seen.add(value)
                target_platforms.append(value)

        if not target_platforms:
            return {
                "error": ReportResult(
                    platform="manager",
                    status=ReportStatus.FAILED,
                    message="No platforms found for this domain",
                )
            }

        results: dict[str, ReportResult] = {}
        marker = f"{note} at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC (SeedBuster operator)"

        for platform in target_platforms:
            latest = await self.database.get_latest_report(domain_id=domain_id, platform=platform)
            if not latest:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    message="No report record found",
                )
                continue

            report_id = int(latest["id"])
            latest_status_lower = str(latest.get("status") or "").strip().lower()
            if latest_status_lower != ReportStatus.MANUAL_REQUIRED.value:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    report_id=str(report_id),
                    message=f"No manual action needed (status: {latest_status_lower or 'unknown'})",
                )
                continue

            prev_response = str(latest.get("response") or "")
            response = prev_response
            if marker not in prev_response:
                response = (prev_response.rstrip() + "\n\n" + marker).strip() if prev_response.strip() else marker

            await self.database.update_report(
                report_id=report_id,
                status=ReportStatus.SUBMITTED.value,
                response=response,
            )
            results[platform] = ReportResult(
                platform=platform,
                status=ReportStatus.SUBMITTED,
                report_id=str(report_id),
                message="Marked as manually submitted",
            )

        await self._mark_domain_reported_if_needed(domain_id, results)
        return results

    def format_results_summary(self, results: dict[str, ReportResult]) -> str:
        """Format report results for display."""
        lines = ["Report Results:"]

        for platform, result in results.items():
            status_emoji = {
                ReportStatus.SUBMITTED: "✅",
                ReportStatus.CONFIRMED: "✅",
                ReportStatus.PENDING: "⏳",
                ReportStatus.MANUAL_REQUIRED: "📝",
                ReportStatus.FAILED: "❌",
                ReportStatus.SKIPPED: "➖",
                ReportStatus.RATE_LIMITED: "⏱️",
                ReportStatus.DUPLICATE: "🔄",
                ReportStatus.REJECTED: "🚫",
            }.get(result.status, "❓")

            line = f"  {status_emoji} {platform}: {result.status.value}"
            if result.message:
                msg = result.message.strip()
                # Prefer to show manual URLs/instructions when automation is blocked.
                max_len = 180 if (result.status in {ReportStatus.PENDING, ReportStatus.MANUAL_REQUIRED} or "http" in msg) else 80
                if len(msg) > max_len:
                    msg = msg[: max_len - 1] + "…"
                line += f" - {msg}"
            lines.append(line)

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Dry-Run Mode - Preview reports before sending
    # -------------------------------------------------------------------------

    async def _dry_run_domain_report(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        dry_run_email: str = "",
    ) -> dict[str, ReportResult]:
        """
        Send dry-run preview of reports to specified email instead of real platforms.

        Each platform's report is sent as a separate email so you can see exactly
        what each abuse team would receive.
        """
        if not dry_run_email and not self._dry_run_save_only_enabled():
            return {
                "error": ReportResult(
                    platform="dry_run",
                    status=ReportStatus.FAILED,
                    message="No dry-run email configured. Set DRY_RUN_EMAIL or pass dry_run_email parameter.",
                )
            }

        # Build evidence
        evidence = await self.build_evidence(domain_id, domain)
        if not evidence:
            return {
                "error": ReportResult(
                    platform="dry_run",
                    status=ReportStatus.FAILED,
                    message=f"Could not build evidence for domain {domain}",
                )
            }

        # Determine platforms
        if platforms is None:
            platforms = self.get_available_platforms()
        else:
            platforms = [p for p in platforms if p in self.reporters]
            if self.enabled_platforms is not None:
                platforms = [p for p in platforms if p in self.enabled_platforms]

        results: dict[str, ReportResult] = {}

        for platform in platforms:
            reporter = self.reporters.get(platform)
            if not reporter or not reporter.is_configured():
                continue

            applicable, skip_reason = reporter.is_applicable(evidence)
            if not applicable:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    message=skip_reason or "Not applicable",
                )
                continue

            # For manual-only platforms, call submit() to get structured response_data
            # for the dashboard, then store in database
            if reporter.manual_only:
                try:
                    result = await reporter.submit(evidence)
                    # Create report in database so dashboard can access structured fields
                    report_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status=result.status.value,
                    )
                    response_data_json = None
                    if result.response_data:
                        try:
                            response_data_json = json.dumps(result.response_data)
                        except Exception:
                            pass
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                        response_data=response_data_json,
                    )
                    result.report_id = str(report_id)
                    results[platform] = result

                    # Also send dry-run preview email for manual platforms
                    try:
                        report_content = self._build_platform_report_preview(platform, evidence)
                        await self._send_dry_run_email(
                            to_email=dry_run_email,
                            platform=platform,
                            domain=domain,
                            report_content=report_content,
                            evidence=evidence,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to send dry-run email for manual platform {platform}: {e}")

                except Exception as e:
                    logger.error(f"Failed to get manual fields for {platform}: {e}")
                    results[platform] = ReportResult(
                        platform=platform,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message=f"Manual submission required: {reporter.platform_url}",
                    )
                continue

            # Build the report content that would be sent
            try:
                report_content = self._build_platform_report_preview(platform, evidence)
                saved = await self._send_dry_run_email(
                    to_email=dry_run_email,
                    platform=platform,
                    domain=domain,
                    report_content=report_content,
                    evidence=evidence,
                )
                if self._dry_run_save_only_enabled():
                    msg = f"Dry-run saved: {saved}"
                else:
                    msg = f"Dry-run sent to {dry_run_email}"
                    if saved:
                        msg += f" (saved: {saved})"
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SUBMITTED,
                    message=msg,
                )
            except Exception as e:
                logger.error(f"Failed to send dry-run for {platform}: {e}")
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=f"Dry-run failed: {e}",
                )

        return results

    def _build_platform_report_preview(self, platform: str, evidence: ReportEvidence) -> str:
        """Build preview of what would be sent to a platform."""
        from .templates import ReportTemplates

        reporter_email = (self.resend_from_email or self.reporter_email or "").strip()
        reporter_email_addr = reporter_email
        if "<" in reporter_email_addr and ">" in reporter_email_addr:
            reporter_email_addr = reporter_email_addr.split("<")[-1].rstrip(">").strip()

        # Get the template content for this platform
        if platform == "digitalocean":
            # Mirror the payload built by DigitalOceanReporter (Playwright form).
            all_domains = (evidence.backend_domains or []) + (evidence.suspicious_endpoints or [])
            do_apps: list[str] = []
            for d in all_domains:
                if not isinstance(d, str):
                    continue
                if "ondigitalocean.app" not in d.lower():
                    continue
                if "://" in d:
                    parsed = urlparse(d)
                    if parsed.netloc:
                        do_apps.append(parsed.netloc)
                else:
                    do_apps.append(d)
            do_apps = sorted(set(do_apps))

            scam_type = ReportTemplates._resolve_scam_type(evidence)
            if scam_type == "crypto_doubler":
                scam_header = "CRYPTOCURRENCY FRAUD - Apps to suspend:"
            elif scam_type == "fake_airdrop":
                scam_header = "CRYPTOCURRENCY FRAUD (FAKE AIRDROP) - Apps to suspend:"
            elif scam_type == "seed_phishing":
                scam_header = "CRYPTOCURRENCY PHISHING - Apps to suspend:"
            else:
                scam_header = "CRYPTOCURRENCY FRAUD - Apps to suspend:"
            observed_line = ReportTemplates._observed_summary_line(evidence)
            highlights = ReportTemplates._summarize_reasons(evidence.detection_reasons, max_items=4)
            impersonation = evidence.get_impersonation_lines()

            description = f"""{scam_header}
{chr(10).join(f'- {app}' for app in do_apps)}

Reported URL: {evidence.url}
Observed: {observed_line}
Confidence: {evidence.confidence_score}%

"""

            if impersonation:
                description += f"""Impersonation indicators:
{chr(10).join(f'- {r}' for r in impersonation)}

"""

            description += f"""Key evidence from our review:
{chr(10).join(f'- {r}' for r in highlights)}

Captured evidence (screenshot + HTML) available on request.

Detected by SeedBuster - github.com/elldeeone/seedbuster"""

            public_line = evidence.get_public_entry_line()
            if public_line:
                description = f"{description.rstrip()}\n{public_line}"

            return f"""
DIGITALOCEAN ABUSE REPORT PREVIEW
=================================

Form URL: https://www.digitalocean.com/company/contact/abuse#phishing

Field: name
Value: Kaspa Security

Field: email
Value: {reporter_email_addr or "(not set)"}

Field: target
Value: Kaspa cryptocurrency wallet users

Field: evidence_url
Value: {evidence.url}

Field: description
Value:
{description}
"""
        elif platform == "cloudflare":
            reporter_name = ""
            reporter_identity = (self.resend_from_email or self.reporter_email or "").strip()
            if "<" in reporter_identity and ">" in reporter_identity:
                reporter_name = reporter_identity.split("<", 1)[0].strip().strip('"')
            reporter_name = reporter_name or os.environ.get("CLOUDFLARE_REPORTER_NAME", "").strip() or "SeedBuster"

            cf_title = os.environ.get("CLOUDFLARE_REPORTER_TITLE", "").strip()
            cf_company = os.environ.get("CLOUDFLARE_REPORTER_COMPANY", "").strip()
            cf_tele = os.environ.get("CLOUDFLARE_REPORTER_TELEPHONE", "").strip()
            cf_brand = os.environ.get("CLOUDFLARE_TARGETED_BRAND", "").strip()
            cf_country = os.environ.get("CLOUDFLARE_REPORTED_COUNTRY", "").strip()
            cf_user_agent = os.environ.get("CLOUDFLARE_REPORTED_USER_AGENT", "").strip()

            template_data = ReportTemplates.cloudflare(evidence, reporter_email_addr or "")

            internal_lines: list[str] = []
            if evidence.backend_domains:
                internal_lines.append("Backend infrastructure (hostnames observed):")
                internal_lines.extend(f"- {b}" for b in evidence.backend_domains[:10])
                internal_lines.append("")
            if evidence.suspicious_endpoints:
                internal_lines.append("Observed data collection endpoints:")
                internal_lines.extend(f"- {u}" for u in evidence.suspicious_endpoints[:10])
                internal_lines.append("")
            if evidence.screenshot_path or evidence.html_path:
                internal_lines.append("Captured evidence (screenshot + HTML) available on request.")
            internal_comments = "\n".join(internal_lines).strip() or "(optional)"

            return f"""
CLOUDFLARE ABUSE REPORT PREVIEW
===============================

Form URL: https://abuse.cloudflare.com/phishing

Abuse type: Phishing & Malware

Field: name
Value: {reporter_name}

Field: email
Value: {reporter_email_addr or "(not set)"}

Field: email2
Value: {reporter_email_addr or "(not set)"}

Field: title (optional)
Value: {cf_title or "(blank)"}

Field: company (optional)
Value: {cf_company or "(blank)"}

Field: telephone (optional)
Value: {cf_tele or "(blank)"}

Field: urls
Value:
{evidence.url}

Field: justification (may be released publicly)
Value:
{template_data.get('body', 'N/A')}

Field: original_work / targeted_brand (optional)
Value:
{cf_brand or "(blank)"}

Field: reported_country (optional)
Value: {cf_country or "(blank)"}

Field: reported_user_agent (optional)
Value: {cf_user_agent or "(blank)"}

Field: comments (internal to Cloudflare)
Value:
{internal_comments}

Note: Cloudflare uses Turnstile; submission is typically manual.
"""
        elif platform == "google":
            additional_info = ReportTemplates.google_safebrowsing_comment(evidence)
            return f"""
GOOGLE SAFE BROWSING REPORT PREVIEW
===================================

Form URL: https://safebrowsing.google.com/safebrowsing/report_phish/

Field: url
Value: {evidence.url}

Field: dq (additional details)
Value:
{additional_info}

Note: Google's form includes dynamic hidden fields; SeedBuster auto-discovers them at submit time.
"""
        elif platform == "netcraft":
            scam_type = ReportTemplates._resolve_scam_type(evidence)
            impersonation = evidence.get_impersonation_lines()
            highlights = ReportTemplates._summarize_reasons(evidence.detection_reasons, max_items=4)

            if scam_type == "crypto_doubler":
                reason_lines = [
                    "Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam).",
                    f"Confidence: {evidence.confidence_score}%",
                    "",
                ]
                if impersonation:
                    reason_lines.extend([
                        "Impersonation indicators:",
                        *[f"- {line}" for line in impersonation],
                        "",
                    ])
                reason_lines.extend([
                    "Key evidence from our review:",
                    *[f"- {r}" for r in highlights],
                    "",
                    "Captured evidence (screenshot + HTML) available on request.",
                    "",
                    "Detected by SeedBuster.",
                ])
            elif scam_type == "fake_airdrop":
                reason_lines = [
                    "Cryptocurrency fraud (fake airdrop/claim).",
                    "Observed fake airdrop/claim flow.",
                    f"Confidence: {evidence.confidence_score}%",
                    "",
                ]
                if impersonation:
                    reason_lines.extend([
                        "Impersonation indicators:",
                        *[f"- {line}" for line in impersonation],
                        "",
                    ])
                reason_lines.extend([
                    "Key evidence from our review:",
                    *[f"- {r}" for r in highlights],
                    "",
                    "Captured evidence (screenshot + HTML) available on request.",
                    "",
                    "Detected by SeedBuster.",
                ])
            elif scam_type == "seed_phishing":
                seed_hint = ReportTemplates._extract_seed_phrase_indicator(evidence.detection_reasons)
                seed_line = (
                    f"Requests seed phrase ('{seed_hint}')."
                    if seed_hint
                    else "Requests cryptocurrency seed phrase."
                )
                reason_lines = [
                    "Cryptocurrency phishing (seed phrase theft).",
                    seed_line,
                    f"Confidence: {evidence.confidence_score}%",
                    "",
                ]
                if impersonation:
                    reason_lines.extend([
                        "Impersonation indicators:",
                        *[f"- {line}" for line in impersonation],
                        "",
                    ])
                reason_lines.extend([
                    "Key evidence from our review:",
                    *[f"- {r}" for r in highlights],
                    "",
                    "Captured evidence (screenshot + HTML) available on request.",
                    "",
                    "Detected by SeedBuster.",
                ])
            else:
                reason_lines = [
                    "Cryptocurrency fraud / phishing.",
                    "Observed cryptocurrency fraud/phishing content.",
                    f"Confidence: {evidence.confidence_score}%",
                    "",
                ]
                if impersonation:
                    reason_lines.extend([
                        "Impersonation indicators:",
                        *[f"- {line}" for line in impersonation],
                        "",
                    ])
                reason_lines.extend([
                    "Key evidence from our review:",
                    *[f"- {r}" for r in highlights],
                    "",
                    "Captured evidence (screenshot + HTML) available on request.",
                    "",
                    "Detected by SeedBuster.",
                ])
            public_line = evidence.get_public_entry_line()
            if public_line:
                reason_lines.append(public_line)
            reason = "\n".join(reason_lines).strip()

            payload: dict[str, object] = {
                "urls": [
                    {
                        "url": evidence.url,
                        "reason": reason,
                    }
                ]
            }
            if reporter_email_addr:
                payload["email"] = reporter_email_addr

            return f"""
NETCRAFT REPORT PREVIEW
======================

Endpoint: https://report.netcraft.com/api/v3/report/urls
Method: POST
Body (JSON):
{json.dumps(payload, indent=2)}
"""
        elif platform in ("registrar", "resend", "smtp"):
            template_data = ReportTemplates.generic_email(evidence, reporter_email or reporter_email_addr or "")
            return f"""
EMAIL REPORT PREVIEW
====================

Would send to: [Registrar abuse contact via RDAP lookup]

Subject: {template_data.get('subject', 'N/A')}

Body:
{template_data.get('body', 'N/A')}
"""
        else:
            return f"""
{platform.upper()} REPORT PREVIEW
{'=' * (len(platform) + 16)}

Platform: {platform}
Domain: {evidence.domain}
URL: {evidence.url}
Confidence: {evidence.confidence_score}%

Evidence Summary:
{evidence.to_summary()}
"""

    async def _send_dry_run_email(
        self,
        to_email: str,
        platform: str,
        domain: str,
        report_content: str,
        evidence: ReportEvidence,
    ) -> Path:
        """Send a dry-run preview email."""
        attachments: list[Path] = []
        if evidence.screenshot_path and evidence.screenshot_path.exists():
            attachments.append(evidence.screenshot_path)
        if evidence.html_path and evidence.html_path.exists():
            attachments.append(evidence.html_path)

        subject = f"[DRY-RUN] Platform: {platform} | Domain: {domain}"
        body = f"""
This is a DRY-RUN preview of what would be submitted to {platform}.

{'=' * 60}
REPORT PREVIEW
{'=' * 60}

{report_content}

{'=' * 60}
EVIDENCE SUMMARY
{'=' * 60}

Domain: {evidence.domain}
URL: {evidence.url}
Confidence: {evidence.confidence_score}%
Detection Time: {evidence.detected_at.isoformat()}

Detection Reasons:
{chr(10).join(f'  - {r}' for r in evidence.detection_reasons)}

Backend Infrastructure:
{chr(10).join(f'  - {b}' for b in evidence.backend_domains) if evidence.backend_domains else '  (none detected)'}

{'=' * 60}
This email was generated by SeedBuster dry-run mode.
To submit for real, run the command without --dry-run.
"""

        out_dir = self._dry_run_email_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_platform = self._safe_filename_component(platform)
        safe_domain = self._safe_filename_component(domain)
        base = out_dir / f"{ts}_{safe_platform}_{safe_domain}"
        txt_path = base.with_suffix(".txt")
        meta_path = base.with_suffix(".json")

        try:
            txt_path.write_text(
                f"To: {to_email}\nSubject: {subject}\n\n{body.lstrip()}",
                encoding="utf-8",
            )
            meta_path.write_text(
                json.dumps(
                    {
                        "saved_at": ts,
                        "to_email": to_email,
                        "subject": subject,
                        "platform": platform,
                        "domain": domain,
                        "evidence_domain": evidence.domain,
                        "url": evidence.url,
                        "attachments": [str(p) for p in attachments],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        except Exception as e:  # pragma: no cover - best-effort only
            logger.warning("Failed to save dry-run preview: %s", e)

        if self._dry_run_save_only_enabled():
            logger.info("DRY_RUN_SAVE_ONLY enabled; skipping sending preview email (%s)", txt_path)
            return txt_path

        resend_reporter = self.reporters.get("resend")
        if resend_reporter and resend_reporter.is_configured():
            try:
                send_email = getattr(resend_reporter, "send_email", None)
                if callable(send_email):
                    await send_email(to_email=to_email, subject=subject, body=body, attachments=attachments)
                    return txt_path
            except Exception as e:
                raise ReporterError(f"Resend dry-run email failed: {e} (saved: {txt_path})") from e

        smtp_reporter = self.reporters.get("smtp")
        if smtp_reporter and smtp_reporter.is_configured():
            try:
                ok = await smtp_reporter.send_email(
                    to_email=to_email,
                    subject=subject,
                    body=body,
                    attachments=attachments,
                )
                if not ok:
                    raise ReporterError("SMTP dry-run email failed")
                return txt_path
            except Exception as e:
                raise ReporterError(f"SMTP dry-run email failed: {e} (saved: {txt_path})") from e

        raise ConfigurationError(
            "No email service configured for dry-run previews. "
            "Configure RESEND_API_KEY or SMTP settings."
            f" (saved: {txt_path})"
        )

    # -------------------------------------------------------------------------
    # Campaign Reporting - Report entire campaigns in parallel
    # -------------------------------------------------------------------------

    async def report_campaign(
        self,
        campaign_id: str,
        campaign_manager: "ThreatCampaignManager",
        platforms: Optional[list[str]] = None,
        *,
        dry_run: bool = False,
        dry_run_email: Optional[str] = None,
        generate_evidence_package: bool = True,
    ) -> dict[str, list[ReportResult]]:
        """
        Report an entire campaign in parallel to all relevant targets.

        Args:
            campaign_id: ID of the campaign to report
            campaign_manager: ThreatCampaignManager instance
            platforms: Specific platforms to report to (None = all)
            dry_run: Send previews to dry_run_email instead of real targets
            dry_run_email: Email for dry-run previews
            generate_evidence_package: Whether to generate PDF/evidence archives

        Returns:
            Dict mapping target type to list of results:
            - "backends": Results from backend provider reports (DO, Vercel)
            - "registrars": Results from registrar reports
            - "blocklists": Results from blocklist submissions
            - "frontends": Results from individual domain reports
        """
        if self._preview_only_enabled():
            dry_run = True
            if dry_run_email is None:
                dry_run_email = os.environ.get("DRY_RUN_EMAIL", "")

        campaign = campaign_manager.campaigns.get(campaign_id)
        if not campaign:
            return {
                "error": [ReportResult(
                    platform="campaign",
                    status=ReportStatus.FAILED,
                    message=f"Campaign not found: {campaign_id}",
                )]
            }

        results: dict[str, list[ReportResult]] = {
            "backends": [],
            "registrars": [],
            "blocklists": [],
            "frontends": [],
        }

        dry_run_email = dry_run_email or os.environ.get("DRY_RUN_EMAIL", "")

        # Generate evidence package if requested
        if generate_evidence_package:
            try:
                from .evidence_packager import EvidencePackager
                packager = EvidencePackager(
                    database=self.database,
                    evidence_store=self.evidence_store,
                    campaign_manager=campaign_manager,
                )
                if dry_run:
                    # Just generate the reports, don't archive
                    from .report_generator import ReportGenerator
                    generator = ReportGenerator(
                        database=self.database,
                        evidence_store=self.evidence_store,
                        campaign_manager=campaign_manager,
                    )
                    html_path = await generator.generate_campaign_html(campaign_id)
                    logger.info(f"Generated campaign report: {html_path}")
                else:
                    archive_path = await packager.create_campaign_archive(campaign_id)
                    logger.info(f"Generated campaign archive: {archive_path}")
            except Exception as e:
                logger.error(f"Failed to generate evidence package: {e}")

        # 1. Report to backend providers (highest priority)
        backend_tasks = []
        for backend in campaign.shared_backends:
            if "digitalocean" in backend.lower():
                backend_tasks.append(
                    self._report_backend(
                        backend=backend,
                        campaign=campaign,
                        platform="digitalocean",
                        dry_run=dry_run,
                        dry_run_email=dry_run_email,
                    )
                )
            elif "vercel" in backend.lower():
                # TODO: Add Vercel reporter
                logger.info(f"Vercel backend detected but no reporter implemented: {backend}")

        if backend_tasks:
            backend_results = await asyncio.gather(*backend_tasks, return_exceptions=True)
            for result in backend_results:
                if isinstance(result, Exception):
                    results["backends"].append(ReportResult(
                        platform="backend",
                        status=ReportStatus.FAILED,
                        message=str(result),
                    ))
                else:
                    results["backends"].append(result)

        # 2. Report to blocklists (parallel)
        blocklist_platforms = ["google", "netcraft"]
        if platforms:
            blocklist_platforms = [p for p in blocklist_platforms if p in platforms]

        for member in campaign.members:
            domain_data = await self.database.get_domain(member.domain)
            if not domain_data:
                continue

            domain_id = domain_data.get("id")
            if not domain_id:
                continue

            blocklist_results = await self.report_domain(
                domain_id=domain_id,
                domain=member.domain,
                platforms=blocklist_platforms,
                dry_run=dry_run,
                dry_run_email=dry_run_email,
            )
            for platform, result in blocklist_results.items():
                results["blocklists"].append(result)

        # 3. Report to registrars (grouped by registrar)
        # TODO: Group domains by registrar and send bulk reports

        # 4. Report individual frontends (if not already done via blocklists)
        frontend_platforms = [p for p in (platforms or self.get_available_platforms())
                             if p not in blocklist_platforms]

        for member in campaign.members:
            domain_data = await self.database.get_domain(member.domain)
            if not domain_data:
                continue

            domain_id = domain_data.get("id")
            if not domain_id:
                continue

            frontend_results = await self.report_domain(
                domain_id=domain_id,
                domain=member.domain,
                platforms=frontend_platforms,
                dry_run=dry_run,
                dry_run_email=dry_run_email,
            )
            for platform, result in frontend_results.items():
                results["frontends"].append(result)

        return results

    async def _report_backend(
        self,
        backend: str,
        campaign: "ThreatCampaign",
        platform: str,
        dry_run: bool = False,
        dry_run_email: str = "",
    ) -> ReportResult:
        """Report a backend server with campaign context."""
        reporter = self.reporters.get(platform)
        if not reporter or not reporter.is_configured():
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message=f"Reporter not configured: {platform}",
            )

        # Build evidence for the backend report
        # Use the first domain in the campaign as the primary evidence
        if not campaign.members:
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message="No domains in campaign",
            )

        primary_domain = campaign.members[0].domain
        domain_data = await self.database.get_domain(primary_domain)
        if not domain_data:
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message=f"Domain not found: {primary_domain}",
            )

        evidence = await self.build_evidence(
            domain_id=domain_data.get("id"),
            domain=primary_domain,
        )
        if not evidence:
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message="Could not build evidence",
            )

        # Enhance evidence with campaign context
        evidence.backend_domains = list(campaign.shared_backends)

        if dry_run:
            report_content = self._build_platform_report_preview(platform, evidence)
            report_content = f"""
CAMPAIGN CONTEXT
================
This backend is part of campaign: {campaign.name}
Total domains using this backend: {len(campaign.members)}
Domains: {', '.join(m.domain for m in campaign.members[:10])}{'...' if len(campaign.members) > 10 else ''}

{report_content}
"""
            saved = await self._send_dry_run_email(
                to_email=dry_run_email,
                platform=f"{platform}_backend",
                domain=backend,
                report_content=report_content,
                evidence=evidence,
            )
            if self._dry_run_save_only_enabled():
                msg = f"Dry-run saved: {saved}"
            else:
                msg = f"Dry-run sent to {dry_run_email}"
                if saved:
                    msg += f" (saved: {saved})"
            return ReportResult(
                platform=f"{platform}_backend",
                status=ReportStatus.SUBMITTED,
                message=msg,
            )

        # Submit real report
        result = await reporter.submit(evidence)
        result.platform = f"{platform}_backend"
        return result
