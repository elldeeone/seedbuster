"""DigitalOcean abuse form reporter for SeedBuster."""

import asyncio
import logging
from datetime import datetime, timezone

from .base import (
    BaseReporter,
    ManualSubmissionData,
    ManualSubmissionField,
    ReportEvidence,
    ReportResult,
    ReportStatus,
)
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


class DigitalOceanReporter(BaseReporter):
    """
    DigitalOcean abuse form reporter.

    Submits phishing reports via DO's abuse form using Playwright
    since the form is a React app that requires JavaScript.
    """

    platform_name = "digitalocean"
    platform_url = "https://www.digitalocean.com/company/contact/abuse#phishing"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 5

    FORM_URL = "https://www.digitalocean.com/company/contact/abuse#phishing"

    def __init__(self, reporter_email: str = "", reporter_name: str = "Kaspa Security"):
        super().__init__()
        self.reporter_email = reporter_email
        self.reporter_name = reporter_name
        self._configured = bool(reporter_email)

    @staticmethod
    def _extract_do_apps(evidence: ReportEvidence) -> list[str]:
        """Extract DigitalOcean App Platform hostnames from evidence."""
        all_domains = (evidence.backend_domains or []) + (evidence.suspicious_endpoints or [])
        do_apps: list[str] = []
        for d in all_domains:
            if not isinstance(d, str):
                continue
            if "ondigitalocean.app" not in d.lower():
                continue
            # Extract just the domain part if it's a URL
            if "://" in d:
                from urllib.parse import urlparse

                parsed = urlparse(d)
                if parsed.netloc:
                    do_apps.append(parsed.netloc)
            else:
                do_apps.append(d)
        return sorted(set(do_apps))

    def is_applicable(self, evidence: ReportEvidence) -> tuple[bool, str]:
        do_apps = self._extract_do_apps(evidence)
        if not do_apps:
            return False, "No DigitalOcean App Platform backends found"
        return True, ""

    def _build_description(self, evidence: ReportEvidence) -> str:
        """Build structured description for DO abuse form."""
        do_apps = self._extract_do_apps(evidence)
        highlights = ReportTemplates._summarize_reasons(evidence.detection_reasons, max_items=4)
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

        return f"""{scam_header}
{chr(10).join(f'- {app}' for app in do_apps)}

Reported URL: {evidence.url}
Observed: {observed_line}
Confidence: {evidence.confidence_score}%

This site runs a cryptocurrency scam against end users.
Victims lose funds immediately and irreversibly.

Key evidence (automated capture):
{chr(10).join(f'- {r}' for r in highlights)}

Captured evidence (screenshot + HTML) available on request.

Detected by SeedBuster - github.com/elldeeone/seedbuster"""

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        """Generate structured manual submission data for public dashboard."""
        do_apps = self._extract_do_apps(evidence)
        description = self._build_description(evidence)

        fields = [
            ManualSubmissionField(
                name="name",
                label="Your full name",
                value=self.reporter_name or "(fill manually)",
            ),
            ManualSubmissionField(
                name="email",
                label="Email address",
                value=self.reporter_email or "(fill manually)",
            ),
            ManualSubmissionField(
                name="target",
                label="Target of phishing campaign",
                value="Kaspa cryptocurrency wallet users",
            ),
            ManualSubmissionField(
                name="url",
                label="Evidence URL",
                value=evidence.url,
            ),
        ]

        if do_apps:
            fields.append(
                ManualSubmissionField(
                    name="do_apps",
                    label="DigitalOcean Apps to suspend",
                    value="\n".join(do_apps),
                    multiline=True,
                )
            )

        fields.append(
            ManualSubmissionField(
                name="description",
                label="Description",
                value=description,
                multiline=True,
            )
        )

        return ManualSubmissionData(
            form_url=self.FORM_URL,
            reason="DigitalOcean abuse form",
            fields=fields,
            notes=[
                "Select 'Phishing' as the abuse type (pre-selected via URL).",
                "The form requires JavaScript; fill fields after page loads.",
                "DigitalOcean SOC team typically responds within 24 hours.",
            ],
        )

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """Submit phishing report to DigitalOcean using Playwright."""
        if not self._configured:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message="Reporter email not configured",
            )

        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Get DO apps from backend domains and suspicious endpoints
        do_apps = self._extract_do_apps(evidence)

        if not do_apps:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message="No DigitalOcean App Platform backends found",
            )

        # Build description and manual submission data
        description = self._build_description(evidence)
        manual_data = self.generate_manual_submission(evidence)

        manual_payload = (
            "Submission not confirmed; manual submission recommended.\n\n"
            f"Manual submission URL: {self.FORM_URL}\n\n"
            f"Reporter name: {self.reporter_name}\n"
            f"Reporter email: {self.reporter_email}\n"
            f"Phishing URL: {evidence.url}\n\n"
            f"Copy/paste description:\n{description}"
        )

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.MANUAL_REQUIRED,
                message="Playwright not installed; manual submission required.",
                response_data={"manual_fields": manual_data.to_dict()},
            )

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                )
                page = await context.new_page()

                # Navigate to the form
                await page.goto(self.FORM_URL, wait_until="domcontentloaded", timeout=60000)

                # Wait for React app to hydrate - the form takes time to render
                await asyncio.sleep(3)

                # Dismiss cookie consent banner if present
                try:
                    cookie_btn = page.locator('button:has-text("AGREE"), button:has-text("Accept")')
                    if await cookie_btn.count() > 0:
                        await cookie_btn.first.click()
                        await asyncio.sleep(0.5)
                except Exception:
                    pass  # Cookie banner might not exist

                # Wait for form inputs to be ready
                await page.wait_for_selector('input', timeout=15000)

                # The URL with #phishing pre-selects the abuse type, so we don't need to change it

                # Fill form fields by placeholder text
                # Your full name
                name_input = page.locator('input[placeholder*="name" i]').first
                if await name_input.count() > 0:
                    await name_input.fill(self.reporter_name)

                # Email Address
                email_input = page.locator('input[placeholder*="email" i]').first
                if await email_input.count() > 0:
                    await email_input.fill(self.reporter_email)

                # Target of phishing campaign
                target_input = page.locator('input[placeholder*="target" i]').first
                if await target_input.count() > 0:
                    await target_input.fill("Kaspa cryptocurrency wallet users")

                # Evidence URL
                evidence_input = page.locator('input[placeholder*="evidence" i], input[placeholder*="URL" i]').first
                if await evidence_input.count() > 0:
                    await evidence_input.fill(evidence.url)

                # Source IP - scroll down first to find more fields
                await page.evaluate("window.scrollBy(0, 300)")
                await asyncio.sleep(0.5)

                ip_input = page.locator('input[placeholder*="IP" i], input[placeholder*="ip" i]').first
                if await ip_input.count() > 0:
                    ip_value = ""
                    try:
                        import socket

                        ip_value = await asyncio.to_thread(socket.gethostbyname, do_apps[0])
                    except Exception:
                        ip_value = ""
                    if ip_value:
                        await ip_input.fill(ip_value)

                # Date field
                now = datetime.now(timezone.utc)
                date_input = page.locator('input[type="date"], input[placeholder*="date" i]').first
                if await date_input.count() > 0:
                    await date_input.fill(now.strftime("%Y-%m-%d"))

                # Time field
                time_input = page.locator('input[type="time"], input[placeholder*="time" i]').first
                if await time_input.count() > 0:
                    await time_input.fill(now.strftime("%H:%M"))

                # Description/comment textarea
                textarea = page.locator('textarea').first
                if await textarea.count() > 0:
                    await textarea.fill(description)

                # Take screenshot for debugging (uncomment if needed)
                # await page.screenshot(path="/tmp/do_form.png")

                # Submit the form
                submit_button = page.locator('button:has-text("Report Abuse"), button[type="submit"]').first
                if await submit_button.count() > 0:
                    await submit_button.click()

                    # Wait for response
                    await asyncio.sleep(3)

                    # Check for success indicators
                    page_content = await page.content()
                    page_text = page_content.lower()

                    if any(word in page_text for word in ["thank", "received", "submitted", "success"]):
                        await browser.close()
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.SUBMITTED,
                            message="Submitted to DigitalOcean SOC team",
                        )

                    await browser.close()
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message="Submission not confirmed; please verify manually.",
                        response_data={"manual_fields": manual_data.to_dict()},
                    )

                await browser.close()

                # If we got here, submission could not be verified.
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.MANUAL_REQUIRED,
                    message="Could not verify submission; please submit manually.",
                    response_data={"manual_fields": manual_data.to_dict()},
                )

        except Exception as e:
            logger.exception("DigitalOcean form submission error")
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.MANUAL_REQUIRED,
                message=f"Auto-submit failed: {e}",
                response_data={"manual_fields": manual_data.to_dict()},
            )
