"""DigitalOcean abuse form reporter for SeedBuster."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus

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
        all_domains = (evidence.backend_domains or []) + (evidence.suspicious_endpoints or [])
        do_apps = []
        for d in all_domains:
            if "ondigitalocean.app" in d.lower():
                # Extract just the domain part if it's a URL
                if "://" in d:
                    from urllib.parse import urlparse
                    parsed = urlparse(d)
                    do_apps.append(parsed.netloc)
                else:
                    do_apps.append(d)
        do_apps = list(set(do_apps))  # Deduplicate

        if not do_apps:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message="No DigitalOcean apps found in evidence",
            )

        # Build description
        description = f"""CRYPTOCURRENCY PHISHING - Apps to suspend:
{chr(10).join(f'- {app}' for app in do_apps)}

Attack: {evidence.domain} steals seed phrases, sends to DO apps above.
Confidence: {evidence.confidence_score}%

Evidence:
{chr(10).join(f'- {r}' for r in evidence.detection_reasons[:3])}

Detected by SeedBuster - github.com/elldeeone/seedbuster"""

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message="Playwright not installed",
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
                    await evidence_input.fill(f"https://{do_apps[0]}")

                # Source IP - scroll down first to find more fields
                await page.evaluate("window.scrollBy(0, 300)")
                await asyncio.sleep(0.5)

                ip_input = page.locator('input[placeholder*="IP" i], input[placeholder*="ip" i]').first
                if await ip_input.count() > 0:
                    await ip_input.fill(do_apps[0])

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

                # If we got here, submission might have worked but we're not sure
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.SUBMITTED,
                    message="Form submitted (verification pending)",
                )

        except Exception as e:
            logger.exception("DigitalOcean form submission error")
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.PENDING,
                message=f"Auto-submit failed: {e}. Manual: {self.FORM_URL}",
            )
