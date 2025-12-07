"""Playwright-based browser analysis for phishing detection."""

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from playwright.async_api import async_playwright, Browser, Page, Error as PlaywrightError

logger = logging.getLogger(__name__)


@dataclass
class BrowserResult:
    """Result of browser-based site analysis."""

    domain: str
    success: bool
    error: Optional[str] = None

    # Collected data
    screenshot: Optional[bytes] = None
    html: Optional[str] = None
    har: Optional[dict] = None
    console_logs: list[str] = field(default_factory=list)

    # Page metadata
    final_url: Optional[str] = None
    title: Optional[str] = None
    status_code: Optional[int] = None

    # Detected forms
    forms: list[dict] = field(default_factory=list)
    input_fields: list[dict] = field(default_factory=list)

    # Network requests
    external_requests: list[str] = field(default_factory=list)
    form_submissions: list[dict] = field(default_factory=list)


class BrowserAnalyzer:
    """Analyzes websites using headless Playwright browser."""

    def __init__(
        self,
        timeout: int = 30,
        headless: bool = True,
    ):
        self.timeout = timeout * 1000  # Convert to ms
        self.headless = headless
        self._playwright = None
        self._browser: Optional[Browser] = None

    async def start(self):
        """Start the browser instance."""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=[
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-gpu",
            ],
        )
        logger.info("Browser started")

    async def stop(self):
        """Stop the browser instance."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("Browser stopped")

    async def analyze(self, domain: str) -> BrowserResult:
        """Analyze a domain and collect evidence."""
        if not self._browser:
            await self.start()

        result = BrowserResult(domain=domain, success=False)
        context = None
        page = None

        try:
            # Create isolated browser context
            context = await self._browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ignore_https_errors=True,  # Many phishing sites have bad certs
            )

            # Set up HAR recording
            har_path = Path(f"/tmp/har_{domain.replace('.', '_')}.har")

            page = await context.new_page()

            # Collect console logs
            page.on("console", lambda msg: result.console_logs.append(f"[{msg.type}] {msg.text}"))

            # Track network requests
            external_domains = set()
            form_posts = []

            async def handle_request(request):
                try:
                    url = request.url
                    # Track external requests
                    if domain not in url and not url.startswith("data:"):
                        external_domains.add(url.split("/")[2] if "/" in url else url)
                    # Track form submissions
                    if request.method == "POST":
                        form_posts.append({
                            "url": url,
                            "method": request.method,
                            "post_data": request.post_data[:500] if request.post_data else None,
                        })
                except Exception:
                    pass

            page.on("request", handle_request)

            # Navigate to the site
            url = f"https://{domain}"
            try:
                response = await page.goto(
                    url,
                    timeout=self.timeout,
                    wait_until="networkidle",
                )
                result.status_code = response.status if response else None
            except PlaywrightError as e:
                # Try HTTP if HTTPS fails
                if "ERR_" in str(e) or "Timeout" in str(e):
                    url = f"http://{domain}"
                    try:
                        response = await page.goto(
                            url,
                            timeout=self.timeout,
                            wait_until="networkidle",
                        )
                        result.status_code = response.status if response else None
                    except PlaywrightError as e2:
                        result.error = f"Failed to load: {str(e2)[:200]}"
                        return result
                else:
                    result.error = f"Failed to load: {str(e)[:200]}"
                    return result

            # Wait a bit for any dynamic content
            await asyncio.sleep(2)

            # Collect evidence
            result.final_url = page.url
            result.title = await page.title()
            result.html = await page.content()
            result.screenshot = await page.screenshot(full_page=True)
            result.external_requests = list(external_domains)
            result.form_submissions = form_posts

            # Analyze forms and inputs
            result.forms = await self._extract_forms(page)
            result.input_fields = await self._extract_inputs(page)

            result.success = True
            logger.info(f"Successfully analyzed {domain}")

        except Exception as e:
            result.error = f"Analysis error: {str(e)[:200]}"
            logger.error(f"Error analyzing {domain}: {e}")

        finally:
            if page:
                await page.close()
            if context:
                await context.close()

        return result

    async def _extract_forms(self, page: Page) -> list[dict]:
        """Extract form information from the page."""
        try:
            forms = await page.evaluate(
                """
                () => {
                    const forms = document.querySelectorAll('form');
                    return Array.from(forms).map(form => ({
                        action: form.action,
                        method: form.method,
                        id: form.id,
                        class: form.className,
                        inputCount: form.querySelectorAll('input').length,
                        hasPasswordField: form.querySelector('input[type="password"]') !== null,
                    }));
                }
            """
            )
            return forms
        except Exception as e:
            logger.error(f"Error extracting forms: {e}")
            return []

    async def _extract_inputs(self, page: Page) -> list[dict]:
        """Extract input field information from the page."""
        try:
            inputs = await page.evaluate(
                """
                () => {
                    const inputs = document.querySelectorAll('input, textarea');
                    return Array.from(inputs).map(input => ({
                        type: input.type,
                        name: input.name,
                        id: input.id,
                        placeholder: input.placeholder,
                        class: input.className,
                        maxLength: input.maxLength,
                        required: input.required,
                    }));
                }
            """
            )
            return inputs
        except Exception as e:
            logger.error(f"Error extracting inputs: {e}")
            return []

    async def capture_fingerprint(self, domain: str) -> Optional[bytes]:
        """Capture just a screenshot for fingerprinting."""
        result = await self.analyze(domain)
        return result.screenshot if result.success else None
