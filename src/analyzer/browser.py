"""Playwright-based browser analysis for phishing detection."""

import asyncio
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from playwright.async_api import async_playwright, Browser, Page, Error as PlaywrightError

logger = logging.getLogger(__name__)

# Known anti-bot/fingerprinting services to block
ANTIBOT_DOMAINS = {
    "ipdata.co",
    "ipinfo.io",
    "ipapi.co",
    "ip-api.com",
    "ipgeolocation.io",
    "ipify.org",
    "api.ipify.org",
    "fingerprint.com",
    "fpjs.io",
    "arkoselabs.com",
    "funcaptcha.com",
    "datadome.co",
    "perimeterx.net",
    "px-cdn.net",
    "hcaptcha.com",
    "recaptcha.net",
    "gstatic.com/recaptcha",
    "challenges.cloudflare.com",
    "kasada.io",
    "queue-it.net",
    "distil.net",
    "imperva.com",
    "incapsula.com",
}

# Realistic user agents for stealth mode
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

# Stealth JavaScript to inject - hides headless browser signatures
STEALTH_SCRIPT = """
// Override navigator.webdriver
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined
});

// Override plugins to look like a real browser
Object.defineProperty(navigator, 'plugins', {
    get: () => [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
        { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' }
    ]
});

// Override languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en']
});

// Fix permissions API
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications' ?
        Promise.resolve({ state: Notification.permission }) :
        originalQuery(parameters)
);

// Fix chrome object
window.chrome = {
    runtime: {},
    loadTimes: function() {},
    csi: function() {},
    app: {}
};

// Ensure consistent screen dimensions
Object.defineProperty(screen, 'availWidth', { get: () => window.innerWidth });
Object.defineProperty(screen, 'availHeight', { get: () => window.innerHeight });

// WebGL fingerprint spoofing
const getParameterProxyHandler = {
    apply: function(target, thisArg, args) {
        const param = args[0];
        const gl = thisArg;
        // Return realistic values for common fingerprinting parameters
        if (param === 37445) return 'Google Inc. (NVIDIA)'; // UNMASKED_VENDOR_WEBGL
        if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)'; // UNMASKED_RENDERER_WEBGL
        return target.apply(thisArg, args);
    }
};
try {
    WebGLRenderingContext.prototype.getParameter = new Proxy(
        WebGLRenderingContext.prototype.getParameter, getParameterProxyHandler
    );
    WebGL2RenderingContext.prototype.getParameter = new Proxy(
        WebGL2RenderingContext.prototype.getParameter, getParameterProxyHandler
    );
} catch(e) {}

// Canvas fingerprint noise injection
const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    if (type === 'image/png' || type === undefined) {
        const context = this.getContext('2d');
        if (context) {
            const imageData = context.getImageData(0, 0, this.width, this.height);
            // Add subtle noise to prevent fingerprinting
            for (let i = 0; i < imageData.data.length; i += 4) {
                imageData.data[i] ^= (Math.random() * 2) | 0;
            }
            context.putImageData(imageData, 0, 0);
        }
    }
    return originalToDataURL.apply(this, arguments);
};

// AudioContext fingerprint spoofing
const originalGetChannelData = AudioBuffer.prototype.getChannelData;
AudioBuffer.prototype.getChannelData = function(channel) {
    const result = originalGetChannelData.apply(this, arguments);
    // Add subtle noise
    for (let i = 0; i < result.length; i += 100) {
        result[i] += (Math.random() * 0.0001);
    }
    return result;
};

// Prevent detection via connection info
Object.defineProperty(navigator, 'connection', {
    get: () => ({
        effectiveType: '4g',
        rtt: 50,
        downlink: 10,
        saveData: false
    })
});

// Mock battery API (often used for fingerprinting)
navigator.getBattery = () => Promise.resolve({
    charging: true,
    chargingTime: 0,
    dischargingTime: Infinity,
    level: 1.0
});
"""


@dataclass
class BrowserResult:
    """Result of browser-based site analysis."""

    domain: str
    success: bool
    error: Optional[str] = None

    # Collected data
    screenshot: Optional[bytes] = None
    screenshot_early: Optional[bytes] = None  # Captured before JS-based redirects
    html: Optional[str] = None
    html_early: Optional[str] = None  # Captured before JS-based redirects
    har: Optional[dict] = None
    console_logs: list[str] = field(default_factory=list)

    # Page metadata
    final_url: Optional[str] = None
    title: Optional[str] = None
    title_early: Optional[str] = None  # Title before JS-based redirects
    status_code: Optional[int] = None

    # Detected forms
    forms: list[dict] = field(default_factory=list)
    input_fields: list[dict] = field(default_factory=list)

    # Network requests
    external_requests: list[str] = field(default_factory=list)
    form_submissions: list[dict] = field(default_factory=list)

    # Anti-evasion data
    blocked_requests: list[str] = field(default_factory=list)  # Blocked anti-bot requests
    evasion_detected: bool = False  # True if content changed significantly after load


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
            # Create isolated browser context with stealth settings
            user_agent = random.choice(USER_AGENTS)
            context = await self._browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=user_agent,
                ignore_https_errors=True,  # Many phishing sites have bad certs
                locale="en-US",
                timezone_id="America/New_York",
                geolocation={"latitude": 40.7128, "longitude": -74.0060},  # NYC
                permissions=["geolocation"],
                color_scheme="light",
                device_scale_factor=1,
                is_mobile=False,
                has_touch=False,
            )

            page = await context.new_page()

            # Inject stealth script before any page loads
            await page.add_init_script(STEALTH_SCRIPT)

            # Collect console logs
            page.on("console", lambda msg: result.console_logs.append(f"[{msg.type}] {msg.text}"))

            # Track network requests and block anti-bot services
            external_domains = set()
            form_posts = []
            blocked_requests = []

            async def handle_route(route):
                """Block requests to known anti-bot services."""
                url = route.request.url
                try:
                    # Extract domain from URL
                    url_parts = url.split("/")
                    if len(url_parts) >= 3:
                        request_domain = url_parts[2].lower()
                        # Check if this is an anti-bot service
                        for antibot in ANTIBOT_DOMAINS:
                            if antibot in request_domain:
                                blocked_requests.append(url)
                                logger.debug(f"Blocked anti-bot request: {url}")
                                await route.abort()
                                return
                except Exception:
                    pass
                await route.continue_()

            # Enable request interception to block anti-bot services
            await page.route("**/*", handle_route)

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

            # Navigate to the site - first wait for DOM, then capture early evidence
            url = f"https://{domain}"
            try:
                # First load: wait only for DOM content (before JS redirects)
                response = await page.goto(
                    url,
                    timeout=self.timeout,
                    wait_until="domcontentloaded",
                )
                result.status_code = response.status if response else None

                # Capture EARLY evidence before JS-based evasion kicks in
                # Wait for body to be visible and content to render
                try:
                    await page.wait_for_selector("body", state="visible", timeout=3000)
                    await asyncio.sleep(1.5)  # Allow more time for initial render
                except:
                    await asyncio.sleep(2.0)  # Fallback wait if selector fails
                result.screenshot_early = await page.screenshot(full_page=True)
                result.html_early = await page.content()
                result.title_early = await page.title()

                # Now wait for full page load (networkidle)
                await page.wait_for_load_state("networkidle", timeout=self.timeout)

            except PlaywrightError as e:
                # Try HTTP if HTTPS fails
                if "ERR_" in str(e) or "Timeout" in str(e):
                    url = f"http://{domain}"
                    try:
                        response = await page.goto(
                            url,
                            timeout=self.timeout,
                            wait_until="domcontentloaded",
                        )
                        result.status_code = response.status if response else None

                        # Capture early evidence
                        try:
                            await page.wait_for_selector("body", state="visible", timeout=3000)
                            await asyncio.sleep(1.5)
                        except:
                            await asyncio.sleep(2.0)
                        result.screenshot_early = await page.screenshot(full_page=True)
                        result.html_early = await page.content()
                        result.title_early = await page.title()

                        await page.wait_for_load_state("networkidle", timeout=self.timeout)
                    except PlaywrightError as e2:
                        result.error = f"Failed to load: {str(e2)[:200]}"
                        return result
                else:
                    result.error = f"Failed to load: {str(e)[:200]}"
                    return result

            # Simulate human-like behavior to evade bot detection
            await self._simulate_human_behavior(page)

            # Collect final evidence
            result.final_url = page.url
            result.title = await page.title()
            result.html = await page.content()
            result.screenshot = await page.screenshot(full_page=True)
            result.external_requests = list(external_domains)
            result.form_submissions = form_posts
            result.blocked_requests = blocked_requests

            # Detect evasion: check if content changed significantly
            if result.title_early and result.title:
                if result.title_early != result.title:
                    result.evasion_detected = True
                    logger.info(f"Evasion detected: title changed from '{result.title_early}' to '{result.title}'")

            # Analyze forms and inputs
            result.forms = await self._extract_forms(page)
            result.input_fields = await self._extract_inputs(page)

            result.success = True
            if blocked_requests:
                logger.info(f"Successfully analyzed {domain} (blocked {len(blocked_requests)} anti-bot requests)")
            else:
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

    async def _simulate_human_behavior(self, page: Page):
        """Simulate human-like behavior to evade bot detection."""
        try:
            # Wait for dynamic content with random delay
            await asyncio.sleep(random.uniform(1.5, 3.0))

            # Get viewport dimensions
            viewport = page.viewport_size
            if not viewport:
                viewport = {"width": 1920, "height": 1080}

            # Simulate random mouse movements
            for _ in range(random.randint(2, 4)):
                x = random.randint(100, viewport["width"] - 100)
                y = random.randint(100, viewport["height"] - 100)
                await page.mouse.move(x, y)
                await asyncio.sleep(random.uniform(0.1, 0.3))

            # Simulate a small scroll
            scroll_amount = random.randint(100, 300)
            await page.evaluate(f"window.scrollBy(0, {scroll_amount})")
            await asyncio.sleep(random.uniform(0.3, 0.6))

            # Scroll back up to capture full page
            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(random.uniform(0.3, 0.5))

        except Exception as e:
            # Don't fail analysis if simulation fails
            logger.debug(f"Human simulation error (non-fatal): {e}")

    async def capture_fingerprint(self, domain: str) -> Optional[bytes]:
        """Capture just a screenshot for fingerprinting."""
        result = await self.analyze(domain)
        return result.screenshot if result.success else None
