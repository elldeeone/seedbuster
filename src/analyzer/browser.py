"""Playwright-based browser analysis for phishing detection."""

import asyncio
import ipaddress
import logging
import os
import random
import re
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

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

# Navigation targets for click-through exploration
# These are buttons/links to click when exploring for hidden phishing content
EXPLORATION_TARGETS = [
    # Legacy Wallet flow (old-school web wallet template)
    {"text": "legacy wallet", "priority": 1},
    {"text": "continue on legacy", "priority": 1},
    {"text": "recover from seed", "priority": 1},

    # Kaspa-NG style landing page buttons
    {"text": "kaspa ng", "priority": 1},
    {"text": "go to", "priority": 2},  # "Go to the new Kaspa NG Wallet"
    {"text": "continue", "priority": 2},  # Generic continue buttons

    # Wallet-related (highest priority - often contains seed form)
    {"text": "wallet", "priority": 1},
    {"text": "open wallet", "priority": 1},
    {"text": "access wallet", "priority": 1},
    {"text": "my wallet", "priority": 1},

    # Recovery/restore (seed phrase forms)
    {"text": "recover", "priority": 1},
    {"text": "restore", "priority": 1},
    {"text": "import", "priority": 1},
    {"text": "recovery", "priority": 1},
    {"text": "import existing", "priority": 1},

    # Create/new wallet flows (may redirect to phishing)
    {"text": "create wallet", "priority": 2},
    {"text": "new wallet", "priority": 2},
    {"text": "create new wallet", "priority": 2},
    {"text": "create", "priority": 3},

    # Mnemonic/seed selection (Kaspa-NG phishing flow)
    {"text": "12-word", "priority": 1},
    {"text": "24-word", "priority": 1},
    {"text": "12 word", "priority": 1},
    {"text": "24 word", "priority": 1},
    {"text": "12 words", "priority": 1},
    {"text": "24 words", "priority": 1},
    {"text": "mnemonic", "priority": 1},
    {"text": "import mnemonic", "priority": 1},
    {"text": "enter mnemonic", "priority": 1},
    {"text": "seed phrase", "priority": 1},
    {"text": "secret phrase", "priority": 1},

    # Continue/next buttons (common in wizard flows)
    {"text": "continue", "priority": 2},
    {"text": "next", "priority": 2},
    {"text": "proceed", "priority": 2},

    # Connect wallet (common phishing vector)
    {"text": "connect", "priority": 2},
    {"text": "connect wallet", "priority": 1},

    # Settings (sometimes hides wallet access)
    {"text": "settings", "priority": 3},
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
class ExplorationStep:
    """A single step in click-through exploration."""

    button_text: str
    screenshot: Optional[bytes] = None
    html: Optional[str] = None
    title: Optional[str] = None
    url: Optional[str] = None
    input_fields: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None


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
    blocked_internal_requests: list[str] = field(default_factory=list)  # Blocked private/local SSRF targets
    evasion_detected: bool = False  # True if content changed significantly after load

    # Click-through exploration results
    exploration_steps: list[ExplorationStep] = field(default_factory=list)
    explored: bool = False  # True if click-through exploration was performed


class BrowserAnalyzer:
    """Analyzes websites using headless Playwright browser."""

    def __init__(
        self,
        timeout: int = 30,
        headless: bool = True,
        exploration_targets: list[dict] | None = None,
    ):
        self.timeout = timeout * 1000  # Convert to ms
        self.headless = headless
        self._playwright = None
        self._browser: Optional[Browser] = None
        self.exploration_targets = exploration_targets or list(EXPLORATION_TARGETS)

    async def start(self):
        """Start the browser instance."""
        self._playwright = await async_playwright().start()
        disable_sandbox = os.getenv("SEEDBUSTER_DISABLE_CHROMIUM_SANDBOX") == "1"
        sandbox_args: list[str] = []
        if disable_sandbox:
            sandbox_args = ["--no-sandbox", "--disable-setuid-sandbox"]
            logger.warning("Chromium sandbox disabled via SEEDBUSTER_DISABLE_CHROMIUM_SANDBOX=1")
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            chromium_sandbox=not disable_sandbox,
            args=[
                "--disable-dev-shm-usage",
                "--disable-gpu",
                *sandbox_args,
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

    async def analyze(self, domain: str, explore: bool = True) -> BrowserResult:
        """Analyze a domain and collect evidence.

        Args:
            domain: The domain to analyze (can include path like domain.com/path)
            explore: If True, click through wallet/recovery buttons to find hidden forms
        """
        if not self._browser:
            await self.start()

        raw_target = domain.strip()
        parsed_target = urlparse(raw_target if "://" in raw_target else f"https://{raw_target}")
        target_host = parsed_target.hostname or raw_target.split("/")[0]

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
            blocked_internal_requests = []
            host_safety_cache: dict[str, bool] = {}

            async def is_global_destination(hostname: str) -> bool:
                """Best-effort check that hostname resolves to global/public IPs."""
                host_key = (hostname or "").strip().lower()
                if not host_key:
                    return True

                cached = host_safety_cache.get(host_key)
                if cached is not None:
                    # Never trust cached-allow for the primary target host (DNS rebinding)
                    if cached is False or host_key != (target_host or "").lower():
                        return cached

                try:
                    ip_obj = ipaddress.ip_address(host_key)
                    safe = ip_obj.is_global
                except ValueError:
                    try:
                        addrinfos = await asyncio.to_thread(
                            socket.getaddrinfo, host_key, None, socket.AF_UNSPEC, socket.SOCK_STREAM
                        )
                        resolved_ips = {sockaddr[0] for *_rest, sockaddr in addrinfos}
                        safe = bool(resolved_ips) and all(
                            ipaddress.ip_address(ip).is_global for ip in resolved_ips
                        )
                    except Exception:
                        # Fail closed on resolution errors to avoid SSRF surprises.
                        safe = False

                # Cache denials always; cache allows only for non-target hosts.
                if safe is False or host_key != (target_host or "").lower():
                    host_safety_cache[host_key] = safe
                return safe

            async def handle_route(route):
                """Block anti-bot services and private/local SSRF targets."""
                url = route.request.url

                url_lower = url.lower()
                if any(antibot in url_lower for antibot in ANTIBOT_DOMAINS):
                    blocked_requests.append(url)
                    logger.debug(f"Blocked anti-bot request: {url}")
                    await route.abort()
                    return

                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if hostname and parsed.scheme in ("http", "https", "ws", "wss"):
                        if not await is_global_destination(hostname):
                            blocked_internal_requests.append(url)
                            logger.debug(f"Blocked private/local request (SSRF guard): {url}")
                            await route.abort()
                            return
                except Exception:
                    # If parsing fails, don't block.
                    ...
                await route.continue_()

            # Enable request interception to block anti-bot services
            await page.route("**/*", handle_route)

            async def handle_request(request):
                try:
                    url = request.url
                    # Track external requests
                    if not url.startswith("data:"):
                        parsed = urlparse(url)
                        request_host = parsed.hostname
                        if request_host and request_host != target_host:
                            external_domains.add(request_host)
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
            url = raw_target if raw_target.startswith(("http://", "https://")) else f"https://{raw_target}"
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
                except Exception:
                    await asyncio.sleep(2.0)  # Fallback wait if selector fails
                result.screenshot_early = await page.screenshot(full_page=True)
                result.html_early = await page.content()
                result.title_early = await page.title()

                # Now wait for full page load (networkidle) - but don't fail if it times out
                # Some sites (WordPress, etc.) have continuous network activity and never become "idle"
                try:
                    await page.wait_for_load_state("networkidle", timeout=self.timeout)
                except PlaywrightError as idle_err:
                    if "Timeout" in str(idle_err):
                        logger.warning(f"networkidle timeout for {domain}, continuing with DOM content")
                    else:
                        raise  # Re-raise non-timeout errors

            except PlaywrightError as e:
                # Try HTTP if HTTPS fails
                if "ERR_" in str(e) or "Timeout" in str(e):
                    url = (
                        raw_target.replace("https://", "http://", 1)
                        if raw_target.startswith("https://")
                        else (raw_target if raw_target.startswith("http://") else f"http://{raw_target}")
                    )
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
                        except Exception:
                            await asyncio.sleep(2.0)
                        result.screenshot_early = await page.screenshot(full_page=True)
                        result.html_early = await page.content()
                        result.title_early = await page.title()

                        # networkidle is non-fatal on HTTP fallback too
                        try:
                            await page.wait_for_load_state("networkidle", timeout=self.timeout)
                        except PlaywrightError as idle_err:
                            if "Timeout" in str(idle_err):
                                logger.warning(f"networkidle timeout for {domain} (HTTP), continuing with DOM content")
                            else:
                                raise
                    except PlaywrightError as e2:
                        # Only fail if the goto itself failed, not networkidle
                        if "goto" in str(e2).lower() or "ERR_" in str(e2):
                            result.error = f"Failed to load: {str(e2)[:200]}"
                            return result
                        logger.warning(f"HTTP fallback issue for {domain}: {e2}")
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
            result.blocked_internal_requests = blocked_internal_requests

            # Detect evasion: check if content changed significantly
            if result.title_early and result.title:
                if result.title_early != result.title:
                    result.evasion_detected = True
                    logger.info(f"Evasion detected: title changed from '{result.title_early}' to '{result.title}'")

            # Analyze forms and inputs
            result.forms = await self._extract_forms(page)
            result.input_fields = await self._extract_inputs(page)

            # Explore navigation to find hidden phishing forms
            if explore:
                try:
                    await self._explore_navigation(page, result)
                except Exception as e:
                    logger.warning(f"Exploration failed (non-fatal): {e}")

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
                        tag: input.tagName.toLowerCase(),
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

    def _is_mnemonic_form(self, inputs: list[dict], page_text: str = "") -> bool:
        """Check if the page contains a mnemonic/seed phrase input form.

        Detects both:
        - 12+ individual word inputs (common pattern)
        - Single textarea for mnemonic entry (like Kaspa-NG phishing)
        """
        page_text_lower = page_text.lower()

        # Check for mnemonic-related keywords in page text
        mnemonic_keywords = [
            "12 words", "24 words", "12-word", "24-word",
            "mnemonic", "seed phrase", "recovery phrase",
            "secret phrase", "backup phrase", "enter mnemonic",
            "import mnemonic", "comprised of 12", "comprised of 24"
        ]
        has_mnemonic_text = any(kw in page_text_lower for kw in mnemonic_keywords)

        # Check for textarea with mnemonic-related attributes
        for inp in inputs:
            if inp.get("tag") == "textarea":
                attrs = (
                    inp.get("placeholder", "") +
                    inp.get("name", "") +
                    inp.get("id", "") +
                    inp.get("class", "")
                ).lower()
                if any(kw in attrs for kw in ["mnemonic", "seed", "phrase", "word", "secret"]):
                    return True
                # If page has mnemonic text and there's a textarea, likely seed form
                if has_mnemonic_text:
                    return True

        # Check for 12+ text inputs (traditional pattern)
        text_inputs = [
            inp for inp in inputs
            if inp.get("type") in ("text", "password", "")
            and inp.get("tag") != "textarea"
        ]
        if len(text_inputs) >= 12:
            return True

        # Check for inputs with seed-related names/placeholders
        seed_inputs = [
            inp for inp in inputs
            if any(kw in (inp.get("placeholder", "") + inp.get("name", "") + inp.get("id", "")).lower()
                   for kw in ["word", "seed", "phrase", "mnemonic"])
        ]
        if seed_inputs and has_mnemonic_text:
            return True

        return False

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

    async def _find_visible_buttons(self, page: Page) -> list[dict]:
        """Find all visible clickable elements on the page with their text."""
        try:
            buttons = await page.evaluate("""
                () => {
                    const clickables = document.querySelectorAll('button, a, [role="button"], [onclick]');
                    const results = [];
                    for (const el of clickables) {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        // Check if element is visible
                        if (rect.width > 10 && rect.height > 10 &&
                            style.display !== 'none' && style.visibility !== 'hidden' &&
                            style.opacity !== '0') {
                            const text = (el.textContent || el.innerText || '').trim();
                            if (text && text.length < 100) {
                                results.push({
                                    text: text.substring(0, 50),
                                    tag: el.tagName.toLowerCase(),
                                    id: el.id || null,
                                    class: el.className || null
                                });
                            }
                        }
                    }
                    return results;
                }
            """)
            return buttons
        except Exception as e:
            logger.debug(f"Error finding visible buttons: {e}")
            return []

    async def _explore_navigation(self, page: Page, result: BrowserResult, max_clicks: int = 6):
        """Click through navigation elements to discover hidden phishing forms.

        This explores wallet/recovery buttons that may hide seed phrase forms.
        After each click, it re-scans for high-priority targets (like mnemonic options)
        that may have appeared on the new page.
        """
        logger.info(f"Starting click-through exploration for {result.domain}")

        # First, log what buttons we can see
        visible_buttons = await self._find_visible_buttons(page)
        if visible_buttons:
            button_texts = [b["text"][:30] for b in visible_buttons[:8]]
            logger.info(f"Found {len(visible_buttons)} buttons: {button_texts}")
        else:
            logger.info("No visible buttons found on page (will still try known targets)")

        explored_texts = set()
        clicks_made = 0

        # Priority groups - we'll re-scan for top priority targets after each click
        HIGH_PRIORITY_TARGETS = [
            "12-word", "24-word", "12 word", "24 word", "12 words", "24 words",
            "mnemonic", "import mnemonic", "enter mnemonic", "seed phrase",
            "secret phrase", "recover", "restore", "import", "recovery"
        ]

        while clicks_made < max_clicks:
            # After each click, first look for high-priority targets (mnemonic options)
            # This ensures we don't miss targets that appear after clicking "Continue"
            found_target = False

            # Log available buttons for debugging
            visible_buttons = await self._find_visible_buttons(page)
            button_texts = [b["text"] for b in visible_buttons[:10]]
            logger.debug(f"Visible buttons on page: {button_texts}")

            # First pass: check for high-priority mnemonic targets
            for target_text in HIGH_PRIORITY_TARGETS:
                target_key = target_text.lower()
                if target_key in explored_texts:
                    continue

                element = await self._find_clickable_element(page, target_text)
                if element:
                    actual_text = await element.text_content()
                    actual_text = actual_text.strip()[:50] if actual_text else target_text

                    logger.info(f"Exploration: clicking HIGH PRIORITY '{actual_text}' on {result.domain}")

                    clicked = await self._click_element_resilient(page, element, label=actual_text)
                    explored_texts.add(target_key)
                    if not clicked:
                        logger.info(
                            f"Exploration: failed to click HIGH PRIORITY '{actual_text}' on {result.domain}"
                        )
                        continue

                    clicks_made += 1

                    # Wait and capture - returns True if seed form found
                    seed_found = await self._wait_and_capture_step(page, result, actual_text)
                    found_target = True
                    if seed_found:
                        # Found the seed form - no need to keep exploring
                        logger.info(f"Stopping exploration - seed form found on {result.domain}")
                        break  # Break out of for loop
                    break  # Re-scan after each click

            if found_target and any(getattr(s, "is_seed_form", False) for s in result.exploration_steps):
                # Seed form found - break out of while loop
                break
            if found_target:
                continue

            # Second pass: check remaining targets by priority
            sorted_targets = sorted(self.exploration_targets, key=lambda x: x.get("priority", 1))
            for target in sorted_targets:
                target_text = str(target.get("text", "")).lower()
                if target_text in explored_texts:
                    continue

                element = await self._find_clickable_element(page, target_text)
                if element:
                    actual_text = await element.text_content()
                    actual_text = actual_text.strip()[:50] if actual_text else target_text

                    logger.info(f"Exploration: clicking '{actual_text}' on {result.domain}")

                    clicked = await self._click_element_resilient(page, element, label=actual_text)
                    explored_texts.add(target_text)
                    if not clicked:
                        logger.info(f"Exploration: failed to click '{actual_text}' on {result.domain}")
                        continue

                    clicks_made += 1

                    # Wait and capture - returns True if seed form found
                    seed_found = await self._wait_and_capture_step(page, result, actual_text)
                    found_target = True
                    if seed_found:
                        # Found the seed form - no need to keep exploring
                        logger.info(f"Stopping exploration - seed form found on {result.domain}")
                    break  # Re-scan after each click

            # Check if we should stop (seed form found or no more targets)
            if any(getattr(s, "is_seed_form", False) for s in result.exploration_steps):
                break
            if not found_target:
                # No more targets to click
                break

        if clicks_made > 0:
            result.explored = True
            logger.info(
                f"Exploration complete: {clicks_made} clicks, "
                f"{len(result.exploration_steps)} steps captured"
            )

    @staticmethod
    def _extract_navigation_target_from_onclick(onclick: str) -> Optional[str]:
        """Extract a navigation target URL from an inline onclick handler."""
        if not onclick:
            return None

        patterns = [
            r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, onclick, re.I)
            if match:
                target = match.group(1).strip()
                return target or None
        return None

    async def _get_element_navigation_target(self, page: Page, element) -> Optional[str]:
        """Try to resolve an element's href/onclick navigation target."""
        try:
            href = await element.get_attribute("href")
            if href:
                return urljoin(page.url, href)
        except Exception:
            pass

        try:
            onclick = await element.get_attribute("onclick")
            target = self._extract_navigation_target_from_onclick(onclick or "")
            if target:
                return urljoin(page.url, target)
        except Exception:
            pass

        return None

    async def _click_element_resilient(self, page: Page, element, label: str) -> bool:
        """Click an element with fallbacks to avoid navigation timeouts/overlays."""
        last_error: Optional[Exception] = None

        # Attempt 1: normal click but don't wait for navigation (we capture after).
        try:
            await element.click(timeout=5000, no_wait_after=True)
            return True
        except Exception as e:
            last_error = e

        # Attempt 2: scroll into view + force click (bypasses actionability issues).
        try:
            try:
                await element.scroll_into_view_if_needed()
            except Exception:
                pass
            await element.click(timeout=5000, force=True, no_wait_after=True)
            return True
        except Exception as e:
            last_error = e

        # Attempt 3: JS click dispatch (bypasses pointer intercept).
        try:
            await page.evaluate("(el) => el.click()", element)
            return True
        except Exception as e:
            last_error = e

        # Attempt 4: direct navigation from href/onclick (covers classic templates).
        try:
            target = await self._get_element_navigation_target(page, element)
            if target:
                await page.goto(target, wait_until="domcontentloaded", timeout=self.timeout)
                return True
        except Exception as e:
            last_error = e

        logger.debug(f"Exploration click failed for '{label}': {str(last_error)[:200]}")
        return False

    async def _find_clickable_element(self, page: Page, target_text: str):
        """Find a clickable element containing the target text."""
        # Use fast JS-based search instead of slow selector waits
        try:
            handle = await page.evaluate_handle(f"""
                () => {{
                    const targetText = '{target_text}'.toLowerCase();
                    // Check buttons first (most likely)
                    let firstMatch = null;
                    for (const el of document.querySelectorAll('button')) {{
                        const text = (el.textContent || '').toLowerCase();
                        if (text.includes(targetText)) {{
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 10 && rect.height > 10) return el;
                            if (!firstMatch) firstMatch = el;
                        }}
                    }}
                    // Then links
                    for (const el of document.querySelectorAll('a')) {{
                        const text = (el.textContent || '').toLowerCase();
                        if (text.includes(targetText)) {{
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 10 && rect.height > 10) return el;
                            if (!firstMatch) firstMatch = el;
                        }}
                    }}
                    // Then role=button
                    for (const el of document.querySelectorAll('[role="button"]')) {{
                        const text = (el.textContent || '').toLowerCase();
                        if (text.includes(targetText)) {{
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 10 && rect.height > 10) return el;
                            if (!firstMatch) firstMatch = el;
                        }}
                    }}
                    // Finally clickable divs (but NOT paragraphs/spans with lots of text)
                    for (const el of document.querySelectorAll('div[onclick], div.btn, div.button')) {{
                        const text = (el.textContent || '').toLowerCase();
                        if (text.includes(targetText) && text.length < 100) {{
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 10 && rect.height > 10) return el;
                            if (!firstMatch) firstMatch = el;
                        }}
                    }}
                    // Fallback: return first matching element even if hidden (UI cloaking often sets display:none).
                    return firstMatch;
                }}
            """)
            element = handle.as_element()
            if element is None:
                await handle.dispose()
                return None
            return element
        except Exception as e:
            logger.debug(f"Fast element search failed for '{target_text}': {e}")
        return None

    async def _wait_and_capture_step(self, page: Page, result: BrowserResult, button_text: str) -> bool:
        """Wait for page update and capture exploration step.

        Returns True if a seed form was found (caller should stop exploring).
        """
        button_lower = button_text.lower()

        # Longer wait for seed/recovery buttons - they typically load a form
        if any(kw in button_lower for kw in ["seed", "recover", "mnemonic", "import", "restore", "legacy"]):
            await asyncio.sleep(2.5)  # Extra wait for seed forms to render
            try:
                # Wait for inputs to appear (seed forms have many inputs)
                await page.wait_for_selector(
                    "input[type='text'], input[type='password'], textarea", timeout=3000
                )
            except Exception:
                pass
        else:
            await asyncio.sleep(1.5)

        try:
            await page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass

        step = ExplorationStep(button_text=button_text)
        try:
            step.screenshot = await page.screenshot()
            step.html = await page.content()
            step.title = await page.title()
            step.url = page.url
            step.input_fields = await self._extract_inputs(page)
            step.forms = await self._extract_forms(page)
            step.success = True

            # Get page text for mnemonic detection
            page_text = await page.evaluate("() => document.body?.innerText || ''")

            # Check if this is a mnemonic/seed form (textarea or 12+ inputs)
            if self._is_mnemonic_form(step.input_fields, page_text):
                step.is_seed_form = True
                logger.warning(
                    f"SEED FORM FOUND after clicking '{button_text}' - "
                    f"page contains mnemonic input form"
                )

            # Log if we found seed-like inputs
            seed_inputs = [
                inp for inp in step.input_fields
                if any(kw in (inp.get("placeholder", "") + inp.get("name", "")).lower()
                       for kw in ["word", "seed", "phrase", "mnemonic"])
            ]
            if seed_inputs and not getattr(step, "is_seed_form", False):
                logger.info(
                    f"Exploration found {len(seed_inputs)} seed-like inputs after clicking '{button_text}'"
                )

            # Check if this step has more inputs than the main page
            if len(step.input_fields) > len(result.input_fields):
                logger.info(
                    f"Exploration step '{button_text}' has {len(step.input_fields)} inputs "
                    f"(main page: {len(result.input_fields)})"
                )

        except Exception as e:
            step.error = str(e)
            logger.debug(f"Error capturing exploration step: {e}")

        result.exploration_steps.append(step)

        # Return True if seed form found - caller should stop exploring
        return getattr(step, "is_seed_form", False)

    async def capture_fingerprint(self, domain: str) -> Optional[bytes]:
        """Capture just a screenshot for fingerprinting."""
        result = await self.analyze(domain)
        return result.screenshot if result.success else None
