#!/usr/bin/env python3
"""Maximum stealth test - patch browser to appear completely normal."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from playwright.async_api import async_playwright


STEALTH_JS = """
// Delete webdriver property
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
    configurable: true
});

// Overwrite the plugins property
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const plugins = [
            {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
            {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
            {name: 'Native Client', filename: 'internal-nacl-plugin'},
        ];
        plugins.length = 3;
        return plugins;
    },
});

// Overwrite languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en'],
});

// Spoof chrome runtime
window.chrome = {
    runtime: {
        connect: () => {},
        sendMessage: () => {},
    },
    loadTimes: () => ({}),
    csi: () => ({}),
    app: {},
};

// Fix permissions query
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications' ?
        Promise.resolve({ state: Notification.permission }) :
        originalQuery(parameters)
);

// Spoof WebGL vendor/renderer
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return 'Intel Inc.';
    if (parameter === 37446) return 'Intel Iris OpenGL Engine';
    return getParameter.call(this, parameter);
};

// Also for WebGL2
if (typeof WebGL2RenderingContext !== 'undefined') {
    const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 37445) return 'Intel Inc.';
        if (parameter === 37446) return 'Intel Iris OpenGL Engine';
        return getParameter2.call(this, parameter);
    };
}

// Hide automation
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;

console.log('Stealth patches applied');
"""


async def main():
    """Test with maximum stealth."""
    domain = "kaspa-wallet.co"

    print(f"Testing MAXIMUM STEALTH against: {domain}")
    print("=" * 60)

    playwright = await async_playwright().start()

    # Launch with extra stealth args
    browser = await playwright.chromium.launch(
        headless=False,
        args=[
            '--disable-blink-features=AutomationControlled',
            '--disable-dev-shm-usage',
            '--disable-infobars',
            '--window-size=1920,1080',
            '--start-maximized',
        ],
    )

    context = await browser.new_context(
        viewport={"width": 1920, "height": 1080},
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        locale="en-US",
        timezone_id="America/New_York",
        ignore_https_errors=True,
    )

    # Inject stealth script BEFORE any page loads
    await context.add_init_script(STEALTH_JS)

    page = await context.new_page()

    try:
        print(f"Loading {domain}...")
        await page.goto(f"https://{domain}", wait_until="networkidle", timeout=30000)

        # Wait and interact like a human
        await asyncio.sleep(2)
        await page.mouse.move(500, 300)
        await asyncio.sleep(0.5)
        await page.mouse.move(700, 400)
        await asyncio.sleep(0.5)

        # Scroll down
        await page.evaluate("window.scrollBy(0, 300)")
        await asyncio.sleep(1)

        print("\nPage loaded! Waiting 8 seconds...")
        await asyncio.sleep(8)

        # Check webdriver detection
        webdriver_status = await page.evaluate("navigator.webdriver")
        print(f"navigator.webdriver: {webdriver_status}")

        # Capture screenshot
        screenshot = await page.screenshot(full_page=True)
        output_path = Path("data/test_stealth_max_screenshot.png")
        output_path.write_bytes(screenshot)
        print(f"Screenshot saved to: {output_path}")

        # Check for inputs
        inputs = await page.query_selector_all('input')
        print(f"Found {len(inputs)} input fields")

        # Check HTML for seed keywords
        html = await page.content()
        print(f"HTML contains 'seed': {'seed' in html.lower()}")
        print(f"HTML contains 'recovery': {'recovery' in html.lower()}")
        print(f"HTML contains 'phrase': {'phrase' in html.lower()}")

        title = await page.title()
        print(f"Title: {title}")

    finally:
        await browser.close()
        await playwright.stop()


if __name__ == "__main__":
    asyncio.run(main())
