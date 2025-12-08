#!/usr/bin/env python3
"""Test with headed (visible) browser to bypass fingerprinting."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from playwright.async_api import async_playwright


async def main():
    """Test with headed browser."""
    domain = "kaspa-wallet.co"

    print(f"Testing HEADED browser against: {domain}")
    print("A browser window will open - watch what content loads!")
    print("=" * 60)

    playwright = await async_playwright().start()

    # Launch HEADED browser (visible window)
    browser = await playwright.chromium.launch(
        headless=False,  # This makes it visible!
        args=["--start-maximized"],
    )

    context = await browser.new_context(
        viewport={"width": 1920, "height": 1080},
        ignore_https_errors=True,
    )

    page = await context.new_page()

    try:
        print(f"Loading {domain}...")
        await page.goto(f"https://{domain}", wait_until="networkidle", timeout=30000)

        # Wait for user to see it
        print("\nPage loaded! Waiting 10 seconds for you to see...")
        await asyncio.sleep(10)

        # Capture screenshot
        screenshot = await page.screenshot(full_page=True)
        output_path = Path("data/test_headed_screenshot.png")
        output_path.write_bytes(screenshot)
        print(f"\nScreenshot saved to: {output_path}")

        # Check for inputs
        inputs = await page.query_selector_all('input')
        print(f"Found {len(inputs)} input fields")

        title = await page.title()
        print(f"Title: {title}")

    finally:
        await browser.close()
        await playwright.stop()


if __name__ == "__main__":
    asyncio.run(main())
