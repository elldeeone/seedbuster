#!/usr/bin/env python3
"""Capture the recovery page by clicking 'Recover from Seed' button."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from playwright.async_api import async_playwright
from src.analyzer.detector import PhishingDetector


async def main():
    """Capture wallet.kaspanet.io recovery dialog."""
    fingerprints_dir = Path("data/fingerprints")
    fingerprints_dir.mkdir(parents=True, exist_ok=True)

    detector = PhishingDetector(fingerprints_dir=fingerprints_dir)

    print("Starting browser...")
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=False)
    context = await browser.new_context(
        viewport={"width": 1280, "height": 800},
        ignore_https_errors=True,
    )
    page = await context.new_page()

    try:
        print("Loading wallet.kaspanet.io...")
        await page.goto("https://wallet.kaspanet.io/", wait_until="networkidle", timeout=60000)

        print("Waiting for app to fully initialize...")
        await asyncio.sleep(8)  # Give the PWA more time

        # First, click somewhere neutral to dismiss any popups/menus
        print("Clicking to dismiss any overlays...")
        await page.mouse.click(100, 100)
        await asyncio.sleep(1)

        # Now look for the exact "Recover from Seed" button
        print("Looking for 'Recover from Seed' button...")

        # Try exact text match with force click
        try:
            recover_btn = page.get_by_text("Recover from Seed", exact=True)
            if await recover_btn.is_visible(timeout=5000):
                print("Found 'Recover from Seed' button, clicking...")
                await recover_btn.click(force=True)
                await asyncio.sleep(3)
        except Exception as e:
            print(f"Exact text match failed: {e}")

        # Check if recovery dialog appeared (should have 12 input fields)
        inputs = await page.query_selector_all('input[type="text"], input:not([type])')
        print(f"Found {len(inputs)} text inputs on page")

        if len(inputs) < 10:
            print("\nRecovery dialog didn't appear automatically.")
            print("Please manually click 'Recover from Seed' button now...")
            print("Waiting 20 seconds...")
            await asyncio.sleep(20)

        # Capture the screen
        print("\nCapturing screenshot...")
        screenshot = await page.screenshot(full_page=True)

        # Save fingerprints
        detector.save_fingerprint("kaspanet-wallet-recovery", screenshot)
        ref_path = fingerprints_dir / "kaspanet-wallet-recovery.png"
        ref_path.write_bytes(screenshot)
        print(f"Recovery page saved: {ref_path}")

        detector.save_fingerprint("kaspanet-wallet", screenshot)
        print("Primary fingerprint updated")

        print("\nDone! Check the screenshot at:")
        print(f"  {ref_path}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        await browser.close()
        await playwright.stop()


if __name__ == "__main__":
    asyncio.run(main())
