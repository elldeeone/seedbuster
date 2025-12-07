#!/usr/bin/env python3
"""Capture fingerprint of legitimate Kaspa wallet site.

Run this once to create the reference fingerprint for clone detection.

Usage:
    python scripts/capture_fingerprint.py
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from playwright.async_api import async_playwright
from src.analyzer.detector import PhishingDetector


async def main():
    """Capture fingerprint of wallet.kaspanet.io recovery page."""
    fingerprints_dir = Path("data/fingerprints")
    fingerprints_dir.mkdir(parents=True, exist_ok=True)

    detector = PhishingDetector(fingerprints_dir=fingerprints_dir)

    print("Starting browser...")
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=True)
    context = await browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
    )
    page = await context.new_page()

    try:
        # Capture landing page first
        print("Loading wallet.kaspanet.io...")
        await page.goto("https://wallet.kaspanet.io/", wait_until="networkidle", timeout=60000)
        await asyncio.sleep(3)  # Wait for JS to render

        # Save landing page fingerprint
        landing_screenshot = await page.screenshot(full_page=True)
        detector.save_fingerprint("kaspanet-wallet-landing", landing_screenshot)
        ref_path = fingerprints_dir / "kaspanet-wallet-landing.png"
        ref_path.write_bytes(landing_screenshot)
        print(f"Landing page fingerprint saved: {ref_path}")

        # Now navigate to recovery/seed entry page
        print("Looking for 'Recover from seed' or similar...")

        # Try various selectors that might lead to seed recovery
        recovery_selectors = [
            "text=Recover",
            "text=recover",
            "text=Import",
            "text=import",
            "text=Restore",
            "text=restore",
            "text=seed",
            "text=Seed",
            "button:has-text('Recover')",
            "a:has-text('Recover')",
            "[data-action='recover']",
        ]

        clicked = False
        for selector in recovery_selectors:
            try:
                element = page.locator(selector).first
                if await element.is_visible(timeout=2000):
                    print(f"Found recovery option: {selector}")
                    await element.click()
                    clicked = True
                    await asyncio.sleep(3)  # Wait for page to load
                    break
            except Exception:
                continue

        if clicked:
            # Capture the seed recovery page
            recovery_screenshot = await page.screenshot(full_page=True)
            detector.save_fingerprint("kaspanet-wallet-recovery", recovery_screenshot)
            ref_path = fingerprints_dir / "kaspanet-wallet-recovery.png"
            ref_path.write_bytes(recovery_screenshot)
            print(f"Recovery page fingerprint saved: {ref_path}")

            # Also save the main fingerprint as the recovery page (most important)
            detector.save_fingerprint("kaspanet-wallet", recovery_screenshot)
            print("Primary fingerprint set to recovery page")
        else:
            print("Could not find recovery option - saving landing page as primary")
            detector.save_fingerprint("kaspanet-wallet", landing_screenshot)

        print("\nCapture complete! Fingerprints saved:")
        for fp in fingerprints_dir.glob("*.hash"):
            print(f"  - {fp.name}")

    except Exception as e:
        print(f"Error during capture: {e}")
        import traceback
        traceback.print_exc()

    finally:
        await browser.close()
        await playwright.stop()


if __name__ == "__main__":
    asyncio.run(main())
