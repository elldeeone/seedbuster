#!/usr/bin/env python3
"""Capture the recovery page by using JavaScript to trigger the dialog."""

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

    print("Starting browser (headed mode for debugging)...")
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=False)  # Headed to see what happens
    context = await browser.new_context(
        viewport={"width": 1280, "height": 800},
        ignore_https_errors=True,
    )
    page = await context.new_page()

    try:
        print("Loading wallet.kaspanet.io...")
        await page.goto("https://wallet.kaspanet.io/", wait_until="networkidle", timeout=60000)

        # Wait for the app to fully load
        print("Waiting for app to initialize...")
        await asyncio.sleep(5)

        # Try to find and click recovery button using various methods
        print("Attempting to trigger recovery dialog...")

        # Method 1: Try clicking any element with "recover" text
        try:
            await page.evaluate("""
                () => {
                    // Find all elements and check their text content
                    const allElements = document.querySelectorAll('*');
                    for (const el of allElements) {
                        if (el.textContent && el.textContent.toLowerCase().includes('recover') &&
                            el.textContent.length < 50) {
                            console.log('Found element:', el.tagName, el.textContent);
                            el.click();
                            return true;
                        }
                    }
                    return false;
                }
            """)
            await asyncio.sleep(3)
        except Exception as e:
            print(f"Method 1 failed: {e}")

        # Method 2: Look for flow-btn or custom elements
        try:
            buttons = await page.query_selector_all('flow-btn, button, [role="button"]')
            for btn in buttons:
                text = await btn.text_content()
                if text and 'recover' in text.lower():
                    print(f"Clicking button: {text}")
                    await btn.click()
                    await asyncio.sleep(3)
                    break
        except Exception as e:
            print(f"Method 2 failed: {e}")

        # Method 3: Dispatch click event
        try:
            await page.evaluate("""
                () => {
                    const event = new MouseEvent('click', {
                        bubbles: true,
                        cancelable: true,
                        view: window
                    });
                    // Try to find recover button in shadow DOM
                    const walker = document.createTreeWalker(
                        document.body,
                        NodeFilter.SHOW_ELEMENT,
                        null,
                        false
                    );
                    let node;
                    while (node = walker.nextNode()) {
                        if (node.shadowRoot) {
                            const shadowElements = node.shadowRoot.querySelectorAll('*');
                            for (const el of shadowElements) {
                                if (el.textContent && el.textContent.toLowerCase().includes('recover')) {
                                    console.log('Found in shadow:', el);
                                    el.dispatchEvent(event);
                                    return;
                                }
                            }
                        }
                    }
                }
            """)
            await asyncio.sleep(3)
        except Exception as e:
            print(f"Method 3 failed: {e}")

        print("\nPlease manually click 'Recover from Seed' in the browser window...")
        print("Waiting 15 seconds for manual interaction...")
        await asyncio.sleep(15)

        # Capture whatever is on screen now
        screenshot = await page.screenshot(full_page=True)

        # Save as recovery fingerprint
        detector.save_fingerprint("kaspanet-wallet-recovery", screenshot)
        ref_path = fingerprints_dir / "kaspanet-wallet-recovery.png"
        ref_path.write_bytes(screenshot)
        print(f"\nRecovery page fingerprint saved: {ref_path}")

        # Also make this the primary fingerprint
        detector.save_fingerprint("kaspanet-wallet", screenshot)
        print("Primary fingerprint updated to recovery page")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        await browser.close()
        await playwright.stop()


if __name__ == "__main__":
    asyncio.run(main())
