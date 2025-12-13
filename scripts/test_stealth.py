#!/usr/bin/env python3
"""Test stealth browser against a known scam site."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer.browser import BrowserAnalyzer


async def main():
    """Test stealth browser."""
    domain = "kaspa-wallet.co"

    print(f"Testing stealth browser against: {domain}")
    print("=" * 50)

    browser = BrowserAnalyzer(timeout=30, headless=True)

    try:
        await browser.start()
        print("Browser started with stealth mode")

        result = await browser.analyze(domain)

        if result.success:
            print("\nSuccess!")
            print(f"Final URL: {result.final_url}")
            print(f"Title: {result.title}")
            print(f"Status: {result.status_code}")
            print(f"Forms found: {len(result.forms)}")
            print(f"Inputs found: {len(result.input_fields)}")
            print(f"External requests: {len(result.external_requests)}")

            if result.external_requests:
                print("\nExternal domains contacted:")
                for ext in result.external_requests[:10]:
                    print(f"  - {ext}")

            # Check HTML for wallet-related content
            if result.html:
                html_lower = result.html.lower()
                print("\nContent analysis:")
                print(f"  - Contains 'seed': {'seed' in html_lower}")
                print(f"  - Contains 'wallet': {'wallet' in html_lower}")
                print(f"  - Contains 'recovery': {'recovery' in html_lower}")
                print(f"  - Contains 'phrase': {'phrase' in html_lower}")
                print(f"  - Contains 'kaspa': {'kaspa' in html_lower}")
                print(f"  - HTML length: {len(result.html)} chars")

            # Save screenshot for comparison
            if result.screenshot:
                output_path = Path("data/test_stealth_screenshot.png")
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(result.screenshot)
                print(f"\nScreenshot saved to: {output_path}")

            # Save HTML for inspection
            if result.html:
                html_path = Path("data/test_stealth_page.html")
                html_path.write_text(result.html)
                print(f"HTML saved to: {html_path}")

            print("\nCompare the screenshot with what you see in your browser!")
        else:
            print(f"\nFailed: {result.error}")

    finally:
        await browser.stop()


if __name__ == "__main__":
    asyncio.run(main())
