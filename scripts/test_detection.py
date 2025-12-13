#!/usr/bin/env python3
"""Test full detection pipeline against a known scam site."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer.browser import BrowserAnalyzer
from src.analyzer.detector import PhishingDetector


async def main():
    """Test detection pipeline."""
    domain = "kaspa-wallet.co"

    print(f"Testing detection pipeline against: {domain}")
    print("=" * 60)

    browser = BrowserAnalyzer(timeout=30, headless=True)
    detector = PhishingDetector(
        fingerprints_dir=Path("data/fingerprints"),
        config_dir=Path("config"),  # Load threat intel from config/
        keywords=["kaspa", "wallet"],
    )

    try:
        await browser.start()
        print("Browser started with stealth mode")

        result = await browser.analyze(domain)

        if result.success:
            print("\nBrowser analysis:")
            print(f"  Final URL: {result.final_url}")
            print(f"  Title: {result.title}")
            print(f"  Forms: {len(result.forms)}")
            print(f"  Inputs: {len(result.input_fields)}")
            print(f"  External requests: {len(result.external_requests)}")

            # Run detection
            detection = detector.detect(result, domain_score=95)  # High domain score for kaspa-wallet.co

            print(f"\n{'='*60}")
            print("DETECTION RESULTS")
            print(f"{'='*60}")
            print(f"Verdict: {detection.verdict.upper()}")
            print(f"Score: {detection.score}/100")
            print(f"Confidence: {detection.confidence:.0%}")
            print("\nReasons:")
            for reason in detection.reasons:
                print(f"  - {reason}")

            if detection.suspicious_endpoints:
                print("\nSuspicious endpoints:")
                for ep in detection.suspicious_endpoints:
                    print(f"  - {ep}")

            print(f"\nVisual match score: {detection.visual_match_score:.0f}%")
            if detection.matched_fingerprint:
                print(f"Matched fingerprint: {detection.matched_fingerprint}")

        else:
            print(f"\nFailed: {result.error}")

    finally:
        await browser.stop()


if __name__ == "__main__":
    asyncio.run(main())
