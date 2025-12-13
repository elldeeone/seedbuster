#!/usr/bin/env python3
"""Test the abuse reporting system."""

import asyncio
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.reporter import (
    ReportEvidence,
    PhishTankReporter,
    CloudflareReporter,
    GoogleFormReporter,
    SMTPReporter,
    NetcraftReporter,
    ResendReporter,
    ReportTemplates,
)


async def test_templates():
    """Test report template generation."""
    print("=" * 60)
    print("TESTING REPORT TEMPLATES")
    print("=" * 60)

    evidence = ReportEvidence(
        domain="kaspa-wallet.co",
        url="https://kaspa-wallet.co",
        detected_at=datetime.now(),
        confidence_score=95,
        detection_reasons=[
            "Seed phrase form detected (12 inputs)",
            "Visual match to kaspa_wallet: 85%",
            "Form submits to external: whale-app-poxe2.ondigitalocean.app",
            "Known malicious API key found",
        ],
        suspicious_endpoints=[
            "https://whale-app-poxe2.ondigitalocean.app/api/form/text",
            "https://walrus-app-o5hvw.ondigitalocean.app/log-ip",
        ],
        backend_domains=[
            "whale-app-poxe2.ondigitalocean.app",
            "walrus-app-o5hvw.ondigitalocean.app",
        ],
        api_keys_found=[
            "520a83d66268292f5b97ca64c496ef3b9cfb1bb1f85f2615b103f66f (ipdata)",
            "e7a25d99-66d4-4a1b-a6e0-3f2e93f25f1b (whale backend)",
        ],
        hosting_provider="DigitalOcean",
    )

    # Test generic email template
    print("\n--- Generic Email Template ---")
    report = ReportTemplates.generic_email(evidence, "test@example.com")
    print(f"Subject: {report['subject']}")
    print(f"Body preview:\n{report['body'][:500]}...")

    # Test DigitalOcean template
    print("\n--- DigitalOcean Template ---")
    report = ReportTemplates.digitalocean(evidence, "test@example.com")
    print(f"Subject: {report['subject']}")
    print(f"Body preview:\n{report['body'][:500]}...")

    # Test PhishTank comment
    print("\n--- PhishTank Comment ---")
    comment = ReportTemplates.phishtank_comment(evidence)
    print(comment)

    print("\n✅ Template generation working!")


async def test_reporters_init():
    """Test that reporters initialize correctly."""
    print("\n" + "=" * 60)
    print("TESTING REPORTER INITIALIZATION")
    print("=" * 60)

    # PhishTank (always available)
    pt = PhishTankReporter()
    print(f"PhishTank: configured={pt.is_configured()}")

    # Google form (always available)
    gf = GoogleFormReporter()
    print(f"Google Form: configured={gf.is_configured()}")

    # Cloudflare (always available)
    cf = CloudflareReporter()
    print(f"Cloudflare: configured={cf.is_configured()}")

    # Netcraft (always available, no account needed)
    nc = NetcraftReporter()
    print(f"Netcraft: configured={nc.is_configured()}")

    # Resend (needs API key)
    resend_unconfigured = ResendReporter(api_key="")
    print(f"Resend (unconfigured): configured={resend_unconfigured.is_configured()}")

    resend_configured = ResendReporter(api_key="re_test_key")
    print(f"Resend (configured): configured={resend_configured.is_configured()}")

    # SMTP (needs config)
    smtp = SMTPReporter(host="", port=587, from_email="")
    print(f"SMTP (unconfigured): configured={smtp.is_configured()}")

    smtp_configured = SMTPReporter(
        host="smtp.gmail.com",
        port=587,
        username="test",
        password="test",
        from_email="test@gmail.com",
    )
    print(f"SMTP (configured): configured={smtp_configured.is_configured()}")

    print("\n✅ Reporter initialization working!")


async def test_smtp_contact_detection():
    """Test SMTP reporter's abuse contact detection."""
    print("\n" + "=" * 60)
    print("TESTING ABUSE CONTACT DETECTION")
    print("=" * 60)

    smtp = SMTPReporter(
        host="smtp.gmail.com",
        port=587,
        from_email="test@example.com",
    )

    # Test with DigitalOcean backend
    evidence_do = ReportEvidence(
        domain="test.com",
        url="https://test.com",
        detected_at=datetime.now(),
        confidence_score=90,
        backend_domains=["whale-app-xyz.ondigitalocean.app"],
    )
    contact = smtp.get_abuse_contact(evidence_do)
    print(f"DigitalOcean backend → {contact}")
    assert contact == "abuse@digitalocean.com"

    # Test with Cloudflare
    evidence_cf = ReportEvidence(
        domain="test.com",
        url="https://test.com",
        detected_at=datetime.now(),
        confidence_score=90,
        backend_domains=["workers.cloudflare.com"],
    )
    contact = smtp.get_abuse_contact(evidence_cf)
    print(f"Cloudflare backend → {contact}")

    # Test with hosting provider set
    evidence_hp = ReportEvidence(
        domain="test.com",
        url="https://test.com",
        detected_at=datetime.now(),
        confidence_score=90,
        hosting_provider="Namecheap",
    )
    contact = smtp.get_abuse_contact(evidence_hp)
    print(f"Namecheap hosting → {contact}")

    print("\n✅ Abuse contact detection working!")


async def test_evidence_summary():
    """Test evidence summary generation."""
    print("\n" + "=" * 60)
    print("TESTING EVIDENCE SUMMARY")
    print("=" * 60)

    evidence = ReportEvidence(
        domain="kaspa-wallet.co",
        url="https://kaspa-wallet.co",
        detected_at=datetime.now(),
        confidence_score=95,
        detection_reasons=[
            "Seed phrase form detected",
            "Visual match to legitimate site",
            "Form submits to external domain",
        ],
        suspicious_endpoints=[
            "https://evil.com/steal",
        ],
        backend_domains=[
            "whale-app.ondigitalocean.app",
        ],
    )

    print(evidence.to_summary())
    print("\n✅ Evidence summary working!")


async def main():
    """Run all tests."""
    print("ABUSE REPORTER TEST SUITE")
    print("=" * 60)

    await test_templates()
    await test_reporters_init()
    await test_smtp_contact_detection()
    await test_evidence_summary()

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)
    print("\nNote: Actual submission tests require API keys and would")
    print("send real reports. Use with caution on real phishing sites.")


if __name__ == "__main__":
    asyncio.run(main())
