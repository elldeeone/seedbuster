from datetime import datetime

from src.reporter.base import ReportEvidence


def test_impersonation_kaspa_wallet_for_seed_phish():
    evidence = ReportEvidence(
        domain="secure-kaspa-wallet.app",
        url="https://secure-kaspa-wallet.app/",
        detected_at=datetime.now(),
        confidence_score=90,
        detection_reasons=["Seed phrase form detected", "Wallet-related title"],
        scam_type="seed_phishing",
        analysis_json={"kit_matches": ["kaspa_ng_phishing"]},
    )

    lines = evidence.get_impersonation_lines()

    assert any("Kaspa Wallet" in line for line in lines)
    assert all("Kaspa NG" not in line for line in lines)


def test_impersonation_kaspa_ng_for_domain_match():
    evidence = ReportEvidence(
        domain="kaspa-ng-support.com",
        url="https://kaspa-ng-support.com/",
        detected_at=datetime.now(),
        confidence_score=90,
        detection_reasons=["Seed phrase form detected"],
        scam_type="seed_phishing",
    )

    lines = evidence.get_impersonation_lines()

    assert any("Kaspa NG" in line for line in lines)
    assert all("Kaspa Wallet" not in line for line in lines)
