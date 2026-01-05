from datetime import datetime

from src.reporter.base import ReportEvidence


def test_review_notes_include_urlscan_when_cloaking(monkeypatch):
    monkeypatch.setenv("DASHBOARD_PUBLIC_URL", "https://seedbuster.xyz")
    evidence = ReportEvidence(
        domain="kaspa-clone.app",
        url="https://kaspa-clone.app/",
        detected_at=datetime.now(),
        confidence_score=90,
        domain_id=123,
        detection_reasons=[
            "TEMPORAL: Cloaking detected (80%): content mismatch",
            "EXTERNAL: urlscan.io historical scan with wallet/seed UI: https://urlscan.io/result/abc123/",
        ],
    )

    summary = evidence.to_summary()

    assert "REVIEWER NOTES:" in summary
    assert "Historical urlscan capture" in summary
    assert "urlscan.io/result/abc123/" in summary
    assert "More information: https://seedbuster.xyz/#/domains/123" in summary


def test_review_notes_anti_bot_message():
    evidence = ReportEvidence(
        domain="kaspa-clone.app",
        url="https://kaspa-clone.app/",
        detected_at=datetime.now(),
        confidence_score=90,
        detection_reasons=["Anti-bot detection active: ipdata.co"],
    )

    summary = evidence.to_summary()

    assert "REVIEWER NOTES:" in summary
    assert "decoy page" in summary
