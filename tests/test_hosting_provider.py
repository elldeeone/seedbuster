from datetime import datetime

from src.reporter.base import ReportEvidence
from src.reporter.hosting_provider import HostingProviderReporter


def test_hosting_provider_form_url_prefers_form_when_no_email():
    evidence = ReportEvidence(
        domain="kaspa.insure",
        url="https://kaspa.insure/home/",
        detected_at=datetime.now(),
        confidence_score=90,
        hosting_provider="CONTABO, DE",
    )
    reporter = HostingProviderReporter()
    manual = reporter.generate_manual_submission(evidence)

    assert manual.form_url == "https://contabo.com/en/abuse/"
