from datetime import datetime

from src.reporter.base import ReportEvidence
from src.reporter.manager import ReportManager
from src.reporter.registrar import RegistrarReporter


def test_dynadot_official_site_prefilled():
    evidence = ReportEvidence(
        domain="kaspa.insure",
        url="https://kaspa.insure/home/",
        detected_at=datetime.now(),
        confidence_score=90,
        detection_reasons=[
            "Seed phrase form detected",
            "Kaspa-related title",
            "Wallet-related title",
        ],
        scam_type="seed_phishing",
    )
    reporter = RegistrarReporter()
    manual = reporter.generate_manual_submission_with_hints(
        evidence,
        registrar_name="Dynadot Inc",
    )
    fields = {f.name: f.value for f in manual.fields}

    assert fields["domain"] == "kaspa.insure"
    assert fields["official_site"] == "https://wallet.kaspanet.io"


def test_public_placeholder_skips_domain_name_fields():
    assert ReportManager._public_placeholder_for_field("domain", "Domain Name Involved") is None
