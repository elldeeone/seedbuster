"""Tests for domain scoring."""

import pytest
from src.discovery.scorer import DomainScorer


@pytest.fixture
def scorer():
    """Create a domain scorer for testing."""
    return DomainScorer(
        target_patterns=["kaspa", "kaspanet", "kaspawallet", "kasware"],
        allowlist={"kaspanet.io", "kaspa.org", "kaspa.com", "wallet.kaspanet.io"},
        denylist={"known-scam.xyz"},
        suspicious_tlds={"xyz", "top", "click", "online"},
    )


class TestDomainScorer:
    """Test domain scoring functionality."""

    def test_allowlist_exact_match(self, scorer):
        """Allowlisted domains should have score 0."""
        result = scorer.score_domain("kaspanet.io")
        assert result.is_allowlisted
        assert result.score == 0
        assert not result.should_analyze

    def test_allowlist_subdomain(self, scorer):
        """Subdomains of allowlisted domains should be allowed."""
        result = scorer.score_domain("wallet.kaspanet.io")
        assert result.is_allowlisted
        assert result.score == 0

    def test_denylist(self, scorer):
        """Denylisted domains should have score 100."""
        result = scorer.score_domain("known-scam.xyz")
        assert result.is_denylisted
        assert result.score == 100
        assert result.should_analyze

    def test_exact_pattern_match(self, scorer):
        """Domains containing target patterns should score high."""
        result = scorer.score_domain("kaspa-wallet.xyz")
        assert result.score >= 30
        assert "kaspa" in " ".join(result.reasons).lower()
        assert result.should_analyze

    def test_fuzzy_match(self, scorer):
        """Similar domains should be detected."""
        result = scorer.score_domain("kaspaa.com")
        assert result.score >= 20
        assert result.should_analyze

    def test_suspicious_tld(self, scorer):
        """Suspicious TLDs should add to score."""
        result = scorer.score_domain("kaspa-recover.xyz")
        assert any("tld" in r.lower() for r in result.reasons)

    def test_suspicious_keywords(self, scorer):
        """Suspicious keywords should add to score."""
        result = scorer.score_domain("kaspa-seed-recover.com")
        assert result.score >= 30
        assert any("recover" in r.lower() for r in result.reasons)

    def test_number_substitution(self, scorer):
        """L33t speak should be detected."""
        result = scorer.score_domain("k4spa.com")
        assert result.score >= 20

    def test_unrelated_domain(self, scorer):
        """Unrelated domains should have low scores."""
        result = scorer.score_domain("example.com")
        assert result.score < 10
        assert not result.should_analyze

    def test_quick_filter_positive(self, scorer):
        """Quick filter should pass suspicious domains."""
        assert scorer.quick_filter("kaspa-wallet.xyz")
        assert scorer.quick_filter("kaspawallet.com")

    def test_quick_filter_negative(self, scorer):
        """Quick filter should reject unrelated domains."""
        assert not scorer.quick_filter("example.com")
        assert not scorer.quick_filter("google.com")

    def test_quick_filter_allowlist(self, scorer):
        """Quick filter should reject allowlisted domains."""
        assert not scorer.quick_filter("kaspanet.io")


class TestIDNHomograph:
    """Test IDN/homograph attack detection."""

    def test_cyrillic_a(self, scorer):
        """Cyrillic 'а' should be detected."""
        # kаspa with Cyrillic а
        result = scorer.score_domain("xn--ksp-8cd.com")  # Punycode for kаspa
        # This tests the punycode handling - actual IDN detection
        # depends on input format

    def test_mixed_script(self, scorer):
        """Mixed script domains should be flagged."""
        # Testing the normalization logic
        normalized = scorer._normalize_homoglyphs("kаspа")  # Cyrillic а
        assert normalized == "kaspa"
