"""Shared storage enums."""

from __future__ import annotations

from enum import Enum


class DomainStatus(str, Enum):
    """Status of a domain in the pipeline."""

    PENDING = "pending"  # Discovered, awaiting analysis
    ANALYZING = "analyzing"  # Currently being analyzed
    ANALYZED = "analyzed"  # Analysis complete
    WATCHLIST = "watchlist"  # Waiting for rescans (suspected cloaking)
    REPORTED = "reported"  # Reported to blocklists
    FALSE_POSITIVE = "false_positive"  # Marked as FP
    ALLOWLISTED = "allowlisted"  # On allowlist


class Verdict(str, Enum):
    """Analysis verdict for a domain."""

    HIGH = "high"  # High confidence phishing
    MEDIUM = "medium"  # Needs manual review
    LOW = "low"  # Likely benign
    BENIGN = "benign"  # Confirmed safe


class ScamType(str, Enum):
    """Type of scam detected on a domain."""

    SEED_PHISHING = "seed_phishing"  # Seed phrase theft (wallet impersonation)
    CRYPTO_DOUBLER = "crypto_doubler"  # "Send X, get 2X back" scams
    FAKE_AIRDROP = "fake_airdrop"  # Fake airdrop/giveaway (overlaps with doubler)
    UNKNOWN = "unknown"  # Detected as malicious but type unclear
