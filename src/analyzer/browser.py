"""Playwright-based browser analysis for phishing detection."""

from .browser_analyzer import BrowserAnalyzer
from .browser_constants import (
    ANTIBOT_DOMAINS,
    META_REFRESH_RE,
    REDIRECT_STATUS_CODES,
    STEALTH_SCRIPT,
    USER_AGENTS,
    _extract_meta_refresh_url,
    _normalize_url_for_compare,
)
from .browser_models import BrowserResult, ExplorationStep

__all__ = [
    "BrowserAnalyzer",
    "BrowserResult",
    "ExplorationStep",
    "ANTIBOT_DOMAINS",
    "USER_AGENTS",
    "REDIRECT_STATUS_CODES",
    "META_REFRESH_RE",
    "STEALTH_SCRIPT",
    "_normalize_url_for_compare",
    "_extract_meta_refresh_url",
]
