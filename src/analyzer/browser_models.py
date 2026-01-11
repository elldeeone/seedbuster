"""Browser analyzer data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExplorationStep:
    """A single step in click-through exploration."""

    button_text: str
    screenshot: Optional[bytes] = None
    html: Optional[str] = None
    title: Optional[str] = None
    url: Optional[str] = None
    input_fields: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None


@dataclass
class BrowserResult:
    """Result of browser-based site analysis."""

    domain: str
    success: bool
    error: Optional[str] = None

    # Collected data
    screenshot: Optional[bytes] = None
    screenshot_early: Optional[bytes] = None
    html: Optional[str] = None
    html_early: Optional[str] = None
    har: Optional[dict] = None
    console_logs: list[str] = field(default_factory=list)

    # Page metadata
    initial_url: Optional[str] = None
    early_url: Optional[str] = None
    final_url: Optional[str] = None
    title: Optional[str] = None
    title_early: Optional[str] = None
    status_code: Optional[int] = None
    redirect_chain: list[dict] = field(default_factory=list)
    redirect_hops: int = 0
    redirect_detected: bool = False
    redirect_error: Optional[str] = None

    # Detected forms
    forms: list[dict] = field(default_factory=list)
    input_fields: list[dict] = field(default_factory=list)

    # Network requests
    external_requests: list[str] = field(default_factory=list)
    form_submissions: list[dict] = field(default_factory=list)

    # Anti-evasion data
    blocked_requests: list[str] = field(default_factory=list)
    blocked_internal_requests: list[str] = field(default_factory=list)
    evasion_detected: bool = False

    # Click-through exploration results
    exploration_steps: list[ExplorationStep] = field(default_factory=list)
    explored: bool = False
