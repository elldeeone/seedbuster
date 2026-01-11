"""Visual matching helpers."""

from __future__ import annotations

import logging
from typing import Optional

from .visual_match import VisualMatchResult

logger = logging.getLogger(__name__)


class DetectorVisualMixin:
    """Visual matching helpers."""

    def _check_visual_match(
        self,
        screenshot: bytes,
        text: Optional[str],
        raw_html: Optional[str],
    ) -> VisualMatchResult:
        """Compare screenshot against stored fingerprints."""
        try:
            return self._visual_matcher.match(screenshot, text=text, raw_html=raw_html)
        except Exception as exc:
            logger.error("Error comparing visual fingerprint: %s", exc)
            return VisualMatchResult(0.0, None, None, 0.0, 0.0, 0.0)
