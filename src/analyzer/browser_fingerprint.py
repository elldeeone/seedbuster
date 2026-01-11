"""Browser analyzer fingerprint helper."""

from __future__ import annotations

from typing import Optional


class BrowserFingerprintMixin:
    """Fingerprint helpers."""

    async def capture_fingerprint(self, domain: str) -> Optional[bytes]:
        """Capture just a screenshot for fingerprinting."""
        result = await self.analyze(domain)
        return result.screenshot if result.success else None
