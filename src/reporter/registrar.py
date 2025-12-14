"""Registrar manual reporter for SeedBuster.

This reporter does not attempt automation. It performs a best-effort RDAP lookup
to identify the domain registrar, then provides an abuse email/form destination
and a copy/paste-ready email template.
"""

import logging
from typing import Optional

import httpx

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


# Registrar abuse destinations (best-effort).
REGISTRAR_ABUSE_EMAILS: dict[str, str] = {
    "namecheap": "abuse@namecheap.com",
    "godaddy": "abuse@godaddy.com",
    "hostinger": "abuse@hostinger.com",
}

REGISTRAR_ABUSE_FORMS: dict[str, str] = {
    # Some registrars prefer web forms; keep this sparse unless confirmed.
}


class RegistrarReporter(BaseReporter):
    """Registrar manual reporting helper (RDAP-based)."""

    platform_name = "registrar"
    platform_url = "https://rdap.org/"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 30

    def __init__(self, reporter_email: str = ""):
        super().__init__()
        self.reporter_email = reporter_email
        self._configured = True

    @staticmethod
    def _extract_first_vcard_value(vcard_array: object, field: str) -> Optional[str]:
        """Extract first vCard value for a given field (e.g., 'fn', 'email')."""
        if not isinstance(vcard_array, list) or len(vcard_array) < 2:
            return None
        entries = vcard_array[1]
        if not isinstance(entries, list):
            return None
        for entry in entries:
            if not isinstance(entry, list) or len(entry) < 4:
                continue
            if str(entry[0]).lower() == field.lower():
                value = entry[3]
                if isinstance(value, str) and value.strip():
                    cleaned = value.strip()
                    if field.lower() == "email" and cleaned.lower().startswith("mailto:"):
                        cleaned = cleaned.split(":", 1)[-1].strip()
                    return cleaned
        return None

    @classmethod
    def _parse_rdap_registrar(cls, data: dict) -> tuple[Optional[str], Optional[str]]:
        """Return (registrar_name, abuse_email) from RDAP JSON."""
        registrar_name: Optional[str] = None
        abuse_email: Optional[str] = None

        entities = data.get("entities", [])
        if not isinstance(entities, list):
            return (None, None)

        # Prefer explicit registrar entity for name.
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles", [])
            if "registrar" not in (roles or []):
                continue
            registrar_name = cls._extract_first_vcard_value(entity.get("vcardArray"), "fn") or registrar_name
            # Some registrars include an abuse mailbox in their vCard; grab if present.
            abuse_email = cls._extract_first_vcard_value(entity.get("vcardArray"), "email") or abuse_email

        # Also look for explicit abuse-role contact.
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles", []) or []
            if "abuse" not in roles:
                continue
            abuse_email = cls._extract_first_vcard_value(entity.get("vcardArray"), "email") or abuse_email

        return (registrar_name, abuse_email)

    @staticmethod
    def _normalize_key(value: str) -> str:
        return (value or "").strip().lower()

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        domain = (evidence.domain or "").strip().lower()
        if not domain:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message="No domain available for RDAP lookup",
            )

        rdap_url = f"https://rdap.org/domain/{domain}"

        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(rdap_url, headers={"User-Agent": "SeedBuster/1.0"})
        except httpx.TimeoutException:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message=f"RDAP lookup timed out: {rdap_url}",
            )
        except Exception as e:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message=f"RDAP lookup failed: {e}",
            )

        if resp.status_code != 200:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message=f"RDAP lookup failed ({resp.status_code}): {rdap_url}",
            )

        try:
            data = resp.json()
        except Exception:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message=f"RDAP returned non-JSON response: {rdap_url}",
            )

        registrar_name, rdap_email = self._parse_rdap_registrar(data)

        registrar_key = self._normalize_key(registrar_name or "")
        abuse_email = REGISTRAR_ABUSE_EMAILS.get(registrar_key) or rdap_email
        abuse_form = REGISTRAR_ABUSE_FORMS.get(registrar_key)

        if not registrar_name and not abuse_email and not abuse_form:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message=f"Registrar not found via RDAP: {rdap_url}",
            )

        template = ReportTemplates.registrar(
            evidence,
            reporter_email=self.reporter_email or "your-email@example.com",
            registrar_name=registrar_name,
        )

        parts: list[str] = []
        if registrar_name:
            parts.append(f"Registrar detected: {registrar_name}")
            parts.append("")

        if abuse_form:
            parts.extend([
                f"Manual submission (web form): {abuse_form}",
                "",
            ])

        if abuse_email:
            parts.extend([
                f"Manual submission (email): {abuse_email}",
                "",
                f"Subject: {template['subject']}",
                "",
                template["body"].strip(),
                "",
            ])
        else:
            parts.extend([
                "No registrar abuse email found; search registrar support for an abuse contact.",
                "",
                f"Suggested email subject: {template['subject']}",
                "",
                template["body"].strip(),
                "",
            ])

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message="\n".join(parts).strip(),
        )
