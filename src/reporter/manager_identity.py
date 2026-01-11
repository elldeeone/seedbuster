"""Report manager identity/scrubbing helpers."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .base import ReportEvidence, ReportResult
from ..utils.domains import extract_hostname


class ReportManagerIdentityMixin:
    """Identity and helper utilities for reporting."""

    # Guardrails for repeated rate limiting to avoid endless churn.
    MAX_RATE_LIMIT_ATTEMPTS: int = 6
    MAX_RATE_LIMIT_BACKOFF_SECONDS: int = 6 * 60 * 60  # 6 hours

    @classmethod
    def _compute_rate_limit_backoff(cls, base_seconds: int, attempts: int) -> int:
        """
        Compute an exponential backoff (capped) for rate-limited retries.

        attempts should be the *next* attempts count after the status update.
        """
        base = max(30, int(base_seconds or 60))
        exponent = min(max(0, int(attempts) - 1), 6)
        return min(base * (2**exponent), cls.MAX_RATE_LIMIT_BACKOFF_SECONDS)

    @staticmethod
    def _preview_only_enabled() -> bool:
        """Return True when reporting should run in preview-only mode."""
        return os.environ.get("REPORT_PREVIEW_ONLY", "false").lower() == "true"

    @staticmethod
    def _dry_run_save_only_enabled() -> bool:
        """Return True when dry-run previews should only be saved locally."""
        return os.environ.get("DRY_RUN_SAVE_ONLY", "false").lower() == "true"

    @staticmethod
    def _dry_run_email_dir() -> Path:
        data_dir = Path(os.environ.get("DATA_DIR", "./data"))
        return data_dir / "packages" / "dry_run_emails"

    @classmethod
    def _extract_hostname(cls, target: str) -> str:
        """Extract hostname from a target that may include path/query/fragment."""
        return extract_hostname(target)

    @classmethod
    def _extract_hostnames_from_endpoints(cls, endpoints: list[object]) -> list[str]:
        """Extract unique hostnames from a list of URL-ish strings."""
        seen: set[str] = set()
        hosts: list[str] = []
        for item in endpoints or []:
            if not isinstance(item, str):
                continue
            raw = item.strip()
            if not raw:
                continue
            host = cls._extract_hostname(raw)
            if not host:
                continue
            if host in seen:
                continue
            seen.add(host)
            hosts.append(host)
        return hosts

    @staticmethod
    def _extract_api_key_indicators(reasons: list[object]) -> list[str]:
        """Extract API-key related indicators from reasons for reporting context."""
        found: list[str] = []
        seen: set[str] = set()
        for reason in reasons or []:
            if not isinstance(reason, str):
                continue
            lower = reason.lower()
            if "api key" not in lower and "apikey" not in lower:
                continue
            entry = reason.strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            found.append(entry)
        return found

    @staticmethod
    def _is_timestamp_due(timestamp: str | None) -> bool:
        """Return True if a timestamp is missing or not in the future."""
        if not timestamp:
            return True
        value = timestamp.strip()
        if not value:
            return True
        try:
            # SQLite may store either "YYYY-MM-DD HH:MM:SS" or ISO strings.
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return True
        # Compare naive timestamps in UTC-ish space (best-effort).
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt <= datetime.now(timezone.utc)

    @staticmethod
    def _build_manual_instructions_text(
        platform: str, evidence: ReportEvidence, result: ReportResult
    ) -> str:
        """Build a text file containing manual reporting instructions."""
        message = (result.message or "").strip()
        lines = [
            "SeedBuster Manual Report Instructions",
            f"Platform: {platform}",
            "",
        ]
        if message:
            lines.extend(["Platform Notes:", message, ""])
        lines.extend(["Evidence Summary:", evidence.to_summary().strip(), ""])
        return "\n".join(lines).strip() + "\n"

    @staticmethod
    def _public_placeholder_for_field(name: str, label: str) -> Optional[str]:
        """Return placeholder text for identity fields in public mode."""
        key = f"{name} {label}".lower()
        if "domain" in key and "name" in key:
            return None
        if "send email to" in key or name.strip().lower() == "to":
            return None
        if "email body" in key or "message" in key or "subject" in key or name.strip().lower() == "body":
            return None
        if "email" in key:
            return "(your email)"
        if "name" in key:
            return "(your name)"
        if "company" in key or "organization" in key or "organisation" in key:
            return "(your organization)"
        if "title" in key:
            return "(your title)"
        if "telephone" in key or "phone" in key or "tele" in key:
            return "(your phone)"
        if "country" in key:
            return "(your country)"
        return None

    @staticmethod
    def _identity_tokens_from(value: str) -> set[str]:
        tokens: set[str] = set()
        raw = (value or "").strip()
        if not raw:
            return tokens
        tokens.add(raw)
        if "<" in raw and ">" in raw:
            name = raw.split("<", 1)[0].strip().strip('"')
            email = raw.split("<", 1)[1].split(">", 1)[0].strip()
            if name:
                tokens.add(name)
            if email:
                tokens.add(email)
        return tokens

    def _public_identity_tokens(self) -> list[str]:
        tokens: set[str] = set()
        tokens.update(self._identity_tokens_from(self.reporter_email))
        tokens.update(self._identity_tokens_from(self.resend_from_email or ""))
        tokens.update(self._identity_tokens_from(self.smtp_config.get("from_email", "")))
        return [t for t in tokens if t]

    def _scrub_public_identity(self, data: dict) -> dict:
        """Scrub private identity values from report form data for public use."""
        if not isinstance(data, dict):
            return data

        fields = data.get("fields")
        if not isinstance(fields, list):
            return data

        tokens = self._public_identity_tokens()
        scrubbed_fields: list[dict] = []

        for field in fields:
            if not isinstance(field, dict):
                continue
            name = str(field.get("name") or "")
            label = str(field.get("label") or "")
            value = field.get("value")

            placeholder = self._public_placeholder_for_field(name, label)
            if placeholder is not None:
                field["value"] = placeholder
            elif isinstance(value, str) and tokens:
                updated = value
                for token in tokens:
                    if token and token in updated:
                        replacement = "(your email)" if "@" in token else "(your details)"
                        updated = updated.replace(token, replacement)
                field["value"] = updated

            scrubbed_fields.append(field)

        data["fields"] = scrubbed_fields
        return data
