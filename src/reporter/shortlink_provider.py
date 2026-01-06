"""Manual reporter for shortlink/redirect providers."""

from __future__ import annotations

from typing import Optional

from .base import (
    BaseReporter,
    ManualSubmissionData,
    ManualSubmissionField,
    ReportEvidence,
    ReportResult,
    ReportStatus,
)

_SERVICE_DISPLAY = {
    "bitly": "Bitly",
    "rebrandly": "Rebrandly",
    "dub": "Dub",
    "vercel": "Vercel",
}

_SERVICE_FORMS = {
    "bitly": "https://bitly.com/pages/trust/report-abuse",
    "rebrandly": "mailto:abuse@rebrandly.com",
    "dub": "https://dub.co/legal/abuse",
    "vercel": "https://vercel.com/abuse",
}


def _clean(value: object) -> str:
    return str(value or "").strip()


def _format_chain(chain: list[dict], limit: int = 6) -> list[str]:
    lines: list[str] = []
    for step in chain or []:
        if not isinstance(step, dict):
            continue
        kind = _clean(step.get("type")) or "redirect"
        from_url = _clean(step.get("from_url"))
        to_url = _clean(step.get("to_url"))
        if not from_url and not to_url:
            continue
        if from_url and to_url:
            lines.append(f"{kind}: {from_url} -> {to_url}")
        elif to_url:
            lines.append(f"{kind}: -> {to_url}")
        else:
            lines.append(f"{kind}: {from_url}")
        if len(lines) >= limit:
            break
    return lines


def _guess_shortlink_url(analysis: dict, evidence: ReportEvidence, chain: list[dict]) -> str:
    for key in ("initial_url", "source_url", "early_url"):
        value = _clean(analysis.get(key))
        if value:
            return value
    for step in chain or []:
        from_url = _clean(step.get("from_url"))
        if from_url:
            return from_url
    return _clean(evidence.url)


def _guess_final_url(analysis: dict, chain: list[dict]) -> str:
    value = _clean(analysis.get("final_url"))
    if value:
        return value
    for step in reversed(chain or []):
        to_url = _clean(step.get("to_url"))
        if to_url:
            return to_url
    return ""


class ShortlinkProviderReporter(BaseReporter):
    """Manual-only reporter for shortlink/redirect providers."""

    manual_only = True
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 30

    def __init__(self):
        super().__init__()
        self.platform_name = "shortlink_provider"
        self.platform_url = ""
        self.display_name = "Shortlink Provider"
        self._configured = True

    def is_applicable(self, evidence: ReportEvidence) -> tuple[bool, str]:
        analysis = evidence.analysis_json or {}
        redirect_service = _clean(analysis.get("redirect_service")).lower()
        redirect_offsite = bool(analysis.get("redirect_offsite"))
        if not redirect_service:
            return False, "No redirect service detected"
        if not redirect_offsite:
            return False, "Redirect stays on-site"
        return True, ""

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        analysis = evidence.analysis_json or {}
        redirect_service = _clean(analysis.get("redirect_service")).lower()
        redirect_header = _clean(analysis.get("redirect_service_header"))
        provider_name = _SERVICE_DISPLAY.get(redirect_service, redirect_service.title() if redirect_service else "Unknown")
        form_url = _SERVICE_FORMS.get(redirect_service, "")

        chain = analysis.get("redirect_chain") or []
        chain_lines = _format_chain(chain)
        shortlink_url = _guess_shortlink_url(analysis, evidence, chain)
        final_url = _guess_final_url(analysis, chain)

        details_lines = [
            "ACTION REQUESTED: Please disable this shortlink and investigate the account.",
            "",
            f"Shortlink URL: {shortlink_url or '(unknown)'}",
            f"Destination URL: {final_url or '(unknown)'}",
        ]

        if chain_lines:
            details_lines.append("")
            details_lines.append("REDIRECT CHAIN:")
            details_lines.extend(f"  - {line}" for line in chain_lines)

        if redirect_header:
            details_lines.extend(["", f"Provider header hint: {redirect_header}"])

        reasons = evidence.get_filtered_reasons(max_items=4)
        if reasons:
            details_lines.append("")
            details_lines.append("KEY EVIDENCE:")
            details_lines.extend(f"  - {reason}" for reason in reasons)

        notes = [f"Provider detected: {provider_name}"]
        if form_url.startswith("mailto:"):
            notes.append("Provider prefers email submission.")
        if not form_url:
            notes.append("Provider abuse form not on file; manual lookup needed.")
        if analysis.get("redirect_only"):
            notes.append("Redirect-only landing page (no scam content hosted).")
        if analysis.get("redirect_target_domain"):
            notes.append(f"Redirect destination: {analysis.get('redirect_target_domain')}")

        fields = [
            ManualSubmissionField(
                name="shortlink_url",
                label="Shortlink URL",
                value=shortlink_url or evidence.url,
            ),
            ManualSubmissionField(
                name="destination_url",
                label="Destination URL",
                value=final_url or "",
            ),
            ManualSubmissionField(
                name="details",
                label="Details / evidence",
                value="\n".join(details_lines).strip(),
                multiline=True,
            ),
        ]

        if chain_lines:
            fields.insert(
                2,
                ManualSubmissionField(
                    name="redirect_chain",
                    label="Redirect chain",
                    value="\n".join(chain_lines),
                    multiline=True,
                ),
            )

        return ManualSubmissionData(
            form_url=form_url,
            reason=f"Shortlink provider detected: {provider_name}",
            fields=fields,
            notes=notes,
        )

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        manual_data = self.generate_manual_submission(evidence)
        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message="Manual submission required for shortlink provider.",
            response_data={"manual_fields": manual_data.to_dict()},
        )
