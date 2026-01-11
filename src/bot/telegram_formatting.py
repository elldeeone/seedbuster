"""Telegram bot formatting helpers."""

from __future__ import annotations

from ..reporter.base import ReportStatus


class TelegramFormattingMixin:
    """Formatting helpers for bot messages."""

    def _format_report_status_message(self, domain: str, reports: list[dict]) -> str:
        """Format report status lines with helpful retry/manual context."""
        status_lines = [f"*Report Status for* `{domain}`:"]
        for r in reports:
            status = str(r.get("status") or "unknown").strip().lower()
            platform = str(r.get("platform") or "unknown").strip()
            response_text = str(r.get("response") or "")
            status_emoji = {
                "submitted": "✅",
                "confirmed": "✅",
                "pending": "⏳",
                "manual_required": "📝",
                "failed": "❌",
                "skipped": "➖",
                "rate_limited": "⏱️",
                "duplicate": "🔄",
                "rejected": "🚫",
            }.get(status, "❓")

            report_id = r.get("id")
            status_label = status
            if status == "pending":
                if response_text and (
                    "manual" in response_text.lower() or self._extract_first_url(response_text)
                ):
                    status_label = "pending (manual action needed)"
                else:
                    status_label = "pending (awaiting approval)"
            platform_label = platform.replace("`", "'")
            status_label = status_label.replace("`", "'")
            line = f"{status_emoji} `{platform_label}`: `{status_label}`"
            if report_id:
                line += f" (id `{report_id}`)"

            if status == "rate_limited":
                next_attempt_at = (r.get("next_attempt_at") or "").strip()
                if next_attempt_at:
                    safe_next_attempt = next_attempt_at.replace("`", "'")
                    line += f" (next attempt: `{safe_next_attempt}`)"
                else:
                    retry_after = r.get("retry_after")
                    if retry_after:
                        line += f" (retry after: `{retry_after}`s)"

            if status in {"pending", "manual_required"}:
                manual_url = self._extract_first_url(response_text)
                if manual_url:
                    safe_manual_url = manual_url.replace("`", "'")
                    line += f" (manual: `{safe_manual_url}`)"

            if status in {"failed", "manual_required", "pending", "skipped"} and response_text:
                response_snippet = response_text.strip().replace("\n", " ")
                if response_snippet:
                    max_len = 200 if status in {"manual_required", "pending"} else 120
                    if len(response_snippet) > max_len:
                        response_snippet = response_snippet[: max_len - 1] + "…"
                    safe_response = response_snippet.replace("`", "'")
                    line += f" - `{safe_response}`"

            status_lines.append(line)
        return "\n".join(status_lines)

    @staticmethod
    def _summarize_report_results_for_button(results: dict) -> str:
        """Return a short, user-friendly status label for a report attempt."""
        statuses: list[str] = []
        for result in (results or {}).values():
            status = getattr(result, "status", None)
            value = getattr(status, "value", None) or str(status or "")
            statuses.append(str(value).strip().lower())

        if not statuses:
            return "⚠️ No report results"

        manual = any(s == ReportStatus.MANUAL_REQUIRED.value for s in statuses)
        rate_limited = any(s == ReportStatus.RATE_LIMITED.value for s in statuses)
        failed = any(s == ReportStatus.FAILED.value for s in statuses)
        if all(s == ReportStatus.SKIPPED.value for s in statuses):
            return "➖ Not Applicable"
        success_statuses = {
            ReportStatus.SUBMITTED.value,
            ReportStatus.CONFIRMED.value,
            ReportStatus.DUPLICATE.value,
        }
        successes = sum(1 for s in statuses if s in success_statuses)

        if manual:
            return "📝 Manual Action Needed"
        if successes and not failed and not rate_limited:
            return "✅ Reports Submitted"
        if rate_limited and successes:
            return "⏱️ Partial (Retry Scheduled)"
        if rate_limited and not successes and not failed:
            return "⏱️ Rate Limited (Retry Scheduled)"
        if failures := (sum(1 for s in statuses if s == ReportStatus.FAILED.value)):
            if successes:
                return "⚠️ Partial Success"
            return f"❌ Failed ({failures})"
        return "✅ Report Attempted"

    def _format_analysis_summary(self, data: dict) -> str:
        """Format analysis JSON into readable summary."""
        lines: list[str] = []

        domain = data.get("domain", "unknown")
        score = data.get("score", 0)
        verdict = data.get("verdict", "unknown")

        lines.append(f"=== ANALYSIS: {domain} ===")
        lines.append(f"Score: {score}/100 ({verdict.upper()})")
        lines.append("")

        reasons = data.get("reasons", [])
        threat_intel = [r for r in reasons if "KNOWN MALICIOUS" in r or "Malicious" in r]
        if threat_intel:
            lines.append("THREAT INTEL:")
            for r in threat_intel:
                lines.append(f"  * {r}")
            lines.append("")

        evasion = [r for r in reasons if "Anti-bot" in r or "blocked" in r.lower()]
        if evasion:
            lines.append("EVASION:")
            for r in evasion:
                lines.append(f"  * {r}")
            lines.append("")

        infra = data.get("infrastructure", {})
        if infra.get("reasons"):
            lines.append("INFRASTRUCTURE:")
            for r in infra.get("reasons", []):
                lines.append(f"  * {r}")
            if infra.get("tls_age_days") is not None:
                lines.append(f"  * TLS cert age: {infra['tls_age_days']} days")
            if infra.get("uses_privacy_dns"):
                lines.append("  * Uses privacy DNS")
            lines.append("")

        code = data.get("code_analysis", {})
        if code.get("reasons") or code.get("kit_matches"):
            lines.append("CODE ANALYSIS:")
            for r in code.get("reasons", []):
                lines.append(f"  * {r}")
            if code.get("kit_matches"):
                lines.append(f"  * Kit matches: {', '.join(code['kit_matches'])}")
            lines.append("")

        campaign = data.get("campaign", {})
        if campaign.get("campaign_name"):
            lines.append("CAMPAIGN:")
            lines.append(f"  * {campaign['campaign_name']}")
            if campaign.get("related_domains"):
                lines.append(f"  * Related: {', '.join(campaign['related_domains'])}")
            lines.append("")

        endpoints = data.get("suspicious_endpoints", [])
        if endpoints:
            lines.append("SUSPICIOUS ENDPOINTS:")
            for ep in endpoints[:5]:
                lines.append(f"  * {ep}")
            if len(endpoints) > 5:
                lines.append(f"  * ... and {len(endpoints) - 5} more")
            lines.append("")

        other = [
            r
            for r in reasons
            if not any(x in r for x in ["KNOWN", "Malicious", "Anti-bot", "blocked", "INFRA", "CODE"])
        ]
        if other:
            lines.append("OTHER SIGNALS:")
            for r in other[:5]:
                lines.append(f"  * {r}")
            lines.append("")

        return "\n".join(lines)
