"""Report preview and dry-run helpers."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .base import ConfigurationError, ReportEvidence, ReportResult, ReportStatus, ReporterError
from ..utils.files import safe_filename_component

logger = logging.getLogger(__name__)


class ReportManagerPreviewMixin:
    """Report preview helpers."""

    def format_results_summary(self, results: dict[str, ReportResult]) -> str:
        """Format report results for display."""
        lines = ["Report Results:"]

        for platform, result in results.items():
            status_emoji = {
                ReportStatus.SUBMITTED: "✅",
                ReportStatus.CONFIRMED: "✅",
                ReportStatus.PENDING: "⏳",
                ReportStatus.MANUAL_REQUIRED: "📝",
                ReportStatus.FAILED: "❌",
                ReportStatus.SKIPPED: "➖",
                ReportStatus.RATE_LIMITED: "⏱️",
                ReportStatus.DUPLICATE: "🔄",
                ReportStatus.REJECTED: "🚫",
            }.get(result.status, "❓")

            line = f"  {status_emoji} {platform}: {result.status.value}"
            if result.message:
                msg = result.message.strip()
                # Prefer to show manual URLs/instructions when automation is blocked.
                max_len = (
                    180
                    if (
                        result.status in {ReportStatus.PENDING, ReportStatus.MANUAL_REQUIRED}
                        or "http" in msg
                    )
                    else 80
                )
                if len(msg) > max_len:
                    msg = msg[: max_len - 1] + "…"
                line += f" - {msg}"
            lines.append(line)

        return "\n".join(lines)

    async def _dry_run_domain_report(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        dry_run_email: str = "",
    ) -> dict[str, ReportResult]:
        """
        Send dry-run preview of reports to specified email instead of real platforms.

        Each platform's report is sent as a separate email so you can see exactly
        what each abuse team would receive.
        """
        if not dry_run_email and not self._dry_run_save_only_enabled():
            return {
                "error": ReportResult(
                    platform="dry_run",
                    status=ReportStatus.FAILED,
                    message=(
                        "No dry-run email configured. Set DRY_RUN_EMAIL or pass "
                        "dry_run_email parameter."
                    ),
                )
            }

        # Build evidence
        evidence = await self.build_evidence(domain_id, domain)
        if not evidence:
            return {
                "error": ReportResult(
                    platform="dry_run",
                    status=ReportStatus.FAILED,
                    message=f"Could not build evidence for domain {domain}",
                )
            }

        # Determine platforms
        if platforms is None:
            platforms = self.get_available_platforms()
        else:
            platforms = [p for p in platforms if p in self.reporters]
            if self.enabled_platforms is not None:
                platforms = [p for p in platforms if p in self.enabled_platforms]

        results: dict[str, ReportResult] = {}

        for platform in platforms:
            reporter = self.reporters.get(platform)
            if not reporter or not reporter.is_configured():
                continue

            applicable, skip_reason = reporter.is_applicable(evidence)
            if not applicable:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    message=skip_reason or "Not applicable",
                )
                continue

            # For manual-only platforms, call submit() to get structured response_data
            # for the dashboard, then store in database.
            if reporter.manual_only:
                try:
                    result = await reporter.submit(evidence)
                    # Create report in database so dashboard can access structured fields.
                    report_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status=result.status.value,
                    )
                    response_data_json = None
                    if result.response_data:
                        try:
                            response_data_json = json.dumps(result.response_data)
                        except Exception:
                            pass
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                        response_data=response_data_json,
                    )
                    result.report_id = str(report_id)
                    results[platform] = result

                    # Also send dry-run preview email for manual platforms.
                    try:
                        report_content = self._build_platform_report_preview(platform, evidence)
                        await self._send_dry_run_email(
                            to_email=dry_run_email,
                            platform=platform,
                            domain=domain,
                            report_content=report_content,
                            evidence=evidence,
                        )
                    except Exception as exc:
                        logger.warning(
                            "Failed to send dry-run email for manual platform %s: %s",
                            platform,
                            exc,
                        )

                except Exception as exc:
                    logger.error("Failed to get manual fields for %s: %s", platform, exc)
                    results[platform] = ReportResult(
                        platform=platform,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message=f"Manual submission required: {reporter.platform_url}",
                    )
                continue

            # Build the report content that would be sent.
            try:
                report_content = self._build_platform_report_preview(platform, evidence)
                saved = await self._send_dry_run_email(
                    to_email=dry_run_email,
                    platform=platform,
                    domain=domain,
                    report_content=report_content,
                    evidence=evidence,
                )
                if self._dry_run_save_only_enabled():
                    msg = f"Dry-run saved: {saved}"
                else:
                    msg = f"Dry-run sent to {dry_run_email}"
                    if saved:
                        msg += f" (saved: {saved})"
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SUBMITTED,
                    message=msg,
                )
            except Exception as exc:
                logger.error("Failed to send dry-run for %s: %s", platform, exc)
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=f"Dry-run failed: {exc}",
                )

        return results

    async def _send_dry_run_email(
        self,
        to_email: str,
        platform: str,
        domain: str,
        report_content: str,
        evidence: ReportEvidence,
    ) -> Path:
        """Send a dry-run preview email."""
        attachments: list[Path] = []
        if evidence.screenshot_path and evidence.screenshot_path.exists():
            attachments.append(evidence.screenshot_path)
        if evidence.html_path and evidence.html_path.exists():
            attachments.append(evidence.html_path)

        subject = f"[DRY-RUN] Platform: {platform} | Domain: {domain}"
        body = f"""
This is a DRY-RUN preview of what would be submitted to {platform}.

{'=' * 60}
REPORT PREVIEW
{'=' * 60}

{report_content}

{'=' * 60}
EVIDENCE SUMMARY
{'=' * 60}

Domain: {evidence.domain}
URL: {evidence.url}
Detection Time: {evidence.detected_at.isoformat()}

Detection Reasons:
{chr(10).join(f'  - {r}' for r in evidence.detection_reasons)}

Backend Infrastructure:
{chr(10).join(f'  - {b}' for b in evidence.backend_domains) if evidence.backend_domains else '  (none detected)'}

{'=' * 60}
This email was generated by SeedBuster dry-run mode.
To submit for real, run the command without --dry-run.
"""

        out_dir = self._dry_run_email_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_platform = safe_filename_component(platform, max_length=80, default="unknown")
        safe_domain = safe_filename_component(domain, max_length=80, default="unknown")
        base = out_dir / f"{ts}_{safe_platform}_{safe_domain}"
        txt_path = base.with_suffix(".txt")
        meta_path = base.with_suffix(".json")

        try:
            txt_path.write_text(
                f"To: {to_email}\nSubject: {subject}\n\n{body.lstrip()}",
                encoding="utf-8",
            )
            meta_path.write_text(
                json.dumps(
                    {
                        "saved_at": ts,
                        "to_email": to_email,
                        "subject": subject,
                        "platform": platform,
                        "domain": domain,
                        "evidence_domain": evidence.domain,
                        "url": evidence.url,
                        "attachments": [str(p) for p in attachments],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        except Exception as exc:  # pragma: no cover - best-effort only
            logger.warning("Failed to save dry-run preview: %s", exc)

        if self._dry_run_save_only_enabled():
            logger.info("DRY_RUN_SAVE_ONLY enabled; skipping sending preview email (%s)", txt_path)
            return txt_path

        resend_reporter = self.reporters.get("resend")
        if resend_reporter and resend_reporter.is_configured():
            try:
                send_email = getattr(resend_reporter, "send_email", None)
                if callable(send_email):
                    await send_email(
                        to_email=to_email,
                        subject=subject,
                        body=body,
                        attachments=attachments,
                    )
                    return txt_path
            except Exception as exc:
                raise ReporterError(
                    f"Resend dry-run email failed: {exc} (saved: {txt_path})"
                ) from exc

        smtp_reporter = self.reporters.get("smtp")
        if smtp_reporter and smtp_reporter.is_configured():
            try:
                ok = await smtp_reporter.send_email(
                    to_email=to_email,
                    subject=subject,
                    body=body,
                    attachments=attachments,
                )
                if not ok:
                    raise ReporterError("SMTP dry-run email failed")
                return txt_path
            except Exception as exc:
                raise ReporterError(
                    f"SMTP dry-run email failed: {exc} (saved: {txt_path})"
                ) from exc

        raise ConfigurationError(
            "No email service configured for dry-run previews. "
            "Configure RESEND_API_KEY or SMTP settings."
            f" (saved: {txt_path})"
        )
