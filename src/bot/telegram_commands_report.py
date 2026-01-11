"""Report command handler."""

from __future__ import annotations

import logging
import os

from telegram import InputFile, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from ..reporter.base import ReportStatus

logger = logging.getLogger(__name__)


class TelegramCommandsReportMixin:
    """/report command handler."""

    async def _cmd_report(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /report command."""
        if not self._is_authorized(update):
            return
        if not context.args:
            await update.message.reply_text(
                "Usage:\n"
                "`/report <domain_id>` - Report to all platforms\n"
                "`/report <domain_id> status` - Check report status\n"
                "`/report <domain_id> done [platform|all]` - Mark manual submissions complete\n"
                "`/report <domain_id> retry [platform|all]` - Force retry of rate-limited reports\n"
                "`/report <domain_id> preview` - Dry-run (send to yourself)\n"
                "`/report <domain_id> pdf` - Generate PDF report\n"
                "`/report <domain_id> package` - Generate evidence package\n"
                "`/report <domain_id> <platform>` - Report to specific platform",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        if not self.report_manager:
            await update.message.reply_text(
                "Reporting not configured. Please set up SMTP or API keys."
            )
            return

        domain_short_id = context.args[0]
        action = context.args[1] if len(context.args) > 1 else "all"

        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await update.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        domain_id = target["id"]
        domain = target["domain"]

        if action == "status":
            reports = await self.report_manager.get_report_status(domain_id)
            if not reports:
                await update.message.reply_text(
                    f"No reports submitted yet for `{domain}`",
                    parse_mode=ParseMode.MARKDOWN,
                )
            else:
                await update.message.reply_text(
                    self._format_report_status_message(domain, reports),
                    parse_mode=ParseMode.MARKDOWN,
                )
        elif action == "done":
            platform = (context.args[2] if len(context.args) > 2 else "").strip().lower()
            platforms = None if not platform or platform == "all" else [platform]

            await update.message.reply_text(
                f"Marking manual reports complete for `{domain}`...",
                parse_mode=ParseMode.MARKDOWN,
            )
            results = await self.report_manager.mark_manual_done(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms,
            )
            summary = self.report_manager.format_results_summary(results)
            await update.message.reply_text(summary)
        elif action == "retry":
            platform = (context.args[2] if len(context.args) > 2 else "").strip().lower()
            requested = None if not platform or platform == "all" else platform

            reports = await self.report_manager.get_report_status(domain_id)
            rate_limited = sorted(
                {
                    str(r.get("platform") or "").strip().lower()
                    for r in (reports or [])
                    if str(r.get("status") or "").strip().lower()
                    == ReportStatus.RATE_LIMITED.value
                }
            )
            if requested:
                rate_limited = [p for p in rate_limited if p == requested]

            if self.report_manager.enabled_platforms is not None:
                enabled = set(self.report_manager.enabled_platforms)
                rate_limited = [p for p in rate_limited if p in enabled]

            if not rate_limited:
                if requested:
                    await update.message.reply_text(
                        f"No rate-limited report to retry for `{domain}` on `{requested}`.",
                        parse_mode=ParseMode.MARKDOWN,
                    )
                else:
                    await update.message.reply_text(
                        f"No rate-limited reports to retry for `{domain}`.",
                        parse_mode=ParseMode.MARKDOWN,
                    )
                return

            platforms = rate_limited
            await update.message.reply_text(
                f"Forcing retry for `{domain}` on "
                + ", ".join(f"`{p}`" for p in platforms)
                + "...",
                parse_mode=ParseMode.MARKDOWN,
            )
            results = await self.report_manager.report_domain(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms,
                force=True,
            )
            summary = self.report_manager.format_results_summary(results)
            await update.message.reply_text(summary)
            await self._send_manual_report_instructions(update.message, domain, results)
        elif action == "preview":
            dry_run_email = os.environ.get("DRY_RUN_EMAIL")
            if not dry_run_email:
                await update.message.reply_text(
                    "Dry-run not configured. Set `DRY_RUN_EMAIL` in your environment.",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

            await update.message.reply_text(
                f"Generating preview reports for `{domain}`...\n"
                f"Reports will be sent to `{dry_run_email}`",
                parse_mode=ParseMode.MARKDOWN,
            )

            results = await self.report_manager.report_domain(
                domain_id=domain_id,
                domain=domain,
                dry_run=True,
                dry_run_email=dry_run_email,
            )

            summary = self.report_manager.format_results_summary(results)
            await update.message.reply_text(
                f"Preview complete.\n\n{summary}\n\n"
                f"Check `{dry_run_email}` to review reports before submitting.",
                parse_mode=ParseMode.MARKDOWN,
            )
        elif action == "pdf":
            if not self.evidence_packager:
                await update.message.reply_text("Evidence packager not configured.")
                return

            await update.message.reply_text(
                f"Generating PDF report for `{domain}`...",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                attachments = await self.evidence_packager.prepare_domain_submission(domain, domain_id)

                if attachments.pdf_path and attachments.pdf_path.exists():
                    with open(attachments.pdf_path, "rb") as f:
                        await update.message.reply_document(
                            document=InputFile(
                                f, filename=f"{domain.replace('.', '_')}_report.pdf"
                            ),
                            caption=f"PDF Report for `{domain}`",
                            parse_mode=ParseMode.MARKDOWN,
                        )
                else:
                    with open(attachments.html_path, "rb") as f:
                        await update.message.reply_document(
                            document=InputFile(
                                f, filename=f"{domain.replace('.', '_')}_report.html"
                            ),
                            caption=(
                                f"HTML Report for `{domain}` (PDF unavailable - install weasyprint)"
                            ),
                            parse_mode=ParseMode.MARKDOWN,
                        )

                if attachments.campaign_context:
                    await update.message.reply_text(
                        f"Note: {attachments.campaign_context}",
                        parse_mode=ParseMode.MARKDOWN,
                    )
            except Exception as exc:
                logger.error("Failed to generate PDF for %s: %s", domain, exc)
                await update.message.reply_text(f"Failed to generate report: {exc}")
        elif action == "package":
            if not self.evidence_packager:
                await update.message.reply_text("Evidence packager not configured.")
                return

            await update.message.reply_text(
                f"Creating evidence archive for `{domain}`...",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                archive_path = await self.evidence_packager.create_domain_archive(domain, domain_id)

                size_mb = archive_path.stat().st_size / (1024 * 1024)
                if size_mb > 50:
                    await update.message.reply_text(
                        f"Archive created but too large to send ({size_mb:.1f}MB).\n"
                        f"Location: `{archive_path}`",
                        parse_mode=ParseMode.MARKDOWN,
                    )
                else:
                    with open(archive_path, "rb") as f:
                        await update.message.reply_document(
                            document=InputFile(f, filename=archive_path.name),
                            caption=f"Evidence archive for `{domain}`",
                            parse_mode=ParseMode.MARKDOWN,
                        )
            except Exception as exc:
                logger.error("Failed to create archive for %s: %s", domain, exc)
                await update.message.reply_text(f"Failed to create archive: {exc}")
        else:
            analysis_score = int(target.get("analysis_score") or 0)
            if analysis_score < self.report_min_score:
                await update.message.reply_text(
                    f"Refusing to report `{domain}`: score {analysis_score} < {self.report_min_score}.\n"
                    "If you still want to report, increase `REPORT_MIN_SCORE` or re-run analysis.",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

            platforms = None if action == "all" else [action]
            await update.message.reply_text(
                f"Submitting reports for `{domain}`...",
                parse_mode=ParseMode.MARKDOWN,
            )

            results = await self.report_manager.report_domain(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms,
            )

            summary = self.report_manager.format_results_summary(results)
            await update.message.reply_text(summary)
            await self._send_manual_report_instructions(update.message, domain, results)
