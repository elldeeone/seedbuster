"""Campaign command handler."""

from __future__ import annotations

import logging
import os

from telegram import InputFile, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

logger = logging.getLogger(__name__)


class TelegramCommandsCampaignMixin:
    """/campaign command handler."""

    async def _cmd_campaign(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /campaign command for campaign operations."""
        if not self._is_authorized(update):
            return

        if not self.campaign_manager:
            await update.message.reply_text("Campaign manager not configured.")
            return

        if not context.args:
            await update.message.reply_text(
                "*Campaign Commands*\n\n"
                "`/campaign list` - Show all campaigns\n"
                "`/campaign <id> summary` - Show campaign details\n"
                "`/campaign <id> report` - Generate PDF report\n"
                "`/campaign <id> package` - Generate evidence archive\n"
                "`/campaign <id> preview` - Dry-run reports to yourself\n"
                "`/campaign <id> submit` - Submit reports to all platforms",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        action = context.args[0].lower()

        if action == "list":
            campaigns = self.campaign_manager.get_all_campaigns()
            if not campaigns:
                await update.message.reply_text(
                    "No campaigns found yet.\n"
                    "Campaigns are created automatically when related phishing sites are detected."
                )
                return

            lines = ["*Active Campaigns*\n"]
            for c in sorted(campaigns, key=lambda x: x["member_count"], reverse=True):
                cid_short = c["campaign_id"][:12]
                lines.append(
                    f"`{cid_short}` *{c['name']}*\n"
                    f"  Domains: {c['member_count']} | Confidence: {c['confidence']:.0f}%"
                )
                if c["shared_backends"]:
                    backends_preview = ", ".join(c["shared_backends"][:2])
                    if len(c["shared_backends"]) > 2:
                        backends_preview += f" +{len(c['shared_backends']) - 2}"
                    lines.append(f"  Backends: `{backends_preview}`")
                lines.append("")

            lines.append("Use `/campaign <id> summary` for details")
            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
            return

        campaign_id_prefix = action
        sub_action = context.args[1].lower() if len(context.args) > 1 else "summary"

        campaign = None
        for c in self.campaign_manager.get_all_campaigns():
            if c["campaign_id"].startswith(campaign_id_prefix):
                campaign = c
                break

        if not campaign:
            await update.message.reply_text(
                f"Campaign not found: {campaign_id_prefix}\n"
                "Use `/campaign list` to see all campaigns.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        campaign_id = campaign["campaign_id"]

        if sub_action == "summary":
            summary = self.campaign_manager.get_campaign_summary(campaign_id)
            if not summary:
                await update.message.reply_text(
                    f"Campaign not found: {campaign_id}",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

            lines = [
                f"*{summary['name']}*",
                f"ID: `{summary['campaign_id']}`",
                f"Domains: {summary['member_count']}",
                f"Confidence: {summary['confidence']:.0f}%",
                "",
            ]
            if summary["shared_backends"]:
                lines.append("*Shared Backends:*")
                lines.extend([f"- `{b}`" for b in summary["shared_backends"]])
                lines.append("")
            if summary["shared_kits"]:
                lines.append("*Shared Kits:*")
                lines.extend([f"- `{k}`" for k in summary["shared_kits"]])
                lines.append("")
            if summary["shared_nameservers"]:
                lines.append("*Shared Nameservers:*")
                lines.extend([f"- `{n}`" for n in summary["shared_nameservers"]])
                lines.append("")
            if summary["shared_asns"]:
                lines.append("*Shared ASNs:*")
                lines.extend([f"- `{a}`" for a in summary["shared_asns"]])
                lines.append("")

            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
        elif sub_action == "report":
            if not self.evidence_packager:
                await update.message.reply_text("Evidence packager not configured.")
                return

            await update.message.reply_text(
                f"Generating PDF report for campaign `{campaign_id}`...",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                attachments = await self.evidence_packager.prepare_campaign_submission(campaign_id)

                if attachments.pdf_path and attachments.pdf_path.exists():
                    with open(attachments.pdf_path, "rb") as f:
                        await update.message.reply_document(
                            document=InputFile(f, filename=f"campaign_{campaign_id[:8]}.pdf"),
                            caption=f"Campaign report for `{campaign_id}`",
                            parse_mode=ParseMode.MARKDOWN,
                        )
                else:
                    with open(attachments.html_path, "rb") as f:
                        await update.message.reply_document(
                            document=InputFile(f, filename=f"campaign_{campaign_id[:8]}.html"),
                            caption="HTML Campaign Report (PDF unavailable)",
                            parse_mode=ParseMode.MARKDOWN,
                        )

            except Exception as exc:
                logger.error("Failed to generate campaign report: %s", exc)
                await update.message.reply_text(f"Failed to generate report: {exc}")
        elif sub_action == "package":
            if not self.evidence_packager:
                await update.message.reply_text("Evidence packager not configured.")
                return

            await update.message.reply_text(
                f"Creating campaign evidence archive for `{campaign_id}`...",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                archive_path = await self.evidence_packager.create_campaign_archive(campaign_id)

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
                            caption=f"Campaign evidence archive for `{campaign_id}`",
                            parse_mode=ParseMode.MARKDOWN,
                        )
            except Exception as exc:
                logger.error("Failed to create campaign archive: %s", exc)
                await update.message.reply_text(f"Failed to create archive: {exc}")
        elif sub_action == "preview":
            if not self.report_manager:
                await update.message.reply_text("Reporting not configured.")
                return

            dry_run_email = os.environ.get("DRY_RUN_EMAIL")
            if not dry_run_email:
                await update.message.reply_text(
                    "Dry-run not configured. Set `DRY_RUN_EMAIL` in your environment.",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

            await update.message.reply_text(
                f"Generating preview reports for campaign `{campaign_id}`...\n"
                f"Reports will be sent to `{dry_run_email}`",
                parse_mode=ParseMode.MARKDOWN,
            )

            results = await self.report_manager.report_campaign(
                campaign_id=campaign_id,
                campaign_manager=self.campaign_manager,
                dry_run=True,
                dry_run_email=dry_run_email,
            )

            summary = self.report_manager.format_results_summary(results)
            await update.message.reply_text(
                f"Preview complete.\n\n{summary}\n\n"
                f"Check `{dry_run_email}` to review reports before submitting.",
                parse_mode=ParseMode.MARKDOWN,
            )
        elif sub_action == "submit":
            if not self.report_manager:
                await update.message.reply_text("Reporting not configured.")
                return

            await update.message.reply_text(
                f"Submitting reports for campaign `{campaign_id}`...",
                parse_mode=ParseMode.MARKDOWN,
            )

            results = await self.report_manager.report_campaign(
                campaign_id=campaign_id,
                campaign_manager=self.campaign_manager,
                dry_run=False,
            )

            summary = self.report_manager.format_results_summary(results)
            await update.message.reply_text(summary)
        else:
            await update.message.reply_text(
                "Unknown campaign action. Use `/campaign <id> summary|report|package|preview|submit`.",
                parse_mode=ParseMode.MARKDOWN,
            )
