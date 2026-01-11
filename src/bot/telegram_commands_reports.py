"""Reporting status command handlers."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes


class TelegramCommandsReportsMixin:
    """Report status command handlers."""

    async def _cmd_reports(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /reports command (list all pending reports)."""
        if not self._is_authorized(update):
            return

        if not self.report_manager:
            await update.message.reply_text("Reporting not configured.")
            return

        pending = await self.report_manager.get_pending_approvals()
        if not pending:
            await update.message.reply_text("No pending report approvals.")
            return

        lines = ["*Pending Reports*:"]
        for p in pending[:20]:
            line = (
                f"• `{p['domain']}` (ID: `{p['domain_id']}`) "
                f"Platforms: {', '.join(p['platforms'])}"
            )
            lines.append(line)

        if len(pending) > 20:
            lines.append(f"...and {len(pending) - 20} more")

        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

    async def _cmd_platforms(self, update: Update, context: ContextTypes.DEFAULT_TYPE):  # noqa: ARG002
        """Handle /platforms command (show enabled/available reporting platforms)."""
        if not self._is_authorized(update):
            return

        if not self.report_manager:
            await update.message.reply_text("Reporting not configured.")
            return

        enabled = (
            sorted(self.report_manager.enabled_platforms)
            if self.report_manager.enabled_platforms is not None
            else None
        )
        available = sorted(self.report_manager.get_available_platforms())
        known = sorted(self.report_manager.reporters.keys())

        lines = ["*Reporting Platforms*"]
        if enabled is None:
            lines.extend(
                [
                    "",
                    "*Available (configured):* "
                    + (", ".join(f"`{p}`" for p in available) or "`(none)`"),
                ]
            )
        else:
            available_set = set(available)
            known_set = set(known)
            not_available = sorted(p for p in enabled if p not in available_set)
            unknown = sorted(p for p in enabled if p not in known_set)

            lines.extend(
                [
                    "",
                    "*Enabled (REPORT_PLATFORMS):* "
                    + (", ".join(f"`{p}`" for p in enabled) or "`(none)`"),
                    "*Available (configured):* "
                    + (", ".join(f"`{p}`" for p in available) or "`(none)`"),
                ]
            )
            if not_available:
                lines.append(
                    "*Enabled but unavailable:* " + ", ".join(f"`{p}`" for p in not_available)
                )
            if unknown:
                lines.append("*Unknown platform names:* " + ", ".join(f"`{p}`" for p in unknown))

        if known:
            lines.extend(
                [
                    "",
                    "*Known platforms:* " + ", ".join(f"`{p}`" for p in known),
                ]
            )

        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
