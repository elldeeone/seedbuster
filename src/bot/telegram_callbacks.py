"""Telegram bot callback handlers."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from ..storage.database import DomainStatus, Verdict

logger = logging.getLogger(__name__)


class TelegramCallbacksMixin:
    """Callback handlers for inline buttons."""

    async def _callback_approve(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle approve button callback."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        if not self.report_manager:
            await query.edit_message_reply_markup(reply_markup=None)
            await query.message.reply_text("Reporting not configured.")
            return

        domain_short_id = query.data.replace("approve_", "")

        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⏳ Submitting reports...", callback_data="noop")]]
            )
        )

        results = await self.report_manager.report_domain(
            domain_id=target["id"],
            domain=target["domain"],
        )

        summary = self.report_manager.format_results_summary(results)

        final_label = self._summarize_report_results_for_button(results)
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton(final_label, callback_data="noop")],
                    [
                        InlineKeyboardButton(
                            "📊 Report Status", callback_data=f"status_{domain_short_id}"
                        ),
                        InlineKeyboardButton(
                            "📁 Evidence", callback_data=f"evidence_{domain_short_id}"
                        ),
                    ],
                ]
            )
        )
        await query.message.reply_text(summary)
        await self._send_manual_report_instructions(query.message, target["domain"], results)

    async def _callback_defer(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle defer button callback - wait for rescans."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        domain_short_id = query.data.replace("defer_", "")

        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        await self.database.update_domain_status(target["id"], DomainStatus.WATCHLIST)

        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("👁 Watchlist - Monitoring", callback_data="noop")]]
            )
        )
        await query.message.reply_text(
            f"👁 Watchlist: `{target['domain']}`\n\n"
            "Monitoring for worsening behavior. Monthly rescans will alert if score increases, verdict escalates, or seed form detected.",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _callback_allowlist(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle allowlist (safe) button callback."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        domain_short_id = query.data.replace("allow_", "")

        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        hostname = self._extract_hostname(target["domain"])
        if not hostname:
            await query.message.reply_text(f"Invalid domain for allowlist: {target['domain']}")
            return

        added = self._add_allowlist_entry(hostname)

        await self.database.update_domain_status(
            target["id"],
            status=DomainStatus.ALLOWLISTED,
            verdict=Verdict.BENIGN,
        )

        try:
            reply_markup = getattr(query.message, "reply_markup", None)
            if reply_markup and getattr(reply_markup, "inline_keyboard", None):
                new_rows = []
                for row in reply_markup.inline_keyboard:
                    new_row = []
                    for button in row:
                        if getattr(button, "callback_data", None) == query.data:
                            new_row.append(
                                InlineKeyboardButton("✅ Allowlisted", callback_data="noop")
                            )
                        else:
                            new_row.append(button)
                    new_rows.append(new_row)
                await query.edit_message_reply_markup(reply_markup=InlineKeyboardMarkup(new_rows))
        except Exception as exc:
            logger.debug("Failed to update allowlist button state: %s", exc)

        if added:
            await query.message.reply_text(
                f"✅ Allowlisted `{hostname}`. Future discoveries will be ignored.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await query.message.reply_text(
                f"✅ `{hostname}` is already allowlisted.",
                parse_mode=ParseMode.MARKDOWN,
            )

    async def _callback_reject(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle reject (false positive) button callback."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        domain_short_id = query.data.replace("reject_", "")

        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        if self.report_manager:
            await self.report_manager.reject_report(target["id"], "false_positive")
        else:
            await self.database.mark_false_positive(target["id"])

        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("🚫 Marked as False Positive", callback_data="noop")]]
            )
        )
        await query.message.reply_text(
            f"Marked `{target['domain']}` as false positive. No reports sent.",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _callback_report_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle report status button callback."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        if not self.report_manager:
            await query.message.reply_text("Reporting not configured.")
            return

        domain_short_id = query.data.replace("status_", "")

        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        reports = await self.report_manager.get_report_status(target["id"])

        if not reports:
            await query.message.reply_text(
                f"No reports submitted yet for `{target['domain']}`\n"
                "Click 'Approve & Report' to submit.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await query.message.reply_text(
                self._format_report_status_message(target["domain"], reports),
                parse_mode=ParseMode.MARKDOWN,
            )

    async def _callback_rescan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle rescan button callback."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        domain_short_id = query.data.replace("rescan_", "")

        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        if not self._rescan_callback:
            await query.message.reply_text("Rescan not available - callback not configured.")
            return

        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔄 Rescanning...", callback_data="noop")]]
            )
        )

        try:
            self._rescan_callback(target["domain"])
            await query.message.reply_text(
                f"🔄 Rescan triggered for `{target['domain']}`\n"
                "Results will be posted when complete.",
                parse_mode=ParseMode.MARKDOWN,
            )
        except Exception as exc:
            await query.message.reply_text(f"Rescan failed: {exc}")

    async def _callback_evidence(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle evidence button callback."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        domain_short_id = query.data.replace("evidence_", "")

        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        evidence_dir = self.evidence_store.get_domain_dir(target["domain"])

        if not evidence_dir.exists():
            await query.message.reply_text(
                f"No evidence found for `{target['domain']}`",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        screenshot_path = None
        try:
            candidates = self.evidence_store.get_all_screenshot_paths(target["domain"])
            screenshot_path = candidates[0] if candidates else None
        except Exception:
            screenshot_path = None
        if not screenshot_path:
            screenshot_path = evidence_dir / "screenshot.png"
        if screenshot_path and Path(screenshot_path).exists():
            with open(screenshot_path, "rb") as f:
                await query.message.reply_photo(
                    photo=InputFile(f),
                    caption=f"Screenshot for `{target['domain']}`",
                    parse_mode=ParseMode.MARKDOWN,
                )

        analysis_file = evidence_dir / "analysis.json"
        if analysis_file.exists():
            try:
                data = json.loads(analysis_file.read_text())
                summary = self._format_analysis_summary(data)
                await query.message.reply_text(summary)
            except Exception as exc:
                logger.error("Error parsing analysis: %s", exc)

            with open(analysis_file, "rb") as f:
                await query.message.reply_document(
                    document=InputFile(f, filename="analysis.json"),
                    caption="Raw analysis JSON",
                )

        instruction_files = self.evidence_store.get_report_instruction_paths(target["domain"])
        for path in instruction_files[:5]:
            try:
                with open(path, "rb") as f:
                    await query.message.reply_document(
                        document=InputFile(f, filename=path.name),
                        caption="Manual report instructions",
                    )
            except Exception as exc:
                logger.warning("Failed to send report instructions %s: %s", path, exc)

    async def _callback_scanpath(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle scan path button callback - analyze a specific URL path."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        full_url = query.data.replace("scanpath_", "")

        if not self.submit_callback:
            await query.message.reply_text("Submission not available - callback not configured.")
            return

        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔄 Scanning...", callback_data="noop")]]
            )
        )

        try:
            self.submit_callback(full_url)
            await query.message.reply_text(
                f"🔍 Submitted `{full_url}` for analysis.\n"
                "Results will be posted when complete.",
                parse_mode=ParseMode.MARKDOWN,
            )
        except Exception as exc:
            await query.message.reply_text(f"Scan failed: {exc}")

    async def _callback_noop(self, update: Update, context: ContextTypes.DEFAULT_TYPE):  # noqa: ARG002
        """Handle no-op callbacks used for disabled buttons."""
        query = getattr(update, "callback_query", None)
        if query:
            await query.answer()
