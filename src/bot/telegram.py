"""Telegram bot for SeedBuster interaction."""

import asyncio
import logging
from pathlib import Path
from typing import Callable, Optional

from telegram import Update, InputFile, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    CallbackQueryHandler,
    filters,
)
from telegram.constants import ParseMode

from .formatters import AlertFormatter, AlertData
from ..storage.database import Database, DomainStatus
from ..storage.evidence import EvidenceStore

logger = logging.getLogger(__name__)


class SeedBusterBot:
    """Telegram bot for SeedBuster alerts and control."""

    def __init__(
        self,
        token: str,
        chat_id: str,
        database: Database,
        evidence_store: EvidenceStore,
        submit_callback: Optional[Callable[[str], None]] = None,
        report_manager: Optional["ReportManager"] = None,
    ):
        self.token = token
        self.chat_id = chat_id
        self.database = database
        self.evidence_store = evidence_store
        self.submit_callback = submit_callback
        self.report_manager = report_manager

        self._app: Optional[Application] = None
        self._queue_size_callback: Optional[Callable[[], int]] = None
        self._is_running = True

    def set_queue_size_callback(self, callback: Callable[[], int]):
        """Set callback to get current queue size."""
        self._queue_size_callback = callback

    async def start(self):
        """Start the Telegram bot."""
        self._app = Application.builder().token(self.token).build()

        # Register handlers
        self._app.add_handler(CommandHandler("start", self._cmd_start))
        self._app.add_handler(CommandHandler("help", self._cmd_help))
        self._app.add_handler(CommandHandler("status", self._cmd_status))
        self._app.add_handler(CommandHandler("recent", self._cmd_recent))
        self._app.add_handler(CommandHandler("stats", self._cmd_stats))
        self._app.add_handler(CommandHandler("submit", self._cmd_submit))
        self._app.add_handler(CommandHandler("ack", self._cmd_ack))
        self._app.add_handler(CommandHandler("fp", self._cmd_fp))
        self._app.add_handler(CommandHandler("evidence", self._cmd_evidence))
        self._app.add_handler(CommandHandler("report", self._cmd_report))
        self._app.add_handler(CommandHandler("threshold", self._cmd_threshold))
        self._app.add_handler(CommandHandler("allowlist", self._cmd_allowlist))

        # Callback handlers for inline buttons
        self._app.add_handler(CallbackQueryHandler(self._callback_approve, pattern="^approve_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_reject, pattern="^reject_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_report_status, pattern="^status_"))

        # Start polling in background
        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)

        logger.info("Telegram bot started")

    async def stop(self):
        """Stop the Telegram bot."""
        self._is_running = False
        if self._app:
            await self._app.updater.stop()
            await self._app.stop()
            await self._app.shutdown()
        logger.info("Telegram bot stopped")

    async def send_alert(self, data: AlertData, include_report_buttons: bool = True):
        """Send a phishing detection alert with optional report approval buttons."""
        if not self._app:
            logger.error("Bot not started, cannot send alert")
            return

        try:
            # Format message (plain text to avoid markdown parsing issues)
            message = AlertFormatter.format_alert(data)

            # Create inline keyboard for report actions (if high confidence)
            keyboard = None
            if include_report_buttons and self.report_manager and data.score >= 70:
                keyboard = InlineKeyboardMarkup([
                    [
                        InlineKeyboardButton(
                            "✅ Approve & Report",
                            callback_data=f"approve_{data.domain_id}"
                        ),
                        InlineKeyboardButton(
                            "❌ False Positive",
                            callback_data=f"reject_{data.domain_id}"
                        ),
                    ],
                    [
                        InlineKeyboardButton(
                            "📊 Report Status",
                            callback_data=f"status_{data.domain_id}"
                        ),
                    ],
                ])

            # Send screenshot if available
            if data.screenshot_path and Path(data.screenshot_path).exists():
                with open(data.screenshot_path, "rb") as f:
                    await self._app.bot.send_photo(
                        chat_id=self.chat_id,
                        photo=InputFile(f),
                        caption=message,
                        reply_markup=keyboard,
                    )
            else:
                await self._app.bot.send_message(
                    chat_id=self.chat_id,
                    text=message,
                    reply_markup=keyboard,
                )

            logger.info(f"Sent alert for {data.domain}")

        except Exception as e:
            logger.error(f"Failed to send alert: {e}")

    async def send_message(self, text: str):
        """Send a simple text message."""
        if not self._app:
            return

        try:
            await self._app.bot.send_message(
                chat_id=self.chat_id,
                text=text,
                parse_mode=ParseMode.MARKDOWN,
            )
        except Exception as e:
            logger.error(f"Failed to send message: {e}")

    # Command handlers

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command."""
        await update.message.reply_text(
            "*SeedBuster* - Kaspa Phishing Detection\n\n"
            "I monitor Certificate Transparency logs for suspicious Kaspa-related domains "
            "and alert you when potential phishing sites are detected.\n\n"
            "Use /help to see available commands.",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command."""
        await update.message.reply_text(
            AlertFormatter.format_help(),
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command."""
        stats = await self.database.get_stats()
        queue_size = self._queue_size_callback() if self._queue_size_callback else 0

        message = AlertFormatter.format_status(
            stats=stats,
            queue_size=queue_size,
            is_running=self._is_running,
        )

        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_recent(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /recent command."""
        limit = 10
        if context.args:
            try:
                limit = int(context.args[0])
                limit = min(limit, 50)  # Cap at 50
            except ValueError:
                pass

        domains = await self.database.get_recent_domains(limit=limit)
        message = AlertFormatter.format_recent(domains, limit)

        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stats command."""
        # Same as status for now
        await self._cmd_status(update, context)

    async def _cmd_submit(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /submit command."""
        if not context.args:
            await update.message.reply_text(
                "Usage: `/submit <domain>`\nExample: `/submit suspicious-kaspa.xyz`",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        domain = context.args[0].lower()
        # Clean up URL if provided
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

        if self.submit_callback:
            self.submit_callback(domain)
            await update.message.reply_text(
                f"Submitted `{domain}` for analysis.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await update.message.reply_text("Submission not available.")

    async def _cmd_ack(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ack command."""
        if not context.args:
            await update.message.reply_text("Usage: `/ack <domain_id>`", parse_mode=ParseMode.MARKDOWN)
            return

        domain_id = context.args[0]
        # Find domain by short ID prefix
        domains = await self.database.get_recent_domains(limit=100)
        target = None
        for d in domains:
            if self.evidence_store.get_domain_id(d["domain"]).startswith(domain_id):
                target = d
                break

        if target:
            await self.database.update_domain_status(target["id"], DomainStatus.ANALYZED)
            await update.message.reply_text(
                f"Acknowledged: `{target['domain']}`",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await update.message.reply_text(f"Domain not found: {domain_id}")

    async def _cmd_fp(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /fp (false positive) command."""
        if not context.args:
            await update.message.reply_text("Usage: `/fp <domain_id>`", parse_mode=ParseMode.MARKDOWN)
            return

        domain_id = context.args[0]
        domains = await self.database.get_recent_domains(limit=100)
        target = None
        for d in domains:
            if self.evidence_store.get_domain_id(d["domain"]).startswith(domain_id):
                target = d
                break

        if target:
            await self.database.mark_false_positive(target["id"])
            await update.message.reply_text(
                f"Marked as false positive: `{target['domain']}`\n"
                "Consider adding to allowlist with `/allowlist add <domain>`",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await update.message.reply_text(f"Domain not found: {domain_id}")

    async def _cmd_evidence(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /evidence command."""
        if not context.args:
            await update.message.reply_text(
                "Usage: `/evidence <domain_id>`",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        domain_id = context.args[0]
        domains = await self.database.get_recent_domains(limit=100)
        target = None
        for d in domains:
            if self.evidence_store.get_domain_id(d["domain"]).startswith(domain_id):
                target = d
                break

        if not target:
            await update.message.reply_text(f"Domain not found: {domain_id}")
            return

        # Send evidence files
        evidence_dir = self.evidence_store.get_domain_dir(target["domain"])

        # Send screenshot
        screenshot = evidence_dir / "screenshot.png"
        if screenshot.exists():
            with open(screenshot, "rb") as f:
                await update.message.reply_photo(
                    photo=InputFile(f),
                    caption=f"Screenshot for `{target['domain']}`",
                    parse_mode=ParseMode.MARKDOWN,
                )

        # Send analysis JSON
        analysis = evidence_dir / "analysis.json"
        if analysis.exists():
            with open(analysis, "rb") as f:
                await update.message.reply_document(
                    document=InputFile(f, filename="analysis.json"),
                    caption="Analysis details",
                )

        # Send HTML if small enough
        html = evidence_dir / "page.html"
        if html.exists() and html.stat().st_size < 1_000_000:  # 1MB limit
            with open(html, "rb") as f:
                await update.message.reply_document(
                    document=InputFile(f, filename="page.html"),
                    caption="HTML snapshot",
                )

    async def _cmd_report(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /report command."""
        if not context.args:
            await update.message.reply_text(
                "Usage:\n"
                "`/report <domain_id>` - Report to all platforms\n"
                "`/report <domain_id> status` - Check report status\n"
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

        # Find domain by short ID
        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await update.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        domain_id = target["id"]
        domain = target["domain"]

        if action == "status":
            # Show report status
            reports = await self.report_manager.get_report_status(domain_id)
            if not reports:
                await update.message.reply_text(
                    f"No reports submitted yet for `{domain}`",
                    parse_mode=ParseMode.MARKDOWN,
                )
            else:
                status_lines = [f"*Report Status for* `{domain}`:\n"]
                for r in reports:
                    status_emoji = {
                        "submitted": "✅",
                        "confirmed": "✅",
                        "pending": "⏳",
                        "failed": "❌",
                        "rate_limited": "⏱️",
                        "duplicate": "🔄",
                        "rejected": "🚫",
                    }.get(r.get("status", ""), "❓")
                    status_lines.append(
                        f"{status_emoji} {r.get('platform', 'unknown')}: {r.get('status', 'unknown')}"
                    )
                await update.message.reply_text(
                    "\n".join(status_lines),
                    parse_mode=ParseMode.MARKDOWN,
                )
        else:
            # Submit reports
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

    async def _find_domain_by_short_id(self, identifier: str) -> Optional[dict]:
        """Find a domain by ID, domain name, or short hash prefix."""
        domains = await self.database.get_recent_domains(limit=100)

        # Try exact domain match first
        for d in domains:
            if d["domain"].lower() == identifier.lower():
                return d

        # Try database ID match
        if identifier.isdigit():
            for d in domains:
                if str(d["id"]) == identifier:
                    return d

        # Try short hash prefix match
        for d in domains:
            if self.evidence_store.get_domain_id(d["domain"]).startswith(identifier):
                return d

        # Try partial domain match
        for d in domains:
            if identifier.lower() in d["domain"].lower():
                return d

        return None

    # Callback handlers for inline buttons

    async def _callback_approve(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle approve button callback."""
        query = update.callback_query
        await query.answer()

        if not self.report_manager:
            await query.edit_message_reply_markup(reply_markup=None)
            await query.message.reply_text("Reporting not configured.")
            return

        # Extract domain ID from callback data
        domain_short_id = query.data.replace("approve_", "")

        # Find the domain
        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        # Update button to show processing
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("⏳ Submitting reports...", callback_data="noop")]
            ])
        )

        # Submit reports
        results = await self.report_manager.report_domain(
            domain_id=target["id"],
            domain=target["domain"],
        )

        # Format and send results
        summary = self.report_manager.format_results_summary(results)

        # Update the message with final status
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Reports Submitted", callback_data="noop")]
            ])
        )
        await query.message.reply_text(summary)

    async def _callback_reject(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle reject (false positive) button callback."""
        query = update.callback_query
        await query.answer()

        domain_short_id = query.data.replace("reject_", "")

        # Find the domain
        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        # Mark as false positive
        if self.report_manager:
            await self.report_manager.reject_report(target["id"], "false_positive")
        else:
            await self.database.mark_false_positive(target["id"])

        # Update button
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🚫 Marked as False Positive", callback_data="noop")]
            ])
        )
        await query.message.reply_text(
            f"Marked `{target['domain']}` as false positive. No reports sent.",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _callback_report_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle report status button callback."""
        query = update.callback_query
        await query.answer()

        if not self.report_manager:
            await query.message.reply_text("Reporting not configured.")
            return

        domain_short_id = query.data.replace("status_", "")

        # Find the domain
        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        # Get report status
        reports = await self.report_manager.get_report_status(target["id"])

        if not reports:
            await query.message.reply_text(
                f"No reports submitted yet for `{target['domain']}`\n"
                "Click 'Approve & Report' to submit.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            status_lines = [f"*Report Status:*\n"]
            for r in reports:
                status_emoji = {
                    "submitted": "✅",
                    "confirmed": "✅",
                    "pending": "⏳",
                    "failed": "❌",
                    "rate_limited": "⏱️",
                    "duplicate": "🔄",
                }.get(r.get("status", ""), "❓")
                status_lines.append(
                    f"{status_emoji} {r.get('platform', 'unknown')}: {r.get('status', 'unknown')}"
                )
            await query.message.reply_text(
                "\n".join(status_lines),
                parse_mode=ParseMode.MARKDOWN,
            )

    async def _cmd_threshold(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /threshold command."""
        # TODO: Implement runtime threshold adjustment
        await update.message.reply_text(
            "Threshold adjustment coming soon.\n"
            "Current threshold is set in `.env` file.",
        )

    async def _cmd_allowlist(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /allowlist command."""
        # TODO: Implement allowlist management
        await update.message.reply_text(
            "Allowlist management coming soon.\n"
            "Currently managed via `config/allowlist.txt`",
        )
