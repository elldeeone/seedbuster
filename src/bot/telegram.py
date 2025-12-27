"""Telegram bot for SeedBuster interaction."""

import logging
import re
from pathlib import Path
from typing import Callable, Optional, TYPE_CHECKING

from telegram import Update, InputFile, InlineKeyboardButton, InlineKeyboardMarkup, InputMediaPhoto
from telegram.error import NetworkError
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    CallbackQueryHandler,
)
from telegram.constants import ParseMode

from .formatters import AlertFormatter, AlertData
from .service import BotService, KeyboardButton
from ..storage.database import Database, DomainStatus, Verdict
from ..storage.evidence import EvidenceStore
from ..reporter.base import ReportStatus

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..reporter.manager import ReportManager
    from ..analyzer.campaigns import ThreatCampaignManager
    from ..reporter.evidence_packager import EvidencePackager


_URL_RE = re.compile(r"https?://\S+")


class SeedBusterBot:
    """Telegram bot for SeedBuster alerts and control."""

    def __init__(
        self,
        token: str,
        chat_id: str,
        database: Database,
        evidence_store: EvidenceStore,
        allowlist_path: Path | None = None,
        submit_callback: Optional[Callable[[str], None]] = None,
        report_manager: Optional["ReportManager"] = None,
        report_require_approval: bool = True,
        report_min_score: int = 70,
        campaign_manager: Optional["ThreatCampaignManager"] = None,
        evidence_packager: Optional["EvidencePackager"] = None,
    ):
        self.token = token
        self.chat_id = chat_id
        self.database = database
        self.evidence_store = evidence_store
        self.allowlist_path = allowlist_path or Path("./config/allowlist.txt")
        self.submit_callback = submit_callback
        self.report_manager = report_manager
        self.report_require_approval = report_require_approval
        self.report_min_score = report_min_score
        self.campaign_manager = campaign_manager
        self.evidence_packager = evidence_packager

        self._app: Optional[Application] = None
        self._queue_size_callback: Optional[Callable[[], int]] = None
        self._rescan_callback: Optional[Callable[[str], None]] = None
        self._reload_callback: Optional[Callable[[], str]] = None
        self._allowlist_add_callback: Optional[Callable[[str], None]] = None
        self._allowlist_remove_callback: Optional[Callable[[str], None]] = None
        self._is_running = True
        self.service = BotService(
            database=database,
            evidence_store=evidence_store,
            report_manager=report_manager,
            queue_size_callback=None,
            submit_callback=submit_callback,
            rescan_callback=None,
        )

    @staticmethod
    def _extract_first_url(text: str) -> Optional[str]:
        """Extract first URL from a block of text (best-effort)."""
        if not text:
            return None
        match = _URL_RE.search(text)
        if not match:
            return None
        return match.group(0).rstrip(").,]}>\"'")

    @staticmethod
    def _extract_hostname(value: str) -> str:
        """Extract a hostname from a domain/URL input (best-effort)."""
        from urllib.parse import urlparse

        raw = str(value or "").strip().lower()
        if not raw:
            return ""

        candidate = raw if "://" in raw else f"http://{raw}"
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or raw.split("/")[0]).strip().lower()
        return hostname.strip(".")

    def _read_allowlist_entries(self) -> set[str]:
        """Read allowlist entries from disk."""
        path = self.allowlist_path
        if not path.exists():
            return set()

        entries: set[str] = set()
        for line in path.read_text().splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            entries.add(value.lower())
        return entries

    def _write_allowlist_entries(self, entries: set[str]) -> None:
        """Write allowlist entries to disk (sorted, atomic)."""
        path = self.allowlist_path
        path.parent.mkdir(parents=True, exist_ok=True)

        header = [
            "# Allowed domains (one per line)",
            "# These will never trigger alerts",
        ]
        content = "\n".join(header + sorted(entries) + [""])

        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(content)
        tmp_path.replace(path)

    def _add_allowlist_entry(self, domain: str) -> bool:
        """Add a domain to the allowlist file and sync callbacks."""
        normalized = self._extract_hostname(domain)
        if not normalized:
            return False

        entries = self._read_allowlist_entries()
        if normalized in entries:
            return False

        entries.add(normalized)
        self._write_allowlist_entries(entries)

        if self._allowlist_add_callback:
            try:
                self._allowlist_add_callback(normalized)
            except Exception as e:
                logger.warning(f"Allowlist add callback failed for {normalized}: {e}")

        return True

    def _remove_allowlist_entry(self, domain: str) -> bool:
        """Remove a domain from the allowlist file and sync callbacks."""
        normalized = self._extract_hostname(domain)
        if not normalized:
            return False

        entries = self._read_allowlist_entries()
        if normalized not in entries:
            return False

        entries.remove(normalized)
        self._write_allowlist_entries(entries)

        if self._allowlist_remove_callback:
            try:
                self._allowlist_remove_callback(normalized)
            except Exception as e:
                logger.warning(f"Allowlist remove callback failed for {normalized}: {e}")

        return True

    @staticmethod
    def _to_markup(button_rows: list[list[KeyboardButton]] | None):
        """Convert plain button rows into Telegram markup."""
        if not button_rows:
            return None
        rows = []
        for row in button_rows:
            rows.append([InlineKeyboardButton(btn.text, callback_data=btn.callback_data) for btn in row])
        return InlineKeyboardMarkup(rows)

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
                if response_text and ("manual" in response_text.lower() or self._extract_first_url(response_text)):
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

    async def _send_manual_report_instructions(self, message: object, domain: str, results: dict) -> int:
        """Send saved manual report instruction files for any MANUAL_REQUIRED platforms."""
        if not message or not results:
            return 0

        instruction_files: list[Path] = []
        for platform, result in results.items():
            status = getattr(result, "status", None)
            if status != ReportStatus.MANUAL_REQUIRED:
                continue
            path = self.evidence_store.get_report_instructions_path(domain, platform)
            if path.exists():
                instruction_files.append(path)

        sent = 0
        for path in instruction_files[:5]:
            try:
                with open(path, "rb") as f:
                    await message.reply_document(
                        document=InputFile(f, filename=path.name),
                        caption="Manual report instructions",
                    )
                sent += 1
            except Exception as e:
                logger.warning(f"Failed to send report instructions {path}: {e}")
        return sent

    def set_queue_size_callback(self, callback: Callable[[], int]):
        """Set callback to get current queue size."""
        self._queue_size_callback = callback
        self.service.queue_size_callback = callback

    def set_rescan_callback(self, callback: Callable[[str], None]):
        """Set callback to trigger manual rescan."""
        self._rescan_callback = callback
        self.service.rescan_callback = callback

    def set_allowlist_callbacks(
        self,
        add_callback: Callable[[str], None] | None = None,
        remove_callback: Callable[[str], None] | None = None,
    ):
        """Set callbacks to keep the in-memory allowlist in sync."""
        self._allowlist_add_callback = add_callback
        self._allowlist_remove_callback = remove_callback

    def set_reload_callback(self, callback: Callable[[], str]):
        """Set callback to reload threat intel (returns version string)."""
        self._reload_callback = callback

    async def start(self):
        """Start the Telegram bot."""
        self._app = Application.builder().token(self.token).build()

        # Avoid "No error handlers are registered" and keep transient network errors from looking like crashes.
        self._app.add_error_handler(self._handle_error)

        # Register handlers
        self._app.add_handler(CommandHandler("start", self._cmd_start))
        self._app.add_handler(CommandHandler("help", self._cmd_help))
        self._app.add_handler(CommandHandler("status", self._cmd_status))
        self._app.add_handler(CommandHandler("recent", self._cmd_recent))
        self._app.add_handler(CommandHandler("stats", self._cmd_stats))
        self._app.add_handler(CommandHandler("submit", self._cmd_submit))
        self._app.add_handler(CommandHandler("bulk", self._cmd_bulk))
        self._app.add_handler(CommandHandler("ack", self._cmd_ack))
        self._app.add_handler(CommandHandler("defer", self._cmd_defer))
        self._app.add_handler(CommandHandler("rescan", self._cmd_rescan))
        self._app.add_handler(CommandHandler("fp", self._cmd_fp))
        self._app.add_handler(CommandHandler("evidence", self._cmd_evidence))
        self._app.add_handler(CommandHandler("report", self._cmd_report))
        self._app.add_handler(CommandHandler("reports", self._cmd_reports))
        self._app.add_handler(CommandHandler("platforms", self._cmd_platforms))
        self._app.add_handler(CommandHandler("threshold", self._cmd_threshold))
        self._app.add_handler(CommandHandler("allowlist", self._cmd_allowlist))
        self._app.add_handler(CommandHandler("reload", self._cmd_reload))
        self._app.add_handler(CommandHandler("campaign", self._cmd_campaign))

        # Callback handlers for inline buttons
        self._app.add_handler(CallbackQueryHandler(self._callback_approve, pattern="^approve_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_reject, pattern="^reject_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_allowlist, pattern="^allow_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_defer, pattern="^defer_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_report_status, pattern="^status_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_rescan, pattern="^rescan_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_evidence, pattern="^evidence_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_scanpath, pattern="^scanpath_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_noop, pattern="^noop$"))

        # Start polling in background
        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)

        logger.info("Telegram bot started")

    async def _handle_error(self, update: object, context: ContextTypes.DEFAULT_TYPE):
        """Handle unexpected exceptions from Telegram handlers."""
        err = getattr(context, "error", None)
        update_id = getattr(update, "update_id", None)

        # Network hiccups to Telegram are expected; log as warning without scary stack traces.
        if isinstance(err, NetworkError):
            logger.warning(f"Telegram network error (update_id={update_id}): {err}")
            return

        logger.exception(f"Unhandled Telegram handler error (update_id={update_id})", exc_info=err)

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

            # Create inline keyboard for actions (report button gated by min score)
            available_platforms = (
                self.report_manager.get_available_platforms()
                if self.report_manager
                else []
            )
            show_report_button = bool(
                include_report_buttons
                and self.report_manager
                and data.score >= self.report_min_score
                and self.report_require_approval
                and available_platforms
            )

            # Context-aware buttons based on detection status.
            # Priority: seed_form_found > cloaking_confirmed > cloaking_suspected > standard
            temporal = data.temporal
            keyboard = None

            if data.seed_form_found:
                # HIGHEST PRIORITY: Seed form found - definitive phishing confirmation
                rows = []
                if show_report_button:
                    rows.append([
                        InlineKeyboardButton(
                            "🎯 Report (Seed Form Found)",
                            callback_data=f"approve_{data.domain_id}",
                        ),
                    ])
                rows.append([
                    InlineKeyboardButton(
                        "✅ Allowlist",
                        callback_data=f"allow_{data.domain_id}",
                    ),
                    InlineKeyboardButton(
                        "❌ False Positive",
                        callback_data=f"reject_{data.domain_id}",
                    ),
                    InlineKeyboardButton(
                        "📊 Report Status",
                        callback_data=f"status_{data.domain_id}",
                    ),
                ])
                keyboard = InlineKeyboardMarkup(rows)
            elif temporal and temporal.is_initial_scan and temporal.cloaking_suspected:
                # Initial scan with suspected cloaking - offer watchlist as primary
                rows = [[
                    InlineKeyboardButton(
                        "👁 Watch (Monitor for Changes)",
                        callback_data=f"defer_{data.domain_id}",
                    ),
                ]]
                if show_report_button:
                    rows.append([
                        InlineKeyboardButton(
                            "✅ Report Now",
                            callback_data=f"approve_{data.domain_id}",
                        ),
                    ])
                rows.append([
                    InlineKeyboardButton(
                        "✅ Allowlist",
                        callback_data=f"allow_{data.domain_id}",
                    ),
                    InlineKeyboardButton(
                        "❌ False Positive",
                        callback_data=f"reject_{data.domain_id}",
                    ),
                    InlineKeyboardButton(
                        "📊 Report Status",
                        callback_data=f"status_{data.domain_id}",
                    ),
                ])
                keyboard = InlineKeyboardMarkup(rows)
            elif temporal and temporal.cloaking_confirmed:
                # Rescan with confirmed cloaking - emphasize reporting
                rows = []
                if show_report_button:
                    rows.append([
                        InlineKeyboardButton(
                            "🚨 Report (Cloaking Confirmed)",
                            callback_data=f"approve_{data.domain_id}",
                        ),
                    ])
                rows.append([
                    InlineKeyboardButton(
                        "✅ Allowlist",
                        callback_data=f"allow_{data.domain_id}",
                    ),
                    InlineKeyboardButton(
                        "❌ False Positive",
                        callback_data=f"reject_{data.domain_id}",
                    ),
                    InlineKeyboardButton(
                        "📊 Report Status",
                        callback_data=f"status_{data.domain_id}",
                    ),
                ])
                keyboard = InlineKeyboardMarkup(rows)
            else:
                # Standard buttons (always show FP + status)
                first_row = []
                if show_report_button:
                    first_row.append(InlineKeyboardButton(
                        "✅ Approve & Report",
                        callback_data=f"approve_{data.domain_id}",
                    ))
                first_row.append(InlineKeyboardButton(
                    "✅ Allowlist",
                    callback_data=f"allow_{data.domain_id}",
                ))
                first_row.append(InlineKeyboardButton(
                    "❌ False Positive",
                    callback_data=f"reject_{data.domain_id}",
                ))
                keyboard = InlineKeyboardMarkup([
                    first_row,
                    [
                        InlineKeyboardButton(
                            "📊 Report Status",
                            callback_data=f"status_{data.domain_id}",
                        ),
                    ],
                ])

            # Optional external link buttons (work even when report buttons are hidden).
            if data.urlscan_result_url:
                urlscan_row = [InlineKeyboardButton("🔎 urlscan.io", url=data.urlscan_result_url)]
                if keyboard:
                    rows = [list(r) for r in keyboard.inline_keyboard]
                    rows.append(urlscan_row)
                    keyboard = InlineKeyboardMarkup(rows)
                else:
                    keyboard = InlineKeyboardMarkup([urlscan_row])

            # Send screenshots if available
            screenshots_to_send = []

            # Check for multiple screenshots first
            if data.screenshot_paths:
                screenshots_to_send = [p for p in data.screenshot_paths if Path(p).exists()]
            elif data.screenshot_path and Path(data.screenshot_path).exists():
                screenshots_to_send = [data.screenshot_path]

            if len(screenshots_to_send) > 1:
                # Send analysis message FIRST (media group captions are limited)
                await self._app.bot.send_message(
                    chat_id=self.chat_id,
                    text=message,
                )

                # Then send screenshots as media group
                media = []
                for i, path in enumerate(screenshots_to_send):
                    with open(path, "rb") as f:
                        # Label each screenshot
                        label = Path(path).stem.replace("screenshot", "").replace("_", " ").strip() or "Final"
                        caption = f"📸 {label.title() if label else 'Final'}"
                        media.append(InputMediaPhoto(
                            media=f.read(),
                            caption=caption,
                        ))

                await self._app.bot.send_media_group(
                    chat_id=self.chat_id,
                    media=media,
                )
                # Send keyboard separately since media_group doesn't support reply_markup
                # Include a brief summary to make the message less orphaned
                action_text = f"`{data.domain}` • {data.score}/100"
                if data.seed_form_found:
                    action_text += " • Seed form found"
                await self._app.bot.send_message(
                    chat_id=self.chat_id,
                    text=action_text,
                    reply_markup=keyboard,
                    parse_mode=ParseMode.MARKDOWN,
                )
            elif screenshots_to_send:
                # Single screenshot
                with open(screenshots_to_send[0], "rb") as f:
                    await self._app.bot.send_photo(
                        chat_id=self.chat_id,
                        photo=InputFile(f),
                        caption=message,
                        reply_markup=keyboard,
                    )
            else:
                # No screenshots
                await self._app.bot.send_message(
                    chat_id=self.chat_id,
                    text=message,
                    reply_markup=keyboard,
                )

            logger.info(f"Sent alert for {data.domain} ({len(screenshots_to_send)} screenshots)")

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

    def _is_authorized(self, update: Update) -> bool:
        """Return True if this update is from the configured chat."""
        chat = update.effective_chat
        if not chat:
            return False
        return str(chat.id) == str(self.chat_id)

    # Command handlers

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command."""
        if not self._is_authorized(update):
            return
        await update.message.reply_text(
            "*SeedBuster* - Kaspa Phishing Detection\n\n"
            "I monitor Certificate Transparency logs for suspicious Kaspa-related domains "
            "and alert you when potential phishing sites are detected.\n\n"
            "Use /help to see available commands.",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command."""
        if not self._is_authorized(update):
            return
        await update.message.reply_text(
            AlertFormatter.format_help(),
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command."""
        if not self._is_authorized(update):
            return
        message = await self.service.format_status(is_running=self._is_running)

        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_recent(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /recent command."""
        if not self._is_authorized(update):
            return
        limit = 10
        if context.args:
            try:
                limit = int(context.args[0])
                limit = min(limit, 50)  # Cap at 50
            except ValueError:
                pass

        message = await self.service.format_recent(limit=limit)

        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stats command."""
        if not self._is_authorized(update):
            return
        message = await self.service.format_status(is_running=self._is_running)
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_submit(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /submit command."""
        if not self._is_authorized(update):
            return
        if not context.args:
            await update.message.reply_text(
                "Usage: `/submit <url>`\n"
                "Examples:\n"
                "  `/submit suspicious-kaspa.xyz`\n"
                "  `/submit suspicious-kaspa.xyz/new`\n"
                "  `/submit https://phishing-site.com/wallet`",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        response = await self.service.submit(context.args[0])
        markup = self._to_markup(response.buttons)
        await update.message.reply_text(
            response.message,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=markup,
        )

    async def _cmd_bulk(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /bulk command for submitting many domains at once."""
        if not self._is_authorized(update):
            return
        if not update.message or not update.message.text:
            return

        # Extract raw text after the command (supports newlines/pasted tables).
        raw = update.message.text
        # Remove leading "/bulk" or "/bulk@botname"
        raw = raw.split(maxsplit=1)[1] if len(raw.split(maxsplit=1)) > 1 else ""
        if not raw.strip():
            await update.message.reply_text(
                "Usage: `/bulk <domains...>`\n"
                "Paste a list of domains/URLs (whitespace/newline separated).",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        result = await self.service.bulk_submit(raw)
        await update.message.reply_text(
            "Bulk submission complete.\n\n" + result.summary(),
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_ack(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ack command."""
        if not self._is_authorized(update):
            return
        if not context.args:
            await update.message.reply_text("Usage: `/ack <domain_id>`", parse_mode=ParseMode.MARKDOWN)
            return

        message = await self.service.acknowledge(context.args[0])
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_defer(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /defer command - wait for rescans before deciding."""
        if not self._is_authorized(update):
            return
        if not context.args:
            await update.message.reply_text("Usage: `/defer <domain_id>`", parse_mode=ParseMode.MARKDOWN)
            return
        message = await self.service.defer(context.args[0])
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_rescan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /rescan command - manually trigger a rescan."""
        if not self._is_authorized(update):
            return
        if not context.args:
            await update.message.reply_text(
                "Usage: `/rescan <domain>`\nExample: `/rescan kaspanet.app`",
                parse_mode=ParseMode.MARKDOWN
            )
            return

        domain = context.args[0].lower().strip()
        # Remove protocol if included
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

        message = self.service.rescan(domain)
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_fp(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /fp (false positive) command."""
        if not self._is_authorized(update):
            return
        if not context.args:
            await update.message.reply_text("Usage: `/fp <domain_id>`", parse_mode=ParseMode.MARKDOWN)
            return
        message = await self.service.mark_false_positive(context.args[0])
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_evidence(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /evidence command."""
        if not self._is_authorized(update):
            return
        if not context.args:
            await update.message.reply_text(
                "Usage: `/evidence <domain_id>`",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        domain_id = context.args[0]
        target = await self.service.find_by_short_id(domain_id)

        if not target:
            await update.message.reply_text(f"Domain not found: {domain_id}")
            return

        # Send evidence files
        evidence_dir = self.evidence_store.get_domain_dir(target["domain"])

        # Send screenshot
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

        # Send any manual report instruction files
        instruction_files = self.evidence_store.get_report_instruction_paths(target["domain"])
        for path in instruction_files[:5]:
            try:
                with open(path, "rb") as f:
                    await update.message.reply_document(
                        document=InputFile(f, filename=path.name),
                        caption="Manual report instructions",
                    )
            except Exception as e:
                logger.warning(f"Failed to send report instructions {path}: {e}")

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
            rate_limited = sorted({
                str(r.get("platform") or "").strip().lower()
                for r in (reports or [])
                if str(r.get("status") or "").strip().lower() == ReportStatus.RATE_LIMITED.value
            })
            if requested:
                rate_limited = [p for p in rate_limited if p == requested]

            # Respect current enabled_platforms selection.
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
                f"Forcing retry for `{domain}` on " + ", ".join(f"`{p}`" for p in platforms) + "...",
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
            # Dry-run: send reports to yourself instead of real abuse teams
            import os
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
            # Generate PDF report
            if not self.evidence_packager:
                await update.message.reply_text(
                    "Evidence packager not configured."
                )
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
                            document=InputFile(f, filename=f"{domain.replace('.', '_')}_report.pdf"),
                            caption=f"PDF Report for `{domain}`",
                            parse_mode=ParseMode.MARKDOWN,
                        )
                else:
                    # Fall back to HTML
                    with open(attachments.html_path, "rb") as f:
                        await update.message.reply_document(
                            document=InputFile(f, filename=f"{domain.replace('.', '_')}_report.html"),
                            caption=f"HTML Report for `{domain}` (PDF unavailable - install weasyprint)",
                            parse_mode=ParseMode.MARKDOWN,
                        )

                if attachments.campaign_context:
                    await update.message.reply_text(
                        f"Note: {attachments.campaign_context}",
                        parse_mode=ParseMode.MARKDOWN,
                    )
            except Exception as e:
                logger.error(f"Failed to generate PDF for {domain}: {e}")
                await update.message.reply_text(f"Failed to generate report: {e}")
        elif action == "package":
            # Generate evidence package (ZIP archive)
            if not self.evidence_packager:
                await update.message.reply_text(
                    "Evidence packager not configured."
                )
                return

            await update.message.reply_text(
                f"Creating evidence archive for `{domain}`...",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                archive_path = await self.evidence_packager.create_domain_archive(domain, domain_id)

                # Check file size (Telegram limit is 50MB)
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
            except Exception as e:
                logger.error(f"Failed to create archive for {domain}: {e}")
                await update.message.reply_text(f"Failed to create archive: {e}")
        else:
            analysis_score = int(target.get("analysis_score") or 0)
            if analysis_score < self.report_min_score:
                await update.message.reply_text(
                    f"Refusing to report `{domain}`: score {analysis_score} < {self.report_min_score}.\n"
                    "If you still want to report, increase `REPORT_MIN_SCORE` or re-run analysis.",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

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
            await self._send_manual_report_instructions(update.message, domain, results)

    async def _cmd_campaign(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /campaign command for campaign operations."""
        if not self._is_authorized(update):
            return

        if not self.campaign_manager:
            await update.message.reply_text(
                "Campaign manager not configured."
            )
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
            # List all campaigns
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

        # All other actions require a campaign ID
        campaign_id_prefix = action
        sub_action = context.args[1].lower() if len(context.args) > 1 else "summary"

        # Find campaign by prefix
        campaign = None
        for cid, c in self.campaign_manager.campaigns.items():
            if cid.startswith(campaign_id_prefix) or cid == campaign_id_prefix:
                campaign = c
                break

        if not campaign:
            await update.message.reply_text(
                f"Campaign not found: `{campaign_id_prefix}`\n"
                "Use `/campaign list` to see available campaigns.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        if sub_action == "summary":
            # Show detailed campaign info
            lines = [
                f"*Campaign: {campaign.name}*\n",
                f"ID: `{campaign.campaign_id}`",
                f"Confidence: {campaign.confidence:.0f}%",
                f"Created: {campaign.created_at.strftime('%Y-%m-%d')}",
                f"Updated: {campaign.updated_at.strftime('%Y-%m-%d')}",
                "",
                f"*Domains ({len(campaign.members)}):*",
            ]
            for m in campaign.members[:10]:
                lines.append(f"  `{m.domain}` (score: {m.score})")
            if len(campaign.members) > 10:
                lines.append(f"  ... and {len(campaign.members) - 10} more")

            if campaign.shared_backends:
                lines.extend(["", "*Shared Backends:*"])
                for b in list(campaign.shared_backends)[:5]:
                    lines.append(f"  `{b}`")

            if campaign.shared_kits:
                lines.extend(["", "*Kit Signatures:*"])
                for k in campaign.shared_kits:
                    lines.append(f"  `{k}`")

            if campaign.shared_nameservers:
                lines.extend(["", "*Shared Nameservers:*"])
                for ns in list(campaign.shared_nameservers)[:3]:
                    lines.append(f"  `{ns}`")

            lines.extend([
                "",
                "*Actions:*",
                f"`/campaign {campaign_id_prefix} report` - Generate report",
                f"`/campaign {campaign_id_prefix} preview` - Dry-run submission",
                f"`/campaign {campaign_id_prefix} submit` - Submit reports",
            ])

            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

        elif sub_action == "report":
            # Generate campaign PDF/HTML report
            if not self.evidence_packager:
                await update.message.reply_text("Evidence packager not configured.")
                return

            await update.message.reply_text(
                f"Generating campaign report for *{campaign.name}*...",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                attachments = await self.evidence_packager.prepare_campaign_submission(campaign.campaign_id)

                if attachments.pdf_path and attachments.pdf_path.exists():
                    with open(attachments.pdf_path, "rb") as f:
                        await update.message.reply_document(
                            document=InputFile(f, filename=f"campaign_{campaign.name.replace(' ', '_')}.pdf"),
                            caption=f"Campaign Report: *{campaign.name}* ({attachments.domain_count} domains)",
                            parse_mode=ParseMode.MARKDOWN,
                        )
                else:
                    with open(attachments.html_path, "rb") as f:
                        await update.message.reply_document(
                            document=InputFile(f, filename=f"campaign_{campaign.name.replace(' ', '_')}.html"),
                            caption=f"Campaign Report: *{campaign.name}* (PDF unavailable)",
                            parse_mode=ParseMode.MARKDOWN,
                        )
            except Exception as e:
                logger.error(f"Failed to generate campaign report: {e}")
                await update.message.reply_text(f"Failed to generate report: {e}")

        elif sub_action == "package":
            # Generate campaign evidence archive
            if not self.evidence_packager:
                await update.message.reply_text("Evidence packager not configured.")
                return

            await update.message.reply_text(
                f"Creating evidence archive for *{campaign.name}* ({len(campaign.members)} domains)...\n"
                "This may take a moment.",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                archive_path = await self.evidence_packager.create_campaign_archive(campaign.campaign_id)

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
                            caption=f"Evidence archive for *{campaign.name}*",
                            parse_mode=ParseMode.MARKDOWN,
                        )
            except Exception as e:
                logger.error(f"Failed to create campaign archive: {e}")
                await update.message.reply_text(f"Failed to create archive: {e}")

        elif sub_action == "preview":
            # Dry-run campaign reports
            if not self.report_manager:
                await update.message.reply_text("Report manager not configured.")
                return

            import os
            dry_run_email = os.environ.get("DRY_RUN_EMAIL")
            if not dry_run_email:
                await update.message.reply_text(
                    "Dry-run not configured. Set `DRY_RUN_EMAIL` in your environment.",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

            await update.message.reply_text(
                f"Generating preview reports for *{campaign.name}*...\n"
                f"Reports will be sent to `{dry_run_email}`\n"
                f"This includes {len(campaign.members)} domains.",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                results = await self.report_manager.report_campaign(
                    campaign_id=campaign.campaign_id,
                    campaign_manager=self.campaign_manager,
                    dry_run=True,
                    dry_run_email=dry_run_email,
                )

                # Count successes
                total_reports = sum(len(r) for r in results.values())
                await update.message.reply_text(
                    f"Preview complete for *{campaign.name}*\n\n"
                    f"Generated {total_reports} report previews.\n"
                    f"Check `{dry_run_email}` to review before submitting.",
                    parse_mode=ParseMode.MARKDOWN,
                )
            except Exception as e:
                logger.error(f"Failed to generate campaign preview: {e}")
                await update.message.reply_text(f"Failed to generate preview: {e}")

        elif sub_action == "submit":
            # Submit campaign reports to all platforms
            if not self.report_manager:
                await update.message.reply_text("Report manager not configured.")
                return

            await update.message.reply_text(
                f"Submitting reports for *{campaign.name}*...\n"
                f"This will report {len(campaign.members)} domains to all platforms.\n"
                "This may take a few minutes.",
                parse_mode=ParseMode.MARKDOWN,
            )

            try:
                results = await self.report_manager.report_campaign(
                    campaign_id=campaign.campaign_id,
                    campaign_manager=self.campaign_manager,
                )

                # Summarize results
                lines = [f"*Campaign Report Results: {campaign.name}*\n"]

                for target_type, target_results in results.items():
                    if target_results:
                        success_count = sum(
                            1 for r in target_results
                            if r.status in [ReportStatus.SUBMITTED, ReportStatus.CONFIRMED]
                        )
                        lines.append(f"*{target_type}*: {success_count}/{len(target_results)} submitted")

                lines.append(f"\nTotal domains: {len(campaign.members)}")
                lines.append("\nUse `/campaign list` to see updated campaign status.")

                await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
            except Exception as e:
                logger.error(f"Failed to submit campaign reports: {e}")
                await update.message.reply_text(f"Failed to submit reports: {e}")
        else:
            await update.message.reply_text(
                f"Unknown action: `{sub_action}`\n"
                "Use `/campaign` for available commands.",
                parse_mode=ParseMode.MARKDOWN,
            )

    async def _cmd_reports(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /reports command (queue of domains needing reporting action)."""
        if not self._is_authorized(update):
            return

        if not self.report_manager:
            await update.message.reply_text("Reporting not configured.")
            return

        # Optional filters: /reports [pending|manual|required|rate|rate_limited] [n]
        filter_arg = str(context.args[0]).strip().lower() if context.args else ""
        limit_arg = str(context.args[1]).strip() if len(context.args) > 1 else ""

        limit = 10
        if filter_arg.isdigit():
            limit = min(50, max(1, int(filter_arg)))
            filter_arg = ""
        elif limit_arg.isdigit():
            limit = min(50, max(1, int(limit_arg)))

        filter_status: str | None = None
        if filter_arg in {"pending"}:
            filter_status = "pending"
        elif filter_arg in {"manual", "manual_required", "required"}:
            filter_status = "manual_required"
        elif filter_arg in {"rate", "rate_limited", "retry"}:
            filter_status = "rate_limited"

        rows = await self.database.get_pending_reports()
        if not rows:
            await update.message.reply_text("No pending/manual/rate-limited reports.")
            return

        # Respect current enabled_platforms selection.
        if self.report_manager.enabled_platforms is not None:
            enabled = set(self.report_manager.enabled_platforms)
            rows = [r for r in rows if str(r.get("platform") or "").strip().lower() in enabled]

        if filter_status:
            rows = [r for r in rows if str(r.get("status") or "").strip().lower() == filter_status]

        if not rows:
            await update.message.reply_text("No matching reports in the queue.")
            return

        by_domain: dict[int, dict[str, object]] = {}
        for r in rows:
            try:
                domain_id = int(r.get("domain_id") or 0)
            except Exception:
                continue
            if not domain_id:
                continue
            domain = str(r.get("domain") or "").strip()
            if not domain:
                continue
            entry = by_domain.setdefault(domain_id, {"domain": domain, "rows": []})
            entry["rows"].append(r)

        items: list[tuple[int, dict[str, object]]] = []
        for domain_id, entry in by_domain.items():
            rows_for_domain = entry["rows"]
            latest_id = 0
            try:
                latest_id = max(int(rr.get("id") or 0) for rr in rows_for_domain)
            except Exception:
                latest_id = 0
            items.append((latest_id, {"domain_id": domain_id, **entry}))

        items.sort(key=lambda t: t[0], reverse=True)
        items = items[:limit]

        lines = ["*Report Queue*"]
        for _, entry in items:
            domain_id = int(entry["domain_id"])
            domain = str(entry["domain"])
            safe_domain = domain.replace("`", "'")
            short_id = self.evidence_store.get_domain_id(domain)

            status_to_platforms: dict[str, list[str]] = {
                "pending": [],
                "manual_required": [],
                "rate_limited": [],
            }
            next_attempts: list[str] = []
            for r in entry["rows"]:
                status = str(r.get("status") or "").strip().lower()
                platform = str(r.get("platform") or "").strip().lower() or "unknown"
                if status in status_to_platforms:
                    status_to_platforms[status].append(platform)
                if status == "rate_limited":
                    next_attempt = str(r.get("next_attempt_at") or "").strip()
                    if next_attempt:
                        next_attempts.append(next_attempt)

            parts: list[str] = []
            if status_to_platforms["pending"]:
                parts.append(f"⏳ pending:{len(status_to_platforms['pending'])}")
            if status_to_platforms["manual_required"]:
                parts.append(f"📝 manual:{len(status_to_platforms['manual_required'])}")
            if status_to_platforms["rate_limited"]:
                parts.append(f"⏱️ retry:{len(status_to_platforms['rate_limited'])}")

            header = f"`{short_id}` `{safe_domain}`"
            if parts:
                header += " — " + ", ".join(parts)
            lines.append(header)

            manual_platforms = sorted(set(status_to_platforms["manual_required"]))
            if manual_platforms:
                lines.append("  📝 " + ", ".join(f"`{p}`" for p in manual_platforms))

            rate_platforms = sorted(set(status_to_platforms["rate_limited"]))
            if rate_platforms:
                line = "  ⏱️ " + ", ".join(f"`{p}`" for p in rate_platforms)
                if next_attempts:
                    earliest = sorted(next_attempts)[0].replace("`", "'")
                    line += f" (next: `{earliest}`)"
                lines.append(line)

            pending_platforms = sorted(set(status_to_platforms["pending"]))
            if pending_platforms:
                lines.append("  ⏳ " + ", ".join(f"`{p}`" for p in pending_platforms))

            lines.append(f"  Actions: `/report {short_id}`, `/report {short_id} status`, `/report {short_id} done all`")

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
            lines.extend([
                "",
                "*Available (configured):* " + (", ".join(f"`{p}`" for p in available) or "`(none)`"),
            ])
        else:
            available_set = set(available)
            known_set = set(known)
            not_available = sorted(p for p in enabled if p not in available_set)
            unknown = sorted(p for p in enabled if p not in known_set)

            lines.extend([
                "",
                "*Enabled (REPORT_PLATFORMS):* " + (", ".join(f"`{p}`" for p in enabled) or "`(none)`"),
                "*Available (configured):* " + (", ".join(f"`{p}`" for p in available) or "`(none)`"),
            ])
            if not_available:
                lines.append("*Enabled but unavailable:* " + ", ".join(f"`{p}`" for p in not_available))
            if unknown:
                lines.append("*Unknown platform names:* " + ", ".join(f"`{p}`" for p in unknown))

        if known:
            lines.extend([
                "",
                "*Known platforms:* " + ", ".join(f"`{p}`" for p in known),
            ])

        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

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
        if not self._is_authorized(update):
            return
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
        final_label = self._summarize_report_results_for_button(results)
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(final_label, callback_data="noop")],
                [
                    InlineKeyboardButton("📊 Report Status", callback_data=f"status_{domain_short_id}"),
                    InlineKeyboardButton("📁 Evidence", callback_data=f"evidence_{domain_short_id}"),
                ],
            ])
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

        # Find the domain
        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        # Update status to watchlist
        await self.database.update_domain_status(target["id"], DomainStatus.WATCHLIST)

        # Update button to show watchlist
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("👁 Watchlist - Monitoring", callback_data="noop")]
            ])
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

        # Disable the allowlist button (best-effort).
        try:
            reply_markup = getattr(query.message, "reply_markup", None)
            if reply_markup and getattr(reply_markup, "inline_keyboard", None):
                new_rows = []
                for row in reply_markup.inline_keyboard:
                    new_row = []
                    for button in row:
                        if getattr(button, "callback_data", None) == query.data:
                            new_row.append(InlineKeyboardButton("✅ Allowlisted", callback_data="noop"))
                        else:
                            new_row.append(button)
                    new_rows.append(new_row)
                await query.edit_message_reply_markup(reply_markup=InlineKeyboardMarkup(new_rows))
        except Exception as e:
            logger.debug(f"Failed to update allowlist button state: {e}")

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
        if not self._is_authorized(update):
            return
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

        # Find the domain
        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        if not self._rescan_callback:
            await query.message.reply_text("Rescan not available - callback not configured.")
            return

        # Update button to show processing
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Rescanning...", callback_data="noop")]
            ])
        )

        # Trigger rescan
        try:
            self._rescan_callback(target["domain"])
            await query.message.reply_text(
                f"🔄 Rescan triggered for `{target['domain']}`\n"
                "Results will be posted when complete.",
                parse_mode=ParseMode.MARKDOWN,
            )
        except Exception as e:
            await query.message.reply_text(f"Rescan failed: {e}")

    async def _callback_evidence(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle evidence button callback."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        domain_short_id = query.data.replace("evidence_", "")

        # Find the domain
        target = await self._find_domain_by_short_id(domain_short_id)
        if not target:
            await query.message.reply_text(f"Domain not found: {domain_short_id}")
            return

        # Send evidence files
        evidence_dir = self.evidence_store.get_domain_dir(target["domain"])

        if not evidence_dir.exists():
            await query.message.reply_text(
                f"No evidence found for `{target['domain']}`",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        # Send screenshot
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

        # Parse and send analysis summary
        analysis_file = evidence_dir / "analysis.json"
        if analysis_file.exists():
            import json
            try:
                data = json.loads(analysis_file.read_text())
                summary = self._format_analysis_summary(data)
                await query.message.reply_text(summary)
            except Exception as e:
                logger.error(f"Error parsing analysis: {e}")

            # Also send the raw JSON file
            with open(analysis_file, "rb") as f:
                await query.message.reply_document(
                    document=InputFile(f, filename="analysis.json"),
                    caption="Raw analysis JSON",
                )

        # Send any manual report instruction files
        instruction_files = self.evidence_store.get_report_instruction_paths(target["domain"])
        for path in instruction_files[:5]:
            try:
                with open(path, "rb") as f:
                    await query.message.reply_document(
                        document=InputFile(f, filename=path.name),
                        caption="Manual report instructions",
                    )
            except Exception as e:
                logger.warning(f"Failed to send report instructions {path}: {e}")

    async def _callback_scanpath(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle scan path button callback - analyze a specific URL path."""
        if not self._is_authorized(update):
            return
        query = update.callback_query
        await query.answer()

        # Extract full URL from callback data
        full_url = query.data.replace("scanpath_", "")

        if not self.submit_callback:
            await query.message.reply_text("Submission not available - callback not configured.")
            return

        # Update button to show processing
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Scanning...", callback_data="noop")]
            ])
        )

        # Submit for analysis
        try:
            self.submit_callback(full_url)
            await query.message.reply_text(
                f"🔍 Submitted `{full_url}` for analysis.\n"
                "Results will be posted when complete.",
                parse_mode=ParseMode.MARKDOWN,
            )
        except Exception as e:
            await query.message.reply_text(f"Scan failed: {e}")

    async def _callback_noop(self, update: Update, context: ContextTypes.DEFAULT_TYPE):  # noqa: ARG002
        """Handle no-op callbacks used for disabled buttons."""
        query = getattr(update, "callback_query", None)
        if query:
            await query.answer()

    def _format_analysis_summary(self, data: dict) -> str:
        """Format analysis JSON into readable summary."""
        lines = []

        domain = data.get("domain", "unknown")
        score = data.get("score", 0)
        verdict = data.get("verdict", "unknown")

        lines.append(f"=== ANALYSIS: {domain} ===")
        lines.append(f"Score: {score}/100 ({verdict.upper()})")
        lines.append("")

        # Threat Intel section
        reasons = data.get("reasons", [])
        threat_intel = [r for r in reasons if "KNOWN MALICIOUS" in r or "Malicious" in r]
        if threat_intel:
            lines.append("THREAT INTEL:")
            for r in threat_intel:
                lines.append(f"  * {r}")
            lines.append("")

        # Evasion section
        evasion = [r for r in reasons if "Anti-bot" in r or "blocked" in r.lower()]
        if evasion:
            lines.append("EVASION:")
            for r in evasion:
                lines.append(f"  * {r}")
            lines.append("")

        # Infrastructure section
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

        # Code Analysis section
        code = data.get("code_analysis", {})
        if code.get("reasons") or code.get("kit_matches"):
            lines.append("CODE ANALYSIS:")
            for r in code.get("reasons", []):
                lines.append(f"  * {r}")
            if code.get("kit_matches"):
                lines.append(f"  * Kit matches: {', '.join(code['kit_matches'])}")
            lines.append("")

        # Campaign section
        campaign = data.get("campaign", {})
        if campaign.get("campaign_name"):
            lines.append("CAMPAIGN:")
            lines.append(f"  * {campaign['campaign_name']}")
            if campaign.get("related_domains"):
                lines.append(f"  * Related: {', '.join(campaign['related_domains'])}")
            lines.append("")

        # Suspicious endpoints
        endpoints = data.get("suspicious_endpoints", [])
        if endpoints:
            lines.append("SUSPICIOUS ENDPOINTS:")
            for ep in endpoints[:5]:  # Limit to 5
                lines.append(f"  * {ep}")
            if len(endpoints) > 5:
                lines.append(f"  * ... and {len(endpoints) - 5} more")
            lines.append("")

        # Other signals
        other = [r for r in reasons if not any(x in r for x in ["KNOWN", "Malicious", "Anti-bot", "blocked", "INFRA", "CODE"])]
        if other:
            lines.append("OTHER SIGNALS:")
            for r in other[:5]:
                lines.append(f"  * {r}")
            lines.append("")

        return "\n".join(lines)

    async def _cmd_threshold(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /threshold command."""
        if not self._is_authorized(update):
            return
        # TODO: Implement runtime threshold adjustment
        await update.message.reply_text(
            "Threshold adjustment coming soon.\n"
            "Current threshold is set in `.env` file.",
        )

    async def _cmd_allowlist(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /allowlist command."""
        if not self._is_authorized(update):
            return
        args = [a.strip() for a in (context.args or []) if a.strip()]

        if not args or args[0].lower() in {"list", "show"}:
            entries = sorted(self._read_allowlist_entries())
            if not entries:
                await update.message.reply_text(
                    "*Allowlist* is empty.\n\n"
                    f"File: `{self.allowlist_path}`\n"
                    "Add: `/allowlist add <domain>`",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

            max_items = 50
            lines = [f"*Allowlist* ({len(entries)} entries)", ""]
            for d in entries[:max_items]:
                lines.append(f"- `{d}`")
            extra = len(entries) - max_items
            if extra > 0:
                lines.append(f"...and {extra} more")
            lines.extend([
                "",
                f"File: `{self.allowlist_path}`",
                "Add: `/allowlist add <domain>`",
                "Remove: `/allowlist remove <domain>`",
            ])
            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
            return

        action = args[0].lower()

        if action in {"add", "+"}:
            if len(args) < 2:
                await update.message.reply_text(
                    "Usage: `/allowlist add <domain>`",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

            added: list[str] = []
            already: list[str] = []
            invalid: list[str] = []

            for raw in args[1:]:
                resolved = await self._find_domain_by_short_id(raw)
                candidate = resolved["domain"] if resolved else raw
                hostname = self._extract_hostname(candidate)
                if not hostname:
                    invalid.append(raw)
                    continue

                changed = self._add_allowlist_entry(hostname)
                if changed:
                    added.append(hostname)
                else:
                    already.append(hostname)

                db_target = resolved or await self.database.get_domain(hostname)
                if db_target:
                    await self.database.update_domain_status(
                        db_target["id"],
                        status=DomainStatus.ALLOWLISTED,
                        verdict=Verdict.BENIGN,
                    )

            lines = ["✅ Allowlist updated."]
            if added:
                lines.append("")
                lines.append("*Added:* " + ", ".join(f"`{d}`" for d in sorted(set(added))))
            if already:
                lines.append("")
                lines.append("*Already present:* " + ", ".join(f"`{d}`" for d in sorted(set(already))))
            if invalid:
                lines.append("")
                lines.append("*Invalid:* " + ", ".join(f"`{d}`" for d in sorted(set(invalid))))

            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
            return

        if action in {"remove", "rm", "del", "delete", "-"}:
            if len(args) < 2:
                await update.message.reply_text(
                    "Usage: `/allowlist remove <domain>`",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

            removed: list[str] = []
            missing: list[str] = []
            invalid: list[str] = []

            for raw in args[1:]:
                resolved = await self._find_domain_by_short_id(raw)
                candidate = resolved["domain"] if resolved else raw
                hostname = self._extract_hostname(candidate)
                if not hostname:
                    invalid.append(raw)
                    continue

                changed = self._remove_allowlist_entry(hostname)
                if changed:
                    removed.append(hostname)
                else:
                    missing.append(hostname)

            lines = ["✅ Allowlist updated."]
            if removed:
                lines.append("")
                lines.append("*Removed:* " + ", ".join(f"`{d}`" for d in sorted(set(removed))))
            if missing:
                lines.append("")
                lines.append("*Not present:* " + ", ".join(f"`{d}`" for d in sorted(set(missing))))
            if invalid:
                lines.append("")
                lines.append("*Invalid:* " + ", ".join(f"`{d}`" for d in sorted(set(invalid))))

            lines.extend([
                "",
                "If you want to re-check a domain, run `/rescan <domain>`.",
            ])

            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
            return

        await update.message.reply_text(
            "Usage:\n"
            "`/allowlist` - view\n"
            "`/allowlist add <domain>`\n"
            "`/allowlist remove <domain>`",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_reload(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /reload command - hot reload threat intel."""
        if not self._is_authorized(update):
            return
        if not self._reload_callback:
            await update.message.reply_text(
                "Reload not available - callback not configured."
            )
            return

        try:
            version = self._reload_callback()
            await update.message.reply_text(
                f"Threat intel reloaded (v{version})",
                parse_mode=ParseMode.MARKDOWN,
            )
            logger.info(f"Threat intel reloaded via /reload command (v{version})")
        except Exception as e:
            logger.error(f"Reload failed: {e}")
            await update.message.reply_text(f"Reload failed: {e}")
