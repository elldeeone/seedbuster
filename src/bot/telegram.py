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
from ..storage.database import Database, DomainStatus
from ..storage.evidence import EvidenceStore

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..reporter.manager import ReportManager


_URL_RE = re.compile(r"https?://\S+")


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
        report_require_approval: bool = True,
        report_min_score: int = 70,
    ):
        self.token = token
        self.chat_id = chat_id
        self.database = database
        self.evidence_store = evidence_store
        self.submit_callback = submit_callback
        self.report_manager = report_manager
        self.report_require_approval = report_require_approval
        self.report_min_score = report_min_score

        self._app: Optional[Application] = None
        self._queue_size_callback: Optional[Callable[[], int]] = None
        self._rescan_callback: Optional[Callable[[str], None]] = None
        self._reload_callback: Optional[Callable[[], str]] = None
        self._is_running = True

    @staticmethod
    def _extract_first_url(text: str) -> Optional[str]:
        """Extract first URL from a block of text (best-effort)."""
        if not text:
            return None
        match = _URL_RE.search(text)
        if not match:
            return None
        return match.group(0).rstrip(").,]}>\"'")

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

            if status in {"failed", "manual_required", "pending"} and response_text:
                response_snippet = response_text.strip().replace("\n", " ")
                if response_snippet:
                    max_len = 200 if status in {"manual_required", "pending"} else 120
                    if len(response_snippet) > max_len:
                        response_snippet = response_snippet[: max_len - 1] + "…"
                    safe_response = response_snippet.replace("`", "'")
                    line += f" - `{safe_response}`"

            status_lines.append(line)
        return "\n".join(status_lines)

    def set_queue_size_callback(self, callback: Callable[[], int]):
        """Set callback to get current queue size."""
        self._queue_size_callback = callback

    def set_rescan_callback(self, callback: Callable[[str], None]):
        """Set callback to trigger manual rescan."""
        self._rescan_callback = callback

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
        self._app.add_handler(CommandHandler("threshold", self._cmd_threshold))
        self._app.add_handler(CommandHandler("allowlist", self._cmd_allowlist))
        self._app.add_handler(CommandHandler("reload", self._cmd_reload))

        # Callback handlers for inline buttons
        self._app.add_handler(CallbackQueryHandler(self._callback_approve, pattern="^approve_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_reject, pattern="^reject_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_defer, pattern="^defer_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_report_status, pattern="^status_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_rescan, pattern="^rescan_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_evidence, pattern="^evidence_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_scanpath, pattern="^scanpath_"))

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

            # Create inline keyboard for report actions (if high confidence)
            keyboard = None
            if include_report_buttons and self.report_manager and data.score >= self.report_min_score:
                # Context-aware buttons based on detection status
                # Priority: seed_form_found > cloaking_confirmed > cloaking_suspected > standard
                available_platforms = self.report_manager.get_available_platforms()
                show_report_button = self.report_require_approval and bool(available_platforms)
                temporal = data.temporal

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
                            "❌ False Positive",
                            callback_data=f"reject_{data.domain_id}",
                        ),
                        InlineKeyboardButton(
                            "📊 Status",
                            callback_data=f"status_{data.domain_id}",
                        ),
                    ])
                    keyboard = InlineKeyboardMarkup(rows)
                elif temporal and temporal.is_initial_scan and temporal.cloaking_suspected:
                    # Initial scan with suspected cloaking - offer defer as primary
                    rows = [[
                        InlineKeyboardButton(
                            "🕐 Defer (Wait for Rescans)",
                            callback_data=f"defer_{data.domain_id}",
                        ),
                    ]]
                    action_row = []
                    if show_report_button:
                        action_row.append(InlineKeyboardButton(
                            "✅ Report Now",
                            callback_data=f"approve_{data.domain_id}",
                        ))
                    action_row.append(InlineKeyboardButton(
                        "❌ False Positive",
                        callback_data=f"reject_{data.domain_id}",
                    ))
                    action_row.append(InlineKeyboardButton(
                        "📊 Status",
                        callback_data=f"status_{data.domain_id}",
                    ))
                    rows.append(action_row)
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
                            "❌ False Positive",
                            callback_data=f"reject_{data.domain_id}",
                        ),
                        InlineKeyboardButton(
                            "📊 Status",
                            callback_data=f"status_{data.domain_id}",
                        ),
                    ])
                    keyboard = InlineKeyboardMarkup(rows)
                else:
                    # Standard buttons
                    first_row = []
                    if show_report_button:
                        first_row.append(InlineKeyboardButton(
                            "✅ Approve & Report",
                            callback_data=f"approve_{data.domain_id}",
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
        if not self._is_authorized(update):
            return
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
        if not self._is_authorized(update):
            return
        # Same as status for now
        await self._cmd_status(update, context)

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

        url_input = context.args[0].lower()
        # Clean up URL - remove protocol but keep path
        url_input = url_input.replace("https://", "").replace("http://", "")

        # Split into domain and path
        if "/" in url_input:
            domain = url_input.split("/")[0]
            path = "/" + "/".join(url_input.split("/")[1:])
            full_url = f"{domain}{path}"
        else:
            domain = url_input
            path = ""
            full_url = domain

        # Check if domain was already analyzed (check both domain and full URL)
        existing = await self.database.get_domain(full_url) or await self.database.get_domain(domain)
        if existing:
            # Domain exists - show previous results with options
            existing_domain = existing.get("domain", domain)
            score = existing.get("analysis_score") or 0
            verdict = existing.get("verdict", "unknown")
            status = existing.get("status", "unknown")
            analyzed_at = existing.get("analyzed_at", "unknown")
            domain_id = self.evidence_store.get_domain_id(existing_domain)

            # Build keyboard - add "Scan This Path" if path differs
            path_note = ""
            has_new_path = path and path not in existing_domain

            if has_new_path:
                # Path differs - offer to scan the specific path
                keyboard = InlineKeyboardMarkup([
                    [
                        InlineKeyboardButton(
                            f"🔍 Scan {path}",
                            callback_data=f"scanpath_{full_url[:50]}"  # Truncate for callback limit
                        ),
                    ],
                    [
                        InlineKeyboardButton(
                            "🔄 Rescan Base",
                            callback_data=f"rescan_{domain_id}"
                        ),
                        InlineKeyboardButton(
                            "📁 Evidence",
                            callback_data=f"evidence_{domain_id}"
                        ),
                    ],
                    [
                        InlineKeyboardButton(
                            "📊 Report Status",
                            callback_data=f"status_{domain_id}"
                        ),
                    ],
                ])
                path_note = f"\n\n_Path `{path}` not yet analyzed._"
            else:
                keyboard = InlineKeyboardMarkup([
                    [
                        InlineKeyboardButton(
                            "🔄 Rescan Now",
                            callback_data=f"rescan_{domain_id}"
                        ),
                        InlineKeyboardButton(
                            "📁 Evidence",
                            callback_data=f"evidence_{domain_id}"
                        ),
                    ],
                    [
                        InlineKeyboardButton(
                            "📊 Report Status",
                            callback_data=f"status_{domain_id}"
                        ),
                    ],
                ])

            await update.message.reply_text(
                f"*Domain already analyzed:* `{existing_domain}`\n\n"
                f"Score: {score}/100 ({verdict})\n"
                f"Status: {status}\n"
                f"Analyzed: {analyzed_at}{path_note}\n\n"
                "Choose an action below:",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=keyboard,
            )
            return

        # New domain/URL - submit for analysis (pass full URL with path)
        if self.submit_callback:
            self.submit_callback(full_url)
            display = full_url if path else domain
            await update.message.reply_text(
                f"Submitted `{display}` for analysis.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await update.message.reply_text("Submission not available.")

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

        # Parse first token per line for table pastes, plus any whitespace-separated tokens.
        candidates: list[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip obvious headers
            if line.lower().startswith(("url", "age", "size", "ips", "asns")):
                continue
            # Take first column to support urlscan "similar pages" tables.
            first = line.split()[0]
            candidates.append(first)

        if not candidates:
            candidates = raw.split()

        def normalize(token: str) -> str | None:
            t = (token or "").strip().strip("`'\"(),;")
            if not t:
                return None
            t = t.replace("https://", "").replace("http://", "")
            t = t.strip().strip("`'\"(),;")
            if not t or "." not in t:
                return None
            return t.lower()

        normalized: list[str] = []
        seen = set()
        invalid = 0
        for token in candidates:
            norm = normalize(token)
            if not norm:
                invalid += 1
                continue
            if norm in seen:
                continue
            seen.add(norm)
            normalized.append(norm)

        if not normalized:
            await update.message.reply_text(
                "No valid domains found. Paste domains/URLs separated by spaces/newlines.",
            )
            return

        if not self.submit_callback:
            await update.message.reply_text("Submission not available.")
            return

        queued = 0
        skipped_existing = 0
        # Avoid huge spam submissions in one go; Telegram message limits will usually cap this anyway.
        max_batch = 200
        if len(normalized) > max_batch:
            normalized = normalized[:max_batch]

        for domain in normalized:
            try:
                if await self.database.domain_exists(domain):
                    skipped_existing += 1
                    continue
                self.submit_callback(domain)
                queued += 1
            except Exception:
                # Best-effort: continue bulk submission even if one entry errors.
                continue

        await update.message.reply_text(
            f"Queued {queued} domains for analysis.\n"
            f"Skipped existing: {skipped_existing}\n"
            f"Ignored invalid/empty: {invalid}",
        )

    async def _cmd_ack(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ack command."""
        if not self._is_authorized(update):
            return
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

    async def _cmd_defer(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /defer command - wait for rescans before deciding."""
        if not self._is_authorized(update):
            return
        if not context.args:
            await update.message.reply_text("Usage: `/defer <domain_id>`", parse_mode=ParseMode.MARKDOWN)
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
            await self.database.update_domain_status(target["id"], DomainStatus.DEFERRED)
            await update.message.reply_text(
                f"\U0001F551 Deferred: `{target['domain']}`\n\n"
                "Waiting for rescans at 6h/12h/24h/48h intervals.\n"
                "You'll receive an update when rescans complete.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await update.message.reply_text(f"Domain not found: {domain_id}")

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

        if not self._rescan_callback:
            await update.message.reply_text("Rescan not available - callback not configured.")
            return

        await update.message.reply_text(
            f"\U0001F504 Triggering rescan for `{domain}`...",
            parse_mode=ParseMode.MARKDOWN,
        )

        try:
            self._rescan_callback(domain)
        except Exception as e:
            await update.message.reply_text(f"Rescan failed: {e}")

    async def _cmd_fp(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /fp (false positive) command."""
        if not self._is_authorized(update):
            return
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
        if not self._is_authorized(update):
            return
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
        if not self._is_authorized(update):
            return
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
                await update.message.reply_text(
                    self._format_report_status_message(domain, reports),
                    parse_mode=ParseMode.MARKDOWN,
                )
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
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Reports Submitted", callback_data="noop")]
            ])
        )
        await query.message.reply_text(summary)

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

        # Update status to deferred
        await self.database.update_domain_status(target["id"], DomainStatus.DEFERRED)

        # Update button to show deferred
        await query.edit_message_reply_markup(
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🕐 Deferred - Awaiting Rescans", callback_data="noop")]
            ])
        )
        await query.message.reply_text(
            f"🕐 Deferred: `{target['domain']}`\n\n"
            "Waiting for rescans at 6h/12h/24h/48h intervals.\n"
            "You'll receive an update when rescans complete.",
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
        screenshot = evidence_dir / "screenshot.png"
        if screenshot.exists():
            with open(screenshot, "rb") as f:
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

        # Cluster section
        cluster = data.get("cluster", {})
        if cluster.get("cluster_name"):
            lines.append("CAMPAIGN:")
            lines.append(f"  * {cluster['cluster_name']}")
            if cluster.get("related_domains"):
                lines.append(f"  * Related: {', '.join(cluster['related_domains'])}")
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
        # TODO: Implement allowlist management
        await update.message.reply_text(
            "Allowlist management coming soon.\n"
            "Currently managed via `config/allowlist.txt`",
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
