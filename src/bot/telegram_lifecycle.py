"""Telegram bot lifecycle helpers."""

from __future__ import annotations

import logging
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile, InputMediaPhoto, Update
from telegram.constants import ParseMode
from telegram.error import NetworkError
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from .formatters import AlertFormatter, AlertData

logger = logging.getLogger(__name__)


class TelegramLifecycleMixin:
    """Lifecycle and messaging helpers."""

    async def start(self):
        """Start the Telegram bot."""
        self._app = Application.builder().token(self.token).build()

        self._app.add_error_handler(self._handle_error)

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

        self._app.add_handler(CallbackQueryHandler(self._callback_approve, pattern="^approve_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_reject, pattern="^reject_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_allowlist, pattern="^allow_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_defer, pattern="^defer_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_report_status, pattern="^status_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_rescan, pattern="^rescan_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_evidence, pattern="^evidence_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_scanpath, pattern="^scanpath_"))
        self._app.add_handler(CallbackQueryHandler(self._callback_noop, pattern="^noop$"))

        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)

        logger.info("Telegram bot started")

    async def _handle_error(self, update: object, context: ContextTypes.DEFAULT_TYPE):
        """Handle unexpected exceptions from Telegram handlers."""
        err = getattr(context, "error", None)
        update_id = getattr(update, "update_id", None)

        if isinstance(err, NetworkError):
            logger.warning("Telegram network error (update_id=%s): %s", update_id, err)
            return

        logger.exception("Unhandled Telegram handler error (update_id=%s)", update_id, exc_info=err)

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
            message = AlertFormatter.format_alert(data)

            available_platforms = (
                self.report_manager.get_available_platforms() if self.report_manager else []
            )
            show_report_button = bool(
                include_report_buttons
                and self.report_manager
                and data.score >= self.report_min_score
                and self.report_require_approval
                and available_platforms
            )

            temporal = data.temporal
            keyboard = None

            if data.seed_form_found:
                rows = []
                if show_report_button:
                    rows.append([
                        InlineKeyboardButton(
                            "🎯 Report (Seed Form Found)",
                            callback_data=f"approve_{data.domain_id}",
                        ),
                    ])
                rows.append([
                    InlineKeyboardButton("✅ Allowlist", callback_data=f"allow_{data.domain_id}"),
                    InlineKeyboardButton("❌ False Positive", callback_data=f"reject_{data.domain_id}"),
                    InlineKeyboardButton("📊 Report Status", callback_data=f"status_{data.domain_id}"),
                ])
                keyboard = InlineKeyboardMarkup(rows)
            elif temporal and temporal.is_initial_scan and temporal.cloaking_suspected:
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
                    InlineKeyboardButton("✅ Allowlist", callback_data=f"allow_{data.domain_id}"),
                    InlineKeyboardButton("❌ False Positive", callback_data=f"reject_{data.domain_id}"),
                    InlineKeyboardButton("📊 Report Status", callback_data=f"status_{data.domain_id}"),
                ])
                keyboard = InlineKeyboardMarkup(rows)
            elif temporal and temporal.cloaking_confirmed:
                rows = []
                if show_report_button:
                    rows.append([
                        InlineKeyboardButton(
                            "🚨 Report (Cloaking Confirmed)",
                            callback_data=f"approve_{data.domain_id}",
                        ),
                    ])
                rows.append([
                    InlineKeyboardButton("✅ Allowlist", callback_data=f"allow_{data.domain_id}"),
                    InlineKeyboardButton("❌ False Positive", callback_data=f"reject_{data.domain_id}"),
                    InlineKeyboardButton("📊 Report Status", callback_data=f"status_{data.domain_id}"),
                ])
                keyboard = InlineKeyboardMarkup(rows)
            else:
                first_row = []
                if show_report_button:
                    first_row.append(
                        InlineKeyboardButton(
                            "✅ Approve & Report",
                            callback_data=f"approve_{data.domain_id}",
                        )
                    )
                first_row.append(
                    InlineKeyboardButton("✅ Allowlist", callback_data=f"allow_{data.domain_id}")
                )
                first_row.append(
                    InlineKeyboardButton("❌ False Positive", callback_data=f"reject_{data.domain_id}")
                )
                keyboard = InlineKeyboardMarkup(
                    [
                        first_row,
                        [
                            InlineKeyboardButton(
                                "📊 Report Status",
                                callback_data=f"status_{data.domain_id}",
                            ),
                        ],
                    ]
                )

            if data.urlscan_result_url:
                urlscan_row = [InlineKeyboardButton("🔎 urlscan.io", url=data.urlscan_result_url)]
                if keyboard:
                    rows = [list(r) for r in keyboard.inline_keyboard]
                    rows.append(urlscan_row)
                    keyboard = InlineKeyboardMarkup(rows)
                else:
                    keyboard = InlineKeyboardMarkup([urlscan_row])

            screenshots_to_send = []
            if data.screenshot_paths:
                screenshots_to_send = [p for p in data.screenshot_paths if Path(p).exists()]
            elif data.screenshot_path and Path(data.screenshot_path).exists():
                screenshots_to_send = [data.screenshot_path]

            if len(screenshots_to_send) > 1:
                await self._app.bot.send_message(
                    chat_id=self.chat_id,
                    text=message,
                )

                media = []
                for path in screenshots_to_send:
                    with open(path, "rb") as f:
                        label = (
                            Path(path).stem.replace("screenshot", "").replace("_", " ").strip()
                            or "Final"
                        )
                        caption = f"📸 {label.title() if label else 'Final'}"
                        media.append(
                            InputMediaPhoto(
                                media=f.read(),
                                caption=caption,
                            )
                        )

                await self._app.bot.send_media_group(
                    chat_id=self.chat_id,
                    media=media,
                )
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
                with open(screenshots_to_send[0], "rb") as f:
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

            logger.info("Sent alert for %s (%s screenshots)", data.domain, len(screenshots_to_send))

        except Exception as exc:
            logger.error("Failed to send alert: %s", exc)

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
        except Exception as exc:
            logger.error("Failed to send message: %s", exc)

    def _is_authorized(self, update: Update) -> bool:
        """Return True if this update is from the configured chat."""
        chat = update.effective_chat
        if not chat:
            return False
        return str(chat.id) == str(self.chat_id)
