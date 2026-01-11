"""Basic command handlers."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from .formatters import AlertFormatter


class TelegramCommandsBasicMixin:
    """Basic command handlers."""

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
                limit = min(limit, 50)
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
