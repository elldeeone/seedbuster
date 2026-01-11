"""Action command handlers."""

from __future__ import annotations

import logging
from pathlib import Path

from telegram import InputFile, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

logger = logging.getLogger(__name__)


class TelegramCommandsActionsMixin:
    """Action command handlers."""

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

        raw = update.message.text
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
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        domain = context.args[0].lower().strip()
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

        evidence_dir = self.evidence_store.get_domain_dir(target["domain"])

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

        analysis = evidence_dir / "analysis.json"
        if analysis.exists():
            with open(analysis, "rb") as f:
                await update.message.reply_document(
                    document=InputFile(f, filename="analysis.json"),
                    caption="Analysis details",
                )
