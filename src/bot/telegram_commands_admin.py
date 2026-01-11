"""Admin command handlers."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from ..storage.database import DomainStatus, Verdict


class TelegramCommandsAdminMixin:
    """Admin command handlers."""

    async def _cmd_threshold(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /threshold command."""
        if not self._is_authorized(update):
            return
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
            lines.extend(
                [
                    "",
                    f"File: `{self.allowlist_path}`",
                    "Add: `/allowlist add <domain>`",
                    "Remove: `/allowlist remove <domain>`",
                ]
            )
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
                lines.append(
                    "*Already present:* " + ", ".join(f"`{d}`" for d in sorted(set(already)))
                )
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
                lines.append(
                    "*Removed:* " + ", ".join(f"`{d}`" for d in sorted(set(removed)))
                )
            if missing:
                lines.append("")
                lines.append(
                    "*Not present:* " + ", ".join(f"`{d}`" for d in sorted(set(missing)))
                )
            if invalid:
                lines.append("")
                lines.append("*Invalid:* " + ", ".join(f"`{d}`" for d in sorted(set(invalid))))

            lines.extend(
                [
                    "",
                    "*Tip:* use `/allowlist list` to confirm the current list.",
                ]
            )

            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
            return

        await update.message.reply_text(
            "Usage: `/allowlist [list|add|remove] <domain>`",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_reload(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /reload command to reload threat intel."""
        if not self._is_authorized(update):
            return
        if not self._reload_callback:
            await update.message.reply_text("Reload callback not configured.")
            return

        version = self._reload_callback()
        await update.message.reply_text(
            f"Threat intel reloaded (v{version}).",
            parse_mode=ParseMode.MARKDOWN,
        )
