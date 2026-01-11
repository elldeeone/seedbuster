"""Telegram report helper methods."""

from __future__ import annotations

import logging
from pathlib import Path

from telegram import InputFile

from ..reporter.base import ReportStatus

logger = logging.getLogger(__name__)


class TelegramReportingMixin:
    """Reporting helper methods."""

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
            except Exception as exc:
                logger.warning("Failed to send report instructions %s: %s", path, exc)
        return sent
