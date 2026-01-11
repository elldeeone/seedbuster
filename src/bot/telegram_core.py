"""Telegram bot core mixin."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Optional, TYPE_CHECKING

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from .service import BotService, KeyboardButton
from ..storage.database import Database
from ..storage.evidence import EvidenceStore
from ..utils.domains import extract_first_url, extract_hostname

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..reporter.manager import ReportManager
    from ..analyzer.campaigns import ThreatCampaignManager
    from ..reporter.evidence_packager import EvidencePackager


class TelegramCoreMixin:
    """Core initialization and helpers."""

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

        self._app = None
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
        return extract_first_url(text)

    @staticmethod
    def _extract_hostname(value: str) -> str:
        """Extract a hostname from a domain/URL input (best-effort)."""
        return extract_hostname(value)

    @staticmethod
    def _to_markup(button_rows: list[list[KeyboardButton]] | None):
        """Convert plain button rows into Telegram markup."""
        if not button_rows:
            return None
        rows = []
        for row in button_rows:
            rows.append([InlineKeyboardButton(btn.text, callback_data=btn.callback_data) for btn in row])
        return InlineKeyboardMarkup(rows)

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
