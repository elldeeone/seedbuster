"""Telegram bot for SeedBuster interaction."""

from .telegram_allowlist import TelegramAllowlistMixin
from .telegram_callbacks import TelegramCallbacksMixin
from .telegram_commands_actions import TelegramCommandsActionsMixin
from .telegram_commands_admin import TelegramCommandsAdminMixin
from .telegram_commands_basic import TelegramCommandsBasicMixin
from .telegram_commands_campaign import TelegramCommandsCampaignMixin
from .telegram_commands_report import TelegramCommandsReportMixin
from .telegram_commands_reports import TelegramCommandsReportsMixin
from .telegram_core import TelegramCoreMixin
from .telegram_formatting import TelegramFormattingMixin
from .telegram_lifecycle import TelegramLifecycleMixin
from .telegram_lookup import TelegramLookupMixin
from .telegram_reporting import TelegramReportingMixin


class SeedBusterBot(
    TelegramCoreMixin,
    TelegramAllowlistMixin,
    TelegramFormattingMixin,
    TelegramReportingMixin,
    TelegramLifecycleMixin,
    TelegramLookupMixin,
    TelegramCallbacksMixin,
    TelegramCommandsBasicMixin,
    TelegramCommandsActionsMixin,
    TelegramCommandsReportMixin,
    TelegramCommandsCampaignMixin,
    TelegramCommandsReportsMixin,
    TelegramCommandsAdminMixin,
):
    """Telegram bot for SeedBuster alerts and control."""

    pass
