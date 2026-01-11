"""SQLite database operations for SeedBuster."""

from __future__ import annotations

from pathlib import Path

from .enums import DomainStatus, Verdict, ScamType
from .db.actions import ActionsMixin
from .db.base import DatabaseBase
from .db.domain_read import DomainReadMixin
from .db.domain_write import DomainWriteMixin
from .db.public import PublicMixin
from .db.reports import ReportsMixin
from .db.stats import StatsMixin
from .db.takedown import TakedownMixin


class Database(
    DatabaseBase,
    DomainWriteMixin,
    DomainReadMixin,
    ActionsMixin,
    ReportsMixin,
    PublicMixin,
    TakedownMixin,
    StatsMixin,
):
    """Async SQLite database for domain tracking."""

    def __init__(self, db_path: Path):
        super().__init__(db_path)


__all__ = ["Database", "DomainStatus", "Verdict", "ScamType"]
