"""Core database setup/migrations."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import aiosqlite

from .helpers import DatabaseFetchMixin
from .maintenance import DatabaseMaintenanceMixin
from .migrations import DatabaseMigrationsMixin
from .schema import DatabaseSchemaMixin

logger = logging.getLogger(__name__)


class DatabaseBase(
    DatabaseSchemaMixin,
    DatabaseMigrationsMixin,
    DatabaseMaintenanceMixin,
    DatabaseFetchMixin,
):
    """Shared connection, migrations, and core helpers."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._connection: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def connect(self):
        """Establish database connection and create tables."""
        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        # Enable better multi-process concurrency for dashboard + pipeline usage.
        # Best-effort because some SQLite builds/settings may reject these pragmas.
        try:
            await self._connection.execute("PRAGMA journal_mode=WAL")
            await self._connection.execute("PRAGMA synchronous=NORMAL")
            await self._connection.execute("PRAGMA busy_timeout=5000")
            await self._connection.commit()
        except Exception:
            pass
        await self._create_tables()

    async def close(self):
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None
