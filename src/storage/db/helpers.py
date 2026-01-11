"""Database row conversion helpers."""

from __future__ import annotations

from typing import Optional


class DatabaseFetchMixin:
    """Row conversion helpers."""

    async def _fetchone_dict(self, cursor) -> Optional[dict]:
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def _fetchall_dicts(self, cursor) -> list[dict]:
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
