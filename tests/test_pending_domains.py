"""Regression tests for pending domain queries."""

from __future__ import annotations

import pytest

from src.storage.database import Database


@pytest.mark.asyncio
async def test_get_pending_domains_allows_no_limit(tmp_path):
    """Ensure LIMIT None does not raise SQLite datatype mismatch."""
    db = Database(tmp_path / "pending.db")
    await db.connect()
    try:
        domain_id = await db.add_domain("pending.example.com", source="manual", domain_score=1)
        assert domain_id is not None

        pending = await db.get_pending_domains(limit=None)
        assert any(row.get("domain") == "pending.example.com" for row in pending)
    finally:
        await db.close()
