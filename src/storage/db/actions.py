"""Dashboard action queue operations."""

from __future__ import annotations

import json


class ActionsMixin:
    """Dashboard actions queue helpers."""

    async def enqueue_dashboard_action(
        self,
        kind: str,
        payload: dict,
        *,
        target: str | None = None,
        bulk_id: str | None = None,
        dedupe: bool = False,
    ) -> int:
        """Add an admin action requested by the dashboard (processed by the pipeline)."""
        record = {
            "kind": str(kind or "").strip().lower(),
            "payload": payload or {},
        }
        if not record["kind"]:
            raise ValueError("Action kind is required")

        resolved_target = (target or record["payload"].get("domain") or "").strip().lower() or None
        resolved_bulk = (bulk_id or "").strip() or None

        async with self._lock:
            if dedupe and resolved_target:
                cursor = await self._connection.execute(
                    """
                    SELECT 1
                    FROM dashboard_actions
                    WHERE kind = ?
                      AND target = ?
                      AND status IN ('pending', 'processing')
                    LIMIT 1
                    """,
                    (record["kind"], resolved_target),
                )
                exists = await cursor.fetchone()
                if exists:
                    return 0

            cursor = await self._connection.execute(
                """
                INSERT INTO dashboard_actions (kind, payload, target, bulk_id, status)
                VALUES (?, ?, ?, ?, 'pending')
                """,
                (
                    record["kind"],
                    json.dumps(record["payload"]),
                    resolved_target,
                    resolved_bulk,
                ),
            )
            await self._connection.commit()
            return int(cursor.lastrowid)

    async def has_pending_dashboard_action(self, kind: str, target: str) -> bool:
        """Check if a pending/processing dashboard action already exists for target."""
        action = str(kind or "").strip().lower()
        target_value = str(target or "").strip().lower()
        if not action or not target_value:
            return False
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT 1
                FROM dashboard_actions
                WHERE kind = ?
                  AND target = ?
                  AND status IN ('pending', 'processing')
                LIMIT 1
                """,
                (action, target_value),
            )
            row = await cursor.fetchone()
            return row is not None

    async def get_bulk_action_stats(self, bulk_id: str) -> dict[str, int]:
        """Return status counts for a bulk dashboard action batch."""
        bulk_value = str(bulk_id or "").strip()
        if not bulk_value:
            return {"total": 0}
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT status, COUNT(*) as count
                FROM dashboard_actions
                WHERE bulk_id = ?
                GROUP BY status
                """,
                (bulk_value,),
            )
            rows = await cursor.fetchall()
        counts = {str(r["status"]): int(r["count"]) for r in rows}
        counts["total"] = sum(counts.values())
        return counts

    async def claim_dashboard_actions(self, limit: int = 20) -> list[dict]:
        """Claim pending dashboard actions for processing (multi-process safe, best-effort)."""
        limit = max(1, min(int(limit), 100))

        async with self._lock:
            try:
                await self._connection.execute("BEGIN IMMEDIATE")
            except Exception:
                # If we can't start a write transaction, just bail and retry later.
                return []

            cursor = await self._connection.execute(
                """
                SELECT id, kind, payload
                FROM dashboard_actions
                WHERE status = 'pending'
                ORDER BY id ASC
                LIMIT ?
                """,
                (limit,),
            )
            rows = await cursor.fetchall()
            ids = [int(r["id"]) for r in rows]

            if ids:
                await self._connection.executemany(
                    """
                    UPDATE dashboard_actions
                    SET status = 'processing', claimed_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND status = 'pending'
                    """,
                    [(i,) for i in ids],
                )
            await self._connection.commit()

        return [dict(r) for r in rows]

    async def finish_dashboard_action(
        self,
        action_id: int,
        *,
        status: str,
        error: str | None = None,
    ) -> None:
        """Mark a dashboard action as done/failed."""
        status_value = (status or "").strip().lower() or "done"
        if status_value not in {"done", "failed"}:
            raise ValueError("Invalid action status")

        async with self._lock:
            await self._connection.execute(
                """
                UPDATE dashboard_actions
                SET status = ?,
                    processed_at = CURRENT_TIMESTAMP,
                    error = ?
                WHERE id = ?
                """,
                (status_value, error, int(action_id)),
            )
            await self._connection.commit()
