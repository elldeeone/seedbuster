"""Report record operations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional


class ReportsMixin:
    """Report CRUD helpers."""

    async def add_report(
        self,
        domain_id: int,
        platform: str,
        status: str = "pending",
    ) -> int:
        """Add a report record for a domain."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                INSERT INTO reports (domain_id, platform, status)
                VALUES (?, ?, ?)
                """,
                (domain_id, platform, status),
            )
            await self._connection.commit()
            return cursor.lastrowid

    async def update_report(
        self,
        report_id: int,
        status: str,
        response: str = None,
        response_data: str | None = None,
        retry_after: int | None = None,
        next_attempt_at: str | None = None,
    ):
        """Update report status."""
        status_lower = (status or "").strip().lower()

        success_statuses = {"submitted", "confirmed", "duplicate"}
        set_submitted_at = status_lower in success_statuses

        if status_lower == "rate_limited":
            if retry_after is None:
                retry_after = 60
            if next_attempt_at is None:
                # Store in a SQLite-friendly format so comparisons with CURRENT_TIMESTAMP
                # behave as expected ("YYYY-MM-DD HH:MM:SS").
                next_attempt_at = (
                    datetime.now(timezone.utc) + timedelta(seconds=int(retry_after))
                ).strftime("%Y-%m-%d %H:%M:%S")

        async with self._lock:
            await self._connection.execute(
                """
                UPDATE reports
                SET status = ?,
                    response = ?,
                    response_data = COALESCE(?, response_data),
                    attempted_at = CURRENT_TIMESTAMP,
                    submitted_at = CASE
                        WHEN ? THEN CURRENT_TIMESTAMP
                        ELSE submitted_at
                    END,
                    attempts = COALESCE(attempts, 0) + 1,
                    retry_after = CASE
                        WHEN ? THEN ?
                        ELSE NULL
                    END,
                    next_attempt_at = CASE
                        WHEN ? THEN ?
                        ELSE NULL
                    END
                WHERE id = ?
                """,
                (
                    status,
                    response,
                    response_data,
                    1 if set_submitted_at else 0,
                    1 if status_lower == "rate_limited" else 0,
                    int(retry_after) if retry_after is not None else None,
                    1 if status_lower == "rate_limited" else 0,
                    next_attempt_at,
                    report_id,
                ),
            )
            await self._connection.commit()

    async def cancel_pending_reports_for_domain(
        self,
        domain_id: int,
        reason: str = "Domain status changed"
    ) -> int:
        """
        Cancel all pending/manual_required/rate_limited reports for a domain.

        Sets their status to 'skipped' and clears retry timing.
        Returns the number of reports cancelled.
        """
        async with self._lock:
            cursor = await self._connection.execute(
                """
                UPDATE reports
                SET status = 'skipped',
                    response = ?,
                    next_attempt_at = NULL,
                    retry_after = NULL
                WHERE domain_id = ?
                  AND status IN ('pending', 'manual_required', 'rate_limited')
                """,
                (reason, domain_id)
            )
            await self._connection.commit()
            return cursor.rowcount

    async def get_reports_for_domain(self, domain_id: int) -> list[dict]:
        """Get all reports for a domain."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT * FROM reports
                WHERE domain_id = ?
                ORDER BY COALESCE(attempted_at, submitted_at, created_at) DESC
                """,
                (domain_id,),
            )
            return await self._fetchall_dicts(cursor)

    async def get_latest_report(self, domain_id: int, platform: str) -> Optional[dict]:
        """Get most recent report row for (domain_id, platform)."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT * FROM reports
                WHERE domain_id = ? AND platform = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (domain_id, platform),
            )
            return await self._fetchone_dict(cursor)

    async def get_due_retry_reports(self, limit: int = 20) -> list[dict]:
        """Get rate-limited reports that are due for retry."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT r.*, d.domain as domain
                FROM reports r
                JOIN domains d ON r.domain_id = d.id
                WHERE r.status = 'rate_limited'
                  AND (
                        r.next_attempt_at IS NULL
                        OR datetime(r.next_attempt_at) <= CURRENT_TIMESTAMP
                        OR datetime(r.next_attempt_at) IS NULL
                      )
                ORDER BY COALESCE(datetime(r.next_attempt_at), r.attempted_at, r.created_at) ASC
                LIMIT ?
                """,
                (limit,),
            )
            return await self._fetchall_dicts(cursor)

    async def get_pending_reports(self) -> list[dict]:
        """Get all domains with pending report status (approval/manual/retry)."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT r.*, d.domain
                FROM reports r
                JOIN domains d ON r.domain_id = d.id
                WHERE r.status IN ('pending', 'manual_required', 'rate_limited')
                  AND d.status NOT IN ('watchlist', 'allowlisted', 'false_positive')
                ORDER BY r.id ASC
                """
            )
            return await self._fetchall_dicts(cursor)
