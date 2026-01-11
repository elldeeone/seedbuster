"""Public submissions and engagement helpers."""

from __future__ import annotations

from typing import Optional


class PublicMixin:
    """Public submissions + engagement + rescan helpers."""

    async def add_public_submission(
        self,
        domain: str,
        canonical_domain: str,
        source_url: Optional[str] = None,
        submitted_url: Optional[str] = None,
        reporter_notes: Optional[str] = None,
    ) -> tuple[int, bool]:
        """
        Insert a public submission or bump the counter if it already exists.

        Returns:
            (submission_id, is_duplicate)
        """
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT id, submission_count
                FROM public_submissions
                WHERE canonical_domain = ?
                """,
                (canonical_domain,),
            )
            row = await cursor.fetchone()

            if row:
                new_count = int(row["submission_count"] or 1) + 1
                await self._connection.execute(
                    """
                    UPDATE public_submissions
                    SET submission_count = ?,
                        last_submitted_at = CURRENT_TIMESTAMP,
                        source_url = COALESCE(?, source_url),
                        submitted_url = COALESCE(?, submitted_url),
                        reporter_notes = CASE
                            WHEN ? IS NOT NULL AND TRIM(?) != '' THEN
                                TRIM(
                                    COALESCE(reporter_notes, '')
                                    || CASE WHEN TRIM(reporter_notes) = '' THEN '' ELSE '\n' END
                                    || TRIM(?)
                                )
                            ELSE reporter_notes
                        END
                    WHERE id = ?
                    """,
                    (
                        new_count,
                        source_url,
                        submitted_url,
                        reporter_notes,
                        reporter_notes,
                        reporter_notes,
                        row["id"],
                    ),
                )
                await self._connection.commit()
                return int(row["id"]), True

            cursor = await self._connection.execute(
                """
                INSERT INTO public_submissions (domain, canonical_domain, source_url, submitted_url, reporter_notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (domain, canonical_domain, source_url, submitted_url, reporter_notes),
            )
            await self._connection.commit()
            return int(cursor.lastrowid), False

    async def get_public_submissions(
        self,
        *,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """List public submissions, optionally filtered by status."""
        status_filter = ""
        params: list[object] = []
        if status:
            status_filter = "WHERE status = ?"
            params.append(status)
        params.extend([limit, offset])

        async with self._lock:
            cursor = await self._connection.execute(
                f"""
                SELECT *
                FROM public_submissions
                {status_filter}
                ORDER BY first_submitted_at ASC
                LIMIT ? OFFSET ?
                """,
                params,
            )
            return await self._fetchall_dicts(cursor)

    async def count_public_submissions(self, *, status: Optional[str] = None) -> int:
        """Count submissions, optionally by status."""
        status_filter = ""
        params: list[object] = []
        if status:
            status_filter = "WHERE status = ?"
            params.append(status)

        async with self._lock:
            cursor = await self._connection.execute(
                f"SELECT COUNT(*) as count FROM public_submissions {status_filter}",
                params,
            )
            row = await cursor.fetchone()
            return int(row["count"] if row else 0)

    async def get_public_submission(self, submission_id: int) -> Optional[dict]:
        """Fetch a single submission by id."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM public_submissions WHERE id = ?",
                (submission_id,),
            )
            return await self._fetchone_dict(cursor)

    async def update_public_submission_status(
        self,
        submission_id: int,
        status: str,
        *,
        reviewer_notes: Optional[str] = None,
        promoted_domain_id: Optional[int] = None,
    ) -> bool:
        """Update status/notes for a submission."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                UPDATE public_submissions
                SET status = ?,
                    reviewed_at = CURRENT_TIMESTAMP,
                    reviewer_notes = COALESCE(?, reviewer_notes),
                    promoted_domain_id = COALESCE(?, promoted_domain_id)
                WHERE id = ?
                """,
                (status, reviewer_notes, promoted_domain_id, submission_id),
            )
            await self._connection.commit()
            return cursor.rowcount > 0

    async def record_report_engagement(
        self,
        domain_id: int,
        platform: str,
        session_hash: str,
        *,
        cooldown_hours: int = 24,
    ) -> tuple[int, bool]:
        """
        Record engagement for a platform.

        Returns:
            (new_count_for_platform, cooldown_triggered)
        """
        cooldown_clause = f"-{int(cooldown_hours)} hours"
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT id,
                       datetime(last_engaged_at) >= datetime('now', ?) AS within_cooldown
                FROM report_engagement
                WHERE domain_id = ? AND platform = ? AND session_hash = ?
                """,
                (cooldown_clause, domain_id, platform, session_hash),
            )
            row = await cursor.fetchone()

            if row:
                within_cooldown = bool(row["within_cooldown"])
                if within_cooldown:
                    count_cursor = await self._connection.execute(
                        """
                        SELECT SUM(click_count) AS count
                        FROM report_engagement
                        WHERE domain_id = ? AND platform = ?
                        """,
                        (domain_id, platform),
                    )
                    count_row = await count_cursor.fetchone()
                    count_value = count_row["count"] if count_row and count_row["count"] is not None else 0
                    return int(count_value), True

                await self._connection.execute(
                    """
                    UPDATE report_engagement
                    SET last_engaged_at = CURRENT_TIMESTAMP,
                        click_count = click_count + 1
                    WHERE id = ?
                    """,
                    (row["id"],),
                )
            else:
                await self._connection.execute(
                    """
                    INSERT INTO report_engagement (domain_id, platform, session_hash, click_count)
                    VALUES (?, ?, ?, 1)
                    """,
                    (domain_id, platform, session_hash),
                )

            await self._connection.commit()

            count_cursor = await self._connection.execute(
                """
                SELECT SUM(click_count) AS count
                FROM report_engagement
                WHERE domain_id = ? AND platform = ?
                """,
                (domain_id, platform),
            )
            count_row = await count_cursor.fetchone()
            count_value = count_row["count"] if count_row and count_row["count"] is not None else 0
            return int(count_value), False

    async def get_report_engagement_counts(self, domain_id: int) -> dict[str, int]:
        """Return engagement counts per platform."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT platform, SUM(click_count) AS count
                FROM report_engagement
                WHERE domain_id = ?
                GROUP BY platform
                """,
                (domain_id,),
            )
            rows = await cursor.fetchall()
            return {row["platform"]: int(row["count"] or 0) for row in rows}

    async def get_report_engagement_total(self, domain_id: int) -> int:
        """Return total engagement rows for a domain."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT SUM(click_count) AS count
                FROM report_engagement
                WHERE domain_id = ?
                """,
                (domain_id,),
            )
            row = await cursor.fetchone()
            count_value = row["count"] if row and row["count"] is not None else 0
            return int(count_value)

    async def record_rescan_request(
        self,
        domain_id: int,
        session_hash: str,
        *,
        cooldown_hours: int = 24,
        window_hours: int = 24,
    ) -> tuple[int, bool]:
        """
        Record a public rescan request.

        Returns:
            (recent_request_count, cooldown_triggered)
        """
        cooldown_clause = f"-{int(cooldown_hours)} hours"
        window_clause = f"-{int(window_hours)} hours"
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT id,
                       datetime(last_requested_at) >= datetime('now', ?) AS within_cooldown
                FROM rescan_requests
                WHERE domain_id = ? AND session_hash = ?
                """,
                (cooldown_clause, domain_id, session_hash),
            )
            row = await cursor.fetchone()

            if row:
                within_cooldown = bool(row["within_cooldown"])
                if within_cooldown:
                    count_cursor = await self._connection.execute(
                        """
                        SELECT SUM(click_count) AS count
                        FROM rescan_requests
                        WHERE domain_id = ?
                          AND datetime(last_requested_at) >= datetime('now', ?)
                        """,
                        (domain_id, window_clause),
                    )
                    count_row = await count_cursor.fetchone()
                    count_value = count_row["count"] if count_row and count_row["count"] is not None else 0
                    return int(count_value), True

                await self._connection.execute(
                    """
                    UPDATE rescan_requests
                    SET last_requested_at = CURRENT_TIMESTAMP,
                        click_count = click_count + 1
                    WHERE id = ?
                    """,
                    (row["id"],),
                )
            else:
                await self._connection.execute(
                    """
                    INSERT INTO rescan_requests (domain_id, session_hash, click_count)
                    VALUES (?, ?, 1)
                    """,
                    (domain_id, session_hash),
                )

            await self._connection.commit()

            count_cursor = await self._connection.execute(
                """
                SELECT SUM(click_count) AS count
                FROM rescan_requests
                WHERE domain_id = ?
                  AND datetime(last_requested_at) >= datetime('now', ?)
                """,
                (domain_id, window_clause),
            )
            count_row = await count_cursor.fetchone()
            count_value = count_row["count"] if count_row and count_row["count"] is not None else 0
            return int(count_value), False

    async def get_rescan_request_count(self, domain_id: int, *, window_hours: int = 24) -> int:
        """Return total recent rescan requests for a domain."""
        window_clause = f"-{int(window_hours)} hours"
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT SUM(click_count) AS count
                FROM rescan_requests
                WHERE domain_id = ?
                  AND datetime(last_requested_at) >= datetime('now', ?)
                """,
                (domain_id, window_clause),
            )
            row = await cursor.fetchone()
            count_value = row["count"] if row and row["count"] is not None else 0
            return int(count_value)

    async def clear_rescan_requests(self, domain_id: int) -> None:
        """Clear rescan requests for a domain after triggering."""
        async with self._lock:
            await self._connection.execute(
                "DELETE FROM rescan_requests WHERE domain_id = ?",
                (domain_id,),
            )
            await self._connection.commit()
