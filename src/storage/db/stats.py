"""Statistics/summary queries."""

from __future__ import annotations


class StatsMixin:
    """Aggregate statistics helpers."""

    async def get_stats(self) -> dict:
        """Return stats for dashboard counts/filters."""
        stats: dict = {}

        async with self._lock:
            # Status breakdown
            cursor = await self._connection.execute(
                """
                SELECT status, COUNT(*) as count
                FROM domains
                GROUP BY status
                """
            )
            status_counts = {row["status"]: row["count"] for row in await cursor.fetchall()}
            stats["by_status"] = status_counts

            # Verdict breakdown
            cursor = await self._connection.execute(
                """
                SELECT verdict, COUNT(*) as count
                FROM domains
                GROUP BY verdict
                """
            )
            verdict_counts = {row["verdict"]: row["count"] for row in await cursor.fetchall()}
            stats["by_verdict"] = verdict_counts

            # Public "active threats" count (matches dangerous filter)
            cursor = await self._connection.execute(
                """
                SELECT COUNT(*) as count
                FROM domains
                WHERE status NOT IN ('watchlist', 'false_positive', 'allowlisted')
                  AND (takedown_status IS NULL OR takedown_status NOT IN ('confirmed_down', 'likely_down'))
                """
            )
            stats["active_threats"] = (await cursor.fetchone())["count"]

            cursor = await self._connection.execute(
                """
                SELECT COUNT(*) as count
                FROM domains
                WHERE status != 'allowlisted'
                """
            )
            stats["tracked_domains"] = (await cursor.fetchone())["count"]

            # Total domains
            cursor = await self._connection.execute("SELECT COUNT(*) as count FROM domains")
            stats["total"] = (await cursor.fetchone())["count"]

            # Domains in last 24h
            cursor = await self._connection.execute(
                """
                SELECT COUNT(*) as count FROM domains
                WHERE created_at > datetime('now', '-1 day')
                """
            )
            stats["last_24h"] = (await cursor.fetchone())["count"]

            # Reporting stats
            cursor = await self._connection.execute(
                """
                SELECT status, COUNT(*) as count
                FROM reports
                GROUP BY status
                """
            )
            report_counts = {row["status"]: row["count"] for row in await cursor.fetchall()}
            stats["reports"] = report_counts

            # Pending dashboard actions
            cursor = await self._connection.execute(
                """
                SELECT status, COUNT(*) as count
                FROM dashboard_actions
                GROUP BY status
                """
            )
            action_counts = {row["status"]: row["count"] for row in await cursor.fetchall()}
            stats["dashboard_actions"] = action_counts

            return stats

    async def get_report_stats(self) -> dict:
        """Return counts of reports by status."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT status, COUNT(*) as count
                FROM reports
                GROUP BY status
                """
            )
            rows = await cursor.fetchall()
        return {row["status"]: row["count"] for row in rows}

    async def get_dashboard_action_stats(self) -> dict:
        """Return counts of dashboard actions by status."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT status, COUNT(*) as count
                FROM dashboard_actions
                GROUP BY status
                """
            )
            rows = await cursor.fetchall()
        return {row["status"]: row["count"] for row in rows}

    async def get_engagement_summary(self, limit_platforms: int = 20) -> dict:
        """Aggregate engagement counts across domains/platforms."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT platform, SUM(click_count) AS clicks
                FROM report_engagement
                GROUP BY platform
                ORDER BY clicks DESC
                LIMIT ?
                """,
                (limit_platforms,),
            )
            rows = await cursor.fetchall()
            platform_counts = {row["platform"]: int(row["clicks"] or 0) for row in rows}

            cursor = await self._connection.execute(
                "SELECT SUM(click_count) AS total FROM report_engagement"
            )
            total_row = await cursor.fetchone()
            total = int(total_row["total"] or 0) if total_row else 0

        return {"total_engagements": total, "by_platform": platform_counts}

    async def get_takedown_metrics(self) -> dict:
        """Return takedown status counts and timing (best-effort)."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT takedown_status, COUNT(*) as count
                FROM domains
                WHERE takedown_status IS NOT NULL
                GROUP BY takedown_status
                """
            )
            rows = await cursor.fetchall()
            by_status = {row["takedown_status"]: row["count"] for row in rows}

            cursor = await self._connection.execute(
                """
                SELECT
                    AVG(
                        CAST(
                            (JULIANDAY(COALESCE(takedown_detected_at, takedown_confirmed_at)) - JULIANDAY(reported_at)) * 24
                            AS REAL
                        )
                    ) AS avg_hours_to_detect
                FROM domains
                WHERE takedown_status IN ('likely_down', 'confirmed_down')
                  AND reported_at IS NOT NULL
                  AND (takedown_detected_at IS NOT NULL OR takedown_confirmed_at IS NOT NULL)
                """
            )
            row = await cursor.fetchone()
            avg_hours = float(row["avg_hours_to_detect"]) if row and row["avg_hours_to_detect"] is not None else None

        return {"by_status": by_status, "avg_hours_to_detect": avg_hours}
