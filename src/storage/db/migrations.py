"""Database migration helpers."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class DatabaseMigrationsMixin:
    """Schema migration helpers."""

    async def _migrate_domains_table(self) -> None:
        """Add columns to domains table (best-effort)."""
        cursor = await self._connection.execute("PRAGMA table_info(domains)")
        rows = await cursor.fetchall()
        existing = {row["name"] for row in rows}

        migrations: list[str] = []
        if "operator_notes" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN operator_notes TEXT")
        if "watchlist_baseline_timestamp" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN watchlist_baseline_timestamp TEXT")
        if "canonical_domain" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN canonical_domain TEXT")
        if "source_url" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN source_url TEXT")
        if "takedown_status" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN takedown_status TEXT DEFAULT 'active'")
        if "takedown_detected_at" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN takedown_detected_at TIMESTAMP")
        if "takedown_confirmed_at" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN takedown_confirmed_at TIMESTAMP")
        if "takedown_override" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN takedown_override BOOLEAN DEFAULT FALSE")
        if "takedown_override_at" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN takedown_override_at TIMESTAMP")
        if "scam_type" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN scam_type TEXT")

        for stmt in migrations:
            try:
                await self._connection.execute(stmt)
            except Exception:
                continue
        if migrations:
            await self._connection.commit()

    async def _migrate_takedown_checks_table(self) -> None:
        """Add columns to takedown_checks table (best-effort)."""
        cursor = await self._connection.execute("PRAGMA table_info(takedown_checks)")
        rows = await cursor.fetchall()
        existing = {row["name"] for row in rows}

        migrations: list[str] = []
        if "provider_signal" not in existing:
            migrations.append("ALTER TABLE takedown_checks ADD COLUMN provider_signal TEXT")
        if "backend_status" not in existing:
            migrations.append("ALTER TABLE takedown_checks ADD COLUMN backend_status INTEGER")
        if "backend_error" not in existing:
            migrations.append("ALTER TABLE takedown_checks ADD COLUMN backend_error TEXT")
        if "backend_target" not in existing:
            migrations.append("ALTER TABLE takedown_checks ADD COLUMN backend_target TEXT")

        for stmt in migrations:
            try:
                await self._connection.execute(stmt)
            except Exception:
                continue
        if migrations:
            await self._connection.commit()

    async def _migrate_reports_table(self) -> None:
        """Add columns to reports table for retry scheduling (best-effort)."""
        cursor = await self._connection.execute("PRAGMA table_info(reports)")
        rows = await cursor.fetchall()
        existing = {row["name"] for row in rows}

        migrations: list[str] = []
        if "attempted_at" not in existing:
            migrations.append("ALTER TABLE reports ADD COLUMN attempted_at TIMESTAMP")
        if "attempts" not in existing:
            migrations.append("ALTER TABLE reports ADD COLUMN attempts INTEGER DEFAULT 0")
        if "retry_after" not in existing:
            migrations.append("ALTER TABLE reports ADD COLUMN retry_after INTEGER")
        if "next_attempt_at" not in existing:
            migrations.append("ALTER TABLE reports ADD COLUMN next_attempt_at TIMESTAMP")
        if "response_data" not in existing:
            migrations.append("ALTER TABLE reports ADD COLUMN response_data TEXT")

        for stmt in migrations:
            try:
                await self._connection.execute(stmt)
            except Exception:
                # If multiple processes raced or SQLite rejects the statement, continue.
                continue
        if migrations:
            await self._connection.commit()

    async def _migrate_report_engagement_table(self) -> None:
        """Add columns to report_engagement table (best-effort)."""
        cursor = await self._connection.execute("PRAGMA table_info(report_engagement)")
        rows = await cursor.fetchall()
        existing = {row["name"] for row in rows}

        if "click_count" not in existing:
            try:
                await self._connection.execute(
                    "ALTER TABLE report_engagement ADD COLUMN click_count INTEGER DEFAULT 1"
                )
            except Exception:
                return
            await self._connection.commit()

    async def _migrate_public_submissions_table(self) -> None:
        """Add columns to public_submissions table (best-effort)."""
        cursor = await self._connection.execute("PRAGMA table_info(public_submissions)")
        rows = await cursor.fetchall()
        existing = {row["name"] for row in rows}
        if "submitted_url" in existing:
            return
        try:
            await self._connection.execute(
                "ALTER TABLE public_submissions ADD COLUMN submitted_url TEXT"
            )
            await self._connection.commit()
        except Exception:
            return

    async def _migrate_dashboard_actions_table(self) -> None:
        """Add columns to dashboard_actions table (best-effort)."""
        cursor = await self._connection.execute("PRAGMA table_info(dashboard_actions)")
        rows = await cursor.fetchall()
        existing = {row["name"] for row in rows}

        migrations: list[str] = []
        if "target" not in existing:
            migrations.append("ALTER TABLE dashboard_actions ADD COLUMN target TEXT")
        if "bulk_id" not in existing:
            migrations.append("ALTER TABLE dashboard_actions ADD COLUMN bulk_id TEXT")

        for stmt in migrations:
            try:
                await self._connection.execute(stmt)
            except Exception:
                continue
        if migrations:
            await self._connection.commit()

    async def _migrate_deferred_to_watchlist(self) -> None:
        """Migrate existing deferred domains to watchlist status."""
        cursor = await self._connection.execute(
            "SELECT COUNT(*) as count FROM domains WHERE status = 'deferred'"
        )
        row = await cursor.fetchone()
        if row["count"] == 0:
            return

        await self._connection.execute(
            """
            UPDATE domains
            SET status = 'watchlist',
                watchlist_baseline_timestamp = updated_at
            WHERE status = 'deferred'
            """
        )
        await self._connection.commit()
        logger.info("Migrated %s domains from deferred to watchlist", row["count"])
