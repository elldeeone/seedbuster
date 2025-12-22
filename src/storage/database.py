"""SQLite database operations for SeedBuster."""

import asyncio
import json
import logging
from enum import Enum
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta, timezone

import aiosqlite

logger = logging.getLogger(__name__)


class DomainStatus(str, Enum):
    """Status of a domain in the pipeline."""

    PENDING = "pending"  # Discovered, awaiting analysis
    ANALYZING = "analyzing"  # Currently being analyzed
    ANALYZED = "analyzed"  # Analysis complete
    WATCHLIST = "watchlist"  # Waiting for rescans (suspected cloaking)
    REPORTED = "reported"  # Reported to blocklists
    FALSE_POSITIVE = "false_positive"  # Marked as FP
    ALLOWLISTED = "allowlisted"  # On allowlist


class Verdict(str, Enum):
    """Analysis verdict for a domain."""

    HIGH = "high"  # High confidence phishing
    MEDIUM = "medium"  # Needs manual review
    LOW = "low"  # Likely benign
    BENIGN = "benign"  # Confirmed safe


class Database:
    """Async SQLite database for domain tracking."""

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

    async def _create_tables(self):
        """Create database tables if they don't exist."""
        async with self._lock:
            await self._connection.executescript(
                """
                    CREATE TABLE IF NOT EXISTS domains (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT UNIQUE NOT NULL,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        source TEXT DEFAULT 'certstream',
                        domain_score INTEGER DEFAULT 0,
                        analysis_score INTEGER,
                        verdict TEXT,
                        verdict_reasons TEXT,
                        operator_notes TEXT,
                        status TEXT DEFAULT 'pending',
                        analyzed_at TIMESTAMP,
                        reported_at TIMESTAMP,
                        evidence_path TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS evidence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        type TEXT NOT NULL,
                        path TEXT NOT NULL,
                        hash TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );

                    CREATE TABLE IF NOT EXISTS reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        platform TEXT NOT NULL,
                        status TEXT DEFAULT 'pending',
                        attempted_at TIMESTAMP,
                        submitted_at TIMESTAMP,
                        response TEXT,
                        response_data TEXT,
                        attempts INTEGER DEFAULT 0,
                        retry_after INTEGER,
                        next_attempt_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );

                    CREATE TABLE IF NOT EXISTS dashboard_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        kind TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        status TEXT DEFAULT 'pending',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        claimed_at TIMESTAMP,
                        processed_at TIMESTAMP,
                        error TEXT
                    );
                """
            )
            await self._connection.commit()

            # Migrations must run before creating indexes that reference newer columns,
            # otherwise existing DBs on older schemas would fail to start up.
            await self._migrate_domains_table()
            await self._migrate_reports_table()
            await self._migrate_deferred_to_watchlist()
            await self._create_indexes()

    async def _create_indexes(self) -> None:
        """Create indexes (best-effort, safe for older DBs)."""
        statements = [
            "CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status)",
            "CREATE INDEX IF NOT EXISTS idx_domains_verdict ON domains(verdict)",
            "CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain)",
            "CREATE INDEX IF NOT EXISTS idx_reports_domain_platform ON reports(domain_id, platform)",
            "CREATE INDEX IF NOT EXISTS idx_reports_status_next_attempt ON reports(status, next_attempt_at)",
            "CREATE INDEX IF NOT EXISTS idx_dashboard_actions_status ON dashboard_actions(status, id)",
        ]

        for stmt in statements:
            try:
                await self._connection.execute(stmt)
            except Exception:
                continue
        await self._connection.commit()

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

    async def _migrate_deferred_to_watchlist(self) -> None:
        """Migrate existing deferred domains to watchlist status."""
        # Note: Called from _create_tables which already holds the lock
        # Check if migration needed
        cursor = await self._connection.execute(
            "SELECT COUNT(*) as count FROM domains WHERE status = 'deferred'"
        )
        row = await cursor.fetchone()
        if row["count"] == 0:
            return

        # Update status and set baseline to updated_at
        await self._connection.execute("""
            UPDATE domains
            SET status = 'watchlist',
                watchlist_baseline_timestamp = updated_at
            WHERE status = 'deferred'
        """)
        await self._connection.commit()
        logger.info(f"Migrated {row['count']} domains from deferred to watchlist")

    async def add_domain(
        self,
        domain: str,
        source: str = "certstream",
        domain_score: int = 0,
    ) -> Optional[int]:
        """Add a new domain to track. Returns domain ID or None if exists."""
        async with self._lock:
            try:
                cursor = await self._connection.execute(
                    """
                    INSERT INTO domains (domain, source, domain_score, status)
                    VALUES (?, ?, ?, ?)
                    """,
                    (domain.lower(), source, domain_score, DomainStatus.PENDING.value),
                )
                await self._connection.commit()
                return cursor.lastrowid
            except aiosqlite.IntegrityError:
                # Domain already exists
                return None

    async def get_domain(self, domain: str) -> Optional[dict]:
        """Get domain record by domain name."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM domains WHERE domain = ?",
                (domain.lower(),),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_domains_by_names(self, domains: list[str]) -> dict[str, dict]:
        """Fetch multiple domains by name, returned as a mapping of domain -> record."""
        normalized = [d.strip().lower() for d in domains if isinstance(d, str) and d.strip()]
        if not normalized:
            return {}

        unique = sorted(set(normalized))
        placeholders = ",".join("?" for _ in unique)
        query = f"SELECT * FROM domains WHERE domain IN ({placeholders})"

        async with self._lock:
            cursor = await self._connection.execute(query, unique)
            rows = await cursor.fetchall()

        return {row["domain"]: dict(row) for row in rows}

    async def get_domain_by_id(self, domain_id: int) -> Optional[dict]:
        """Get domain record by ID."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM domains WHERE id = ?",
                (domain_id,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_pending_domains(self, limit: int | None = 10) -> list[dict]:
        """Get domains pending analysis (optionally limited)."""
        async with self._lock:
            if limit and limit > 0:
                cursor = await self._connection.execute(
                    """
                    SELECT * FROM domains
                    WHERE status = ?
                    ORDER BY domain_score DESC, created_at ASC
                    LIMIT ?
                    """,
                    (DomainStatus.PENDING.value, limit),
                )
            else:
                cursor = await self._connection.execute(
                    """
                    SELECT * FROM domains
                    WHERE status = ?
                    ORDER BY domain_score DESC, created_at ASC
                    """,
                    (DomainStatus.PENDING.value,),
                )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def update_domain_status(
        self,
        domain_id: int,
        status: DomainStatus | str | None = None,
        verdict: Verdict | str | None = None,
    ):
        """Update domain status and/or verdict."""
        if status is None and verdict is None:
            return

        status_value = status.value if isinstance(status, Enum) else status
        verdict_value = verdict.value if isinstance(verdict, Enum) else verdict

        updates = []
        params = []

        if status_value is not None:
            updates.append("status = ?")
            params.append(status_value)
            if status_value == DomainStatus.ANALYZED.value:
                updates.append("analyzed_at = COALESCE(analyzed_at, CURRENT_TIMESTAMP)")
            elif status_value == DomainStatus.REPORTED.value:
                updates.append("reported_at = COALESCE(reported_at, CURRENT_TIMESTAMP)")
        if verdict_value is not None:
            updates.append("verdict = ?")
            params.append(verdict_value)

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(domain_id)

        async with self._lock:
            await self._connection.execute(
                f"""
                UPDATE domains
                SET {', '.join(updates)}
                WHERE id = ?
                """,
                params,
            )
            await self._connection.commit()

        # Set baseline timestamp when marking domain as watchlist
        if status_value == DomainStatus.WATCHLIST.value:
            async with self._lock:
                await self._connection.execute(
                    "UPDATE domains SET watchlist_baseline_timestamp = CURRENT_TIMESTAMP WHERE id = ?",
                    (domain_id,)
                )
                await self._connection.commit()

        # Auto-cancel pending reports for certain status changes
        if status_value in (
            DomainStatus.WATCHLIST.value,
            DomainStatus.ALLOWLISTED.value,
            DomainStatus.FALSE_POSITIVE.value,
        ):
            await self.cancel_pending_reports_for_domain(
                domain_id,
                reason=f"Domain marked as {status_value}"
            )

    async def update_domain_admin_fields(
        self,
        domain_id: int,
        *,
        status: str | None = None,
        verdict: str | None = None,
        operator_notes: str | None = None,
    ) -> None:
        """Update admin-controlled fields on a domain."""
        updates: list[str] = []
        params: list[object] = []

        status_value = (status or "").strip().lower() if status is not None else None
        verdict_value = (verdict or "").strip().lower() if verdict is not None else None

        if status_value is not None:
            updates.append("status = ?")
            params.append(status_value or None)
            if status_value == DomainStatus.ANALYZED.value:
                updates.append("analyzed_at = COALESCE(analyzed_at, CURRENT_TIMESTAMP)")
            elif status_value == DomainStatus.REPORTED.value:
                updates.append("reported_at = COALESCE(reported_at, CURRENT_TIMESTAMP)")

        if verdict_value is not None:
            updates.append("verdict = ?")
            params.append(verdict_value or None)

        if operator_notes is not None:
            updates.append("operator_notes = ?")
            params.append(operator_notes)

        if not updates:
            return

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(domain_id)

        async with self._lock:
            await self._connection.execute(
                f"""
                UPDATE domains
                SET {', '.join(updates)}
                WHERE id = ?
                """,
                params,
            )
            await self._connection.commit()

    async def update_watchlist_baseline(
        self,
        domain_id: int,
    ) -> Optional[str]:
        """Update watchlist baseline to current timestamp.

        Returns the new baseline timestamp or None if domain not found.
        """
        async with self._lock:
            # Verify domain exists and is watchlist status
            cursor = await self._connection.execute(
                "SELECT status FROM domains WHERE id = ?",
                (domain_id,)
            )
            row = await cursor.fetchone()
            if not row or row["status"] != "watchlist":
                return None

            # Update baseline to current timestamp
            await self._connection.execute(
                "UPDATE domains SET watchlist_baseline_timestamp = CURRENT_TIMESTAMP WHERE id = ?",
                (domain_id,)
            )
            await self._connection.commit()

            # Return the new timestamp
            cursor = await self._connection.execute(
                "SELECT watchlist_baseline_timestamp FROM domains WHERE id = ?",
                (domain_id,)
            )
            row = await cursor.fetchone()
            return row["watchlist_baseline_timestamp"] if row else None

    async def update_domain_analysis(
        self,
        domain_id: int,
        analysis_score: int,
        verdict: Verdict,
        verdict_reasons: str,
        evidence_path: str,
    ):
        """Update domain with analysis results."""
        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET analysis_score = ?,
                    verdict = ?,
                    verdict_reasons = ?,
                    evidence_path = ?,
                    status = ?,
                    analyzed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    analysis_score,
                    verdict.value,
                    verdict_reasons,
                    evidence_path,
                    DomainStatus.ANALYZED.value,
                    domain_id,
                ),
            )
            await self._connection.commit()

    async def add_evidence(
        self,
        domain_id: int,
        evidence_type: str,
        path: str,
        file_hash: str = None,
    ) -> int:
        """Add evidence record for a domain."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                INSERT INTO evidence (domain_id, type, path, hash)
                VALUES (?, ?, ?, ?)
                """,
                (domain_id, evidence_type, path, file_hash),
            )
            await self._connection.commit()
            return cursor.lastrowid

    async def get_recent_domains(
        self,
        limit: int = 10,
        status: Optional[DomainStatus] = None,
    ) -> list[dict]:
        """Get recently processed domains."""
        async with self._lock:
            if status:
                cursor = await self._connection.execute(
                    """
                    SELECT * FROM domains
                    WHERE status = ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (status.value, limit),
                )
            else:
                cursor = await self._connection.execute(
                    """
                    SELECT * FROM domains
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def list_domains(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
        verdict: str | None = None,
        query: str | None = None,
    ) -> list[dict]:
        """List domains with optional filters and pagination."""
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))

        where: list[str] = []
        params: list[object] = []

        if status:
            where.append("status = ?")
            params.append(status.strip().lower())
        if verdict:
            where.append("verdict = ?")
            params.append(verdict.strip().lower())
        if query:
            where.append("domain LIKE ?")
            params.append(f"%{query.strip().lower()}%")

        sql = "SELECT * FROM domains"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with self._lock:
            cursor = await self._connection.execute(sql, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def count_domains(
        self,
        *,
        status: str | None = None,
        verdict: str | None = None,
        query: str | None = None,
    ) -> int:
        """Return total domains matching filters (for pagination)."""
        where: list[str] = []
        params: list[object] = []

        if status:
            where.append("status = ?")
            params.append(status.strip().lower())
        if verdict:
            where.append("verdict = ?")
            params.append(verdict.strip().lower())
        if query:
            where.append("domain LIKE ?")
            params.append(f"%{query.strip().lower()}%")

        sql = "SELECT COUNT(*) as count FROM domains"
        if where:
            sql += " WHERE " + " AND ".join(where)

        async with self._lock:
            cursor = await self._connection.execute(sql, params)
            row = await cursor.fetchone()
            return int(row["count"] or 0)

    async def get_watchlist_domains_due_rescan(
        self,
        days_since_update: int = 30,
        limit: int = 20,
    ) -> list[dict]:
        """Get watchlist domains that haven't been checked in X days.

        Used for watchlist/monitoring - periodic rescans of suspicious domains.
        """
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT * FROM domains
                WHERE status = 'watchlist'
                  AND (
                    updated_at IS NULL
                    OR updated_at < datetime('now', ? || ' days')
                  )
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (f"-{days_since_update}", limit),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def enqueue_dashboard_action(self, kind: str, payload: dict) -> int:
        """Add an admin action requested by the dashboard (processed by the pipeline)."""
        record = {
            "kind": str(kind or "").strip().lower(),
            "payload": payload or {},
        }
        if not record["kind"]:
            raise ValueError("Action kind is required")

        async with self._lock:
            cursor = await self._connection.execute(
                """
                INSERT INTO dashboard_actions (kind, payload, status)
                VALUES (?, ?, 'pending')
                """,
                (record["kind"], json.dumps(record["payload"])),
            )
            await self._connection.commit()
            return int(cursor.lastrowid)

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

    async def mark_false_positive(self, domain_id: int):
        """Mark domain as false positive."""
        await self.update_domain_status(domain_id, DomainStatus.FALSE_POSITIVE)

    async def get_stats(self) -> dict:
        """Get pipeline statistics."""
        async with self._lock:
            stats = {}

            # Count by status
            cursor = await self._connection.execute(
                """
                SELECT status, COUNT(*) as count
                FROM domains
                GROUP BY status
                """
            )
            status_counts = {row["status"]: row["count"] for row in await cursor.fetchall()}
            stats["by_status"] = status_counts

            # Count by verdict
            cursor = await self._connection.execute(
                """
                SELECT verdict, COUNT(*) as count
                FROM domains
                WHERE verdict IS NOT NULL
                GROUP BY verdict
                """
            )
            verdict_counts = {row["verdict"]: row["count"] for row in await cursor.fetchall()}
            stats["by_verdict"] = verdict_counts

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

    async def domain_exists(self, domain: str) -> bool:
        """Check if domain already exists in database."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT 1 FROM domains WHERE domain = ?",
                (domain.lower(),),
            )
            return await cursor.fetchone() is not None

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
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

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
            row = await cursor.fetchone()
            return dict(row) if row else None

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
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

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
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
