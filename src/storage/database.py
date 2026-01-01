"""SQLite database operations for SeedBuster."""

import asyncio
import json
import logging
from enum import Enum
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta, timezone

import aiosqlite

from ..utils.domains import canonicalize_domain

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


class ScamType(str, Enum):
    """Type of scam detected on a domain."""

    SEED_PHISHING = "seed_phishing"  # Seed phrase theft (wallet impersonation)
    CRYPTO_DOUBLER = "crypto_doubler"  # "Send X, get 2X back" scams
    FAKE_AIRDROP = "fake_airdrop"  # Fake airdrop/giveaway (overlaps with doubler)
    UNKNOWN = "unknown"  # Detected as malicious but type unclear


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
                        canonical_domain TEXT,
                        watchlist_baseline_timestamp TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        source TEXT DEFAULT 'certstream',
                        domain_score INTEGER DEFAULT 0,
                        analysis_score INTEGER,
                        verdict TEXT,
                        verdict_reasons TEXT,
                        operator_notes TEXT,
                        status TEXT DEFAULT 'pending',
                        scam_type TEXT,
                        analyzed_at TIMESTAMP,
                        reported_at TIMESTAMP,
                        takedown_status TEXT DEFAULT 'active',
                        takedown_detected_at TIMESTAMP,
                        takedown_confirmed_at TIMESTAMP,
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
                        target TEXT,
                        bulk_id TEXT,
                        status TEXT DEFAULT 'pending',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        claimed_at TIMESTAMP,
                        processed_at TIMESTAMP,
                        error TEXT
                    );

                    -- Public submissions held for admin review
                    CREATE TABLE IF NOT EXISTS public_submissions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        canonical_domain TEXT NOT NULL,
                        source_url TEXT,
                        reporter_notes TEXT,
                        submission_count INTEGER DEFAULT 1,
                        first_submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'pending_review',
                        reviewed_at TIMESTAMP,
                        reviewer_notes TEXT,
                        promoted_domain_id INTEGER,
                        UNIQUE(canonical_domain),
                        FOREIGN KEY (promoted_domain_id) REFERENCES domains(id)
                    );

                    -- Engagement tracking for public report clicks (deduped by session)
                    CREATE TABLE IF NOT EXISTS report_engagement (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        platform TEXT NOT NULL,
                        session_hash TEXT NOT NULL,
                        click_count INTEGER DEFAULT 1,
                        first_engaged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_engaged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(domain_id, platform, session_hash),
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );

                    -- Public rescan requests (deduped by session)
                    CREATE TABLE IF NOT EXISTS rescan_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        session_hash TEXT NOT NULL,
                        click_count INTEGER DEFAULT 1,
                        first_requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(domain_id, session_hash),
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );

                    -- Historical takedown checks for domains
                    CREATE TABLE IF NOT EXISTS takedown_checks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        http_status INTEGER,
                        http_error TEXT,
                        dns_resolves BOOLEAN,
                        dns_result TEXT,
                        is_sinkholed BOOLEAN DEFAULT FALSE,
                        domain_status TEXT,
                        content_hash TEXT,
                        still_phishing BOOLEAN,
                        takedown_status TEXT,
                        confidence REAL,
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );
                """
            )
            await self._connection.commit()

        # Migrations must run before creating indexes that reference newer columns,
        # otherwise existing DBs on older schemas would fail to start up.
        await self._migrate_domains_table()
        await self._migrate_reports_table()
        await self._migrate_report_engagement_table()
        await self._migrate_dashboard_actions_table()
        await self._migrate_deferred_to_watchlist()
        await self._backfill_canonical_domains(lock_held=True)
        await self._merge_canonical_duplicates()
        await self._create_indexes()

    async def _create_indexes(self) -> None:
        """Create indexes (best-effort, safe for older DBs)."""
        statements = [
            "CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status)",
            "CREATE INDEX IF NOT EXISTS idx_domains_verdict ON domains(verdict)",
            "CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain)",
            "CREATE INDEX IF NOT EXISTS idx_domains_canonical ON domains(canonical_domain)",
            "CREATE INDEX IF NOT EXISTS idx_reports_domain_platform ON reports(domain_id, platform)",
            "CREATE INDEX IF NOT EXISTS idx_reports_status_next_attempt ON reports(status, next_attempt_at)",
            "CREATE INDEX IF NOT EXISTS idx_dashboard_actions_status ON dashboard_actions(status, id)",
            "CREATE INDEX IF NOT EXISTS idx_dashboard_actions_bulk_status ON dashboard_actions(bulk_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_dashboard_actions_kind_target_status ON dashboard_actions(kind, target, status)",
            "CREATE INDEX IF NOT EXISTS idx_public_submissions_status ON public_submissions(status, first_submitted_at)",
            "CREATE INDEX IF NOT EXISTS idx_report_engagement_domain_platform ON report_engagement(domain_id, platform)",
            "CREATE INDEX IF NOT EXISTS idx_report_engagement_last_engaged ON report_engagement(last_engaged_at)",
            "CREATE INDEX IF NOT EXISTS idx_rescan_requests_domain ON rescan_requests(domain_id)",
            "CREATE INDEX IF NOT EXISTS idx_rescan_requests_last_requested ON rescan_requests(last_requested_at)",
            "CREATE INDEX IF NOT EXISTS idx_takedown_checks_domain ON takedown_checks(domain_id, checked_at DESC)",
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
        if "canonical_domain" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN canonical_domain TEXT")
        if "takedown_status" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN takedown_status TEXT DEFAULT 'active'")
        if "takedown_detected_at" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN takedown_detected_at TIMESTAMP")
        if "takedown_confirmed_at" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN takedown_confirmed_at TIMESTAMP")
        if "scam_type" not in existing:
            migrations.append("ALTER TABLE domains ADD COLUMN scam_type TEXT")

        for stmt in migrations:
            try:
                await self._connection.execute(stmt)
            except Exception:
                continue
        if migrations:
            await self._connection.commit()

    async def _backfill_canonical_domains(self, *, lock_held: bool = False) -> None:
        """Populate canonical_domain for existing rows (best-effort)."""
        if lock_held:
            cursor = await self._connection.execute(
                """
                SELECT id, domain, canonical_domain
                FROM domains
                WHERE canonical_domain IS NULL OR canonical_domain = ''
                """
            )
            rows = await cursor.fetchall()
        else:
            async with self._lock:
                cursor = await self._connection.execute(
                    """
                    SELECT id, domain, canonical_domain
                    FROM domains
                    WHERE canonical_domain IS NULL OR canonical_domain = ''
                    """
                )
                rows = await cursor.fetchall()

        if not rows:
            return

        updates: list[tuple[str, int]] = []
        for row in rows:
            domain = row["domain"] or ""
            canonical = canonicalize_domain(domain)
            if not canonical:
                continue
            updates.append((canonical, row["id"]))

        if not updates:
            return

        if lock_held:
            await self._connection.executemany(
                "UPDATE domains SET canonical_domain = ? WHERE id = ?",
                updates,
            )
            await self._connection.commit()
        else:
            async with self._lock:
                await self._connection.executemany(
                    "UPDATE domains SET canonical_domain = ? WHERE id = ?",
                    updates,
                )
                await self._connection.commit()

    async def _merge_canonical_duplicates(self) -> int:
        """Merge duplicate domain rows that share the same canonical key.

        Returns:
            Number of canonical groups merged.
        """
        # Use centralized verdict/status rankings from constants module
        from ..constants import VERDICT_RANK, STATUS_RANK
        verdict_rank = VERDICT_RANK
        status_rank = STATUS_RANK

        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT canonical_domain, GROUP_CONCAT(id) AS ids
                FROM domains
                WHERE canonical_domain IS NOT NULL AND canonical_domain != ''
                GROUP BY canonical_domain
                HAVING COUNT(*) > 1
                """
            )
            dup_groups = await cursor.fetchall()

        merged_groups = 0
        for group in dup_groups:
            canonical = group["canonical_domain"]
            id_list = [
                int(p)
                for p in (group["ids"] or "").split(",")
                if str(p).strip().isdigit()
            ]
            if len(id_list) < 2:
                continue

            placeholders = ",".join("?" for _ in id_list)
            async with self._lock:
                cursor = await self._connection.execute(
                    f"SELECT * FROM domains WHERE id IN ({placeholders})",
                    id_list,
                )
                rows = [dict(r) for r in await cursor.fetchall()]

            if len(rows) < 2:
                continue

            def _score(row: dict) -> tuple:
                analysis_score = row.get("analysis_score")
                domain_score = row.get("domain_score")
                verdict = row.get("verdict")
                status = row.get("status")
                return (
                    int(analysis_score) if analysis_score is not None else -1,
                    int(domain_score) if domain_score is not None else -1,
                    verdict_rank.get((verdict or "").lower(), 0),
                    status_rank.get((status or "").lower(), 0),
                    -int(row.get("id") or 0),
                )

            rows_sorted = sorted(rows, key=_score, reverse=True)
            primary = rows_sorted[0]
            secondary = rows_sorted[1:]
            primary_id = int(primary["id"])
            secondary_ids = [int(r["id"]) for r in secondary]

            # Consolidate best values
            best_domain_score = max(
                (r.get("domain_score") or 0) for r in rows_sorted
            )
            best_analysis_score = max(
                (r.get("analysis_score") or -1) for r in rows_sorted
            )
            best_verdict = max(
                ((r.get("verdict") or "").lower() for r in rows_sorted),
                key=lambda v: verdict_rank.get(v, 0),
                default=primary.get("verdict"),
            )
            best_status = max(
                ((r.get("status") or "").lower() for r in rows_sorted),
                key=lambda s: status_rank.get(s, 0),
                default=primary.get("status"),
            )
            best_evidence_path = (
                primary.get("evidence_path")
                or next((r.get("evidence_path") for r in secondary if r.get("evidence_path")), None)
            )

            async with self._lock:
                # Move child rows to primary
                placeholders_secondary = ",".join("?" for _ in secondary_ids)
                params = [primary_id] + secondary_ids
                if secondary_ids:
                    await self._connection.execute(
                        f"UPDATE evidence SET domain_id = ? WHERE domain_id IN ({placeholders_secondary})",
                        params,
                    )
                    await self._connection.execute(
                        f"UPDATE reports SET domain_id = ? WHERE domain_id IN ({placeholders_secondary})",
                        params,
                    )

                # Update primary fields if we found better data
                await self._connection.execute(
                    """
                    UPDATE domains
                    SET domain_score = ?,
                        analysis_score = CASE WHEN ? >= 0 THEN ? ELSE analysis_score END,
                        verdict = COALESCE(?, verdict),
                        status = COALESCE(?, status),
                        evidence_path = COALESCE(?, evidence_path),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        best_domain_score,
                        best_analysis_score,
                        best_analysis_score,
                        best_verdict,
                        best_status,
                        best_evidence_path,
                        primary_id,
                    ),
                )

                # Delete duplicates
                if secondary_ids:
                    await self._connection.execute(
                        f"DELETE FROM domains WHERE id IN ({placeholders_secondary})",
                        secondary_ids,
                    )

                await self._connection.commit()

            merged_groups += 1

        return merged_groups

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
                await self._connection.execute("ALTER TABLE report_engagement ADD COLUMN click_count INTEGER DEFAULT 1")
                await self._connection.commit()
            except Exception:
                pass

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
        normalized = (domain or "").strip().lower()
        canonical = canonicalize_domain(normalized)
        if not normalized or not canonical:
            return None

        # If canonical already exists, return existing ID and update score if higher.
        existing = await self.get_domain_by_canonical(canonical)
        if existing:
            try:
                current_score = int(existing.get("domain_score") or 0)
            except Exception:
                current_score = 0
            if domain_score > current_score:
                async with self._lock:
                    await self._connection.execute(
                        "UPDATE domains SET domain_score = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (domain_score, existing["id"]),
                    )
                    await self._connection.commit()
            return int(existing["id"])

        async with self._lock:
            try:
                cursor = await self._connection.execute(
                    """
                    INSERT INTO domains (domain, canonical_domain, source, domain_score, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (normalized, canonical, source, domain_score, DomainStatus.PENDING.value),
                )
                await self._connection.commit()
                return cursor.lastrowid
            except aiosqlite.IntegrityError:
                # Domain already exists
                return None

    async def get_domain(self, domain: str) -> Optional[dict]:
        """Get domain record by domain name."""
        domain_lower = (domain or "").strip().lower()
        canonical = canonicalize_domain(domain_lower)

        async with self._lock:
            if canonical:
                cursor = await self._connection.execute(
                    """
                    SELECT * FROM domains
                    WHERE domain = ? OR canonical_domain = ?
                    ORDER BY id ASC
                    LIMIT 1
                    """,
                    (domain_lower, canonical),
                )
            else:
                cursor = await self._connection.execute(
                    "SELECT * FROM domains WHERE domain = ?",
                    (domain_lower,),
                )
            row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_domain_by_canonical(self, domain: str) -> Optional[dict]:
        """Get domain record by canonicalized domain key."""
        canonical = canonicalize_domain(domain)
        if not canonical:
            return None
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT * FROM domains
                WHERE canonical_domain = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (canonical,),
            )
            row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_domains_by_names(self, domains: list[str]) -> dict[str, dict]:
        """Fetch multiple domains by name, returned as a mapping of domain -> record."""
        normalized = [d.strip().lower() for d in domains if isinstance(d, str) and d.strip()]
        if not normalized:
            return {}

        canonical_keys = {canonicalize_domain(d) for d in normalized}
        canonical_keys.discard("")
        candidates = sorted(set(normalized) | canonical_keys)
        if not candidates:
            return {}

        placeholders = ",".join("?" for _ in candidates)
        query = (
            f"SELECT * FROM domains WHERE domain IN ({placeholders})"
            f" OR canonical_domain IN ({placeholders})"
        )

        async with self._lock:
            cursor = await self._connection.execute(query, candidates * 2)
            rows = await cursor.fetchall()

        result: dict[str, dict] = {}
        for row in rows:
            record = dict(row)
            result[row["domain"]] = record
            canon = record.get("canonical_domain")
            if canon:
                result[canon] = record
        return result

    async def get_domain_by_id(self, domain_id: int) -> Optional[dict]:
        """Get domain record by ID."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM domains WHERE id = ?",
                (domain_id,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_domains_by_ids(self, domain_ids: list[int]) -> list[dict]:
        """Fetch multiple domains by ID."""
        ids = [int(d) for d in domain_ids if isinstance(d, int) or str(d).isdigit()]
        if not ids:
            return []

        placeholders = ",".join("?" for _ in ids)
        query = f"SELECT * FROM domains WHERE id IN ({placeholders})"
        async with self._lock:
            cursor = await self._connection.execute(query, ids)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

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

    async def get_analyzing_domains(self, limit: int | None = None) -> list[dict]:
        """Get domains stuck in analyzing status."""
        async with self._lock:
            if limit and limit > 0:
                cursor = await self._connection.execute(
                    """
                    SELECT * FROM domains
                    WHERE status = ?
                    ORDER BY updated_at ASC
                    LIMIT ?
                    """,
                    (DomainStatus.ANALYZING.value, limit),
                )
            else:
                cursor = await self._connection.execute(
                    """
                    SELECT * FROM domains
                    WHERE status = ?
                    ORDER BY updated_at ASC
                    """,
                    (DomainStatus.ANALYZING.value,),
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
        if status_value == DomainStatus.ALLOWLISTED.value and verdict_value is None:
            verdict_value = Verdict.BENIGN.value

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

    async def update_domain_score(self, domain_id: int, domain_score: int) -> None:
        """Update domain_score for an existing domain."""
        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET domain_score = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (int(domain_score), domain_id),
            )
            await self._connection.commit()

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
        if status_value == DomainStatus.ALLOWLISTED.value and verdict_value is None:
            verdict_value = Verdict.BENIGN.value

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
        scam_type: Optional["ScamType"] = None,
        status: DomainStatus | str | None = None,
    ):
        """Update domain with analysis results."""
        scam_type_value = scam_type.value if scam_type else None
        status_value = status.value if isinstance(status, Enum) else status
        if not status_value:
            status_value = DomainStatus.ANALYZED.value
        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET analysis_score = ?,
                    verdict = ?,
                    verdict_reasons = ?,
                    evidence_path = ?,
                    scam_type = COALESCE(?, scam_type),
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
                    scam_type_value,
                    status_value,
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
        exclude_statuses: list[str] | None = None,
        exclude_takedowns: bool = False,
    ) -> list[dict]:
        """List domains with optional filters and pagination.

        Args:
            exclude_statuses: List of status values to exclude (e.g. ['watchlist', 'false_positive'])
        """
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))

        where: list[str] = []
        params: list[object] = []

        if status:
            where.append("status = ?")
            params.append(status.strip().lower())
        elif exclude_statuses:
            placeholders = ",".join("?" for _ in exclude_statuses)
            where.append(f"status NOT IN ({placeholders})")
            params.extend(s.strip().lower() for s in exclude_statuses)
        if verdict:
            where.append("verdict = ?")
            params.append(verdict.strip().lower())
        if query:
            like = f"%{query.strip().lower()}%"
            where.append("(domain LIKE ? OR canonical_domain LIKE ?)")
            params.extend([like, like])
        if exclude_takedowns:
            where.append(
                "(takedown_status IS NULL OR takedown_status NOT IN ('confirmed_down', 'likely_down'))"
            )

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
        exclude_statuses: list[str] | None = None,
        exclude_takedowns: bool = False,
    ) -> int:
        """Return total domains matching filters (for pagination).

        Args:
            exclude_statuses: List of status values to exclude (e.g. ['watchlist', 'false_positive'])
        """
        where: list[str] = []
        params: list[object] = []

        if status:
            where.append("status = ?")
            params.append(status.strip().lower())
        elif exclude_statuses:
            placeholders = ",".join("?" for _ in exclude_statuses)
            where.append(f"status NOT IN ({placeholders})")
            params.extend(s.strip().lower() for s in exclude_statuses)
        if verdict:
            where.append("verdict = ?")
            params.append(verdict.strip().lower())
        if query:
            like = f"%{query.strip().lower()}%"
            where.append("(domain LIKE ? OR canonical_domain LIKE ?)")
            params.extend([like, like])
        if exclude_takedowns:
            where.append(
                "(takedown_status IS NULL OR takedown_status NOT IN ('confirmed_down', 'likely_down'))"
            )

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

    async def mark_false_positive(self, domain_id: int):
        """Mark domain as false positive."""
        await self.update_domain_status(domain_id, DomainStatus.FALSE_POSITIVE)

    async def apply_allowlist_entry(self, domain: str) -> int:
        """Mark matching domains as allowlisted based on a registrable domain entry."""
        from ..utils.domains import normalize_allowlist_domain

        normalized = normalize_allowlist_domain(domain)
        if not normalized:
            return 0

        suffix_match = f"%.{normalized}"
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT id
                FROM domains
                WHERE canonical_domain = ?
                   OR canonical_domain LIKE ?
                """,
                (normalized, suffix_match),
            )
            rows = await cursor.fetchall()

        ids = [int(row["id"]) for row in rows]
        for domain_id in ids:
            await self.update_domain_status(domain_id, DomainStatus.ALLOWLISTED)
        return len(ids)

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
                  AND status != 'allowlisted'
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

    async def domain_exists(self, domain: str) -> bool:
        """Check if domain already exists in database."""
        domain_lower = (domain or "").strip().lower()
        canonical = canonicalize_domain(domain_lower)

        async with self._lock:
            if canonical:
                cursor = await self._connection.execute(
                    "SELECT 1 FROM domains WHERE canonical_domain = ? LIMIT 1",
                    (canonical,),
                )
                if await cursor.fetchone():
                    return True
            cursor = await self._connection.execute(
                "SELECT 1 FROM domains WHERE domain = ? LIMIT 1",
                (domain_lower,),
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

    # =========================================================================
    # Public submissions
    # =========================================================================

    async def add_public_submission(
        self,
        domain: str,
        canonical_domain: str,
        source_url: Optional[str] = None,
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
                    (new_count, source_url, reporter_notes, reporter_notes, reporter_notes, row["id"]),
                )
                await self._connection.commit()
                return int(row["id"]), True

            cursor = await self._connection.execute(
                """
                INSERT INTO public_submissions (domain, canonical_domain, source_url, reporter_notes)
                VALUES (?, ?, ?, ?)
                """,
                (domain, canonical_domain, source_url, reporter_notes),
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
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

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
            row = await cursor.fetchone()
            return dict(row) if row else None

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

    # =========================================================================
    # Report engagement counters
    # =========================================================================

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

    # =========================================================================
    # Public rescan requests
    # =========================================================================

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

    # =========================================================================
    # Takedown tracking
    # =========================================================================

    async def add_takedown_check(
        self,
        domain_id: int,
        *,
        http_status: Optional[int] = None,
        http_error: Optional[str] = None,
        dns_resolves: Optional[bool] = None,
        dns_result: Optional[str] = None,
        is_sinkholed: Optional[bool] = None,
        domain_status: Optional[str] = None,
        content_hash: Optional[str] = None,
        still_phishing: Optional[bool] = None,
        takedown_status: Optional[str] = None,
        confidence: Optional[float] = None,
    ) -> int:
        """Insert a takedown check row."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                INSERT INTO takedown_checks (
                    domain_id,
                    http_status,
                    http_error,
                    dns_resolves,
                    dns_result,
                    is_sinkholed,
                    domain_status,
                    content_hash,
                    still_phishing,
                    takedown_status,
                    confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    domain_id,
                    http_status,
                    http_error,
                    dns_resolves,
                    dns_result,
                    is_sinkholed,
                    domain_status,
                    content_hash,
                    still_phishing,
                    takedown_status,
                    confidence,
                ),
            )
            await self._connection.commit()
            return int(cursor.lastrowid)

    async def get_recent_takedown_checks(self, domain_id: int, limit: int = 5) -> list[dict]:
        """Return recent takedown checks for a domain."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT *
                FROM takedown_checks
                WHERE domain_id = ?
                ORDER BY datetime(checked_at) DESC
                LIMIT ?
                """,
                (domain_id, limit),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_last_takedown_check(self, domain_id: int) -> Optional[dict]:
        """Return the most recent takedown check."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT *
                FROM takedown_checks
                WHERE domain_id = ?
                ORDER BY datetime(checked_at) DESC
                LIMIT 1
                """,
                (domain_id,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def update_domain_takedown_status(
        self,
        domain_id: int,
        status: str,
        *,
        detected_at: Optional[str] = None,
        confirmed_at: Optional[str] = None,
    ) -> None:
        """Update takedown status columns on domains."""
        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET takedown_status = ?,
                    takedown_detected_at = COALESCE(?, takedown_detected_at),
                    takedown_confirmed_at = COALESCE(?, takedown_confirmed_at)
                WHERE id = ?
                """,
                (status, detected_at, confirmed_at, domain_id),
            )
            await self._connection.commit()

    async def get_domains_for_takedown_check(self, limit: int = 200) -> list[dict]:
        """
        Return domains with their last takedown check timestamps.

        Ordered by oldest check first so schedulers can pick in priority order.
        """
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT
                    d.id,
                    d.domain,
                    d.status,
                    d.verdict,
                    d.reported_at,
                    d.created_at,
                    d.takedown_status,
                    MAX(tc.checked_at) AS last_checked_at
                FROM domains d
                LEFT JOIN takedown_checks tc ON tc.domain_id = d.id
                WHERE d.status NOT IN ('false_positive', 'allowlisted')
                GROUP BY d.id
                ORDER BY
                    COALESCE(datetime(last_checked_at), datetime(d.reported_at), datetime(d.created_at)) ASC
                LIMIT ?
                """,
                (limit,),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
