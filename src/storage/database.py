"""SQLite database operations for SeedBuster."""

import asyncio
from enum import Enum
from pathlib import Path
from typing import Optional

import aiosqlite


class DomainStatus(str, Enum):
    """Status of a domain in the pipeline."""

    PENDING = "pending"  # Discovered, awaiting analysis
    ANALYZING = "analyzing"  # Currently being analyzed
    ANALYZED = "analyzed"  # Analysis complete
    DEFERRED = "deferred"  # Waiting for rescans (suspected cloaking)
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
                    submitted_at TIMESTAMP,
                    response TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains(id)
                );

                CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
                CREATE INDEX IF NOT EXISTS idx_domains_verdict ON domains(verdict);
                CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
            """
            )
            await self._connection.commit()

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

    async def get_domain_by_id(self, domain_id: int) -> Optional[dict]:
        """Get domain record by ID."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM domains WHERE id = ?",
                (domain_id,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_pending_domains(self, limit: int = 10) -> list[dict]:
        """Get domains pending analysis."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT * FROM domains
                WHERE status = ?
                ORDER BY domain_score DESC, created_at ASC
                LIMIT ?
                """,
                (DomainStatus.PENDING.value, limit),
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

            return stats

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
    ):
        """Update report status."""
        async with self._lock:
            await self._connection.execute(
                """
                UPDATE reports
                SET status = ?,
                    response = ?,
                    submitted_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (status, response, report_id),
            )
            await self._connection.commit()

    async def get_reports_for_domain(self, domain_id: int) -> list[dict]:
        """Get all reports for a domain."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT * FROM reports
                WHERE domain_id = ?
                ORDER BY submitted_at DESC
                """,
                (domain_id,),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_pending_reports(self) -> list[dict]:
        """Get all domains with pending report status."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT r.*, d.domain
                FROM reports r
                JOIN domains d ON r.domain_id = d.id
                WHERE r.status IN ('pending', 'rate_limited')
                ORDER BY r.id ASC
                """
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
