"""Domain read/query operations."""

from __future__ import annotations

from typing import Optional

from ...utils.domains import canonicalize_domain
from ..enums import DomainStatus


class DomainReadMixin:
    """Domain read/query helpers."""

    async def get_domain(self, domain: str) -> Optional[dict]:
        """Get domain by name (canonicalized)."""
        canonical = canonicalize_domain(domain)
        if not canonical:
            return None
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM domains WHERE canonical_domain = ?",
                (canonical,),
            )
            return await self._fetchone_dict(cursor)

    async def get_domain_by_canonical(self, domain: str) -> Optional[dict]:
        """Get domain by canonical key."""
        canonical = canonicalize_domain(domain)
        if not canonical:
            return None
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM domains WHERE canonical_domain = ?",
                (canonical,),
            )
            return await self._fetchone_dict(cursor)

    async def get_domains_by_names(self, domains: list[str]) -> dict[str, dict]:
        """Get domains by a list of names (canonicalized)."""
        normalized = [canonicalize_domain(d) for d in domains]
        normalized = [d for d in normalized if d]
        if not normalized:
            return {}

        placeholders = ",".join("?" for _ in normalized)
        async with self._lock:
            cursor = await self._connection.execute(
                f"SELECT * FROM domains WHERE canonical_domain IN ({placeholders})",
                normalized,
            )
            rows = await self._fetchall_dicts(cursor)
        return {r.get("canonical_domain"): r for r in rows if r.get("canonical_domain")}

    async def get_domain_by_id(self, domain_id: int) -> Optional[dict]:
        """Get domain by ID."""
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT * FROM domains WHERE id = ?",
                (domain_id,),
            )
            return await self._fetchone_dict(cursor)

    async def get_domains_by_ids(self, domain_ids: list[int]) -> list[dict]:
        """Get multiple domains by IDs."""
        if not domain_ids:
            return []
        placeholders = ",".join("?" for _ in domain_ids)
        async with self._lock:
            cursor = await self._connection.execute(
                f"SELECT * FROM domains WHERE id IN ({placeholders})",
                domain_ids,
            )
            return await self._fetchall_dicts(cursor)

    async def get_pending_domains(self, limit: int | None = 10) -> list[dict]:
        """Get pending domains to analyze."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT * FROM domains
                WHERE status = ?
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (DomainStatus.PENDING.value, limit),
            )
            return await self._fetchall_dicts(cursor)

    async def get_analyzing_domains(self, limit: int | None = None) -> list[dict]:
        """Get domains currently being analyzed."""
        async with self._lock:
            if limit is None:
                cursor = await self._connection.execute(
                    "SELECT * FROM domains WHERE status = ?",
                    (DomainStatus.ANALYZING.value,),
                )
            else:
                cursor = await self._connection.execute(
                    "SELECT * FROM domains WHERE status = ? LIMIT ?",
                    (DomainStatus.ANALYZING.value, limit),
                )
            return await self._fetchall_dicts(cursor)

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
            return await self._fetchall_dicts(cursor)

    def _build_domain_filters(
        self,
        *,
        status: str | None = None,
        verdict: str | None = None,
        query: str | None = None,
        exclude_statuses: list[str] | None = None,
        exclude_takedowns: bool = False,
    ) -> tuple[list[str], list[object]]:
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

        return where, params

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

        where, params = self._build_domain_filters(
            status=status,
            verdict=verdict,
            query=query,
            exclude_statuses=exclude_statuses,
            exclude_takedowns=exclude_takedowns,
        )

        sql = "SELECT * FROM domains"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with self._lock:
            cursor = await self._connection.execute(sql, params)
            return await self._fetchall_dicts(cursor)

    async def list_scams_for_export(self) -> list[dict]:
        """List domains considered malicious for public export."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT id, domain, first_seen, scam_type, source, created_at
                FROM domains
                WHERE status NOT IN ('watchlist', 'false_positive', 'allowlisted')
                ORDER BY updated_at DESC, id DESC
                """
            )
            return await self._fetchall_dicts(cursor)

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
        where, params = self._build_domain_filters(
            status=status,
            verdict=verdict,
            query=query,
            exclude_statuses=exclude_statuses,
            exclude_takedowns=exclude_takedowns,
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
            return await self._fetchall_dicts(cursor)

    async def domain_exists(self, domain: str) -> bool:
        """Return True if a domain exists in the database."""
        canonical = canonicalize_domain(domain)
        if not canonical:
            return False
        async with self._lock:
            cursor = await self._connection.execute(
                "SELECT id FROM domains WHERE canonical_domain = ?",
                (canonical,),
            )
            row = await cursor.fetchone()
            return row is not None
