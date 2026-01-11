"""Takedown tracking helpers."""

from __future__ import annotations

from typing import Optional


class TakedownMixin:
    """Takedown check operations."""

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
        provider_signal: Optional[str] = None,
        backend_status: Optional[int] = None,
        backend_error: Optional[str] = None,
        backend_target: Optional[str] = None,
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
                    confidence,
                    provider_signal,
                    backend_status,
                    backend_error,
                    backend_target
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    provider_signal,
                    backend_status,
                    backend_error,
                    backend_target,
                ),
            )
            await self._connection.commit()
            return cursor.lastrowid

    async def get_recent_takedown_checks(self, domain_id: int, limit: int = 5) -> list[dict]:
        """Get recent takedown checks for a domain."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT *
                FROM takedown_checks
                WHERE domain_id = ?
                ORDER BY checked_at DESC
                LIMIT ?
                """,
                (domain_id, limit),
            )
            return await self._fetchall_dicts(cursor)

    async def get_takedown_checks(
        self,
        *,
        domain_id: int | None = None,
        domain: str | None = None,
        domain_query: str | None = None,
        exclude_statuses: list[str] | None = None,
        status: str | None = None,
        provider_signal: str | None = None,
        signal: str | None = None,
        backend_only: bool = False,
        limit: int = 200,
        offset: int = 0,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict]:
        """Query takedown checks with filters."""
        where: list[str] = []
        params: list[object] = []
        provider_signal = provider_signal or signal

        if domain_id is not None:
            where.append("t.domain_id = ?")
            params.append(int(domain_id))
        if domain:
            where.append("(d.canonical_domain = ? OR d.domain = ?)")
            params.extend([domain, domain])
        if domain_query:
            like = f"%{domain_query.strip().lower()}%"
            where.append("(lower(d.domain) LIKE ? OR lower(d.canonical_domain) LIKE ?)")
            params.extend([like, like])
        if exclude_statuses:
            normalized = [s.strip().lower() for s in exclude_statuses if s.strip()]
            if normalized:
                placeholders = ", ".join("?" for _ in normalized)
                where.append(f"lower(d.status) NOT IN ({placeholders})")
                params.extend(normalized)
        if status:
            where.append("t.takedown_status = ?")
            params.append(status)
        if provider_signal:
            where.append("t.provider_signal = ?")
            params.append(provider_signal)
        if backend_only:
            where.append("t.backend_status IS NOT NULL")
        if since:
            where.append("t.checked_at >= ?")
            params.append(since)
        if until:
            where.append("t.checked_at <= ?")
            params.append(until)

        sql = (
            "SELECT t.*, d.domain, d.status AS domain_status, d.canonical_domain "
            "FROM takedown_checks t "
            "JOIN domains d ON d.id = t.domain_id"
        )
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY t.checked_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with self._lock:
            cursor = await self._connection.execute(sql, params)
            return await self._fetchall_dicts(cursor)

    async def get_last_takedown_check(self, domain_id: int) -> Optional[dict]:
        """Get most recent takedown check for a domain."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT *
                FROM takedown_checks
                WHERE domain_id = ?
                ORDER BY checked_at DESC
                LIMIT 1
                """,
                (domain_id,),
            )
            return await self._fetchone_dict(cursor)

    async def set_takedown_override(self, domain_id: int, override: bool) -> None:
        """Set takedown override for a domain."""
        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET takedown_override = ?,
                    takedown_override_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (1 if override else 0, domain_id),
            )
            await self._connection.commit()

    async def update_domain_takedown_status(
        self,
        domain_id: int,
        status: str,
        *,
        detected_at: str | None = None,
        confirmed_at: str | None = None,
    ) -> None:
        """Update takedown status for a domain."""
        status_value = (status or "").strip().lower()
        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET takedown_status = ?,
                    takedown_detected_at = COALESCE(?, takedown_detected_at),
                    takedown_confirmed_at = COALESCE(?, takedown_confirmed_at),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (status_value, detected_at, confirmed_at, domain_id),
            )
            await self._connection.commit()

    async def get_domains_for_takedown_check(self, limit: int = 200) -> list[dict]:
        """Get domains for takedown checks (active + recently analyzed)."""
        async with self._lock:
            cursor = await self._connection.execute(
                """
                SELECT *
                FROM domains
                WHERE status NOT IN ('watchlist', 'false_positive', 'allowlisted')
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            return await self._fetchall_dicts(cursor)
