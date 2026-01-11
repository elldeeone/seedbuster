"""Domain write operations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from ...utils.domains import canonicalize_domain
from ..enums import DomainStatus, Verdict, ScamType


class DomainWriteMixin:
    """Domain write helpers (insert/update)."""

    async def add_domain(
        self,
        domain: str,
        source: str = "certstream",
        domain_score: int = 0,
        source_url: str | None = None,
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
            existing_source_url = str(existing.get("source_url") or "").strip()
            if domain_score > current_score:
                async with self._lock:
                    await self._connection.execute(
                        "UPDATE domains SET domain_score = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (domain_score, existing["id"]),
                    )
                    await self._connection.commit()
            if source_url and not existing_source_url:
                async with self._lock:
                    await self._connection.execute(
                        "UPDATE domains SET source_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (source_url, existing["id"]),
                    )
                    await self._connection.commit()
            return int(existing["id"])

        async with self._lock:
            try:
                cursor = await self._connection.execute(
                    """
                    INSERT INTO domains (domain, canonical_domain, source, source_url, domain_score, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (normalized, canonical, source, source_url, domain_score, DomainStatus.PENDING.value),
                )
                await self._connection.commit()
                return cursor.lastrowid
            except aiosqlite.IntegrityError:
                # Domain already exists
                return None

    async def update_domain_status(
        self,
        domain_id: int,
        status: DomainStatus | str,
        verdict: Verdict | str | None = None,
        verdict_reasons: Optional[str] = None,
        operator_notes: Optional[str] = None,
    ) -> None:
        """Update status and/or verdict for a domain."""
        status_value = status.value if isinstance(status, DomainStatus) else str(status)
        verdict_value = verdict.value if isinstance(verdict, Verdict) else verdict
        if status_value == DomainStatus.ALLOWLISTED.value and verdict_value is None:
            verdict_value = Verdict.BENIGN.value

        # Update timestamps based on status
        analyzed_at = None
        reported_at = None
        if status_value == DomainStatus.ANALYZED.value:
            analyzed_at = datetime.now(timezone.utc)
        elif status_value == DomainStatus.REPORTED.value:
            reported_at = datetime.now(timezone.utc)

        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET status = ?,
                    verdict = COALESCE(?, verdict),
                    verdict_reasons = COALESCE(?, verdict_reasons),
                    operator_notes = COALESCE(?, operator_notes),
                    analyzed_at = COALESCE(?, analyzed_at),
                    reported_at = COALESCE(?, reported_at),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    status_value,
                    verdict_value,
                    verdict_reasons,
                    operator_notes,
                    analyzed_at,
                    reported_at,
                    domain_id,
                ),
            )
            await self._connection.commit()

    async def update_domain_score(self, domain_id: int, domain_score: int) -> None:
        """Update domain score for a domain."""
        async with self._lock:
            await self._connection.execute(
                "UPDATE domains SET domain_score = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (domain_score, domain_id),
            )
            await self._connection.commit()

    async def update_domain_admin_fields(
        self,
        domain_id: int,
        verdict: Verdict | str | None = None,
        verdict_reasons: Optional[str] = None,
        operator_notes: Optional[str] = None,
        status: DomainStatus | str | None = None,
    ) -> None:
        """Update admin-editable fields for a domain."""
        verdict_value = verdict.value if isinstance(verdict, Verdict) else verdict
        status_value = status.value if isinstance(status, DomainStatus) else status
        if status_value == DomainStatus.ALLOWLISTED.value and verdict_value is None:
            verdict_value = Verdict.BENIGN.value

        # Update timestamps based on status
        analyzed_at = None
        reported_at = None
        if status_value == DomainStatus.ANALYZED.value:
            analyzed_at = datetime.now(timezone.utc)
        elif status_value == DomainStatus.REPORTED.value:
            reported_at = datetime.now(timezone.utc)

        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET verdict = COALESCE(?, verdict),
                    verdict_reasons = COALESCE(?, verdict_reasons),
                    operator_notes = COALESCE(?, operator_notes),
                    status = COALESCE(?, status),
                    analyzed_at = COALESCE(?, analyzed_at),
                    reported_at = COALESCE(?, reported_at),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    verdict_value,
                    verdict_reasons,
                    operator_notes,
                    status_value,
                    analyzed_at,
                    reported_at,
                    domain_id,
                ),
            )
            await self._connection.commit()

    async def update_watchlist_baseline(self, domain_id: int, *, baseline_timestamp: str | None = None) -> None:
        """Update watchlist baseline timestamp for a domain."""
        value = (baseline_timestamp or "").strip() or None
        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET watchlist_baseline_timestamp = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (value, domain_id),
            )
            await self._connection.commit()

    async def update_domain_analysis(
        self,
        domain_id: int,
        analysis_score: int,
        verdict: Verdict,
        verdict_reasons: str,
        evidence_path: str,
        scam_type: Optional[ScamType] = None,
        status: DomainStatus | str | None = None,
    ) -> None:
        """Update analysis results for a domain."""
        scam_type_value = scam_type.value if isinstance(scam_type, ScamType) else scam_type
        status_value = status.value if isinstance(status, DomainStatus) else status
        if status_value is None:
            status_value = DomainStatus.ANALYZED.value
        if status_value == DomainStatus.ALLOWLISTED.value and verdict is None:
            verdict = Verdict.BENIGN

        async with self._lock:
            await self._connection.execute(
                """
                UPDATE domains
                SET analysis_score = ?,
                    verdict = ?,
                    verdict_reasons = ?,
                    evidence_path = ?,
                    scam_type = ?,
                    status = ?,
                    analyzed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    analysis_score,
                    verdict.value if isinstance(verdict, Verdict) else verdict,
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

    async def mark_false_positive(self, domain_id: int):
        await self.update_domain_status(domain_id, DomainStatus.FALSE_POSITIVE)

    async def apply_allowlist_entry(self, domain: str) -> int:
        normalized = (domain or "").strip().lower()
        canonical = canonicalize_domain(normalized)
        if not canonical:
            return 0

        async with self._lock:
            cursor = await self._connection.execute(
                """
                UPDATE domains
                SET status = ?, verdict = ?, updated_at = CURRENT_TIMESTAMP
                WHERE canonical_domain = ?
                """,
                (DomainStatus.ALLOWLISTED.value, Verdict.BENIGN.value, canonical),
            )
            await self._connection.commit()
            return cursor.rowcount
