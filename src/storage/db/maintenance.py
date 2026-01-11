"""Database maintenance helpers."""

from __future__ import annotations

from ...utils.domains import canonicalize_domain
from ..rankings import VERDICT_RANK, STATUS_RANK


class DatabaseMaintenanceMixin:
    """Maintenance helpers for canonicalization and dedupe."""

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
        """Merge duplicate domain rows that share the same canonical key."""
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

                if secondary_ids:
                    await self._connection.execute(
                        f"DELETE FROM domains WHERE id IN ({placeholders_secondary})",
                        secondary_ids,
                    )

                await self._connection.commit()

            merged_groups += 1

        return merged_groups
