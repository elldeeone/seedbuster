"""Evidence + snapshot helpers for dashboard server."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from .server_helpers import _try_relative_to


class DashboardServerEvidenceMixin:
    """Evidence resolution helpers."""

    def _resolve_evidence(self, domain: dict) -> tuple[Path | None, str | None]:
        raw = (domain.get("evidence_path") or "").strip()
        if not raw:
            return None, None
        evidence_dir = Path(raw)

        rel = _try_relative_to(evidence_dir, self.evidence_dir)
        if rel and len(rel.parts) >= 1:
            base = f"/evidence/{quote(rel.parts[0])}"
            return self.evidence_dir / rel.parts[0], base

        base = f"/evidence/{quote(evidence_dir.name)}"
        return evidence_dir, base

    def _get_screenshots(self, domain: dict, evidence_dir: Path | None) -> list[Path]:
        if not evidence_dir:
            return []
        try:
            shots = sorted(evidence_dir.glob("screenshot*.png"))
        except Exception:
            return []
        priority = {"screenshot.png": 0, "screenshot_early.png": 1, "screenshot_final.png": 2}
        return sorted(shots, key=lambda p: (priority.get(p.name, 50), p.name))

    def _get_instruction_files(self, evidence_dir: Path | None) -> list[Path]:
        if not evidence_dir:
            return []
        try:
            return sorted(evidence_dir.glob("report_instructions_*.txt"))
        except Exception:
            return []

    def _sanitize_snapshot_id(self, snapshot_id: str | None) -> str | None:
        raw = (snapshot_id or "").strip()
        if not raw:
            return None
        safe = "".join(c for c in raw if c.isalnum() or c in "._-")
        if safe != raw:
            return None
        return safe

    def _parse_snapshot_time(self, value: str | None, fallback: Path | None = None) -> datetime | None:
        if value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        if fallback and fallback.exists():
            return datetime.fromtimestamp(fallback.stat().st_mtime, tz=timezone.utc)
        return None

    def _parse_report_time(self, value: str | None) -> datetime | None:
        if not value:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                if fmt.endswith("%z"):
                    return datetime.strptime(value, fmt)
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _format_iso_timestamp(self, value: str | None) -> str | None:
        dt = self._parse_report_time(value)
        if not dt:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _report_timestamp(self, report: dict) -> datetime | None:
        return (
            self._parse_report_time(report.get("submitted_at"))
            or self._parse_report_time(report.get("attempted_at"))
            or self._parse_report_time(report.get("created_at"))
        )

    def _snapshot_window(
        self,
        snapshots: list[dict],
        snapshot_id: str | None,
    ) -> tuple[datetime | None, datetime | None]:
        if not snapshot_id:
            return None, None
        ordered = []
        for snap in snapshots:
            ts_raw = snap.get("timestamp")
            ts = self._parse_snapshot_time(ts_raw) if isinstance(ts_raw, str) else None
            ordered.append((snap.get("id"), ts))
        ordered = [entry for entry in ordered if entry[0] and entry[1]]
        for idx, (sid, ts) in enumerate(ordered):
            if sid == snapshot_id:
                end = ordered[idx - 1][1] if idx > 0 else None
                return ts, end
        return None, None

    def _filter_reports_for_snapshot(
        self,
        reports: list[dict],
        snapshots: list[dict],
        snapshot_id: str | None,
    ) -> list[dict]:
        start, end = self._snapshot_window(snapshots, snapshot_id)
        if not start:
            return reports
        filtered = []
        for report in reports:
            ts = self._report_timestamp(report)
            if not ts:
                continue
            if ts >= start and (end is None or ts < end):
                filtered.append(report)
        return filtered

    def _snapshot_meta(self, analysis_path: Path, snapshot_id: str, is_latest: bool) -> tuple[dict, datetime | None]:
        data: dict = {}
        timestamp = None
        try:
            data = json.loads(analysis_path.read_text(encoding="utf-8"))
            timestamp = self._parse_snapshot_time(data.get("saved_at"), analysis_path)
        except Exception:
            timestamp = self._parse_snapshot_time(None, analysis_path)
        meta = {
            "id": snapshot_id,
            "timestamp": timestamp.isoformat() if timestamp else None,
            "score": data.get("score"),
            "verdict": data.get("verdict"),
            "scan_reason": data.get("scan_reason"),
            "source_url": data.get("source_url"),
            "final_url": data.get("final_url"),
            "is_latest": is_latest,
        }
        return meta, timestamp

    def _derive_snapshot_id(self, analysis_path: Path) -> str | None:
        try:
            data = json.loads(analysis_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        scan_id = self._sanitize_snapshot_id(data.get("scan_id"))
        if scan_id:
            return scan_id
        saved_at = data.get("saved_at")
        parsed = self._parse_snapshot_time(saved_at, analysis_path)
        if not parsed:
            return None
        return parsed.strftime("%Y%m%dT%H%M%S%fZ").lower()

    def _list_snapshots(self, domain_dir: Path) -> tuple[list[dict], str | None]:
        snapshots: list[dict] = []
        latest_id = None
        latest_path = domain_dir / "analysis.json"
        if latest_path.exists():
            latest_id = self._derive_snapshot_id(latest_path) or "latest"
            meta, timestamp = self._snapshot_meta(latest_path, latest_id, True)
            meta["is_latest"] = True
            meta["_sort_ts"] = timestamp
            snapshots.append(meta)

        runs_dir = domain_dir / "runs"
        if runs_dir.exists():
            for run_dir in sorted(runs_dir.iterdir()):
                if not run_dir.is_dir():
                    continue
                analysis_path = run_dir / "analysis.json"
                if not analysis_path.exists():
                    continue
                meta, timestamp = self._snapshot_meta(analysis_path, run_dir.name, False)
                meta["_sort_ts"] = timestamp
                snapshots.append(meta)

        snapshots.sort(
            key=lambda s: (
                s.get("_sort_ts") or datetime.fromtimestamp(0, tz=timezone.utc),
                0 if not s.get("is_latest") else 1,
            ),
            reverse=True,
        )
        for meta in snapshots:
            meta.pop("_sort_ts", None)
        return snapshots, latest_id

    def _resolve_snapshot_dir(
        self,
        domain_dir: Path,
        snapshot_id: str | None,
        latest_id: str | None,
    ) -> tuple[Path | None, str | None, bool]:
        safe_snapshot = self._sanitize_snapshot_id(snapshot_id)
        if not safe_snapshot or safe_snapshot == "latest" or (latest_id and safe_snapshot == latest_id):
            if domain_dir.exists():
                return domain_dir, latest_id, True
            return None, None, False
        candidate = domain_dir / "runs" / safe_snapshot
        if candidate.exists():
            return candidate, safe_snapshot, False
        return None, None, False
