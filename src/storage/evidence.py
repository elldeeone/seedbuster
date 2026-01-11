"""Evidence file storage for SeedBuster."""

import asyncio
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from ..utils.files import safe_filename_component


class EvidenceStore:
    """Manages evidence file storage for analyzed domains."""

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def get_domain_dir(self, domain: str) -> Path:
        """Get or create evidence directory for a domain."""
        # Use hash prefix to avoid filesystem issues with special chars
        domain_hash = hashlib.sha256(domain.lower().encode()).hexdigest()[:12]
        safe_domain = "".join(c if c.isalnum() or c in ".-" else "_" for c in domain)
        dir_name = f"{safe_domain}_{domain_hash}"

        domain_dir = self.evidence_dir / dir_name
        domain_dir.mkdir(parents=True, exist_ok=True)
        return domain_dir

    def get_domain_id(self, domain: str) -> str:
        """Get short ID for domain (used in Telegram commands)."""
        return hashlib.sha256(domain.lower().encode()).hexdigest()[:8]

    async def save_screenshot(self, domain: str, screenshot_bytes: bytes, suffix: str = "") -> Path:
        """Save screenshot for a domain. Optional suffix for multiple screenshots."""
        domain_dir = self.get_domain_dir(domain)
        filename = f"screenshot{suffix}.png"
        path = domain_dir / filename
        await asyncio.to_thread(path.write_bytes, screenshot_bytes)
        return path

    async def save_html(self, domain: str, html_content: str) -> Path:
        """Save HTML snapshot for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "page.html"
        await asyncio.to_thread(path.write_text, html_content, encoding="utf-8")
        return path

    async def save_har(self, domain: str, har_data: dict) -> Path:
        """Save HAR network trace for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "network.har"
        har_json = json.dumps(har_data, indent=2)
        await asyncio.to_thread(path.write_text, har_json, encoding="utf-8")
        return path

    async def save_analysis(self, domain: str, analysis_data: dict) -> Path:
        """Save analysis results for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "analysis.json"

        # Add timestamp
        now = datetime.now(timezone.utc)
        analysis_data["saved_at"] = now.isoformat()
        scan_id = analysis_data.get("scan_id")
        if scan_id:
            analysis_data["scan_id"] = safe_filename_component(str(scan_id), lower=True)
        else:
            analysis_data["scan_id"] = self._format_scan_id(now)

        analysis_json = json.dumps(analysis_data, indent=2)
        await asyncio.to_thread(path.write_text, analysis_json, encoding="utf-8")
        return path

    async def save_console_logs(self, domain: str, logs: list[str]) -> Path:
        """Save browser console logs for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "console.log"
        content = "\n".join(logs)
        await asyncio.to_thread(path.write_text, content, encoding="utf-8")
        return path

    @staticmethod
    def _sanitize_snapshot_id(snapshot_id: str | None) -> str | None:
        raw = (snapshot_id or "").strip()
        if not raw:
            return None
        safe = "".join(c for c in raw if c.isalnum() or c in "._-")
        if safe != raw:
            return None
        return safe

    def _resolve_snapshot_dir(self, domain_dir: Path, snapshot_id: str | None) -> Path:
        safe_snapshot = self._sanitize_snapshot_id(snapshot_id)
        if not safe_snapshot or safe_snapshot == "latest":
            return domain_dir
        analysis_path = domain_dir / "analysis.json"
        if analysis_path.exists():
            current_id = self._read_scan_id(analysis_path)
            if current_id and safe_snapshot == current_id:
                return domain_dir
        return domain_dir / "runs" / safe_snapshot

    def get_report_instructions_path(self, domain: str, platform: str) -> Path:
        """Get path for a manual report instruction file for a platform."""
        domain_dir = self.get_domain_dir(domain)
        safe_platform = safe_filename_component(platform, lower=True)
        return domain_dir / f"report_instructions_{safe_platform}.txt"

    def get_report_instruction_paths(self, domain: str) -> list[Path]:
        """List saved manual report instruction files for a domain."""
        domain_dir = self.get_domain_dir(domain)
        return sorted(domain_dir.glob("report_instructions_*.txt"))

    async def save_report_instructions(self, domain: str, platform: str, content: str) -> Path:
        """Save manual report instructions for a platform."""
        path = self.get_report_instructions_path(domain, platform)
        await asyncio.to_thread(path.write_text, content or "", encoding="utf-8")
        return path

    def clear_exploration_screenshots(self, domain: str) -> int:
        """Remove old exploration screenshots for a domain.

        Evidence directories are reused across rescans, so stale exploration screenshots
        can otherwise leak into later alerts (e.g., showing a seed form that wasn't found
        in the current scan).
        """
        domain_dir = self.get_domain_dir(domain)
        removed = 0
        for path in domain_dir.glob("screenshot_exploration*.png"):
            try:
                path.unlink()
                removed += 1
            except FileNotFoundError:
                continue
            except OSError:
                continue
        return removed

    def clear_standard_evidence(self, domain: str) -> int:
        """Remove standard evidence files from the latest scan (screenshots/HTML/etc)."""
        domain_dir = self.get_domain_dir(domain)
        removed = 0
        filenames = (
            "screenshot.png",
            "screenshot_early.png",
            "screenshot_final.png",
            "page.html",
            "network.har",
            "console.log",
        )
        for name in filenames:
            path = domain_dir / name
            try:
                path.unlink()
                removed += 1
            except FileNotFoundError:
                continue
            except OSError:
                continue
        return removed

    def clear_report_instructions(self, domain: str) -> int:
        """Remove stale report instruction files for a domain."""
        domain_dir = self.get_domain_dir(domain)
        removed = 0
        for path in domain_dir.glob("report_instructions_*.txt"):
            try:
                path.unlink()
                removed += 1
            except FileNotFoundError:
                continue
            except OSError:
                continue
        return removed

    def archive_current_evidence(self, domain: str) -> Optional[str]:
        """Move current evidence files into a snapshot run directory.

        Returns the snapshot id if evidence was archived, otherwise None.
        """
        domain_dir = self.get_domain_dir(domain)
        analysis_path = domain_dir / "analysis.json"
        if not analysis_path.exists():
            return None

        scan_id = self._read_scan_id(analysis_path)
        if not scan_id:
            scan_id = self._format_scan_id(
                datetime.fromtimestamp(analysis_path.stat().st_mtime, tz=timezone.utc)
            )

        runs_dir = domain_dir / "runs"
        runs_dir.mkdir(parents=True, exist_ok=True)
        scan_id = self._ensure_unique_scan_id(runs_dir, scan_id)
        target_dir = runs_dir / scan_id
        target_dir.mkdir(parents=True, exist_ok=True)

        moved = 0
        for path in domain_dir.iterdir():
            if path.name == "runs":
                continue
            if path.is_dir():
                continue
            if path.name.startswith("report_instructions_"):
                continue
            try:
                path.rename(target_dir / path.name)
                moved += 1
            except FileNotFoundError:
                continue
            except OSError:
                continue

        return scan_id if moved else None

    @staticmethod
    def _format_scan_id(value: datetime) -> str:
        """Format a timestamp as a stable snapshot id."""
        return value.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ").lower()

    def _read_scan_id(self, analysis_path: Path) -> Optional[str]:
        try:
            data = json.loads(analysis_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        scan_id = (data.get("scan_id") or "").strip()
        if scan_id:
            return safe_filename_component(scan_id, lower=True)
        saved_at = (data.get("saved_at") or "").strip()
        if saved_at:
            try:
                parsed = datetime.fromisoformat(saved_at.replace("Z", "+00:00"))
                return self._format_scan_id(parsed)
            except ValueError:
                pass
        if analysis_path.exists():
            return self._format_scan_id(
                datetime.fromtimestamp(analysis_path.stat().st_mtime, tz=timezone.utc)
            )
        return None

    @staticmethod
    def _ensure_unique_scan_id(base_dir: Path, scan_id: str) -> str:
        candidate = scan_id
        counter = 1
        while (base_dir / candidate).exists():
            candidate = f"{scan_id}-{counter:02d}"
            counter += 1
        return candidate

    def get_evidence_path(self, domain: str, snapshot_id: Optional[str] = None) -> Path:
        """Get the evidence directory path for a domain (optionally for a snapshot)."""
        domain_dir = self.get_domain_dir(domain)
        return self._resolve_snapshot_dir(domain_dir, snapshot_id)

    def get_screenshot_path(self, domain: str, snapshot_id: Optional[str] = None) -> Optional[Path]:
        """Get screenshot path if it exists."""
        path = self.get_evidence_path(domain, snapshot_id) / "screenshot.png"
        return path if path.exists() else None

    def get_all_screenshot_paths(
        self, domain: str, snapshot_id: Optional[str] = None
    ) -> list[Path]:
        """Get all screenshot paths for a domain, prioritizing suspicious findings."""
        domain_dir = self.get_evidence_path(domain, snapshot_id)
        screenshots = []

        # Priority order: seedform > suspicious > early > main > other exploration
        # First: seed form screenshots (most important evidence)
        seedform_shots = sorted(domain_dir.glob("screenshot_exploration_seedform_*.png"))
        screenshots.extend(seedform_shots)

        # Then: suspicious exploration screenshots
        suspicious_shots = sorted(domain_dir.glob("screenshot_exploration_suspicious_*.png"))
        screenshots.extend(suspicious_shots)

        # Then: early screenshot (before anti-bot blocking)
        early = domain_dir / "screenshot_early.png"
        if early.exists():
            screenshots.append(early)

        # Then: main screenshot
        main = domain_dir / "screenshot.png"
        if main.exists():
            screenshots.append(main)

        # Then: final screenshot
        final = domain_dir / "screenshot_final.png"
        if final.exists():
            screenshots.append(final)

        # Finally: other exploration screenshots (limited to avoid spam)
        other_exploration = sorted(domain_dir.glob("screenshot_exploration_[0-9]*.png"))[:2]
        screenshots.extend(other_exploration)

        return screenshots

    def get_analysis_path(self, domain: str, snapshot_id: Optional[str] = None) -> Optional[Path]:
        """Get analysis JSON path if it exists."""
        path = self.get_evidence_path(domain, snapshot_id) / "analysis.json"
        return path if path.exists() else None

    def load_analysis(self, domain: str, snapshot_id: Optional[str] = None) -> Optional[dict]:
        """Load analysis results for a domain."""
        path = self.get_analysis_path(domain, snapshot_id)
        if path:
            return json.loads(path.read_text(encoding="utf-8"))
        return None

    def file_hash(self, path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def cleanup_old_evidence(self, days: int = 30):
        """Remove evidence older than specified days."""
        import shutil

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        for domain_dir in self.evidence_dir.iterdir():
            if not domain_dir.is_dir():
                continue

            # Check analysis.json for timestamp
            analysis_path = domain_dir / "analysis.json"
            if analysis_path.exists():
                try:
                    data = json.loads(analysis_path.read_text())
                    saved_at = datetime.fromisoformat(data.get("saved_at", ""))
                    if saved_at < cutoff:
                        shutil.rmtree(domain_dir)
                except (json.JSONDecodeError, ValueError):
                    pass
