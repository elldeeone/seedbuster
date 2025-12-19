"""Evidence file storage for SeedBuster."""

import asyncio
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


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
        analysis_data["saved_at"] = datetime.now(timezone.utc).isoformat()

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
    def _safe_filename_component(value: str) -> str:
        """Convert a string into a filesystem-friendly filename component."""
        raw = (value or "").strip().lower()
        if not raw:
            return "unknown"
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in raw)

    def get_report_instructions_path(self, domain: str, platform: str) -> Path:
        """Get path for a manual report instruction file for a platform."""
        domain_dir = self.get_domain_dir(domain)
        safe_platform = self._safe_filename_component(platform)
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

    def get_evidence_path(self, domain: str) -> Path:
        """Get the evidence directory path for a domain."""
        return self.get_domain_dir(domain)

    def get_screenshot_path(self, domain: str) -> Optional[Path]:
        """Get screenshot path if it exists."""
        path = self.get_domain_dir(domain) / "screenshot.png"
        return path if path.exists() else None

    def get_all_screenshot_paths(self, domain: str) -> list[Path]:
        """Get all screenshot paths for a domain, prioritizing suspicious findings."""
        domain_dir = self.get_domain_dir(domain)
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

    def get_analysis_path(self, domain: str) -> Optional[Path]:
        """Get analysis JSON path if it exists."""
        path = self.get_domain_dir(domain) / "analysis.json"
        return path if path.exists() else None

    def load_analysis(self, domain: str) -> Optional[dict]:
        """Load analysis results for a domain."""
        path = self.get_analysis_path(domain)
        if path:
            return json.loads(path.read_text(encoding="utf-8"))
        return None

    def file_hash(self, path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def cleanup_old_evidence(self, days: int = 30):
        """Remove evidence older than specified days."""
        import shutil
        from datetime import timedelta

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
