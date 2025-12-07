"""Evidence file storage for SeedBuster."""

import hashlib
import json
from datetime import datetime
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

    async def save_screenshot(self, domain: str, screenshot_bytes: bytes) -> Path:
        """Save screenshot for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "screenshot.png"
        path.write_bytes(screenshot_bytes)
        return path

    async def save_html(self, domain: str, html_content: str) -> Path:
        """Save HTML snapshot for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "page.html"
        path.write_text(html_content, encoding="utf-8")
        return path

    async def save_har(self, domain: str, har_data: dict) -> Path:
        """Save HAR network trace for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "network.har"
        path.write_text(json.dumps(har_data, indent=2), encoding="utf-8")
        return path

    async def save_analysis(self, domain: str, analysis_data: dict) -> Path:
        """Save analysis results for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "analysis.json"

        # Add timestamp
        analysis_data["saved_at"] = datetime.utcnow().isoformat()

        path.write_text(json.dumps(analysis_data, indent=2), encoding="utf-8")
        return path

    async def save_console_logs(self, domain: str, logs: list[str]) -> Path:
        """Save browser console logs for a domain."""
        domain_dir = self.get_domain_dir(domain)
        path = domain_dir / "console.log"
        path.write_text("\n".join(logs), encoding="utf-8")
        return path

    def get_evidence_path(self, domain: str) -> Path:
        """Get the evidence directory path for a domain."""
        return self.get_domain_dir(domain)

    def get_screenshot_path(self, domain: str) -> Optional[Path]:
        """Get screenshot path if it exists."""
        path = self.get_domain_dir(domain) / "screenshot.png"
        return path if path.exists() else None

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

        cutoff = datetime.utcnow() - timedelta(days=days)

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
