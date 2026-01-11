"""Dashboard configuration dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class DashboardConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8080
    admin_user: str = "admin"
    admin_password: str = ""
    health_url: str = ""
    frontend_dir: Path | None = None
    allowlist_path: Path | None = None
    allowlist: set[str] = field(default_factory=set)
    public_rescan_threshold: int = 3
    public_rescan_window_hours: int = 24
    public_rescan_cooldown_hours: int = 24
