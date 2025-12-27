"""Global pytest configuration."""

from __future__ import annotations

import os

# Avoid preview-only reporting during tests even if .env sets it.
os.environ.setdefault("REPORT_PREVIEW_ONLY", "false")
