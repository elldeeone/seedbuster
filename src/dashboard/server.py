# -*- coding: utf-8 -*-
"""A tiny aiohttp-powered dashboard (public + admin views).

This is intentionally simple: server-rendered HTML, SQLite-backed, no JS framework.
"""

from __future__ import annotations

import aiohttp
import tldextract
import asyncio
import base64
import html
import json
import os
import hashlib
import secrets
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import quote, urlencode, urlparse

from aiohttp import web

from ..storage.database import Database, DomainStatus, Verdict
from ..utils.domains import canonicalize_domain


def _escape(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _coerce_int(value: object, *, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    if min_value is not None:
        parsed = max(min_value, parsed)
    if max_value is not None:
        parsed = min(max_value, parsed)
    return parsed


def _extract_hostname(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    hostname = (parsed.hostname or raw.split("/")[0]).strip().lower()
    return hostname.strip(".")


def _try_relative_to(path: Path, base: Path) -> Path | None:
    try:
        return path.resolve().relative_to(base.resolve())
    except Exception:
        return None


def _domain_dir_name(domain: str) -> str:
    """Replicate EvidenceStore directory naming for cross-process use."""
    domain_hash = hashlib.sha256(domain.lower().encode()).hexdigest()[:12]
    safe_domain = "".join(c if c.isalnum() or c in ".-" else "_" for c in domain)
    return f"{safe_domain}_{domain_hash}"


def _format_bytes(num: int) -> str:
    """Human-readable bytes."""
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(num or 0)
    for unit in units:
        if n < step:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= step
    return f"{n:.1f} PB"


def _status_badge(value: str) -> str:
    status = (value or "").strip().lower() or "unknown"
    badge_class = f"sb-badge sb-badge-{status}"
    return f'<span class="{badge_class}">{_escape(status)}</span>'


def _verdict_badge(value: str | None) -> str:
    verdict = (value or "").strip().lower() or "unknown"
    badge_class = f"sb-badge sb-badge-{verdict}"
    return f'<span class="{badge_class}">{_escape(verdict)}</span>'


def _report_badge(value: str | None) -> str:
    status = (value or "").strip().lower() or "unknown"
    badge_class = f"sb-badge sb-badge-{status}"
    return f'<span class="{badge_class}">{_escape(status)}</span>'

# Keep filter options in sync with the admin SPA
STATUS_FILTER_OPTIONS = [
    "dangerous",
    "",
    "pending",
    "analyzing",
    "analyzed",
    "reported",
    "failed",
    "watchlist",
    "allowlisted",
    "false_positive",
]

VERDICT_FILTER_OPTIONS = ["", "high", "medium", "low", "benign", "unknown", "false_positive"]
DANGEROUS_EXCLUDE_STATUSES = ["watchlist", "false_positive", "allowlisted"]


def _layout(*, title: str, body: str, admin: bool) -> str:
    # Build navigation links
    clusters_href = "/admin/clusters" if admin else "/clusters"
    nav_items = [f'<a class="nav-link" href="{clusters_href}">Threat Campaigns</a>']
    if admin:
        nav_items.append('<a class="nav-link" href="/">Public View</a>')
    nav = "".join(nav_items)

    mode_indicator = "ADMIN" if admin else "PUBLIC"
    mode_class = "mode-admin" if admin else "mode-public"

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>{_escape(title)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
      *, *::before, *::after {{ box-sizing: border-box; }}

      :root {{
        --bg-deep: #0a0c10;
        --bg-base: #0d1117;
        --bg-surface: #161b22;
        --bg-elevated: #1c2128;
        --bg-overlay: #21262d;

        --border-subtle: rgba(240, 246, 252, 0.06);
        --border-default: rgba(240, 246, 252, 0.1);
        --border-emphasis: rgba(240, 246, 252, 0.15);

        --text-primary: #f0f6fc;
        --text-secondary: #b1bac4;
        --text-tertiary: #8b949e;
        --text-link: #58a6ff;

        --accent-amber: #d29922;
        --accent-amber-subtle: rgba(210, 153, 34, 0.15);
        --accent-red: #f85149;
        --accent-red-subtle: rgba(248, 81, 73, 0.15);
        --accent-green: #3fb950;
        --accent-green-subtle: rgba(63, 185, 80, 0.15);
        --accent-blue: #58a6ff;
        --accent-blue-subtle: rgba(88, 166, 255, 0.12);
        --accent-purple: #a371f7;
        --accent-purple-subtle: rgba(163, 113, 247, 0.15);
        --accent-cyan: #39c5cf;
        --accent-cyan-subtle: rgba(57, 197, 207, 0.15);
        --accent-orange: #f0883e;
        --accent-orange-subtle: rgba(240, 136, 62, 0.15);
        --accent-gray: #8b949e;
        --accent-gray-subtle: rgba(139, 148, 158, 0.15);

        --font-mono: 'JetBrains Mono', 'SF Mono', Consolas, monospace;
        --font-sans: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;

        --radius-sm: 4px;
        --radius-md: 6px;
        --radius-lg: 8px;
        --radius-xl: 12px;

        --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
        --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
        --shadow-lg: 0 8px 24px rgba(0,0,0,0.5);

        --transition-fast: 120ms ease;
        --transition-base: 200ms ease;
      }}

      html {{
        background: var(--bg-deep);
        min-height: 100%;
      }}

      body {{
        margin: 0;
        font-family: var(--font-sans);
        font-size: 15px;
        line-height: 1.55;
        background:
          linear-gradient(180deg, var(--bg-base) 0%, var(--bg-deep) 100%),
          repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(255,255,255,0.01) 2px,
            rgba(255,255,255,0.01) 4px
          );
        background-attachment: fixed;
        color: var(--text-primary);
        -webkit-font-smoothing: antialiased;
        min-height: 100vh;
      }}

      a {{
        color: var(--text-link);
        text-decoration: none;
        transition: color var(--transition-fast);
      }}
      a:hover {{
        color: var(--text-primary);
      }}

      /* Layout */
      .sb-container {{
        max-width: 1400px;
        margin: 0 auto;
        padding: 24px 32px 48px;
      }}

      @media (max-width: 768px) {{
        .sb-container {{ padding: 16px; }}
      }}

      /* Header */
      .sb-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 24px;
        margin-bottom: 32px;
        padding-bottom: 20px;
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-brand {{
        display: flex;
        align-items: center;
        gap: 16px;
      }}

      .sb-logo {{
        display: flex;
        align-items: center;
        gap: 12px;
        text-decoration: none;
        color: inherit;
        transition: opacity var(--transition-fast);
      }}

      .sb-logo:hover {{
        opacity: 0.85;
      }}

      .sb-logo-icon {{
        width: 36px;
        height: 36px;
        background: linear-gradient(135deg, var(--accent-amber) 0%, var(--accent-orange) 100%);
        border-radius: var(--radius-lg);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: var(--font-mono);
        font-weight: 700;
        font-size: 18px;
        color: var(--bg-deep);
        box-shadow: var(--shadow-sm), 0 0 20px rgba(210, 153, 34, 0.2);
      }}

      .sb-logo-text {{
        font-family: var(--font-mono);
        font-size: 20px;
        font-weight: 700;
        letter-spacing: -0.5px;
        color: var(--text-primary);
      }}

      .sb-mode {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.1em;
        padding: 4px 10px;
        border-radius: var(--radius-sm);
        text-transform: uppercase;
      }}

      .mode-admin {{
        background: var(--accent-amber-subtle);
        color: var(--accent-amber);
        border: 1px solid rgba(210, 153, 34, 0.3);
      }}

      .mode-public {{
        background: var(--accent-cyan-subtle);
        color: var(--accent-cyan);
        border: 1px solid rgba(57, 197, 207, 0.3);
      }}

      .sb-nav {{
        display: flex;
        align-items: center;
        gap: 12px;
      }}

      .nav-link {{
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 500;
        padding: 8px 14px;
        border-radius: var(--radius-md);
        background: var(--bg-surface);
        border: 1px solid var(--border-default);
        color: var(--text-secondary);
        transition: all var(--transition-fast);
      }}

      .nav-link:hover {{
        background: var(--bg-elevated);
        color: var(--text-primary);
        border-color: var(--border-emphasis);
      }}

      /* Grid System */
      .sb-grid {{
        display: grid;
        grid-template-columns: repeat(12, 1fr);
        gap: 16px;
      }}

      .col-12 {{ grid-column: span 12; }}
      .col-8 {{ grid-column: span 8; }}
      .col-6 {{ grid-column: span 6; }}
      .col-4 {{ grid-column: span 4; }}
      .col-3 {{ grid-column: span 3; }}

      @media (max-width: 1024px) {{
        .col-8, .col-6 {{ grid-column: span 12; }}
        .col-4, .col-3 {{ grid-column: span 6; }}
      }}

      @media (max-width: 640px) {{
        .col-4, .col-3 {{ grid-column: span 12; }}
      }}

      /* Panels */
      .sb-panel {{
        background: var(--bg-surface);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-xl);
        padding: 20px;
        margin-bottom: 16px;
        transition: border-color var(--transition-fast);
      }}

      .sb-panel:hover {{
        border-color: var(--border-emphasis);
      }}

      .sb-panel-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 16px;
        padding-bottom: 12px;
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-panel-title {{
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--text-tertiary);
      }}

      /* Stats Cards */
      .sb-stat {{
        background: var(--bg-surface);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-xl);
        padding: 20px 24px;
        position: relative;
        overflow: hidden;
        transition: all var(--transition-base);
      }}

      .sb-stat:hover {{
        border-color: var(--border-emphasis);
        transform: translateY(-2px);
        box-shadow: var(--shadow-md);
      }}

      .sb-stat::before {{
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, var(--accent-amber), var(--accent-orange));
        opacity: 0;
        transition: opacity var(--transition-fast);
      }}

      .sb-stat:hover::before {{
        opacity: 1;
      }}

      .sb-stat-label {{
        font-family: var(--font-mono);
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--text-tertiary);
        margin-bottom: 8px;
      }}

      .sb-stat-value {{
        font-family: var(--font-mono);
        font-size: 36px;
        font-weight: 700;
        color: var(--text-primary);
        line-height: 1;
        letter-spacing: -1px;
      }}

      .sb-stat-meta {{
        font-family: var(--font-mono);
        font-size: 13px;
        color: var(--text-tertiary);
        margin-top: 10px;
      }}

      .sb-stat-meta b {{
        color: var(--text-secondary);
      }}

      /* Breakdown Lists */
      .sb-breakdown {{
        display: flex;
        flex-direction: column;
        gap: 6px;
      }}

      .sb-breakdown-item {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px 14px;
        background: var(--bg-elevated);
        border-radius: var(--radius-md);
        font-family: var(--font-mono);
        font-size: 13px;
        transition: background var(--transition-fast);
      }}

      .sb-breakdown-item:hover {{
        background: var(--bg-overlay);
      }}

      .sb-breakdown-key {{
        color: var(--text-secondary);
      }}

      .sb-breakdown-val {{
        font-weight: 600;
        color: var(--text-primary);
      }}

      /* Tables */
      .sb-table-wrap {{
        overflow-x: auto;
        margin: 0 -4px;
        padding: 0 4px;
      }}

      .sb-table {{
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        font-family: var(--font-mono);
        font-size: 14px;
      }}

      .sb-table th {{
        text-align: left;
        padding: 12px 14px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--text-tertiary);
        background: var(--bg-elevated);
        border-bottom: 1px solid var(--border-default);
        position: sticky;
        top: 0;
        z-index: 1;
        white-space: nowrap;
      }}

      .sb-table th:first-child {{
        border-radius: var(--radius-md) 0 0 0;
      }}

      .sb-table th:last-child {{
        border-radius: 0 var(--radius-md) 0 0;
      }}

      .sb-table td {{
        padding: 14px 14px;
        border-bottom: 1px solid var(--border-subtle);
        vertical-align: middle;
        color: var(--text-secondary);
        transition: background var(--transition-fast);
      }}

      .sb-table tbody tr:hover td {{
        background: rgba(88, 166, 255, 0.03);
      }}

      .sb-table tbody tr:last-child td {{
        border-bottom: none;
      }}

      .sb-table .domain-cell {{
        max-width: 320px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }}

      .sb-table .domain-link {{
        font-weight: 500;
        color: var(--text-primary);
      }}

      .sb-table .domain-link:hover {{
        color: var(--text-link);
      }}

      /* Badges */
      .sb-badge {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 12px;
        border-radius: 100px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.02em;
        white-space: nowrap;
      }}

      .sb-badge::before {{
        content: '';
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: currentColor;
      }}

      .sb-badge-pending {{ background: var(--accent-amber-subtle); color: var(--accent-amber); }}
      .sb-badge-analyzing {{ background: var(--accent-blue-subtle); color: var(--accent-blue); }}
      .sb-badge-analyzed {{ background: var(--accent-gray-subtle); color: var(--accent-gray); }}
      .sb-badge-watchlist {{ background: var(--accent-orange-subtle); color: var(--accent-orange); }}
      .sb-badge-reported {{ background: var(--accent-green-subtle); color: var(--accent-green); }}
      .sb-badge-false_positive {{ background: var(--accent-purple-subtle); color: var(--accent-purple); }}
      .sb-badge-allowlisted {{ background: var(--accent-cyan-subtle); color: var(--accent-cyan); }}

      .sb-badge-high {{ background: var(--accent-red-subtle); color: var(--accent-red); }}
      .sb-badge-medium {{ background: var(--accent-orange-subtle); color: var(--accent-orange); }}
      .sb-badge-low {{ background: var(--accent-amber-subtle); color: var(--accent-amber); }}
      .sb-badge-benign {{ background: var(--accent-green-subtle); color: var(--accent-green); }}
      .sb-badge-unknown {{ background: var(--accent-gray-subtle); color: var(--accent-gray); }}

      .sb-badge-submitted, .sb-badge-confirmed, .sb-badge-duplicate {{
        background: var(--accent-green-subtle); color: var(--accent-green);
      }}
      .sb-badge-manual_required {{ background: var(--accent-orange-subtle); color: var(--accent-orange); }}
      .sb-badge-rate_limited {{ background: var(--accent-blue-subtle); color: var(--accent-blue); }}
      .sb-badge-failed {{ background: var(--accent-red-subtle); color: var(--accent-red); }}
      .sb-badge-skipped {{ background: var(--accent-gray-subtle); color: var(--accent-gray); }}
      .sb-badge-rejected {{ background: var(--accent-gray-subtle); color: var(--accent-gray); }}

      /* Score Display */
      .sb-score {{
        font-family: var(--font-mono);
        font-weight: 600;
        font-size: 13px;
        padding: 3px 10px;
        border-radius: var(--radius-sm);
        background: var(--bg-overlay);
        color: var(--text-secondary);
      }}

      /* Forms */
      .sb-input, .sb-select, .sb-textarea {{
        width: 100%;
        padding: 10px 14px;
        font-family: var(--font-mono);
        font-size: 13px;
        background: var(--bg-elevated);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        color: var(--text-primary);
        outline: none;
        transition: all var(--transition-fast);
      }}

      .sb-input:focus, .sb-select:focus, .sb-textarea:focus {{
        border-color: var(--accent-blue);
        box-shadow: 0 0 0 3px var(--accent-blue-subtle);
      }}

      .sb-input::placeholder {{
        color: var(--text-tertiary);
      }}

      .sb-select {{
        cursor: pointer;
        appearance: none;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%238b949e' d='M2.5 4.5L6 8l3.5-3.5'/%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 12px center;
        padding-right: 36px;
      }}

      .sb-textarea {{
        min-height: 100px;
        resize: vertical;
        line-height: 1.6;
      }}

      .sb-label {{
        display: block;
        font-family: var(--font-mono);
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: var(--text-tertiary);
        margin-bottom: 8px;
      }}

      /* Buttons */
      .sb-btn {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 10px 18px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        border-radius: var(--radius-md);
        border: 1px solid var(--border-default);
        background: var(--bg-elevated);
        color: var(--text-secondary);
        cursor: pointer;
        transition: all var(--transition-fast);
        text-decoration: none;
      }}

      .sb-btn:hover {{
        background: var(--bg-overlay);
        color: var(--text-primary);
        border-color: var(--border-emphasis);
        transform: translateY(-1px);
      }}

      .sb-btn-primary {{
        background: var(--accent-blue-subtle);
        border-color: rgba(88, 166, 255, 0.3);
        color: var(--accent-blue);
      }}

      .sb-btn-primary:hover {{
        background: rgba(88, 166, 255, 0.2);
        color: var(--text-primary);
        border-color: var(--accent-blue);
      }}

      .sb-btn-danger {{
        background: var(--accent-red-subtle);
        border-color: rgba(248, 81, 73, 0.3);
        color: var(--accent-red);
      }}

      .sb-btn-danger:hover {{
        background: rgba(248, 81, 73, 0.2);
        color: var(--text-primary);
        border-color: var(--accent-red);
      }}

      .sb-btn-success {{
        background: var(--accent-green-subtle);
        border-color: rgba(63, 185, 80, 0.3);
        color: var(--accent-green);
      }}

      .sb-btn-success:hover {{
        background: rgba(63, 185, 80, 0.2);
        color: var(--text-primary);
        border-color: var(--accent-green);
      }}

      /* Manual Submission Helper */
      .sb-manual-helper {{
        background: var(--bg-surface);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-lg);
        padding: 20px;
        margin: 12px 0;
      }}

      .sb-manual-helper-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        margin-bottom: 16px;
        padding-bottom: 12px;
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-manual-helper-title {{
        font-family: var(--font-mono);
        font-size: 13px;
        font-weight: 600;
        color: var(--accent-orange);
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }}

      .sb-manual-helper-reason {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-tertiary);
        background: var(--bg-overlay);
        padding: 4px 10px;
        border-radius: var(--radius-sm);
      }}

      .sb-copy-field {{
        background: var(--bg-elevated);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        padding: 12px 14px;
        margin-bottom: 10px;
        position: relative;
      }}

      .sb-copy-field-label {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--text-tertiary);
        margin-bottom: 6px;
      }}

      .sb-copy-field-value {{
        font-family: var(--font-mono);
        font-size: 13px;
        color: var(--text-secondary);
        white-space: pre-wrap;
        word-break: break-word;
        line-height: 1.5;
      }}

      .sb-copy-field-value.multiline {{
        max-height: 140px;
        overflow-y: auto;
        padding-right: 8px;
      }}

      .sb-copy-btn {{
        position: absolute;
        top: 10px;
        right: 10px;
        padding: 4px 10px;
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        background: var(--bg-overlay);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-sm);
        color: var(--text-tertiary);
        cursor: pointer;
        transition: all var(--transition-fast);
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }}

      .sb-copy-btn:hover {{
        background: var(--accent-blue-subtle);
        color: var(--accent-blue);
        border-color: rgba(88, 166, 255, 0.3);
      }}

      .sb-copy-btn.copied {{
        background: var(--accent-green-subtle);
        color: var(--accent-green);
        border-color: rgba(63, 185, 80, 0.3);
      }}

      .sb-manual-helper-actions {{
        display: flex;
        align-items: center;
        gap: 12px;
        margin-top: 16px;
        padding-top: 16px;
        border-top: 1px solid var(--border-subtle);
      }}

      .sb-manual-helper-notes {{
        margin-top: 16px;
        padding: 12px 14px;
        background: var(--bg-overlay);
        border-radius: var(--radius-md);
        border-left: 3px solid var(--accent-amber);
      }}

      .sb-manual-helper-notes-title {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--accent-amber);
        margin-bottom: 8px;
      }}

      .sb-manual-helper-notes ul {{
        margin: 0;
        padding-left: 16px;
        font-size: 12px;
        color: var(--text-tertiary);
      }}

      .sb-manual-helper-notes li {{
        margin-bottom: 4px;
      }}

      /* New Manual Submission UI */
      .sb-manual-cta {{
        display: flex;
        gap: 12px;
        margin-bottom: 20px;
        padding-bottom: 20px;
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-manual-cta-btn {{
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 14px 24px;
        font-family: var(--font-mono);
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        background: linear-gradient(135deg, var(--accent-blue) 0%, #4a90d9 100%);
        color: #fff;
        border: none;
        border-radius: var(--radius-md);
        text-decoration: none;
        cursor: pointer;
        transition: all var(--transition-fast);
        box-shadow: 0 2px 8px rgba(88, 166, 255, 0.3);
      }}

      .sb-manual-cta-btn:hover {{
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(88, 166, 255, 0.4);
        background: linear-gradient(135deg, #6ab0ff 0%, #5a9ee9 100%);
      }}

      .sb-manual-cta-icon {{
        font-size: 16px;
      }}

      .sb-manual-copy-all {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 14px 20px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        background: var(--bg-overlay);
        color: var(--text-secondary);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-manual-copy-all:hover {{
        background: var(--bg-elevated);
        border-color: var(--accent-blue);
        color: var(--accent-blue);
      }}

      .sb-manual-copy-all.copied {{
        background: var(--accent-green-subtle);
        color: var(--accent-green);
        border-color: rgba(63, 185, 80, 0.3);
      }}

      .sb-copy-card-grid {{
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 12px;
      }}

      .sb-copy-card {{
        background: var(--bg-elevated);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        overflow: hidden;
        transition: border-color var(--transition-fast);
      }}

      .sb-copy-card:hover {{
        border-color: var(--border-muted);
      }}

      .sb-copy-card-full {{
        grid-column: 1 / -1;
      }}

      .sb-copy-card-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 8px 12px;
        background: var(--bg-overlay);
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-copy-card-label {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--text-tertiary);
      }}

      .sb-copy-card-btn {{
        padding: 4px 10px;
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        background: transparent;
        border: 1px solid var(--border-default);
        border-radius: var(--radius-sm);
        color: var(--text-tertiary);
        cursor: pointer;
        transition: all var(--transition-fast);
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }}

      .sb-copy-card-btn:hover {{
        background: var(--accent-blue-subtle);
        color: var(--accent-blue);
        border-color: rgba(88, 166, 255, 0.3);
      }}

      .sb-copy-card-btn.copied {{
        background: var(--accent-green-subtle);
        color: var(--accent-green);
        border-color: rgba(63, 185, 80, 0.3);
      }}

      .sb-copy-card-btn.copied .sb-copy-card-btn-text {{
        display: none;
      }}

      .sb-copy-card-btn.copied::after {{
        content: 'Copied!';
      }}

      .sb-copy-card-value {{
        padding: 10px 12px;
        font-family: var(--font-mono);
        font-size: 13px;
        color: var(--text-primary);
        word-break: break-all;
        line-height: 1.4;
      }}

      .sb-copy-card-value-multi {{
        max-height: 120px;
        overflow-y: auto;
        white-space: pre-wrap;
        word-break: break-word;
      }}

      .sb-manual-notes {{
        margin-top: 16px;
        padding: 12px 14px;
        background: rgba(210, 153, 34, 0.08);
        border-radius: var(--radius-md);
        border: 1px solid rgba(210, 153, 34, 0.2);
      }}

      .sb-manual-notes-title {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--accent-amber);
        margin-bottom: 8px;
      }}

      .sb-manual-notes ul {{
        margin: 0;
        padding-left: 16px;
        font-size: 12px;
        color: var(--text-secondary);
      }}

      .sb-manual-notes li {{
        margin-bottom: 4px;
      }}

      /* Platform Categories */
      .sb-platform-section {{
        margin-bottom: 16px;
      }}

      .sb-platform-section-title {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--text-tertiary);
        margin-bottom: 8px;
        padding-bottom: 6px;
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-platform-section-title.manual {{
        color: var(--accent-orange);
        border-bottom-color: rgba(240, 136, 62, 0.2);
      }}

      .sb-platform-section-desc {{
        font-size: 11px;
        color: var(--text-tertiary);
        margin-bottom: 8px;
      }}

      /* ========================================
         TWO-STAGE MANUAL SUBMISSION MODAL
         ======================================== */

      /* Notification Bar */
      .sb-notify-bar {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 18px;
        margin-bottom: 16px;
        background: linear-gradient(135deg, rgba(240, 136, 62, 0.08) 0%, rgba(240, 136, 62, 0.03) 100%);
        border: 1px solid rgba(240, 136, 62, 0.25);
        border-left: 3px solid var(--accent-orange);
        border-radius: var(--radius-md);
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-notify-bar:hover {{
        background: linear-gradient(135deg, rgba(240, 136, 62, 0.14) 0%, rgba(240, 136, 62, 0.06) 100%);
        border-color: rgba(240, 136, 62, 0.4);
        transform: translateX(2px);
      }}

      .sb-notify-bar-content {{
        display: flex;
        align-items: center;
        gap: 14px;
      }}

      .sb-notify-bar-icon {{
        display: flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        background: var(--accent-orange);
        color: var(--bg-deep);
        border-radius: 6px;
        font-size: 16px;
        font-weight: 800;
        flex-shrink: 0;
      }}

      .sb-notify-bar-text {{
        font-family: var(--font-mono);
        font-size: 13px;
        font-weight: 500;
        color: var(--text-primary);
      }}

      .sb-notify-bar-text strong {{
        color: var(--accent-orange);
        font-weight: 700;
      }}

      .sb-notify-bar-hint {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--accent-orange);
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 6px 12px;
        background: rgba(240, 136, 62, 0.1);
        border-radius: var(--radius-sm);
        transition: all var(--transition-fast);
      }}

      .sb-notify-bar:hover .sb-notify-bar-hint {{
        background: rgba(240, 136, 62, 0.2);
      }}

      /* Modal Overlay */
      .sb-modal-overlay {{
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.7);
        backdrop-filter: blur(6px);
        z-index: 1000;
        opacity: 0;
        visibility: hidden;
        transition: opacity 0.25s ease, visibility 0.25s ease;
      }}

      .sb-modal-overlay.open {{
        opacity: 1;
        visibility: visible;
      }}

      /* Two-Stage Modal Panel */
      .sb-modal-panel {{
        position: fixed;
        top: 0;
        right: 0;
        height: 100vh;
        background: var(--bg-base);
        border-left: 1px solid var(--border-default);
        box-shadow: -12px 0 40px rgba(0, 0, 0, 0.5);
        z-index: 1001;
        transform: translateX(100%);
        transition: transform 0.3s cubic-bezier(0.32, 0.72, 0, 1), width 0.3s cubic-bezier(0.32, 0.72, 0, 1);
        display: flex;
        flex-direction: column;
        width: 320px;
      }}

      .sb-modal-panel.open {{
        transform: translateX(0);
      }}

      .sb-modal-panel.expanded {{
        width: 580px;
      }}

      @media (max-width: 640px) {{
        .sb-modal-panel {{
          width: 100vw;
        }}
        .sb-modal-panel.expanded {{
          width: 100vw;
        }}
      }}

      /* Modal Header */
      .sb-modal-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px 20px;
        background: var(--bg-surface);
        border-bottom: 1px solid var(--border-default);
        flex-shrink: 0;
        min-height: 64px;
      }}

      .sb-modal-header-left {{
        display: flex;
        align-items: center;
        gap: 12px;
      }}

      .sb-modal-back {{
        display: none;
        align-items: center;
        justify-content: center;
        width: 28px;
        height: 28px;
        background: var(--bg-overlay);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-sm);
        color: var(--text-secondary);
        cursor: pointer;
        transition: all var(--transition-fast);
        font-size: 14px;
      }}

      .sb-modal-panel.expanded .sb-modal-back {{
        display: flex;
      }}

      .sb-modal-back:hover {{
        background: var(--bg-elevated);
        border-color: var(--text-tertiary);
        color: var(--text-primary);
      }}

      .sb-modal-title {{
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 700;
        color: var(--accent-orange);
        text-transform: uppercase;
        letter-spacing: 0.1em;
      }}

      .sb-modal-subtitle {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-tertiary);
        margin-top: 2px;
      }}

      .sb-modal-close {{
        width: 28px;
        height: 28px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: transparent;
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-sm);
        color: var(--text-tertiary);
        cursor: pointer;
        transition: all var(--transition-fast);
        font-size: 16px;
      }}

      .sb-modal-close:hover {{
        background: var(--bg-overlay);
        border-color: var(--text-tertiary);
        color: var(--text-primary);
      }}

      /* Modal Body */
      .sb-modal-body {{
        flex: 1;
        overflow-y: auto;
        overflow-x: hidden;
      }}

      /* Stage 1: Platform List */
      .sb-platform-list {{
        padding: 12px;
      }}

      .sb-platform-list-item {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 16px;
        margin-bottom: 8px;
        background: var(--bg-surface);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-platform-list-item:hover {{
        background: var(--bg-elevated);
        border-color: var(--accent-orange);
        transform: translateX(3px);
      }}

      .sb-platform-list-item.done {{
        opacity: 0.6;
        border-color: rgba(63, 185, 80, 0.3);
      }}

      .sb-platform-list-item.done:hover {{
        opacity: 0.8;
        border-color: rgba(63, 185, 80, 0.5);
      }}

      .sb-platform-list-info {{
        display: flex;
        align-items: center;
        gap: 12px;
      }}

      .sb-platform-list-icon {{
        width: 36px;
        height: 36px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: var(--bg-overlay);
        border-radius: var(--radius-sm);
        font-size: 16px;
      }}

      .sb-platform-list-item.done .sb-platform-list-icon {{
        background: var(--accent-green-subtle);
        color: var(--accent-green);
      }}

      .sb-platform-list-name {{
        font-family: var(--font-mono);
        font-size: 13px;
        font-weight: 600;
        color: var(--text-primary);
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }}

      .sb-platform-list-status {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 500;
        color: var(--text-tertiary);
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }}

      .sb-platform-list-item.done .sb-platform-list-status {{
        color: var(--accent-green);
      }}

      .sb-platform-list-arrow {{
        color: var(--text-tertiary);
        font-size: 14px;
        transition: transform var(--transition-fast);
      }}

      .sb-platform-list-item:hover .sb-platform-list-arrow {{
        transform: translateX(3px);
        color: var(--accent-orange);
      }}

      .sb-platform-list-item.done .sb-platform-list-arrow {{
        color: var(--accent-green);
      }}

      /* Stage 2: Platform Detail View */
      .sb-platform-detail {{
        display: none;
        padding: 0;
      }}

      .sb-modal-panel.expanded .sb-platform-list {{
        display: none;
      }}

      .sb-modal-panel.expanded .sb-platform-detail.active {{
        display: block;
      }}

      /* Detail Header */
      .sb-detail-header {{
        padding: 20px;
        background: linear-gradient(180deg, var(--bg-surface) 0%, var(--bg-base) 100%);
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-detail-platform {{
        font-family: var(--font-mono);
        font-size: 18px;
        font-weight: 700;
        color: var(--text-primary);
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 4px;
      }}

      .sb-detail-subtitle {{
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-tertiary);
      }}

      /* Open Form CTA */
      .sb-detail-cta {{
        padding: 16px 20px;
        background: var(--bg-surface);
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-detail-cta-btn {{
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        width: 100%;
        padding: 14px 20px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        background: linear-gradient(135deg, var(--accent-blue) 0%, #4a90d9 100%);
        color: #fff;
        border: none;
        border-radius: var(--radius-md);
        text-decoration: none;
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-detail-cta-btn:hover {{
        transform: translateY(-1px);
        box-shadow: 0 6px 20px rgba(88, 166, 255, 0.35);
      }}

      .sb-detail-cta-btn span {{
        font-size: 16px;
      }}

      /* Form Fields Section */
      .sb-detail-fields {{
        padding: 16px 20px;
      }}

      .sb-detail-fields-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 12px;
      }}

      .sb-detail-fields-title {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 700;
        color: var(--text-tertiary);
        text-transform: uppercase;
        letter-spacing: 0.12em;
      }}

      .sb-detail-fields-progress {{
        font-family: var(--font-mono);
        font-size: 10px;
        color: var(--text-tertiary);
        padding: 4px 8px;
        background: var(--bg-overlay);
        border-radius: var(--radius-sm);
      }}

      /* Individual Copy Field */
      .sb-field {{
        position: relative;
        margin-bottom: 10px;
        background: var(--bg-surface);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        transition: all var(--transition-fast);
        overflow: hidden;
      }}

      .sb-field.copied {{
        border-color: rgba(63, 185, 80, 0.4);
        background: rgba(63, 185, 80, 0.03);
      }}

      .sb-field-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 12px 8px 12px;
        background: var(--bg-elevated);
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-field-label {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }}

      .sb-field.copied .sb-field-label {{
        color: var(--accent-green);
      }}

      .sb-field-copy {{
        display: flex;
        align-items: center;
        gap: 4px;
        padding: 4px 8px;
        font-family: var(--font-mono);
        font-size: 9px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        background: var(--bg-overlay);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-sm);
        color: var(--text-tertiary);
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-field-copy:hover {{
        background: var(--bg-surface);
        border-color: var(--accent-blue);
        color: var(--accent-blue);
      }}

      .sb-field.copied .sb-field-copy {{
        background: var(--accent-green-subtle);
        border-color: rgba(63, 185, 80, 0.3);
        color: var(--accent-green);
      }}

      .sb-field-value {{
        padding: 10px 12px;
        font-family: var(--font-mono);
        font-size: 12px;
        color: var(--text-primary);
        line-height: 1.5;
        word-break: break-word;
        white-space: pre-wrap;
        max-height: 120px;
        overflow-y: auto;
      }}

      .sb-field-value.multiline {{
        max-height: 200px;
        font-size: 11px;
        background: var(--bg-deep);
        border-radius: 0 0 var(--radius-md) var(--radius-md);
      }}

      /* Evidence Section */
      .sb-detail-evidence {{
        padding: 16px 20px;
        border-top: 1px solid var(--border-subtle);
        background: var(--bg-surface);
      }}

      .sb-detail-evidence-title {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 700;
        color: var(--text-tertiary);
        text-transform: uppercase;
        letter-spacing: 0.12em;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
      }}

      .sb-detail-evidence-title::before {{
        content: '\U0001f4ce';
        font-size: 12px;
      }}

      .sb-evidence-files {{
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }}

      .sb-evidence-file {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 8px 12px;
        font-family: var(--font-mono);
        font-size: 11px;
        font-weight: 500;
        background: var(--bg-overlay);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-sm);
        color: var(--text-secondary);
        text-decoration: none;
        transition: all var(--transition-fast);
      }}

      .sb-evidence-file:hover {{
        background: var(--bg-elevated);
        border-color: var(--accent-blue);
        color: var(--accent-blue);
      }}

      .sb-evidence-file-icon {{
        font-size: 14px;
      }}

      /* Detail Footer / Mark as Done */
      .sb-detail-footer {{
        padding: 16px 20px;
        background: var(--bg-surface);
        border-top: 1px solid var(--border-default);
        margin-top: auto;
      }}

      .sb-detail-done-btn {{
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        width: 100%;
        padding: 14px 20px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        background: var(--accent-green-subtle);
        border: 1px solid rgba(63, 185, 80, 0.3);
        border-radius: var(--radius-md);
        color: var(--accent-green);
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-detail-done-btn:hover {{
        background: rgba(63, 185, 80, 0.2);
        border-color: var(--accent-green);
        transform: translateY(-1px);
      }}

      .sb-detail-done-btn:disabled {{
        opacity: 0.5;
        cursor: not-allowed;
        transform: none;
      }}

      /* Tips Section */
      .sb-detail-tips {{
        padding: 12px 20px;
        background: var(--bg-overlay);
        border-top: 1px solid var(--border-subtle);
      }}

      .sb-detail-tips-title {{
        font-family: var(--font-mono);
        font-size: 9px;
        font-weight: 700;
        color: var(--accent-amber);
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-bottom: 8px;
      }}

      .sb-detail-tips ul {{
        margin: 0;
        padding-left: 14px;
        font-family: var(--font-mono);
        font-size: 10px;
        color: var(--text-tertiary);
        line-height: 1.6;
      }}

      .sb-detail-tips li {{
        margin-bottom: 2px;
      }}

      /* Confirmation Dialog */
      .sb-confirm-dialog {{
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%) scale(0.95);
        background: var(--bg-surface);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-lg);
        padding: 24px;
        width: 380px;
        max-width: 90vw;
        z-index: 1002;
        opacity: 0;
        visibility: hidden;
        transition: all 0.2s cubic-bezier(0.32, 0.72, 0, 1);
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
      }}

      .sb-confirm-dialog.open {{
        opacity: 1;
        visibility: visible;
        transform: translate(-50%, -50%) scale(1);
      }}

      .sb-confirm-title {{
        font-family: var(--font-mono);
        font-size: 13px;
        font-weight: 700;
        color: var(--text-primary);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 12px;
      }}

      .sb-confirm-message {{
        font-family: var(--font-mono);
        font-size: 12px;
        color: var(--text-secondary);
        margin-bottom: 20px;
        line-height: 1.6;
      }}

      .sb-confirm-actions {{
        display: flex;
        gap: 10px;
        justify-content: flex-end;
      }}

      .sb-platform-card-status {{
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 600;
        padding: 4px 8px;
        border-radius: var(--radius-sm);
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }}

      .sb-platform-card-status.pending {{
        background: rgba(240, 136, 62, 0.15);
        color: var(--accent-orange);
      }}

      .sb-platform-card-status.done {{
        background: var(--accent-green-subtle);
        color: var(--accent-green);
      }}

      .sb-platform-card-toggle {{
        font-size: 12px;
        color: var(--text-tertiary);
        transition: transform var(--transition-fast);
      }}

      .sb-platform-card.expanded .sb-platform-card-toggle {{
        transform: rotate(180deg);
      }}

      .sb-platform-card-body {{
        display: none;
        padding: 16px;
        border-top: 1px solid var(--border-subtle);
      }}

      .sb-platform-card.expanded .sb-platform-card-body {{
        display: block;
      }}

      .sb-platform-card-actions {{
        display: flex;
        gap: 12px;
        margin-bottom: 16px;
        padding-bottom: 16px;
        border-bottom: 1px solid var(--border-subtle);
      }}

      .sb-platform-open-btn {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 12px 20px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        background: linear-gradient(135deg, var(--accent-blue) 0%, #4a90d9 100%);
        color: #fff;
        border: none;
        border-radius: var(--radius-md);
        text-decoration: none;
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-platform-open-btn:hover {{
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(88, 166, 255, 0.3);
      }}

      .sb-platform-done-btn {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 12px 20px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        background: var(--accent-green-subtle);
        color: var(--accent-green);
        border: 1px solid rgba(63, 185, 80, 0.3);
        border-radius: var(--radius-md);
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-platform-done-btn:hover {{
        background: rgba(63, 185, 80, 0.2);
        border-color: var(--accent-green);
      }}

      .sb-platform-done-btn:disabled {{
        opacity: 0.5;
        cursor: not-allowed;
      }}

      /* Confirmation Dialog */
      .sb-confirm-dialog {{
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%) scale(0.9);
        background: var(--bg-surface);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-lg);
        padding: 24px;
        width: 400px;
        max-width: 90vw;
        z-index: 1002;
        opacity: 0;
        visibility: hidden;
        transition: all 0.2s ease;
        box-shadow: 0 16px 48px rgba(0, 0, 0, 0.4);
      }}

      .sb-confirm-dialog.open {{
        opacity: 1;
        visibility: visible;
        transform: translate(-50%, -50%) scale(1);
      }}

      .sb-confirm-title {{
        font-family: var(--font-mono);
        font-size: 14px;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 12px;
      }}

      .sb-confirm-text {{
        font-size: 13px;
        color: var(--text-secondary);
        margin-bottom: 20px;
        line-height: 1.5;
      }}

      .sb-confirm-actions {{
        display: flex;
        gap: 12px;
        justify-content: flex-end;
      }}

      .sb-confirm-cancel {{
        padding: 10px 16px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        background: transparent;
        border: 1px solid var(--border-default);
        border-radius: var(--radius-md);
        color: var(--text-secondary);
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-confirm-cancel:hover {{
        background: var(--bg-overlay);
        border-color: var(--text-tertiary);
      }}

      .sb-confirm-ok {{
        padding: 10px 16px;
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        background: var(--accent-green);
        border: none;
        border-radius: var(--radius-md);
        color: var(--bg-deep);
        cursor: pointer;
        transition: all var(--transition-fast);
      }}

      .sb-confirm-ok:hover {{
        background: #4ec969;
      }}

      /* Expandable Report Row */
      .sb-report-expandable {{
        border: none;
        background: none;
        width: 100%;
      }}

      .sb-report-expandable summary {{
        cursor: pointer;
        list-style: none;
        display: contents;
      }}

      .sb-report-expandable summary::-webkit-details-marker {{
        display: none;
      }}

      .sb-report-expandable[open] .sb-expand-icon {{
        transform: rotate(90deg);
      }}

      .sb-expand-icon {{
        display: inline-block;
        transition: transform var(--transition-fast);
        font-size: 10px;
        margin-right: 6px;
      }}

      /* Code */
      .sb-code {{
        font-family: var(--font-mono);
        font-size: 12px;
        padding: 2px 8px;
        background: var(--bg-overlay);
        border-radius: var(--radius-sm);
        color: var(--text-secondary);
      }}

      /* Flash Messages */
      .sb-flash {{
        padding: 14px 18px;
        border-radius: var(--radius-lg);
        font-family: var(--font-mono);
        font-size: 13px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        gap: 12px;
        animation: slideIn 0.3s ease;
      }}

      @keyframes slideIn {{
        from {{ opacity: 0; transform: translateY(-8px); }}
        to {{ opacity: 1; transform: translateY(0); }}
      }}

      .sb-flash-success {{
        background: var(--accent-green-subtle);
        border: 1px solid rgba(63, 185, 80, 0.3);
        color: var(--accent-green);
      }}

      .sb-flash-error {{
        background: var(--accent-red-subtle);
        border: 1px solid rgba(248, 81, 73, 0.3);
        color: var(--accent-red);
      }}

      /* Toasts */
      .sb-toast-container {{
        position: fixed;
        top: 16px;
        right: 16px;
        z-index: 1000;
        display: flex;
        flex-direction: column;
        gap: 8px;
        pointer-events: none;
      }}

      .sb-toast {{
        pointer-events: auto;
        min-width: 220px;
        max-width: 360px;
        padding: 12px 14px;
        border-radius: var(--radius-lg);
        background: var(--bg-elevated);
        border: 1px solid var(--border-default);
        color: var(--text-primary);
        box-shadow: var(--shadow-md);
        font-family: var(--font-mono);
        font-size: 13px;
        animation: toastIn 0.2s ease;
      }}

      .sb-toast-success {{
        background: var(--accent-green-subtle);
        border-color: rgba(63, 185, 80, 0.4);
        color: var(--accent-green);
      }}

      .sb-toast-error {{
        background: var(--accent-red-subtle);
        border-color: rgba(248, 81, 73, 0.4);
        color: var(--accent-red);
      }}

      .sb-toast-hide {{
        opacity: 0;
        transform: translateY(-4px);
        transition: opacity 160ms ease, transform 160ms ease;
      }}

      @keyframes toastIn {{
        from {{ opacity: 0; transform: translateY(6px); }}
        to {{ opacity: 1; transform: translateY(0); }}
      }}

      /* Utility */
      .sb-muted {{ color: var(--text-tertiary); }}
      .sb-text-secondary {{ color: var(--text-secondary); }}

      .sb-row {{
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        align-items: center;
      }}

      .sb-row > * {{ flex: 0 0 auto; }}

      .sb-space-between {{
        justify-content: space-between;
      }}

      /* Images/Evidence */
      .sb-evidence-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 16px;
      }}

      .sb-screenshot {{
        background: var(--bg-elevated);
        border: 1px solid var(--border-default);
        border-radius: var(--radius-lg);
        padding: 12px;
        transition: all var(--transition-base);
      }}

      .sb-screenshot:hover {{
        border-color: var(--border-emphasis);
        box-shadow: var(--shadow-md);
      }}

      .sb-screenshot img {{
        width: 100%;
        border-radius: var(--radius-md);
        border: 1px solid var(--border-subtle);
      }}

      .sb-screenshot-label {{
        margin-top: 10px;
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-tertiary);
        text-align: center;
      }}

      /* Domain Detail Header */
      .sb-domain-header {{
        margin-bottom: 24px;
      }}

      .sb-domain-name {{
        font-family: var(--font-mono);
        font-size: 24px;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 12px;
        word-break: break-all;
      }}

      .sb-domain-meta {{
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
      }}

      .sb-domain-id {{
        font-family: var(--font-mono);
        font-size: 12px;
        color: var(--text-tertiary);
      }}

      /* KV Table */
      .sb-kv-table {{
        font-family: var(--font-mono);
        font-size: 13px;
      }}

      .sb-kv-table tr:hover {{
        background: var(--bg-elevated);
      }}

      .sb-kv-table th {{
        padding: 10px 16px;
        font-weight: 500;
        color: var(--text-tertiary);
        text-align: left;
        width: 140px;
        vertical-align: top;
      }}

      .sb-kv-table td {{
        padding: 10px 16px;
        color: var(--text-secondary);
      }}

      /* Checkbox styling */
      input[type="checkbox"] {{
        appearance: none;
        width: 16px;
        height: 16px;
        border: 1px solid var(--border-default);
        border-radius: var(--radius-sm);
        background: var(--bg-elevated);
        cursor: pointer;
        transition: all var(--transition-fast);
        position: relative;
      }}

      input[type="checkbox"]:checked {{
        background: var(--accent-blue);
        border-color: var(--accent-blue);
      }}

      input[type="checkbox"]:checked::after {{
        content: '&#10003;';
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 10px;
        color: var(--bg-deep);
        font-weight: 700;
      }}

      /* Preformatted text */
      .sb-pre {{
        font-family: var(--font-mono);
        font-size: 12px;
        line-height: 1.6;
        white-space: pre-wrap;
        word-break: break-word;
        margin: 0;
        padding: 12px;
        background: var(--bg-elevated);
        border-radius: var(--radius-md);
        color: var(--text-secondary);
      }}

      /* Footer */
      .sb-footer {{
        margin-top: 48px;
        padding-top: 24px;
        border-top: 1px solid var(--border-subtle);
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-tertiary);
        display: flex;
        justify-content: space-between;
        align-items: center;
      }}

      /* Pagination */
      .sb-pagination {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px 0;
      }}

      .sb-page-info {{
        font-family: var(--font-mono);
        font-size: 12px;
        color: var(--text-tertiary);
      }}

      /* Action cards in admin */
      .sb-action-card {{
        background: var(--bg-elevated);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-lg);
        padding: 16px;
        margin-bottom: 12px;
      }}

      .sb-action-card-title {{
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        color: var(--text-secondary);
        margin-bottom: 12px;
      }}

      /* Scrollbar */
      ::-webkit-scrollbar {{
        width: 8px;
        height: 8px;
      }}

      ::-webkit-scrollbar-track {{
        background: var(--bg-surface);
      }}

      ::-webkit-scrollbar-thumb {{
        background: var(--bg-overlay);
        border-radius: 4px;
      }}

      ::-webkit-scrollbar-thumb:hover {{
        background: var(--border-emphasis);
      }}
    </style>
    <script>
      // Toast helpers (shared)
      function _sbToastContainer() {{
        let el = document.getElementById('sb-toast-container');
        if (!el) {{
          el = document.createElement('div');
          el.id = 'sb-toast-container';
          el.className = 'sb-toast-container';
          document.body.appendChild(el);
        }}
        return el;
      }}

      function sbToast(message, type) {{
        const container = _sbToastContainer();
        const toast = document.createElement('div');
        toast.className = 'sb-toast' + (type ? ' sb-toast-' + type : '');
        toast.textContent = message;
        container.appendChild(toast);
        const dismiss = () => {{
          toast.classList.add('sb-toast-hide');
          setTimeout(() => toast.remove(), 220);
        }};
        toast.addEventListener('click', dismiss);
        setTimeout(dismiss, 4000);
      }}

      // Copy field to clipboard
      function copyField(fieldId, btnId) {{
        const el = document.getElementById(fieldId);
        const btn = document.getElementById(btnId);
        if (!el || !btn) return;
        const text = el.textContent.trim();
        navigator.clipboard.writeText(text).then(() => {{
          btn.classList.add('copied');
          setTimeout(() => {{ btn.classList.remove('copied'); }}, 2000);
        }}).catch(err => {{
          console.error('Copy failed:', err);
        }});
      }}

      // Copy all fields in a container
      function copyAllFields(containerId) {{
        const container = document.getElementById(containerId);
        if (!container) return;
        const cards = container.querySelectorAll('.sb-copy-card');
        let text = '';
        cards.forEach(card => {{
          const label = card.querySelector('.sb-copy-card-label');
          const value = card.querySelector('.sb-copy-card-value');
          if (label && value) {{
            text += label.textContent.trim() + ':\\n' + value.textContent.trim() + '\\n\\n';
          }}
        }});
        // Also try the older format
        const fields = container.querySelectorAll('.sb-copy-field');
        fields.forEach(field => {{
          const label = field.querySelector('.sb-copy-field-label');
          const value = field.querySelector('.sb-copy-field-value');
          if (label && value) {{
            text += label.textContent.trim() + ':\\n' + value.textContent.trim() + '\\n\\n';
          }}
        }});
        navigator.clipboard.writeText(text.trim()).then(() => {{
          const btn = container.querySelector('.sb-manual-copy-all, .sb-copy-all-btn');
          if (btn) {{
            btn.classList.add('copied');
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => {{
              btn.textContent = orig;
              btn.classList.remove('copied');
            }}, 2000);
          }}
        }});
      }}

      // Toggle report row in table
      function toggleManualHelper(rowId) {{
        const row = document.getElementById(rowId);
        const icon = document.getElementById(rowId + '_icon');
        if (!row) return;
        if (row.style.display === 'none') {{
          row.style.display = 'table-row';
          if (icon) icon.style.transform = 'rotate(90deg)';
        }} else {{
          row.style.display = 'none';
          if (icon) icon.style.transform = 'rotate(0deg)';
        }}
      }}

      // ==========================================
      // TWO-STAGE MANUAL SUBMISSION MODAL
      // ==========================================
      let currentPanelId = null;
      let currentPlatformId = null;
      let pendingMarkDone = null;

      // Open modal (Stage 1: Platform List)
      function openManualModal(panelId) {{
        currentPanelId = panelId;
        const overlay = document.getElementById(panelId + '_overlay');
        const modal = document.getElementById(panelId + '_modal');
        if (overlay && modal) {{
          overlay.classList.add('open');
          modal.classList.add('open');
          modal.classList.remove('expanded');
          document.body.style.overflow = 'hidden';
          // Hide all detail views
          modal.querySelectorAll('.sb-platform-detail').forEach(d => d.classList.remove('active'));
        }}
      }}

      // Close modal completely
      function closeManualModal(panelId) {{
        panelId = panelId || currentPanelId;
        const overlay = document.getElementById(panelId + '_overlay');
        const modal = document.getElementById(panelId + '_modal');
        if (overlay) overlay.classList.remove('open');
        if (modal) {{
          modal.classList.remove('open');
          modal.classList.remove('expanded');
        }}
        document.body.style.overflow = '';
        currentPlatformId = null;
      }}

      // Expand to show platform detail (Stage 2)
      function showPlatformDetail(panelId, platformId) {{
        currentPlatformId = platformId;
        const modal = document.getElementById(panelId + '_modal');
        if (!modal) return;

        // Expand modal
        modal.classList.add('expanded');

        // Hide all details, show selected
        modal.querySelectorAll('.sb-platform-detail').forEach(d => d.classList.remove('active'));
        const detail = document.getElementById(platformId + '_detail');
        if (detail) detail.classList.add('active');

        // Update header title
        const titleEl = document.getElementById(panelId + '_title');
        const platform = detail?.dataset.platform || '';
        if (titleEl) titleEl.textContent = platform.toUpperCase();
      }}

      // Back to platform list (Stage 1)
      function backToList(panelId) {{
        const modal = document.getElementById(panelId + '_modal');
        if (!modal) return;

        modal.classList.remove('expanded');
        modal.querySelectorAll('.sb-platform-detail').forEach(d => d.classList.remove('active'));
        currentPlatformId = null;

        // Reset header title
        const titleEl = document.getElementById(panelId + '_title');
        if (titleEl) titleEl.textContent = 'Manual Submissions';
      }}

      // Copy field with visual feedback
      function copyFieldValue(fieldId, btnId) {{
        const field = document.getElementById(fieldId);
        const btn = document.getElementById(btnId);
        if (!field) return;

        const text = field.textContent.trim();
        navigator.clipboard.writeText(text).then(() => {{
          // Mark field as copied
          const fieldContainer = field.closest('.sb-field');
          if (fieldContainer) fieldContainer.classList.add('copied');

          // Update button
          if (btn) {{
            btn.innerHTML = '&#10003; Copied';
            setTimeout(() => {{
              btn.innerHTML = 'Copy';
            }}, 2000);
          }}

          // Update progress
          updateFieldProgress();
        }}).catch(err => {{
          console.error('Copy failed:', err);
          sbToast('Failed to copy. Please select and copy manually.', 'error');
        }});
      }}

      // Update field copy progress counter
      function updateFieldProgress() {{
        document.querySelectorAll('.sb-platform-detail.active').forEach(detail => {{
          const totalFields = detail.querySelectorAll('.sb-field').length;
          const copiedFields = detail.querySelectorAll('.sb-field.copied').length;
          const progressEl = detail.querySelector('.sb-detail-fields-progress');
          if (progressEl) {{
            progressEl.textContent = `${{copiedFields}}/${{totalFields}} copied`;
          }}
        }});
      }}

      // Show confirmation dialog
      function showConfirmDialog(platformId, platform, domainId) {{
        const panelId = platformId.replace(/_platform_\d+$/, '');
        const csrf = document.querySelector('input[name="csrf"]')?.value || '';
        pendingMarkDone = {{ platformId, platform, domainId, csrf, panelId }};

        const dialog = document.getElementById(panelId + '_confirm');
        const platformEl = document.getElementById(panelId + '_confirm_platform');
        if (dialog && platformEl) {{
          platformEl.textContent = platform.toUpperCase();
          dialog.classList.add('open');
        }}
      }}

      // Hide confirmation dialog
      function hideConfirmDialog(panelId) {{
        panelId = panelId || (pendingMarkDone && pendingMarkDone.panelId);
        if (panelId) {{
          const dialog = document.getElementById(panelId + '_confirm');
          if (dialog) dialog.classList.remove('open');
        }}
        pendingMarkDone = null;
      }}

      // Confirm and mark as done
      async function confirmMarkDone(panelId) {{
        if (!pendingMarkDone) return;
        const {{ platformId, platform, domainId, csrf }} = pendingMarkDone;

        const confirmBtn = document.querySelector('#' + panelId + '_confirm .sb-btn-success');
        if (confirmBtn) {{
          confirmBtn.disabled = true;
          confirmBtn.textContent = 'Submitting...';
        }}

        try {{
          const formData = new FormData();
          formData.append('csrf', csrf);
          formData.append('note', 'Manually submitted via dashboard');
          formData.append('platform', platform);

          const response = await fetch(`/admin/domains/${{domainId}}/manual_done`, {{
            method: 'POST',
            body: formData,
          }});

          if (response.ok || response.redirected) {{
            // Mark list item as done
            const listItem = document.getElementById(platformId);
            if (listItem) {{
              listItem.classList.add('done');
              const statusEl = listItem.querySelector('.sb-platform-list-status');
              if (statusEl) statusEl.textContent = 'Submitted';
              const iconEl = listItem.querySelector('.sb-platform-list-icon');
              if (iconEl) iconEl.textContent = '&#10003;';
            }}

            // Go back to list
            backToList(panelId);
            updateModalProgress(panelId);

            // Check if all done
            const modal = document.getElementById(panelId + '_modal');
            const pendingItems = modal ? modal.querySelectorAll('.sb-platform-list-item:not(.done)') : [];
            if (pendingItems.length === 0) {{
              setTimeout(() => {{
                closeManualModal(panelId);
                const notifyBar = document.getElementById(panelId + '_notify');
                if (notifyBar) notifyBar.style.display = 'none';
                const url = new URL(window.location);
                url.searchParams.delete('manual_pending');
                window.history.replaceState({{}}, '', url);
              }}, 600);
            }}
          }} else {{
            sbToast('Failed to mark as submitted. Please try again.', 'error');
          }}
        }} catch (err) {{
          console.error('Error:', err);
          sbToast('Failed to mark as submitted. Please try again.', 'error');
        }} finally {{
          hideConfirmDialog(panelId);
          if (confirmBtn) {{
            confirmBtn.disabled = false;
            confirmBtn.textContent = "Yes, I've Submitted";
          }}
        }}
      }}

      // Update modal progress counter
      function updateModalProgress(panelId) {{
        const modal = document.getElementById(panelId + '_modal');
        if (!modal) return;
        const totalItems = modal.querySelectorAll('.sb-platform-list-item').length;
        const doneItems = modal.querySelectorAll('.sb-platform-list-item.done').length;
        const pending = totalItems - doneItems;

        const progressEl = document.getElementById(panelId + '_progress');
        if (progressEl) {{
          progressEl.textContent = `${{pending}} of ${{totalItems}} pending`;
        }}

        const notifyBar = document.getElementById(panelId + '_notify');
        if (notifyBar) {{
          const textEl = notifyBar.querySelector('.sb-notify-bar-text');
          if (textEl && pending > 0) {{
            textEl.innerHTML = `<strong>Action Required:</strong> ${{pending}} platform${{pending > 1 ? 's' : ''}} need manual submission`;
          }}
        }}
      }}

      // Keyboard handlers
      document.addEventListener('keydown', function(e) {{
        if (e.key === 'Escape') {{
          // Close confirm dialog first if open
          if (pendingMarkDone && pendingMarkDone.panelId) {{
            const dialog = document.getElementById(pendingMarkDone.panelId + '_confirm');
            if (dialog && dialog.classList.contains('open')) {{
              hideConfirmDialog(pendingMarkDone.panelId);
              return;
            }}
          }}
          // If expanded, go back to list
          if (currentPanelId) {{
            const modal = document.getElementById(currentPanelId + '_modal');
            if (modal && modal.classList.contains('expanded')) {{
              backToList(currentPanelId);
              return;
            }}
          }}
          if (currentPanelId) {{
            closeManualModal(currentPanelId);
          }}
        }}
      }});

      // Auto-open modal if manual_pending is in URL
      document.addEventListener('DOMContentLoaded', function() {{
        const params = new URLSearchParams(window.location.search);
        if (params.has('manual_pending')) {{
          // Find the notification bar and extract panel ID
          const notifyBar = document.querySelector('.sb-notify-bar');
          if (notifyBar && notifyBar.id) {{
            const panelId = notifyBar.id.replace('_notify', '');
            openManualModal(panelId);
          }}
        }}
      }});
    </script>
  </head>
  <body>
    <div id="sb-toast-container" class="sb-toast-container" aria-live="polite"></div>
    <div class="sb-container">
      <header class="sb-header">
        <div class="sb-brand">
          <a class="sb-logo" href="{"/admin" if admin else "/"}">
            <div class="sb-logo-icon">SB</div>
            <span class="sb-logo-text">SeedBuster</span>
          </a>
          <span class="sb-mode {mode_class}">{mode_indicator}</span>
        </div>
        <nav class="sb-nav">{nav}</nav>
      </header>
      {body}
      <footer class="sb-footer">
        <span>SeedBuster Phishing Detection Pipeline</span>
        <span>{("admin" if admin else "public")} view</span>
      </footer>
    </div>
  </body>
</html>
"""


def _flash(msg: str | None, *, error: bool = False) -> str:
    if not msg:
        return ""
    cls = "sb-flash sb-flash-error" if error else "sb-flash sb-flash-success"
    icon = "&#10005;" if error else "&#10003;"
    return f'<div class="{cls}"><span>{icon}</span><span>{_escape(msg)}</span></div>'


def _build_query_link(base: str, **params: object) -> str:
    clean = {k: v for k, v in params.items() if v not in (None, "", [], False)}
    if not clean:
        return base
    return f"{base}?{urlencode(clean, doseq=True)}"


def _render_stats(stats: dict, *, admin: bool) -> str:
    by_status = stats.get("by_status") or {}
    by_verdict = stats.get("by_verdict") or {}
    by_reports = stats.get("reports") or {}
    by_actions = stats.get("dashboard_actions") or {}

    def _breakdown(items: dict) -> str:
        if not items:
            return '<div class="sb-muted">No data</div>'
        parts = []
        for k in sorted(items.keys()):
            parts.append(
                f'<div class="sb-breakdown-item">'
                f'<span class="sb-breakdown-key">{_escape(k)}</span>'
                f'<span class="sb-breakdown-val">{_escape(items[k])}</span>'
                f'</div>'
            )
        return f'<div class="sb-breakdown">{"".join(parts)}</div>'

    reports_section = (
        ""
        if not admin
        else f"""
        <div class="col-4">
          <div class="sb-stat">
            <div class="sb-stat-label">Reports</div>
            {_breakdown(by_reports)}
          </div>
        </div>
        """
    )

    actions_section = (
        ""
        if not admin
        else f"""
        <div class="col-4">
          <div class="sb-stat">
            <div class="sb-stat-label">Dashboard Actions</div>
            {_breakdown(by_actions)}
          </div>
        </div>
        """
    )

    evidence_section = (
        ""
        if not admin
        else f"""
        <div class="col-4">
          <div class="sb-stat">
            <div class="sb-stat-label">Evidence Storage</div>
            <div class="sb-stat-value">{_escape(_format_bytes(stats.get("evidence_bytes", 0)))}</div>
            <div class="sb-stat-meta">Approximate size of evidence directory</div>
          </div>
        </div>
        """
    )

    return f"""
      <div class="sb-grid" style="margin-bottom: 24px;">
        <div class="col-4">
          <div class="sb-stat">
            <div class="sb-stat-label">Total Domains</div>
            <div class="sb-stat-value">{_escape(stats.get("total", 0))}</div>
            <div class="sb-stat-meta">Last 24h: <b>{_escape(stats.get("last_24h", 0))}</b></div>
          </div>
        </div>
        <div class="col-4">
          <div class="sb-stat">
            <div class="sb-stat-label">By Status</div>
            {_breakdown(by_status)}
          </div>
        </div>
        <div class="col-4">
          <div class="sb-stat">
            <div class="sb-stat-label">By Verdict</div>
            {_breakdown(by_verdict)}
          </div>
        </div>
        {reports_section}
        {actions_section}
        {evidence_section}
      </div>
    """


def _render_health(health_url: str, health: dict | None) -> str:
    if not health_url:
        return ""

    status_line = "Unknown"
    details = ""
    if health:
        if health.get("ok"):
            status_line = "Healthy"
        else:
            status_line = "Unhealthy"
        data = health.get("data") or {}
        queue_bits = []
        for key in ("discovery_queue_size", "analysis_queue_size", "pending_rescans", "domains_tracked"):
            if isinstance(data, dict) and key in data:
                queue_bits.append(f"{key.replace('_', ' ')}: {data.get(key)}")
        if queue_bits:
            details = "<br/>".join(_escape(bit) for bit in queue_bits)
        elif health.get("error"):
            details = _escape(health.get("error"))

    return f"""
      <div class="sb-panel" id="health-panel" data-url="{_escape(health_url)}" style="border-color: rgba(88, 166, 255, 0.2);">
        <div class="sb-panel-header" style="border-bottom: 1px solid var(--border-subtle);">
          <span class="sb-panel-title">Health</span>
          <a class="sb-link" href="{_escape(health_url)}" target="_blank" rel="noreferrer">View healthz</a>
        </div>
        <div id="health-status"><b>{_escape(status_line)}</b></div>
        <div class="sb-muted" id="health-details">{details or "Best-effort link to the pipeline health endpoint (if enabled)."}</div>
      </div>
    """

def _render_domains_section(
    domains: list[dict],
    *,
    admin: bool,
    total: int,
    status: str,
    verdict: str,
    q: str,
    limit: int,
    page: int,
    include_dangerous: bool = False,
) -> str:
    action = "/admin" if admin else "/"
    total_count = total or len(domains)
    limit_safe = max(1, limit or 1)
    total_pages = max(1, (total_count + limit_safe - 1) // limit_safe)
    page_display = max(1, min(page, total_pages))
    can_prev = page_display > 1
    can_next = page_display < total_pages

    def _render_status_options() -> str:
        options: list[str] = []
        for value in STATUS_FILTER_OPTIONS:
            if value == "dangerous" and not include_dangerous:
                continue
            label = "All Statuses" if value == "" else ("Dangerous Only" if value == "dangerous" else value)
            options.append(
                f'<option value="{_escape(value)}" {"selected" if status == value else ""}>{_escape(label)}</option>'
            )
        return "".join(options)

    def _render_verdict_options() -> str:
        options: list[str] = []
        for value in VERDICT_FILTER_OPTIONS:
            label = "All Verdicts" if value == "" else value
            options.append(
                f'<option value="{_escape(value)}" {"selected" if verdict == value else ""}>{_escape(label)}</option>'
            )
        return "".join(options)

    def _render_domain_rows() -> str:
        if not domains:
            col_span = 8 if admin else 7
            return (
                f'<tr><td colspan="{col_span}" class="sb-muted" style="text-align: center; padding: 20px;">'
                "No domains found matching your criteria."
                "</td></tr>"
            )

        rows = []
        for d in domains:
            did = d.get("id")
            domain = d.get("domain") or ""
            href = f"/admin/domains/{did}" if admin else f"/domains/{did}"
            domain_score = d.get("domain_score")
            analysis_score = d.get("analysis_score")

            actions_cell = ""
            if admin:
                actions_cell = (
                    f'<td class="sb-muted">'
                    f'<button class="sb-btn sb-btn-ghost js-rescan" data-domain="{_escape(domain)}" data-domain-id="{_escape(did)}">Rescan</button> '
                    f'<button class="sb-btn sb-btn-ghost js-report" data-domain="{_escape(domain)}" data-domain-id="{_escape(did)}">Report</button>'
                    f"</td>"
                )

            rows.append(
                "<tr>"
                f'<td class="domain-cell" title="{_escape(domain)}"><a class="domain-link" href="{_escape(href)}">{_escape(domain)}</a></td>'
                f"<td>{_status_badge(str(d.get('status') or ''))}</td>"
                f"<td>{_verdict_badge(d.get('verdict'))}</td>"
                f'<td><span class="sb-score">{_escape(domain_score) if domain_score is not None else "&mdash;"}</span></td>'
                f'<td><span class="sb-score">{_escape(analysis_score) if analysis_score is not None else "&mdash;"}</span></td>'
                f'<td class="sb-muted">{_escape(d.get("source") or "&mdash;")}</td>'
                f'<td class="sb-muted">{_escape(d.get("first_seen") or "&mdash;")}</td>'
                f"{actions_cell}"
                "</tr>"
            )
        return "".join(rows)

    prev_link = ""
    if can_prev:
        prev_link = _build_query_link(action, status=status, verdict=verdict, q=q, limit=limit, page=page_display - 1)
        prev_link = f'<a class="sb-btn" href="{_escape(prev_link)}">&larr; Previous</a>'

    next_link = ""
    if can_next:
        next_link = _build_query_link(action, status=status, verdict=verdict, q=q, limit=limit, page=page_display + 1)
        next_link = f'<a class="sb-btn" href="{_escape(next_link)}">Next &rarr;</a>'

    return f"""
      <div class="sb-panel">
        <div class="sb-panel-header">
          <span class="sb-panel-title">Tracked Domains</span>
          <span class="sb-muted">Showing {len(domains)} / {total_count} (page {page_display} of {total_pages})</span>
        </div>
        <form method="get" action="{_escape(action)}" style="margin-bottom: 12px;">
          <div class="sb-grid">
            <div class="col-3">
              <label class="sb-label">Status</label>
              <select class="sb-select" name="status">
                {_render_status_options()}
              </select>
            </div>
            <div class="col-3">
              <label class="sb-label">Verdict</label>
              <select class="sb-select" name="verdict">
                {_render_verdict_options()}
              </select>
            </div>
            <div class="col-3">
              <label class="sb-label">Search</label>
              <input class="sb-input" type="text" name="q" value="{_escape(q)}" placeholder="domain contains..." />
            </div>
            <div class="col-3">
              <label class="sb-label">Results</label>
              <div class="sb-row">
                <select class="sb-select" name="limit" style="width: auto; flex: 1;">
                  {''.join(
                      f'<option value="{n}" {"selected" if limit == n else ""}>{n}</option>'
                      for n in (25, 50, 100, 200, 500)
                  )}
                </select>
                <input class="sb-input" type="text" name="page" value="{_escape(page)}" style="width: 60px; flex: 0 0 auto; text-align: center;" />
              </div>
            </div>
            <div class="col-12" style="display:flex;gap:12px;padding-top:8px;">
              <button class="sb-btn sb-btn-primary" type="submit">Apply Filters</button>
              <a class="sb-btn" href="{_escape(action)}">Reset</a>
            </div>
          </div>
        </form>
        <div class="sb-table-wrap">
          <table class="sb-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>D-Score</th>
                <th>A-Score</th>
                <th>Source</th>
                <th>First Seen</th>
                { '<th>Actions</th>' if admin else '' }
              </tr>
            </thead>
            <tbody>
              {_render_domain_rows()}
            </tbody>
          </table>
        </div>
        <div class="sb-pagination">
          <div class="sb-page-info">Page {page_display} of {total_pages}</div>
          <div class="sb-row">
            {prev_link}
            {next_link}
          </div>
        </div>
      </div>
    """


def _render_pending_reports(pending: list[dict], *, admin: bool, limit: int = 50) -> str:
    if not pending:
        return ""
    rows = []
    for r in pending[:limit]:
        domain = r.get("domain") or ""
        did = r.get("domain_id")
        href = f"/admin/domains/{did}" if admin else f"/domains/{did}"
        platform = r.get("platform") or ""
        status = r.get("status") or ""
        next_attempt_at = r.get("next_attempt_at") or ""
        rows.append(
            "<tr>"
            f'<td><a class="domain-link" href="{_escape(href)}">{_escape(domain)}</a></td>'
            f"<td>{_escape(platform)}</td>"
            f"<td>{_report_badge(str(status))}</td>"
            f'<td class="sb-muted">{_escape(next_attempt_at) or "&mdash;"}</td>'
            "</tr>"
        )

    return f"""
      <div class="sb-panel" style="border-color: rgba(240, 136, 62, 0.3); margin-bottom: 24px;">
        <div class="sb-panel-header" style="border-color: rgba(240, 136, 62, 0.2);">
          <span class="sb-panel-title" style="color: var(--accent-orange);">&#9888; Reports Needing Attention</span>
          <span class="sb-muted">showing {min(len(pending), limit)} of {len(pending)}</span>
        </div>
        <div class="sb-table-wrap">
          <table class="sb-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Platform</th>
                <th>Status</th>
                <th>Next Attempt</th>
              </tr>
            </thead>
            <tbody>
              {''.join(rows)}
            </tbody>
          </table>
        </div>
      </div>
    """


def _render_cluster_info(cluster: dict | None, related_domains: list[dict], admin: bool) -> str:
    """Render threat campaign info panel for domain detail page."""
    if not cluster:
        return ""

    cluster_name = cluster.get("name", "Unknown Campaign")
    cluster_id = cluster.get("cluster_id", "")
    confidence = cluster.get("confidence", 0)
    shared_backends = list(cluster.get("shared_backends", []))
    shared_kits = list(cluster.get("shared_kits", []))
    shared_nameservers = list(cluster.get("shared_nameservers", []))

    # Related domains list - make them clickable links
    related_html = ""
    if related_domains:
        base_url = "/admin/domains" if admin else "/domains"
        visible_items = []
        hidden_items = []

        for i, member in enumerate(related_domains):
            domain = member.get("domain", "")
            domain_id = member.get("id")
            score = member.get("score", 0)
            # Link directly to domain detail page if we have the ID
            if domain_id:
                href = f"{base_url}/{domain_id}"
            else:
                # Fallback to search if ID not found
                fallback_url = "/admin" if admin else "/"
                href = f"{fallback_url}?q={quote(domain)}"
            item_html = (
                f'<div class="sb-breakdown-item">'
                f'<a href="{_escape(href)}" class="sb-breakdown-key" style="color: var(--text-link);">{_escape(domain)}</a>'
                f'<span class="sb-score">{_escape(score)}</span>'
                f'</div>'
            )
            if i < 10:
                visible_items.append(item_html)
            else:
                hidden_items.append(item_html)

        related_html = f'<div class="sb-breakdown">{"".join(visible_items)}</div>'

        if hidden_items:
            related_html += f'''
              <details style="margin-top: 8px;">
                <summary class="sb-muted" style="cursor: pointer; padding: 8px 0; font-size: 12px;">
                  + {len(hidden_items)} more domains
                </summary>
                <div class="sb-breakdown" style="margin-top: 8px;">{"".join(hidden_items)}</div>
              </details>
            '''
    else:
        related_html = '<div class="sb-muted">No other domains in this campaign yet.</div>'

    # Shared indicators - vertical layout with expandable lists
    def render_indicator_list(label: str, items: list) -> str:
        if not items:
            return ""
        visible = items[:3]
        hidden = items[3:]

        visible_html = "".join(
            f'<code class="sb-code" style="display: inline-block; margin: 2px 4px 2px 0;">{_escape(item)}</code>'
            for item in visible
        )

        if hidden:
            hidden_html = "".join(
                f'<code class="sb-code" style="display: inline-block; margin: 2px 4px 2px 0;">{_escape(item)}</code>'
                for item in hidden
            )
            return f'''
              <div style="margin-bottom: 12px;">
                <div class="sb-label" style="margin-bottom: 6px;">{_escape(label)}</div>
                <div>{visible_html}</div>
                <details style="margin-top: 4px;">
                  <summary class="sb-muted" style="cursor: pointer; font-size: 11px;">+ {len(hidden)} more</summary>
                  <div style="margin-top: 4px;">{hidden_html}</div>
                </details>
              </div>
            '''
        else:
            return f'''
              <div style="margin-bottom: 12px;">
                <div class="sb-label" style="margin-bottom: 6px;">{_escape(label)}</div>
                <div>{visible_html}</div>
              </div>
            '''

    indicators_html = ""
    indicators_html += render_indicator_list("Backends", shared_backends)
    indicators_html += render_indicator_list("Kits", shared_kits)
    indicators_html += render_indicator_list("Nameservers", shared_nameservers)

    if not indicators_html:
        indicators_html = '<div class="sb-muted">No shared indicators.</div>'

    # Confidence badge color
    if confidence >= 70:
        conf_class = "sb-badge-high"
    elif confidence >= 40:
        conf_class = "sb-badge-medium"
    else:
        conf_class = "sb-badge-low"

    clusters_link = "/admin/clusters" if admin else "/campaigns"
    confidence_display = f"{confidence:.0f}% confidence"

    return f"""
      <div class="sb-panel" style="border-color: rgba(163, 113, 247, 0.3); margin-bottom: 16px;">
        <div class="sb-panel-header" style="border-color: rgba(163, 113, 247, 0.2);">
          <div>
            <span class="sb-panel-title" style="color: var(--accent-purple);">Threat Campaign</span>
            <a href="{_escape(clusters_link)}" class="sb-muted" style="margin-left: 12px; font-size: 12px;">View all campaigns &rarr;</a>
          </div>
          <span class="sb-badge {conf_class}">{_escape(confidence_display)}</span>
        </div>
        <div class="sb-grid">
          <div class="col-6">
            <div style="margin-bottom: 16px;">
              <div class="sb-label">Campaign Name</div>
              <div style="font-size: 16px; font-weight: 600; color: var(--text-primary);">{_escape(cluster_name)}</div>
              <div class="sb-muted" style="font-size: 12px; margin-top: 4px;">ID: <code class="sb-code">{_escape(cluster_id)}</code></div>
            </div>
            <div>
              <div class="sb-label">Shared Indicators</div>
              {indicators_html}
            </div>
          </div>
          <div class="col-6">
            <div class="sb-label">Related Domains ({len(related_domains)} linked)</div>
            {related_html}
          </div>
        </div>
      </div>
    """


def _render_clusters_list(clusters: list[dict], admin: bool, q: str = "") -> str:
    """Render the threat campaigns listing page."""
    search = (q or "").strip().lower()
    filtered: list[dict] = []
    for cluster in clusters:
        if not search:
            filtered.append(cluster)
            continue
        name = str(cluster.get("name") or cluster.get("cluster_id") or "").lower()
        cid = str(cluster.get("cluster_id") or "").lower()
        member_hit = any(search in (m.get("domain", "").lower()) for m in cluster.get("members", []))
        if search in name or search in cid or member_hit:
            filtered.append(cluster)

    total_count = len(clusters)
    display_count = len(filtered)
    action_href = "/admin/clusters" if admin else "/campaigns"

    search_form = f"""
      <form class="sb-row" method="get" action="{_escape(action_href)}" style="gap: 10px; margin-bottom: 12px; flex-wrap: wrap;">
        <input class="sb-input" type="text" name="q" value="{_escape(q)}" placeholder="Search campaigns" style="flex: 1; min-width: 260px;" />
        <button class="sb-btn sb-btn-primary" type="submit">Search</button>
        {f'<a class="sb-btn" href="{_escape(action_href)}">Reset</a>' if search else ''}
      </form>
    """

    if not filtered:
        empty_state = "No campaigns match your search." if search else "No threat campaigns identified yet."
        return f"""
          <div class="sb-panel" style="margin-bottom: 16px;">
            <div class="sb-panel-header">
              <span class="sb-panel-title" style="color: var(--accent-purple);">Threat Campaigns</span>
              <span class="sb-muted">{total_count} campaign(s)</span>
            </div>
            <div class="sb-muted" style="margin-bottom: 12px;">
              Threat campaigns group related phishing sites that share common infrastructure like backends, phishing kits, or nameservers.
            </div>
            {search_form}
            <div class="sb-muted" style="padding: 16px 0;">{_escape(empty_state)}</div>
          </div>
        """

    cluster_cards = []
    for cluster in filtered:
        cluster_id = cluster.get("cluster_id", "")
        cluster_name = cluster.get("name", "") or cluster_id or "Unknown Campaign"
        members = cluster.get("members", []) or []
        member_count = len(members)
        shared_backends = cluster.get("shared_backends", []) or []
        shared_kits = cluster.get("shared_kits", []) or []
        shared_nameservers = cluster.get("shared_nameservers", []) or []

        detail_href = f"/admin/clusters/{cluster_id}" if admin else f"/campaigns/{cluster_id}"

        # Members preview (first 3)
        member_items: list[str] = []
        for member in members[:3]:
            domain = member.get("domain", "")
            added_at = (member.get("added_at") or "")[:10]
            domain_id = member.get("id")
            href = f"/admin/domains/{domain_id}" if (admin and domain_id) else (f"/domains/{domain_id}" if domain_id else "")
            if not href:
                href = f"/admin?q={quote(domain)}" if admin else f"/?q={quote(domain)}"
            meta_html = _escape(added_at) if added_at else "&nbsp;"
            member_items.append(
                f'<div class="sb-breakdown-item">'
                f'<a href="{_escape(href)}" class="sb-breakdown-key" style="color: var(--text-link);">{_escape(domain)}</a>'
                f'<span class="sb-muted">{meta_html}</span>'
                f"</div>"
            )

        indicators = (shared_backends or []) + (shared_nameservers or []) + (shared_kits or [])
        indicator_chips = "".join(
            f'<code class="sb-code">{_escape(v)}</code>'
            for v in indicators[:3]
        )

        cluster_cards.append(f"""
          <div class="col-6">
            <div class="sb-panel" style="border-color: rgba(163, 113, 247, 0.25); margin: 0;">
              <div class="sb-panel-header" style="border-color: rgba(163, 113, 247, 0.18);">
                <div>
                  <div class="sb-panel-title" style="color: var(--accent-purple);">{_escape(cluster_name)}</div>
                  <div class="sb-muted" style="font-size: 12px;">Campaign ID: <code class="sb-code">{_escape(cluster_id)}</code></div>
                  <div class="sb-muted" style="font-size: 12px;">Members: {member_count}</div>
                </div>
                <a class="sb-btn" href="{_escape(detail_href)}">View</a>
              </div>
              <div class="sb-label">Recent Members</div>
              <div class="sb-breakdown" style="margin-bottom: 8px;">
                {''.join(member_items) if member_items else '<div class="sb-muted">No members yet.</div>'}
              </div>
              {indicator_chips and f'<div class="sb-row" style="flex-wrap: wrap; gap: 6px; margin-top: 8px;">{indicator_chips}</div>' or ''}
            </div>
          </div>
        """)

    return f"""
      <div class="sb-panel" style="margin-bottom: 16px;">
        <div class="sb-panel-header">
          <span class="sb-panel-title" style="color: var(--accent-purple);">Threat Campaigns</span>
          <span class="sb-muted">{display_count} campaign(s){f" of {total_count}" if total_count != display_count else ""}</span>
        </div>
        <div class="sb-muted" style="margin-bottom: 12px;">
          Threat campaigns group related phishing sites that share common infrastructure like backends, phishing kits, or nameservers.
        </div>
        {search_form}
      </div>
      <div class="sb-grid" style="gap: 16px;">
        {"".join(cluster_cards)}
      </div>
    """


def _render_cluster_detail(cluster: dict, admin: bool) -> str:
    """Render the detailed threat campaign page with action buttons."""
    cluster_id = cluster.get("cluster_id", "")
    cluster_name = cluster.get("name", "Unknown Campaign")
    members = cluster.get("members", []) or []
    shared_backends = cluster.get("shared_backends", []) or []
    shared_kits = cluster.get("shared_kits", []) or []
    shared_nameservers = cluster.get("shared_nameservers", []) or []
    shared_asns = cluster.get("shared_asns", []) or []
    actor_id = cluster.get("actor_id", "")
    actor_notes = cluster.get("actor_notes", "")

    # Back button
    back_href = "/admin/clusters" if admin else "/campaigns"

    # Build action buttons (admin only)
    action_buttons = ""
    if admin:
        action_buttons = f"""
          <div class="sb-row" style="flex-wrap: wrap; gap: 8px; margin-top: 8px;">
            <a class="sb-btn" href="/admin/clusters/{_escape(cluster_id)}/pdf">Campaign PDF</a>
            <a class="sb-btn" href="/admin/clusters/{_escape(cluster_id)}/package">Campaign Package</a>
            <form method="post" action="/admin/clusters/{_escape(cluster_id)}/preview" style="display: inline;">
              <input type="hidden" name="csrf" value="__SET_COOKIE__" />
              <button type="submit" class="sb-btn">Preview Reports</button>
            </form>
            <form method="post" action="/admin/clusters/{_escape(cluster_id)}/submit" style="display: inline;">
              <input type="hidden" name="csrf" value="__SET_COOKIE__" />
              <button type="submit" class="sb-btn sb-btn-danger">Submit All Reports</button>
            </form>
          </div>
        """

    # Actor attribution
    actor_html = ""
    if actor_id or actor_notes:
        actor_html = f"""
          <div class="sb-panel" style="margin-bottom: 16px; border-color: rgba(245, 158, 11, 0.3);">
            <div class="sb-label" style="color: var(--accent-yellow);">Threat Actor Attribution</div>
            <div class="sb-code" style="margin-bottom: 8px;">{_escape(actor_id) if actor_id else '(unattributed)'}</div>
            <div class="sb-muted">{_escape(actor_notes)}</div>
          </div>
        """

    # Shared indicators (chips with +more)
    def render_indicator(label: str, values: list[str]) -> str:
        if not values:
            return ""
        visible = values[:6]
        chips = "".join(
            f'<code class="sb-code" style="display: inline-block; margin: 2px 4px 2px 0;">{_escape(v)}</code>'
            for v in visible
        )
        remainder = len(values) - len(visible)
        more = f'<span class="sb-muted" style="font-size: 12px;">+{remainder} more</span>' if remainder > 0 else ""
        return (
            f'<div style="margin-right: 16px; margin-bottom: 8px;">'
            f'<div class="sb-muted" style="font-size: 12px; margin-bottom: 4px;">{_escape(label)}</div>'
            f'<div>{chips}{more}</div>'
            f"</div>"
        )

    indicators_html = "".join([
        render_indicator("Backends", shared_backends),
        render_indicator("Kits", shared_kits),
        render_indicator("Nameservers", shared_nameservers),
        render_indicator("ASNs", shared_asns),
    ])
    if not indicators_html:
        indicators_html = '<div class="sb-muted">No shared indicators.</div>'

    # Related/member domains list (read-only)
    visible_members = members[:12]
    hidden_members = members[12:]
    member_items: list[str] = []
    for member in visible_members:
        domain = member.get("domain", "")
        status = member.get("status")
        verdict = member.get("verdict")
        score = member.get("score")
        added = (member.get("added_at") or "")[:10]
        ip = member.get("ip_address") or ""
        domain_id = member.get("id")
        href = f"/admin/domains/{domain_id}" if (admin and domain_id) else (f"/domains/{domain_id}" if domain_id else "")
        if not href:
            href = f"/admin?q={quote(domain)}" if admin else f"/?q={quote(domain)}"
        badges = []
        if status:
            badges.append(_status_badge(str(status)))
        if verdict:
            badges.append(_verdict_badge(str(verdict)))
        score_html = f'<span class="sb-score">{_escape(score)}</span>' if score is not None else ""
        meta = " ".join(badges + [score_html]) if (badges or score_html) else ""
        footer_parts = []
        if added:
            footer_parts.append(f'<span class="sb-muted">Added { _escape(added)}</span>')
        if ip:
            footer_parts.append(f'<span class="sb-muted">IP { _escape(ip)}</span>')
        footer = " \u2022 ".join(footer_parts) if footer_parts else ""
        meta_display = meta if meta else '<span class="sb-muted">&mdash;</span>'
        footer_html = f'<div class="sb-muted" style="font-size: 12px; margin-top: 2px;">{footer}</div>' if footer else ""
        member_items.append(
            f'<div class="sb-breakdown-item">'
            f'<a href="{_escape(href)}" class="sb-breakdown-key" style="color: var(--text-link);">{_escape(domain)}</a>'
            f'<div class="sb-row" style="gap: 8px; flex-wrap: wrap; align-items: center;">{meta_display}</div>'
            f'{footer_html}'
            f"</div>"
        )

    related_html = f'<div class="sb-breakdown">{"".join(member_items)}</div>' if member_items else '<div class="sb-muted">No related domains yet.</div>'
    if hidden_members:
        hidden_items = []
        for member in hidden_members:
            domain = member.get("domain", "")
            score = member.get("score")
            score_badge = f'<span class="sb-score">{_escape(score)}</span>' if score is not None else ""
            hidden_items.append(
                f'<div class="sb-breakdown-item">'
                f'<span class="sb-breakdown-key">{_escape(domain)}</span>'
                f'{score_badge}'
                f"</div>"
            )
        related_html += f"""
          <details style="margin-top: 8px;">
            <summary class="sb-muted" style="cursor: pointer; padding: 8px 0; font-size: 12px;">
              + {len(hidden_members)} more domains
            </summary>
            <div class="sb-breakdown" style="margin-top: 8px;">{"".join(hidden_items)}</div>
          </details>
        """

    # Full table to expose all member data (read-only)
    table_rows = []
    for member in members:
        domain = member.get("domain", "")
        status = member.get("status")
        verdict = member.get("verdict")
        score = member.get("score")
        added = (member.get("added_at") or "")[:10] or "&mdash;"
        ip = member.get("ip_address") or "&mdash;"
        domain_id = member.get("id")
        href = f"/admin/domains/{domain_id}" if (admin and domain_id) else (f"/domains/{domain_id}" if domain_id else "")
        if not href:
            href = f"/admin?q={quote(domain)}" if admin else f"/?q={quote(domain)}"
        table_rows.append(
            "<tr>"
            f'<td><a href="{_escape(href)}" class="sb-code">{_escape(domain)}</a></td>'
            f"<td>{_status_badge(str(status)) if status else '&mdash;'}</td>"
            f"<td>{_verdict_badge(str(verdict)) if verdict else '&mdash;'}</td>"
            f'<td class="sb-text-right">{_escape(score) if score is not None else "&mdash;"}</td>'
            f"<td class=\"sb-muted\">{_escape(added)}</td>"
            f"<td class=\"sb-code\">{_escape(ip)}</td>"
            "</tr>"
        )

    members_table = f"""
      <div class="sb-panel">
        <div class="sb-panel-header">
          <span class="sb-panel-title">All Member Domains ({len(members)})</span>
        </div>
        <div style="max-height: 420px; overflow-y: auto;">
          <table class="sb-table" style="width: 100%;">
            <thead><tr><th>Domain</th><th>Status</th><th>Verdict</th><th class="sb-text-right">Score</th><th>Added</th><th>IP</th></tr></thead>
            <tbody>{"".join(table_rows)}</tbody>
          </table>
        </div>
      </div>
    """

    return f"""
      <div class="sb-row" style="margin-bottom: 24px; align-items: center; flex-wrap: wrap; gap: 8px;">
        <a class="sb-btn" href="{_escape(back_href)}">&larr; Back to Campaigns</a>
        <h1 style="flex: 1; margin: 0 0 0 12px; font-size: 24px;">{_escape(cluster_name)}</h1>
      </div>

      <div class="sb-panel" style="border-color: rgba(163, 113, 247, 0.3); margin-bottom: 16px;">
        <div class="sb-panel-header" style="border-color: rgba(163, 113, 247, 0.2);">
          <div>
            <span class="sb-panel-title" style="color: var(--accent-purple);">Threat Campaign</span>
            <span class="sb-muted" style="margin-left: 10px; font-size: 12px;">ID: <code class="sb-code">{_escape(cluster_id)}</code></span>
          </div>
          {action_buttons}
        </div>
        <div class="sb-grid" style="align-items: flex-start;">
          <div class="col-8">
            <div class="sb-label">Campaign Name</div>
            <div style="font-size: 20px; font-weight: 700; margin-top: 4px;">{_escape(cluster_name)}</div>
          </div>
          <div class="col-4">
            <div class="sb-label">Members</div>
            <div style="font-size: 20px; font-weight: 600; margin-top: 4px;">{len(members)}</div>
          </div>
        </div>
        <div style="margin-top: 12px;">
          <div class="sb-label">Shared Indicators</div>
          <div class="sb-row" style="flex-wrap: wrap; gap: 8px; align-items: flex-start; margin-top: 6px;">
            {indicators_html}
          </div>
        </div>
      </div>

      {actor_html}

      <div class="sb-panel" style="margin-bottom: 16px;">
        <div class="sb-panel-header">
          <span class="sb-panel-title">Related Domains</span>
          <span class="sb-muted">{len(members)} total</span>
        </div>
        {related_html}
      </div>

      {members_table}
    """


def _render_kv_table(items: Iterable[tuple[str, object]]) -> str:
    rows = []
    for k, v in items:
        value = "" if v is None else str(v)
        rows.append(f"<tr><th>{_escape(k)}</th><td>{_escape(value) or '&mdash;'}</td></tr>")
    return f"""
      <div class="sb-panel">
        <table class="sb-kv-table" style="width: 100%;">
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    """


def _render_manual_helper(report: dict, helper_id: str) -> str:
    """Render the manual submission helper UI for a MANUAL_REQUIRED report."""
    # Parse response_data from JSON if it's a string (from database)
    response_data = report.get("response_data")
    if isinstance(response_data, str):
        try:
            response_data = json.loads(response_data)
        except (json.JSONDecodeError, TypeError):
            response_data = {}
    response_data = response_data or {}

    manual_fields = response_data.get("manual_fields")
    platform = report.get("platform", "unknown")

    if not manual_fields:
        # Fallback: parse the plain text message and create a basic UI
        msg = report.get("response") or report.get("message") or ""
        # Try to extract URL from the message
        import re
        url_match = re.search(r'https?://[^\s<>"]+', msg)
        form_url = url_match.group(0) if url_match else ""

        return f"""
          <div id="{helper_id}" class="sb-manual-helper">
            <div class="sb-manual-helper-header">
              <div class="sb-manual-helper-title">{_escape(platform.upper())} Manual Submission</div>
            </div>
            {f'''<div class="sb-manual-cta">
              <a class="sb-manual-cta-btn" href="{_escape(form_url)}" target="_blank" rel="noreferrer">
                <span class="sb-manual-cta-icon">&nearr;</span>
                <span>Open Abuse Form</span>
              </a>
            </div>''' if form_url else ''}
            <div class="sb-copy-field">
              <div class="sb-copy-field-label">Report Details</div>
              <div id="{helper_id}_fallback" class="sb-copy-field-value multiline">{_escape(msg)}</div>
              <button type="button" id="{helper_id}_fallback_btn" class="sb-copy-btn" onclick="copyField('{helper_id}_fallback', '{helper_id}_fallback_btn')">Copy</button>
            </div>
          </div>
        """

    form_url = manual_fields.get("form_url", "")
    reason = manual_fields.get("reason", "")
    fields = manual_fields.get("fields", [])
    notes = manual_fields.get("notes", [])

    # Determine if this is an email (mailto:) or web form
    is_email = form_url.startswith("mailto:")
    open_btn_text = "Open Email Client" if is_email else "Open Abuse Form"
    open_btn_icon = "&#9993;" if is_email else "&nearr;"

    # Render the CTA button
    cta_html = ""
    if form_url:
        cta_html = f"""
          <div class="sb-manual-cta">
            <a class="sb-manual-cta-btn" href="{_escape(form_url)}" target="_blank" rel="noreferrer">
              <span class="sb-manual-cta-icon">{open_btn_icon}</span>
              <span>{open_btn_text}</span>
            </a>
            <button type="button" class="sb-manual-copy-all" onclick="copyAllFields('{helper_id}')">
              Copy All Fields
            </button>
          </div>
        """

    # Render fields in a 2-column grid for short fields, full width for long ones
    field_html = []
    for i, f in enumerate(fields):
        field_id = f"{helper_id}_field_{i}"
        btn_id = f"{helper_id}_btn_{i}"
        is_multiline = f.get("multiline", False)
        value = f.get("value", "")
        is_long = is_multiline or len(value) > 60

        field_class = "sb-copy-card sb-copy-card-full" if is_long else "sb-copy-card"
        value_class = "sb-copy-card-value sb-copy-card-value-multi" if is_multiline else "sb-copy-card-value"

        field_html.append(f"""
          <div class="{field_class}">
            <div class="sb-copy-card-header">
              <span class="sb-copy-card-label">{_escape(f.get("label", ""))}</span>
              <button type="button" id="{btn_id}" class="sb-copy-card-btn" onclick="copyField('{field_id}', '{btn_id}')">
                <span class="sb-copy-card-btn-text">Copy</span>
              </button>
            </div>
            <div id="{field_id}" class="{value_class}">{_escape(value)}</div>
          </div>
        """)

    # Render notes
    notes_html = ""
    if notes:
        notes_items = "".join(f"<li>{_escape(n)}</li>" for n in notes)
        notes_html = f"""
          <div class="sb-manual-notes">
            <div class="sb-manual-notes-title">Tips</div>
            <ul>{notes_items}</ul>
          </div>
        """

    return f"""
      <div id="{helper_id}" class="sb-manual-helper">
        <div class="sb-manual-helper-header">
          <div class="sb-manual-helper-title">{_escape(platform.upper())} Manual Submission</div>
          {f'<div class="sb-manual-helper-reason">{_escape(reason)}</div>' if reason else ''}
        </div>

        {cta_html}

        <div class="sb-copy-card-grid">
          {''.join(field_html)}
        </div>

        {notes_html}
      </div>
    """


def _render_platform_detail(
    report: dict,
    platform_id: str,
    domain_id: int,
    panel_id: str,
    evidence_base_url: str | None = None,
) -> str:
    """Render the detail view for a single platform with form fields and evidence."""
    # Parse response_data from JSON if it's a string
    response_data = report.get("response_data")
    if isinstance(response_data, str):
        try:
            response_data = json.loads(response_data)
        except (json.JSONDecodeError, TypeError):
            response_data = {}
    response_data = response_data or {}

    manual_fields = response_data.get("manual_fields")
    platform = report.get("platform", "unknown")

    # Get form URL and fields
    if manual_fields:
        form_url = manual_fields.get("form_url", "")
        fields = manual_fields.get("fields", [])
        notes = manual_fields.get("notes", [])
    else:
        # Fallback: extract from plain text
        msg = report.get("response") or report.get("message") or ""
        import re
        url_match = re.search(r'https?://[^\s<>"]+', msg)
        form_url = url_match.group(0) if url_match else ""
        fields = [{"label": "Report Details", "value": msg, "multiline": True}] if msg else []
        notes = []

    # Determine button text
    is_email = form_url.startswith("mailto:") if form_url else False
    open_btn_text = "Open Email Client" if is_email else "Open Abuse Form"
    open_btn_icon = "&#9993;" if is_email else "&nearr;"

    # Render CTA button
    cta_html = ""
    if form_url:
        cta_html = f"""
          <div class="sb-detail-cta">
            <a class="sb-detail-cta-btn" href="{_escape(form_url)}" target="_blank" rel="noreferrer">
              <span>{open_btn_icon}</span>
              {open_btn_text}
            </a>
          </div>
        """

    # Render form fields
    fields_html = []
    for i, f in enumerate(fields):
        field_id = f"{platform_id}_field_{i}"
        btn_id = f"{platform_id}_btn_{i}"
        is_multiline = f.get("multiline", False)
        value = f.get("value", "")
        value_class = "sb-field-value multiline" if is_multiline else "sb-field-value"

        fields_html.append(f"""
          <div class="sb-field">
            <div class="sb-field-header">
              <span class="sb-field-label">{_escape(f.get("label", ""))}</span>
              <button type="button" id="{btn_id}" class="sb-field-copy" onclick="copyFieldValue('{field_id}', '{btn_id}')">Copy</button>
            </div>
            <div id="{field_id}" class="{value_class}">{_escape(value)}</div>
          </div>
        """)

    fields_section = ""
    if fields_html:
        fields_section = f"""
          <div class="sb-detail-fields">
            <div class="sb-detail-fields-header">
              <span class="sb-detail-fields-title">Form Fields</span>
              <span class="sb-detail-fields-progress">0/{len(fields)} copied</span>
            </div>
            {''.join(fields_html)}
          </div>
        """

    # Render notes/tips
    tips_html = ""
    if notes:
        notes_items = "".join(f"<li>{_escape(n)}</li>" for n in notes)
        tips_html = f"""
          <div class="sb-detail-tips">
            <div class="sb-detail-tips-title">Tips</div>
            <ul>{notes_items}</ul>
          </div>
        """

    return f"""
      <div id="{platform_id}_detail" class="sb-platform-detail" data-platform="{_escape(platform)}">
        <div class="sb-detail-header">
          <div class="sb-detail-platform">{_escape(platform.upper())}</div>
          <div class="sb-detail-subtitle">Copy the fields below and paste into the abuse form</div>
        </div>

        {cta_html}
        {fields_section}
        {tips_html}

        <div class="sb-detail-footer">
          <button type="button" class="sb-detail-done-btn" onclick="showConfirmDialog('{platform_id}', '{_escape(platform)}', {domain_id})">
            &#10003; Mark as Submitted
          </button>
        </div>
      </div>
    """


def _render_action_required_panel(
    manual_pending: list[str],
    reports: list[dict],
    domain_id: int,
    evidence_base_url: str | None = None,
) -> str:
    """Render two-stage notification bar + slide-out modal for manual platform submissions."""
    if not manual_pending:
        return ""

    # Build a map of platform -> report
    reports_by_platform: dict[str, dict] = {}
    for r in reports:
        platform = (r.get("platform") or "").lower()
        if platform in manual_pending:
            existing = reports_by_platform.get(platform)
            if not existing or (r.get("status") or "").lower() == "manual_required":
                reports_by_platform[platform] = r

    # Create placeholders for platforms without reports
    for platform in manual_pending:
        if platform not in reports_by_platform:
            reports_by_platform[platform] = {
                "platform": platform,
                "status": "manual_required",
                "response": f"Manual submission required for {platform.upper()}",
            }

    manual_reports = list(reports_by_platform.values())
    if not manual_reports:
        return ""

    panel_id = f"action_required_{domain_id}"
    count = len(manual_reports)
    platform_word = "platform" if count == 1 else "platforms"

    # Platform icons
    platform_icons = {
        "cloudflare": "&#9729;",
        "google": "\U0001f50d",
        "microsoft": "\U0001fa9f",
        "netcraft": "\U0001f6e1",
        "apwg": "\U0001f3a3",
        "phishtank": "\U0001f41f",
        "registrar": "\U0001f4dd",
        "hosting_provider": "\U0001f5a5",
        "digitalocean": "\U0001f30a",
    }

    # Build platform list items and detail views
    list_items = []
    detail_views = []

    for i, r in enumerate(manual_reports):
        platform = (r.get("platform") or "unknown").lower()
        platform_display = platform.upper()
        platform_id = f"{panel_id}_platform_{i}"
        icon = platform_icons.get(platform, "\U0001f4cb")

        # List item
        list_items.append(f"""
          <div id="{platform_id}" class="sb-platform-list-item" onclick="showPlatformDetail('{panel_id}', '{platform_id}')">
            <div class="sb-platform-list-info">
              <div class="sb-platform-list-icon">{icon}</div>
              <div>
                <div class="sb-platform-list-name">{_escape(platform_display)}</div>
                <div class="sb-platform-list-status">Pending</div>
              </div>
            </div>
            <span class="sb-platform-list-arrow">&rarr;</span>
          </div>
        """)

        # Detail view
        detail_views.append(_render_platform_detail(
            r, platform_id, domain_id, panel_id, evidence_base_url
        ))

    # Notification bar
    notification_bar = f"""
      <div id="{panel_id}_notify" class="sb-notify-bar" onclick="openManualModal('{panel_id}')">
        <div class="sb-notify-bar-content">
          <span class="sb-notify-bar-icon">!</span>
          <span class="sb-notify-bar-text">
            <strong>Action Required:</strong> {count} {platform_word} need manual submission
          </span>
        </div>
        <span class="sb-notify-bar-hint">Review &rarr;</span>
      </div>
    """

    # Slide-out modal with two stages
    modal = f"""
      <div id="{panel_id}_overlay" class="sb-modal-overlay" onclick="closeManualModal('{panel_id}')"></div>
      <div id="{panel_id}_modal" class="sb-modal-panel">
        <div class="sb-modal-header">
          <div class="sb-modal-header-left">
            <button type="button" class="sb-modal-back" onclick="backToList('{panel_id}')">&larr;</button>
            <div>
              <div class="sb-modal-title" id="{panel_id}_title">Manual Submissions</div>
              <div class="sb-modal-subtitle" id="{panel_id}_progress">{count} of {count} pending</div>
            </div>
          </div>
          <button type="button" class="sb-modal-close" onclick="closeManualModal('{panel_id}')">&times;</button>
        </div>
        <div class="sb-modal-body">
          <div class="sb-platform-list">
            {''.join(list_items)}
          </div>
          {''.join(detail_views)}
        </div>
      </div>
    """

    # Confirmation dialog
    confirm_dialog = f"""
      <div id="{panel_id}_confirm" class="sb-confirm-dialog">
        <div class="sb-confirm-content">
          <div class="sb-confirm-title">Confirm Submission</div>
          <div class="sb-confirm-message">
            Have you submitted the abuse report to <strong id="{panel_id}_confirm_platform"></strong>?
          </div>
          <div class="sb-confirm-actions">
            <button type="button" class="sb-btn" onclick="hideConfirmDialog('{panel_id}')">Not Yet</button>
            <button type="button" class="sb-btn sb-btn-success" onclick="confirmMarkDone('{panel_id}')">Yes, I've Submitted</button>
          </div>
        </div>
      </div>
    """

    return notification_bar + modal + confirm_dialog


def _render_domain_detail(
    domain: dict,
    reports: list[dict],
    *,
    evidence_dir: Path | None,
    evidence_base_url: str | None,
    screenshots: list[Path],
    instruction_files: list[Path],
    admin: bool,
    csrf: str | None,
    msg: str | None,
    error: bool,
    available_platforms: list[str],
    platform_info: dict[str, dict] | None = None,
    cluster: dict | None = None,
    related_domains: list[dict] | None = None,
    manual_pending: list[str] | None = None,
) -> str:
    did = domain.get("id")
    domain_name = domain.get("domain") or ""

    # Header action buttons - no admin link in public view
    header_links = []
    header_links.append(f'<a class="sb-btn" href="{_escape("/admin" if admin else "/")}">&larr; Back</a>')
    if admin:
        header_links.append(f'<a class="sb-btn" href="{_escape(f"/domains/{did}")}">Public View</a>')

    open_url = f"https://{domain_name}"
    header_links.append(f'<a class="sb-btn" href="{_escape(open_url)}" target="_blank" rel="noreferrer">Visit Site &nearr;</a>')

    # Evidence section
    evidence_bits = ""
    if evidence_base_url and (screenshots or instruction_files or evidence_dir):
        files = []
        for label, filename in (
            ("analysis.json", "analysis.json"),
            ("page.html", "page.html"),
            ("console.log", "console.log"),
            ("network.har", "network.har"),
        ):
            if evidence_dir and (evidence_dir / filename).exists():
                files.append(
                    f'<a class="sb-btn" style="font-size: 11px; padding: 6px 12px;" href="{_escape(evidence_base_url + "/" + quote(filename))}" target="_blank" rel="noreferrer">{_escape(label)}</a>'
                )
        for p in instruction_files:
            files.append(
                f'<a class="sb-btn" style="font-size: 11px; padding: 6px 12px;" href="{_escape(evidence_base_url + "/" + quote(p.name))}" target="_blank" rel="noreferrer">{_escape(p.name)}</a>'
            )

        images = []
        for p in screenshots:
            images.append(
                f'<div class="sb-screenshot"><a href="{_escape(evidence_base_url + "/" + quote(p.name))}" target="_blank" rel="noreferrer">'
                f'<img src="{_escape(evidence_base_url + "/" + quote(p.name))}" loading="lazy" alt="{_escape(p.name)}" />'
                f'</a><div class="sb-screenshot-label">{_escape(p.name)}</div></div>'
            )

        evidence_bits = f"""
          <div class="sb-panel">
            <div class="sb-panel-header">
              <span class="sb-panel-title">Evidence Files</span>
              <span class="sb-muted"><code class="sb-code">{_escape(str(evidence_dir) if evidence_dir else "&mdash;")}</code></span>
            </div>
            <div class="sb-row" style="gap: 8px;">
              {''.join(files) if files else '<span class="sb-muted">No evidence files found.</span>'}
            </div>
          </div>
          <div class="sb-panel">
            <div class="sb-panel-header">
              <span class="sb-panel-title">Screenshots</span>
              <span class="sb-muted">{len(images)} captured</span>
            </div>
            <div class="sb-evidence-grid">{''.join(images) if images else '<div class="sb-muted">No screenshots available.</div>'}</div>
          </div>
        """

    # Reports table
    reports_rows = []
    for idx, r in enumerate(reports):
        status = (r.get("status") or "").lower()
        platform = r.get("platform") or ""

        if status == "manual_required":
            # Expandable row for manual submission helper
            helper_id = f"manual_helper_{did}_{idx}"
            row_id = f"manual_row_{did}_{idx}"
            helper_html = _render_manual_helper(r, helper_id)
            reports_rows.append(
                f'<tr style="cursor: pointer;" onclick="toggleManualHelper(\'{row_id}\')">'
                f'<td><span id="{row_id}_icon" class="sb-expand-icon">&#9654;</span> {_escape(platform)}</td>'
                f"<td>{_report_badge(status)}</td>"
                f'<td class="sb-muted">{_escape(r.get("attempts") or 0)}</td>'
                f'<td class="sb-muted">{_escape(r.get("attempted_at") or "&mdash;")}</td>'
                f'<td class="sb-muted">{_escape(r.get("submitted_at") or "&mdash;")}</td>'
                f'<td class="sb-muted">{_escape(r.get("next_attempt_at") or "&mdash;")}</td>'
                f'<td class="sb-muted" style="font-size: 11px; color: var(--accent-orange);">Click to expand</td>'
                "</tr>"
                f'<tr id="{row_id}" style="display: none;"><td colspan="7" style="padding: 0; border-top: none;">'
                f"{helper_html}"
                f"</td></tr>"
            )
        else:
            # Standard row for other statuses
            reports_rows.append(
                "<tr>"
                f"<td>{_escape(platform)}</td>"
                f"<td>{_report_badge(status)}</td>"
                f'<td class="sb-muted">{_escape(r.get("attempts") or 0)}</td>'
                f'<td class="sb-muted">{_escape(r.get("attempted_at") or "&mdash;")}</td>'
                f'<td class="sb-muted">{_escape(r.get("submitted_at") or "&mdash;")}</td>'
                f'<td class="sb-muted">{_escape(r.get("next_attempt_at") or "&mdash;")}</td>'
                f'<td class="sb-muted" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">{_escape((r.get("response") or "")[:120])}</td>'
                "</tr>"
            )

    reports_table = f"""
      <div class="sb-panel">
        <div class="sb-panel-header">
          <span class="sb-panel-title">Report History</span>
          <span class="sb-muted">{len(reports)} records</span>
        </div>
        <div class="sb-table-wrap">
          <table class="sb-table">
            <thead>
              <tr>
                <th>Platform</th>
                <th>Status</th>
                <th>Attempts</th>
                <th>Attempted</th>
                <th>Submitted</th>
                <th>Next Attempt</th>
                <th>Response</th>
              </tr>
            </thead>
            <tbody>
              {''.join(reports_rows) if reports_rows else '<tr><td class="sb-muted" colspan="7" style="text-align: center; padding: 24px;">No reports yet.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    """

    notes = domain.get("operator_notes") or ""

    # Admin forms section
    admin_forms = ""
    if admin and csrf:
        status_val = (domain.get("status") or "").strip().lower()
        verdict_val = (domain.get("verdict") or "").strip().lower()

        # Categorize platforms into automated vs manual
        pinfo = platform_info or {}
        automated_platforms = []
        manual_platforms = []
        for p in available_platforms:
            info = pinfo.get(p, {})
            if info.get("manual_only", False):
                manual_platforms.append(p)
            else:
                automated_platforms.append(p)

        def render_platform_checkbox(p: str) -> str:
            return (
                f'<label style="display:flex;gap:10px;align-items:center;padding:6px 0;'
                f'font-family:var(--font-mono);font-size:12px;color:var(--text-secondary);cursor:pointer;">'
                f'<input type="checkbox" name="platform" value="{_escape(p)}" checked />'
                f'<span>{_escape(p)}</span>'
                f"</label>"
            )

        platform_checks_html = ""
        if automated_platforms:
            auto_checks = "".join(render_platform_checkbox(p) for p in automated_platforms)
            platform_checks_html += f"""
              <div class="sb-platform-section">
                <div class="sb-platform-section-title">Automated Platforms</div>
                <div class="sb-platform-section-desc">Submitted automatically via API or form</div>
                {auto_checks}
              </div>
            """
        if manual_platforms:
            manual_checks = "".join(render_platform_checkbox(p) for p in manual_platforms)
            platform_checks_html += f"""
              <div class="sb-platform-section">
                <div class="sb-platform-section-title manual">Manual Submission Required</div>
                <div class="sb-platform-section-desc">Generates copy-paste data for manual forms</div>
                {manual_checks}
              </div>
            """
        if not automated_platforms and not manual_platforms:
            platform_checks_html = '<div class="sb-muted" style="padding: 12px 0;">No configured reporters.</div>'

        admin_forms = f"""
          <div class="sb-panel" style="border-color: rgba(210, 153, 34, 0.3);">
            <div class="sb-panel-header" style="border-color: rgba(210, 153, 34, 0.2);">
              <span class="sb-panel-title" style="color: var(--accent-amber);">Admin Actions</span>
            </div>
            <div class="sb-grid">
              <div class="col-6">
                <div class="sb-action-card">
                  <div class="sb-action-card-title">Update Domain</div>
                  <form method="post" action="/admin/domains/{_escape(did)}/update">
                    <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                    <div class="sb-grid" style="gap: 12px;">
                      <div class="col-6">
                        <label class="sb-label">Status</label>
                        <select class="sb-select" name="status">
                          {''.join(
                              f'<option value="{_escape(s.value)}" {"selected" if status_val == s.value else ""}>{_escape(s.value)}</option>'
                              for s in DomainStatus
                          )}
                        </select>
                      </div>
                      <div class="col-6">
                        <label class="sb-label">Verdict</label>
                        <select class="sb-select" name="verdict">
                          <option value="" {"selected" if not verdict_val else ""}>unknown</option>
                          {''.join(
                              f'<option value="{_escape(v.value)}" {"selected" if verdict_val == v.value else ""}>{_escape(v.value)}</option>'
                              for v in Verdict
                          )}
                        </select>
                      </div>
                      <div class="col-12">
                        <label class="sb-label">Notes (visible in public view)</label>
                        <textarea class="sb-textarea" name="notes" placeholder="Current state or next steps...">{_escape(notes)}</textarea>
                      </div>
                      <div class="col-12">
                        <button class="sb-btn sb-btn-primary" type="submit">Save Changes</button>
                      </div>
                    </div>
                  </form>
                </div>
              </div>

              <div class="col-6">
                <div class="sb-action-card">
                  <div class="sb-action-card-title">Quick Actions</div>
                  <div class="sb-row" style="margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                    <form method="post" action="/admin/domains/{_escape(did)}/rescan">
                      <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                      <button class="sb-btn" type="submit">Queue Rescan</button>
                    </form>
                    <form method="post" action="/admin/domains/{_escape(did)}/false_positive">
                      <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                      <button class="sb-btn sb-btn-danger" type="submit">Mark False Positive</button>
                    </form>
                  </div>
                </div>

                <div class="sb-action-card">
                  <div class="sb-action-card-title">Evidence & Reports</div>
                  <div class="sb-row" style="flex-wrap: wrap; gap: 8px;">
                    <a class="sb-btn sb-btn-primary" href="/admin/domains/{_escape(did)}/pdf">Download PDF</a>
                    <a class="sb-btn" href="/admin/domains/{_escape(did)}/package">Evidence Archive</a>
                    <form method="post" action="/admin/domains/{_escape(did)}/preview" style="display: inline;">
                      <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                      <button class="sb-btn" type="submit">Preview (Dry-Run)</button>
                    </form>
                  </div>
                </div>

                <div class="sb-action-card">
                  <div class="sb-action-card-title">Submit Reports</div>
                  <form method="post" action="/admin/domains/{_escape(did)}/report">
                    <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                    <div style="max-height:220px;overflow:auto;border:1px solid var(--border-default);border-radius:var(--radius-md);padding:8px 12px;margin-bottom:12px;background:var(--bg-elevated);">
                      {platform_checks_html}
                    </div>
                    <div class="sb-row">
                      <label style="display:flex;gap:8px;align-items:center;font-family:var(--font-mono);font-size:12px;color:var(--text-secondary);cursor:pointer;">
                        <input type="checkbox" name="force" value="1" />
                        <span>Force (bypass rate limits)</span>
                      </label>
                      <button class="sb-btn sb-btn-success" type="submit">Submit Reports</button>
                    </div>
                  </form>
                </div>

                <div class="sb-action-card">
                  <div class="sb-action-card-title">Mark Manual Done</div>
                  <form method="post" action="/admin/domains/{_escape(did)}/manual_done">
                    <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                    <div class="sb-row">
                      <input class="sb-input" type="text" name="note" placeholder="Optional note..." style="flex: 1;" />
                      <button class="sb-btn" type="submit">Mark Complete</button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          </div>
        """

    reasons = domain.get("verdict_reasons") or ""
    reasons_html = f'<pre class="sb-pre">{_escape(reasons)}</pre>' if reasons else '<div class="sb-muted">&mdash;</div>'
    notes_html = f'<pre class="sb-pre">{_escape(notes)}</pre>' if notes else '<div class="sb-muted">&mdash;</div>'

    info = _render_kv_table(
        [
            ("domain", domain_name),
            ("source", domain.get("source") or ""),
            ("status", domain.get("status") or ""),
            ("verdict", domain.get("verdict") or ""),
            ("domain_score", domain.get("domain_score") or 0),
            ("analysis_score", domain.get("analysis_score") if domain.get("analysis_score") is not None else ""),
            ("first_seen", domain.get("first_seen") or ""),
            ("analyzed_at", domain.get("analyzed_at") or ""),
            ("reported_at", domain.get("reported_at") or ""),
            ("updated_at", domain.get("updated_at") or ""),
        ]
    )

    # Render the Action Required panel if manual platforms are pending
    action_required_html = ""
    if manual_pending and admin:
        action_required_html = _render_action_required_panel(
            manual_pending, reports, did, evidence_base_url
        )

    return f"""
      <div class="sb-domain-header">
        <div class="sb-row sb-space-between" style="margin-bottom: 16px;">
          <div>
            <div class="sb-domain-name">{_escape(domain_name)}</div>
            <div class="sb-domain-meta">
              {_status_badge(str(domain.get("status") or ""))}
              {_verdict_badge(domain.get("verdict"))}
              <span class="sb-domain-id">ID: <code class="sb-code">{_escape(did)}</code></span>
            </div>
          </div>
          <div class="sb-row">{''.join(header_links)}</div>
        </div>
      </div>
      {_flash(msg, error=error)}
      {action_required_html}
      <div class="sb-grid" style="margin-bottom: 16px;">
        <div class="col-6">{info}</div>
        <div class="col-6">
          <div class="sb-panel">
            <div class="sb-panel-header">
              <span class="sb-panel-title">Verdict Reasons</span>
            </div>
            {reasons_html}
          </div>
          <div class="sb-panel">
            <div class="sb-panel-header">
              <span class="sb-panel-title">Operator Notes</span>
            </div>
            {notes_html}
          </div>
        </div>
      </div>
      {_render_cluster_info(cluster, related_domains or [], admin)}
      {admin_forms}
      {evidence_bits}
      {reports_table}
    """


@dataclass(slots=True)
class DashboardConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8080
    admin_user: str = "admin"
    admin_password: str = ""
    health_url: str = ""
    frontend_dir: Path | None = None
    allowlist: set[str] = field(default_factory=set)


class DashboardServer:
    """Runs a small aiohttp server with public and admin dashboards."""

    def __init__(
        self,
        *,
        config: DashboardConfig,
        database: Database,
        evidence_dir: Path,
        clusters_dir: Path | None = None,
        submit_callback: Callable[[str], None] | None = None,
        rescan_callback: Callable[[str], None] | None = None,
        report_callback: Callable[[int, str, Optional[list[str]], bool], object] | None = None,
        mark_manual_done_callback: Callable[[int, str, Optional[list[str]], str], object] | None = None,
        get_available_platforms: Callable[[], list[str]] | None = None,
        get_platform_info: Callable[[], dict[str, dict]] | None = None,
        get_manual_report_options: Callable[[int, str, Optional[list[str]]], object] | None = None,
        # New callbacks for enhanced reporting
        generate_domain_pdf_callback: Callable[[str, int | None], Path | None] | None = None,
        generate_domain_package_callback: Callable[[str, int | None], Path | None] | None = None,
        preview_domain_report_callback: Callable[[int, str], dict] | None = None,
        generate_campaign_pdf_callback: Callable[[str], Path | None] | None = None,
        generate_campaign_package_callback: Callable[[str], Path | None] | None = None,
        preview_campaign_report_callback: Callable[[str], dict] | None = None,
        submit_campaign_report_callback: Callable[[str], dict] | None = None,
    ):
        self.config = config
        self.database = database
        self._allowlist = {d.lower() for d in getattr(config, "allowlist", [])}
        self.evidence_dir = evidence_dir
        self.clusters_dir = clusters_dir
        self.frontend_dir = Path(
            config.frontend_dir
            or os.environ.get("DASHBOARD_FRONTEND_DIST")
            or Path(__file__).parent / "frontend" / "dist"
        )
        self._frontend_available = (self.frontend_dir / "index.html").exists()
        self.submit_callback = submit_callback
        self.rescan_callback = rescan_callback
        self.report_callback = report_callback
        self.mark_manual_done_callback = mark_manual_done_callback
        self.get_available_platforms = get_available_platforms or (lambda: [])
        self.get_platform_info = get_platform_info or (lambda: {})
        self.get_manual_report_options = get_manual_report_options
        # New callbacks
        self.generate_domain_pdf_callback = generate_domain_pdf_callback
        self.generate_domain_package_callback = generate_domain_package_callback
        self.preview_domain_report_callback = preview_domain_report_callback
        self.generate_campaign_pdf_callback = generate_campaign_pdf_callback
        self.generate_campaign_package_callback = generate_campaign_package_callback
        self.preview_campaign_report_callback = preview_campaign_report_callback
        self.submit_campaign_report_callback = submit_campaign_report_callback

        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        # Simple per-IP rate limiter for public submission endpoint
        self._public_rate_limits: dict[str, list[float]] = {}

        self._app = web.Application(middlewares=[self._admin_auth_middleware])
        self._register_routes()

    def _load_clusters(self) -> list[dict]:
        """Load all threat campaigns from clusters.json."""
        if not self.clusters_dir:
            return []
        clusters_file = self.clusters_dir / "clusters.json"
        if not clusters_file.exists():
            return []
        try:
            with open(clusters_file, "r") as f:
                data = json.load(f)
            return data.get("clusters", [])
        except Exception:
            return []

    def _normalize_domain_key(self, domain: str) -> str:
        """Normalize a domain for lookups (strip scheme/path, lowercase)."""
        return canonicalize_domain(domain) or _extract_hostname(domain)

    def _registered_domain(self, domain: str) -> str:
        """Return the registered domain (second-level + suffix) for allowlist checks."""
        host = self._normalize_domain_key(domain)
        if not host:
            return ""
        extracted = tldextract.extract(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        return host

    def _is_allowlisted_domain(self, domain: str) -> bool:
        """Return True if the domain (or its registered form) is allowlisted."""
        host = self._normalize_domain_key(domain)
        registered = self._registered_domain(domain)
        return (host in self._allowlist) or (registered in self._allowlist)

    def _client_ip(self, request: web.Request) -> str:
        """Best-effort client IP extraction (supports X-Forwarded-For)."""
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        # aiohttp's request.remote may include port, so strip it for rate limiting
        remote = (request.remote or "").split(":")[0]
        return remote or "unknown"

    def _session_hash(self, request: web.Request) -> str:
        """Generate a stable, non-PII session hash for deduping."""
        raw = f"{self._client_ip(request)}:{request.headers.get('User-Agent', 'unknown')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _is_disallowed_public_host(self, host: str) -> bool:
        """Block localhost/private/internal submissions."""
        candidate = (host or "").strip().lower().strip("[]")
        # Handle simple host:port pattern
        host_only = candidate.split(":", 1)[0] if ":" in candidate and candidate.count(":") == 1 else candidate
        try:
            ip_obj = ipaddress.ip_address(host_only)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local or ip_obj.is_multicast:
                return True
        except ValueError:
            pass

        if host_only in {"localhost", "local", "localhost.localdomain"}:
            return True
        if host_only.endswith((".local", ".internal", ".localhost")):
            return True
        return False

    def _rate_limit_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        """
        Simple sliding-window rate limiter keyed by arbitrary string (e.g., IP).
        Returns True when within limit.
        """
        now = datetime.utcnow().timestamp()
        window_start = now - float(window_seconds)
        entries = [t for t in self._public_rate_limits.get(key, []) if t >= window_start]
        if len(entries) >= limit:
            self._public_rate_limits[key] = entries
            return False
        entries.append(now)
        self._public_rate_limits[key] = entries
        return True

    async def _filter_clusters(self, clusters: list[dict]) -> list[dict]:
        """Hide campaigns whose members are all allowlisted/watchlist/false positive."""
        if not clusters:
            return []

        # Collect member domains for bulk lookup
        member_domains: set[str] = set()
        for cluster in clusters:
            for member in cluster.get("members", []):
                name = (member.get("domain") or "").strip().lower()
                if name:
                    member_domains.add(name)
                    normalized = self._normalize_domain_key(name)
                    if normalized:
                        member_domains.add(normalized)

        domain_records = await self.database.get_domains_by_names(list(member_domains))
        excluded_statuses = {
            DomainStatus.ALLOWLISTED.value,
            DomainStatus.FALSE_POSITIVE.value,
            DomainStatus.WATCHLIST.value,
        }

        seen_normalized: set[str] = set()
        filtered: list[dict] = []
        for cluster in clusters:
            kept_members: list[dict] = []
            new_keys: set[str] = set()
            for member in cluster.get("members", []):
                domain_name = (member.get("domain") or "").strip()
                if not domain_name:
                    continue

                normalized_key = self._normalize_domain_key(domain_name)
                record = domain_records.get(domain_name.lower()) or domain_records.get(normalized_key)
                status = (record.get("status") if record else "") or ""
                verdict = (record.get("verdict") if record else "") or ""

                # Treat config allowlist as authoritative even if DB record missing
                if self._is_allowlisted_domain(domain_name):
                    status = DomainStatus.ALLOWLISTED.value

                if status in excluded_statuses:
                    continue

                if normalized_key and normalized_key in seen_normalized:
                    continue

                enriched = dict(member)
                if record:
                    enriched.update(record)
                if status:
                    enriched["status"] = status
                if verdict and not enriched.get("verdict"):
                    enriched["verdict"] = verdict
                kept_members.append(enriched)
                if normalized_key:
                    new_keys.add(normalized_key)

            if kept_members:
                seen_normalized.update(new_keys)
                new_cluster = dict(cluster)
                new_cluster["members"] = kept_members
                filtered.append(new_cluster)

        return filtered

    def _get_cluster_for_domain(self, domain: str) -> dict | None:
        """Get campaign info for a specific domain."""
        if self._is_allowlisted_domain(domain):
            return None
        clusters = self._load_clusters()
        for cluster in clusters:
            members = cluster.get("members", [])
            for member in members:
                if member.get("domain") == domain:
                    return cluster
        return None

    def _get_related_domains(self, domain: str, cluster: dict | None) -> list[dict]:
        """Get list of related domains from the same campaign."""
        if not cluster:
            return []
        members = cluster.get("members", [])
        current_key = self._normalize_domain_key(domain)
        return [
            m for m in members
            if self._normalize_domain_key(m.get("domain")) != current_key
        ]

    async def _enrich_related_domains_with_ids(self, related_domains: list[dict]) -> list[dict]:
        """Look up domain IDs from database and add them to related_domains."""
        enriched = []
        for member in related_domains:
            domain_name = member.get("domain", "")
            domain_record = await self.database.get_domain(domain_name)
            enriched_member = dict(member)
            if domain_record:
                enriched_member["id"] = domain_record.get("id")
            enriched.append(enriched_member)
        return enriched

    def _compute_evidence_bytes(self) -> int:
        total = 0
        for root, _dirs, files in os.walk(self.evidence_dir):
            for name in files:
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    continue
        return total

    async def _fetch_health_status(self) -> dict | None:
        url = getattr(self.config, "health_url", "") or ""
        url = url.strip()
        if not url:
            return None
        try:
            timeout = aiohttp.ClientTimeout(total=2)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    try:
                        payload = await resp.json(content_type=None)
                    except Exception:
                        payload = {"body": await resp.text()}
                    return {"ok": resp.status == 200, "status": payload.get("status") if isinstance(payload, dict) else None, "data": payload}
        except Exception as exc:  # pragma: no cover - best-effort
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Evidence retention/cleanup
    # ------------------------------------------------------------------
    def _collect_old_evidence(self, days: int) -> list[dict]:
        """Gather evidence directories older than N days with metadata."""
        from datetime import timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        candidates: list[dict] = []
        for domain_dir in self.evidence_dir.iterdir():
            if not domain_dir.is_dir():
                continue
            analysis_path = domain_dir / "analysis.json"
            if not analysis_path.exists():
                continue
            try:
                data = json.loads(analysis_path.read_text())
                saved_at = data.get("saved_at")
                if not saved_at:
                    continue
                ts = datetime.fromisoformat(saved_at)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    size = 0
                    try:
                        for p in domain_dir.rglob("*"):
                            if p.is_file():
                                size += p.stat().st_size
                    except Exception:
                        pass
                    candidates.append({"path": domain_dir, "saved_at": ts, "size": size})
            except Exception:
                continue
        return candidates

    async def _admin_api_cleanup_evidence(self, request: web.Request) -> web.Response:
        data = await request.json()
        days = int(data.get("days") or 30)
        if days < 1:
            days = 1
        preview = bool(data.get("preview"))
        loop = asyncio.get_event_loop()
        if preview:
            candidates = await loop.run_in_executor(None, lambda: self._collect_old_evidence(days))
            total_bytes = sum(item.get("size", 0) for item in candidates)
            return web.json_response(
                {
                    "status": "ok",
                    "preview": True,
                    "would_remove": len(candidates),
                    "would_bytes": total_bytes,
                }
            )

        removed, removed_bytes = await loop.run_in_executor(
            None, lambda: self._cleanup_evidence(days)
        )
        return web.json_response(
            {"status": "ok", "removed_dirs": removed, "removed_bytes": removed_bytes}
        )

    def _cleanup_evidence(self, days: int) -> tuple[int, int]:
        """Remove evidence older than N days. Returns (dirs removed, bytes freed)."""
        import shutil
        removed = 0
        freed_bytes = 0
        for item in self._collect_old_evidence(days):
            try:
                shutil.rmtree(item["path"])
                removed += 1
                freed_bytes += int(item.get("size") or 0)
            except Exception:
                continue
        return removed, freed_bytes

    def _register_routes(self) -> None:
        # Health check
        self._app.router.add_get("/healthz", self._healthz)

        # Public API routes (read-only, reuse admin handlers)
        self._app.router.add_get("/api/stats", self._admin_api_stats)
        self._app.router.add_get("/api/domains", self._admin_api_domains)
        self._app.router.add_get("/api/clusters", self._admin_api_clusters)
        self._app.router.add_get("/api/clusters/{cluster_id}", self._admin_api_cluster)
        self._app.router.add_get("/api/domains/{domain_id}", self._admin_api_domain)
        self._app.router.add_get("/api/platforms", self._admin_api_platforms)
        self._app.router.add_post("/api/public/submit", self._public_api_submit)
        self._app.router.add_get("/api/domains/{domain_id}/report-options", self._public_api_report_options)
        self._app.router.add_post("/api/domains/{domain_id}/report-engagement", self._public_api_report_engagement)

        # Evidence directory is public by design for transparency.
        self._app.router.add_static("/evidence", str(self.evidence_dir), show_index=False)
        # Public download routes for reports/evidence packages
        self._app.router.add_get("/domains/{domain_id}/pdf", self._admin_domain_pdf)
        self._app.router.add_get("/domains/{domain_id}/package", self._admin_domain_package)
        self._app.router.add_get("/clusters/{cluster_id}/pdf", self._admin_cluster_pdf)
        self._app.router.add_get("/clusters/{cluster_id}/package", self._admin_cluster_package)

        # Admin API routes
        self._app.router.add_get("/admin/api/stats", self._admin_api_stats)
        self._app.router.add_get("/admin/api/domains", self._admin_api_domains)
        self._app.router.add_get("/admin/api/domains/{domain_id}", self._admin_api_domain)
        self._app.router.add_post("/admin/api/submit", self._admin_api_submit)
        self._app.router.add_post("/admin/api/domains/{domain_id}/rescan", self._admin_api_rescan)
        self._app.router.add_post("/admin/api/report", self._admin_api_report)
        self._app.router.add_post("/admin/api/domains/{domain_id}/false_positive", self._admin_api_false_positive)
        self._app.router.add_patch("/admin/api/domains/{domain_id}/status", self._admin_api_update_domain_status)
        self._app.router.add_post("/admin/api/domains/{domain_id}/baseline", self._admin_api_update_baseline)
        self._app.router.add_get("/admin/api/domains/{domain_id}/evidence", self._admin_api_evidence)
        self._app.router.add_post("/admin/api/cleanup_evidence", self._admin_api_cleanup_evidence)
        self._app.router.add_get("/admin/api/clusters", self._admin_api_clusters)
        self._app.router.add_get("/admin/api/clusters/{cluster_id}", self._admin_api_cluster)
        self._app.router.add_patch("/admin/api/domains/{domain_id}/notes", self._admin_api_update_notes)
        self._app.router.add_patch("/admin/api/clusters/{cluster_id}/name", self._admin_api_update_cluster_name)
        self._app.router.add_get("/admin/api/platforms", self._admin_api_platforms)
        self._app.router.add_get("/admin/api/analytics", self._admin_api_analytics)
        self._app.router.add_get("/admin/api/submissions", self._admin_api_submissions)
        self._app.router.add_get("/admin/api/submissions/{submission_id}", self._admin_api_submission)
        self._app.router.add_post("/admin/api/submissions/{submission_id}/approve", self._admin_api_approve_submission)
        self._app.router.add_post("/admin/api/submissions/{submission_id}/reject", self._admin_api_reject_submission)
        
        self._app.router.add_get("/admin/domains/{domain_id}/pdf", self._admin_domain_pdf)
        self._app.router.add_get("/admin/domains/{domain_id}/package", self._admin_domain_package)
        self._app.router.add_post("/admin/domains/{domain_id}/preview", self._admin_domain_preview)
        # Campaign routes
        self._app.router.add_get("/admin/clusters/{cluster_id}/pdf", self._admin_cluster_pdf)
        self._app.router.add_get("/admin/clusters/{cluster_id}/package", self._admin_cluster_package)
        self._app.router.add_post("/admin/clusters/{cluster_id}/preview", self._admin_cluster_preview)
        self._app.router.add_post("/admin/clusters/{cluster_id}/submit", self._admin_cluster_submit)

        # UI routes: prefer SPA when built; fall back to server-rendered HTML otherwise
        if self._frontend_available:
            assets_dir = self.frontend_dir / "assets"
            if assets_dir.exists():
                self._app.router.add_static("/admin/assets", str(assets_dir), show_index=False)
                # Also serve assets from root for public SPA
                self._app.router.add_static("/assets", str(assets_dir), show_index=False)
            # Admin SPA (protected via middleware)
            self._app.router.add_get("/admin", self._serve_frontend)
            self._app.router.add_get("/admin/", self._serve_frontend)
            self._app.router.add_get("/admin/{tail:.*}", self._serve_frontend)
            # Public SPA (campaigns + optional root)
            self._app.router.add_get("/", self._serve_frontend)
            self._app.router.add_get("/campaigns", self._serve_frontend)
            self._app.router.add_get("/campaigns/{tail:.*}", self._serve_frontend)
        else:
            # If frontend not built, return a clear error.
            async def _frontend_missing(_request: web.Request) -> web.Response:
                raise web.HTTPNotFound(text="Frontend not built (run npm run build in frontend/)")

            self._app.router.add_get("/admin", _frontend_missing)
            self._app.router.add_get("/admin/{tail:.*}", _frontend_missing)
            self._app.router.add_get("/", _frontend_missing)
            self._app.router.add_get("/campaigns", _frontend_missing)
            self._app.router.add_get("/campaigns/{tail:.*}", _frontend_missing)

    async def _serve_frontend(self, request: web.Request) -> web.Response:
        """Serve built SPA assets for the admin dashboard."""
        index_path = self.frontend_dir / "index.html"
        if not index_path.exists():
            raise web.HTTPNotFound(text="Frontend not built (run npm run build in frontend/)")
        try:
            html_out = index_path.read_text(encoding="utf-8")
        except Exception:
            raise web.HTTPInternalServerError(text="Failed to read frontend bundle.")

        mode = "admin" if (request.path or "").startswith("/admin") else "public"
        mode_script = f"<script>window.__SB_MODE=\"{mode}\";</script>"
        if "</head>" in html_out:
            html_out = html_out.replace("</head>", f"{mode_script}</head>", 1)
        else:
            html_out = mode_script + html_out

        return web.Response(
            text=html_out,
            content_type="text/html",
            headers={"Cache-Control": "no-cache"},
        )

    @web.middleware
    async def _admin_auth_middleware(self, request: web.Request, handler):  # type: ignore[override]
        # Only protect /admin and /admin/api; public routes (including /campaigns) should pass through.
        path = request.path or ""
        if not path.startswith("/admin"):
            return await handler(request)

        # Allow static assets and manifest under /admin without auth (used by public SPA).
        if (
            path.startswith("/admin/assets")
            or path.startswith("/admin/manifest")
            or path.startswith("/admin/favicon")
            or path.startswith("/admin/.well-known")
        ):
            return await handler(request)

        if not self.config.admin_password:
            raise web.HTTPForbidden(text="Admin dashboard not configured (set DASHBOARD_ADMIN_PASSWORD).")

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="SeedBuster Admin"'},
                text="Authentication required.",
            )

        try:
            raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            user, password = raw.split(":", 1)
        except Exception:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="SeedBuster Admin"'},
                text="Invalid Authorization header.",
            )

        if user != self.config.admin_user or password != self.config.admin_password:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="SeedBuster Admin"'},
                text="Invalid credentials.",
            )

        return await handler(request)

    def _get_or_set_csrf(self, request: web.Request, response: web.StreamResponse) -> str:
        name = "sb_admin_csrf"
        token = (request.cookies.get(name) or "").strip()
        if not token:
            token = secrets.token_urlsafe(32)
            response.set_cookie(
                name,
                token,
                path="/admin",
                httponly=True,
                samesite="Strict",
                secure=(request.url.scheme == "https"),
            )
        return token

    async def _require_csrf(self, request: web.Request) -> web.MultiDictProxy:
        name = "sb_admin_csrf"
        cookie = (request.cookies.get(name) or "").strip()
        data = await request.post()
        sent = (data.get("csrf") or "").strip()
        if not cookie or not sent or sent != cookie:
            raise web.HTTPForbidden(text="CSRF check failed.")
        return data

    async def start(self) -> None:
        if not self.config.enabled:
            return
        if self._runner:
            return
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host=self.config.host, port=int(self.config.port))
        await self._site.start()

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._runner = None
        self._site = None

    async def _healthz(self, request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    async def _public_index(self, request: web.Request) -> web.Response:
        status_param_present = "status" in request.query
        status_raw = (request.query.get("status") or "").strip().lower()
        status = status_raw if status_param_present else "dangerous"
        verdict = (request.query.get("verdict") or "").strip().lower()
        q = (request.query.get("q") or "").strip().lower()
        limit = _coerce_int(request.query.get("limit"), default=100, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        stats = await self.database.get_stats()

        status_filter = None if status == "dangerous" else (status or None)
        exclude_statuses = DANGEROUS_EXCLUDE_STATUSES if status == "dangerous" else None

        total_count = await self.database.count_domains(
            status=status_filter,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
        )
        await self._fetch_health_status()
        domains = await self.database.list_domains(
            limit=limit,
            offset=offset,
            status=status_filter,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
        )

        body = (
            _flash(request.query.get("msg"))
            + _render_stats(stats, admin=False)
            + _render_domains_section(
                domains,
                admin=False,
                total=total_count,
                status=status,
                verdict=verdict,
                q=q,
                limit=limit,
                page=page,
                include_dangerous=True,
            )
        )
        html_out = _layout(title="SeedBuster Dashboard", body=body, admin=False)
        return web.Response(text=html_out, content_type="text/html")

    async def _public_domain(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        reports = await self.database.get_reports_for_domain(did)

        evidence_dir, evidence_base = self._resolve_evidence(domain)
        screenshots = self._get_screenshots(domain, evidence_dir)
        instruction_files = self._get_instruction_files(evidence_dir)

        # Get cluster info for this domain
        domain_name = domain.get("domain") or ""
        cluster = self._get_cluster_for_domain(domain_name)
        related_domains = self._get_related_domains(domain_name, cluster)
        related_domains = await self._enrich_related_domains_with_ids(related_domains)

        body = _render_domain_detail(
            domain,
            reports,
            evidence_dir=evidence_dir,
            evidence_base_url=evidence_base,
            screenshots=screenshots,
            instruction_files=instruction_files,
            admin=False,
            csrf=None,
            msg=request.query.get("msg"),
            error=(request.query.get("error") == "1"),
            available_platforms=[],
            cluster=cluster,
            related_domains=related_domains,
        )
        html_out = _layout(title="SeedBuster Dashboard", body=body, admin=False)
        return web.Response(text=html_out, content_type="text/html")

    async def _public_clusters(self, request: web.Request) -> web.Response:
        search = (request.query.get("q") or "").strip()
        clusters = await self._filter_clusters(self._load_clusters())
        body = _render_clusters_list(clusters, admin=False, q=search)
        html_out = _layout(title="SeedBuster - Threat Campaigns", body=body, admin=False)
        return web.Response(text=html_out, content_type="text/html")

    async def _public_cluster_detail(self, request: web.Request) -> web.Response:
        cluster_id = (request.match_info.get("cluster_id") or "").strip()
        if not cluster_id:
            raise web.HTTPNotFound(text="Campaign not found.")

        clusters = await self._filter_clusters(self._load_clusters())
        cluster = next(
            (
                c for c in clusters
                if str(c.get("cluster_id")) == cluster_id or str(c.get("cluster_id", "")).startswith(cluster_id)
            ),
            None,
        )
        if not cluster:
            raise web.HTTPNotFound(text="Campaign not found.")

        enriched_members = await self._enrich_related_domains_with_ids(cluster.get("members", []))
        cluster = dict(cluster)
        cluster["members"] = enriched_members

        body = _render_cluster_detail(cluster, admin=False)
        html_out = _layout(title=f"Campaign: {cluster.get('name', 'Unknown Campaign')}", body=body, admin=False)
        return web.Response(text=html_out, content_type="text/html")

    async def _admin_clusters(self, request: web.Request) -> web.Response:
        search = (request.query.get("q") or "").strip()
        clusters = await self._filter_clusters(self._load_clusters())
        body = _render_clusters_list(clusters, admin=True, q=search)
        html_out = _layout(title="SeedBuster - Threat Campaigns", body=body, admin=True)
        return web.Response(text=html_out, content_type="text/html")

    async def _admin_index(self, request: web.Request) -> web.Response:
        status = (request.query.get("status") or "").strip().lower()
        verdict = (request.query.get("verdict") or "").strip().lower()
        q = (request.query.get("q") or "").strip().lower()
        limit = _coerce_int(request.query.get("limit"), default=100, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        stats = await self.database.get_stats()
        stats["evidence_bytes"] = self._compute_evidence_bytes()
        health_status = await self._fetch_health_status()

        status_filter = None if status == "dangerous" else (status or None)
        exclude_statuses = DANGEROUS_EXCLUDE_STATUSES if status == "dangerous" else None
        total_count = await self.database.count_domains(
            status=status_filter,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
        )
        domains = await self.database.list_domains(
            limit=limit,
            offset=offset,
            status=status_filter,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
        )
        pending_reports = await self.database.get_pending_reports()

        msg = request.query.get("msg")
        error = request.query.get("error") == "1"

        submit_panel = """
          <div class="sb-panel" style="border-color: rgba(88, 166, 255, 0.3); margin-bottom: 24px;">
            <div class="sb-panel-header" style="border-color: rgba(88, 166, 255, 0.2);">
              <span class="sb-panel-title" style="color: var(--accent-blue);">Manual Submission</span>
              <span class="sb-muted">Submit a domain or URL for analysis</span>
            </div>
            <form method="post" action="/admin/submit" id="submit-form">
              <input type="hidden" name="csrf" value="__SET_COOKIE__" />
              <div class="sb-row">
                <input class="sb-input" type="text" name="target" placeholder="example.com or https://example.com/path" style="flex: 1;" />
                <button class="sb-btn sb-btn-primary" type="submit">Submit / Rescan</button>
              </div>
            </form>
          </div>
          <div class="sb-panel" style="border-color: rgba(63, 185, 80, 0.3); margin-bottom: 24px;">
            <div class="sb-panel-header" style="border-color: rgba(63, 185, 80, 0.2);">
              <span class="sb-panel-title" style="color: var(--accent-green);">Evidence Cleanup</span>
              <span class="sb-muted">Remove evidence older than N days</span>
            </div>
            <form id="cleanup-form">
              <div class="sb-row">
                <input class="sb-input" type="number" name="days" value="30" min="1" style="width: 120px;" />
                <button class="sb-btn sb-btn-secondary" type="submit">Cleanup</button>
              </div>
            </form>
            <div class="sb-muted" id="cleanup-result"></div>
          </div>
        """

        html_out = _layout(
            title="SeedBuster Dashboard",
            body=(
                _flash(msg, error=error)
                + _render_stats(stats, admin=True)
                + _render_health(getattr(self.config, "health_url", ""), health_status)
                + submit_panel
                + _render_pending_reports(pending_reports, admin=True)
                + _render_domains_section(
                    domains,
                    admin=True,
                    total=total_count,
                    status=status,
                    verdict=verdict,
                    q=q,
                    limit=limit,
                    page=page,
                    include_dangerous=True,
                )
            ),
            admin=True,
        )
        resp = web.Response(text=html_out, content_type="text/html")
        csrf = self._get_or_set_csrf(request, resp)
        resp.text = resp.text.replace("__SET_COOKIE__", csrf)
        # Inline script to handle JSON API interactions (submit/rescan/report/cleanup/health)
        resp.text += f"""
        <script>
        (function() {{
          const showToast = (message, type = 'info') => {{
            if (window.sbToast) return window.sbToast(message, type);
            // Fallback
            if (type === 'error') {{ console.error(message); }} else {{ console.log(message); }}
          }};

          const cleanupForm = document.getElementById('cleanup-form');
          const cleanupResult = document.getElementById('cleanup-result');
          if (cleanupForm) {{
            cleanupForm.addEventListener('submit', async (e) => {{
              e.preventDefault();
              cleanupResult.textContent = 'Cleaning...';
              const days = parseInt(cleanupForm.elements['days'].value || '30', 10) || 30;
              try {{
                const res = await fetch('/admin/api/cleanup_evidence', {{
                  method: 'POST',
                  headers: {{ 'Content-Type': 'application/json' }},
                  body: JSON.stringify({{ days }}),
                }});
                const data = await res.json();
                if (res.ok) {{
                  cleanupResult.textContent = `Removed ${'{'}data.removed_dirs || 0{'}'} directories older than ${'{'}days{'}'} days.`;
                  showToast(cleanupResult.textContent, 'success');
                }} else {{
                  const msg = data.error || 'Cleanup failed';
                  cleanupResult.textContent = msg;
                  showToast(msg, 'error');
                }}
              }} catch (err) {{
                const msg = 'Cleanup failed: ' + err;
                cleanupResult.textContent = msg;
                showToast(msg, 'error');
              }}
            }});
          }}

          // Submit form via JSON API for faster feedback
          const submitForm = document.getElementById('submit-form');
          if (submitForm) {{
            submitForm.addEventListener('submit', async (e) => {{
              e.preventDefault();
              const target = submitForm.elements['target'].value || '';
              if (!target.trim()) return;
              const btn = submitForm.querySelector('button[type="submit"]');
              btn.disabled = true;
              btn.textContent = 'Submitting...';
              try {{
                const res = await fetch('/admin/api/submit', {{
                  method: 'POST',
                  headers: {{ 'Content-Type': 'application/json' }},
                  body: JSON.stringify({{ target }}),
                }});
                const data = await res.json();
                const msg = data.status === 'rescan_queued'
                  ? `Rescan queued for ${'{'}data.domain{'}'}`
                  : `Submitted ${'{'}data.domain || target{'}'}`;
                showToast(msg, 'success');
              }} catch (err) {{
                showToast('Submit failed: ' + err, 'error');
              }} finally {{
                btn.disabled = false;
                btn.textContent = 'Submit / Rescan';
              }}
            }});
          }}

          async function postJSON(url, payload) {{
            const res = await fetch(url, {{
              method: 'POST',
              headers: {{ 'Content-Type': 'application/json' }},
              body: JSON.stringify(payload || {{}}),
            }});
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || res.statusText);
            return data;
          }}

          // Delegate rescan/report actions
          document.body.addEventListener('click', async (e) => {{
            const target = e.target.closest('.js-rescan, .js-report');
            if (!target) return;
            e.preventDefault();
            const domain = target.dataset.domain;
            const domainId = target.dataset.domainId;
            const type = target.classList.contains('js-rescan') ? 'rescan' : 'report';
            target.disabled = true;
            try {{
              if (type === 'rescan') {{
                await postJSON(`/admin/api/domains/${'{'}domainId{'}'}/rescan`, {{ domain }});
                showToast(`Rescan queued for ${'{'}domain{'}'}`, 'success');
              }} else {{
                await postJSON('/admin/api/report', {{ domain_id: parseInt(domainId, 10), domain }});
                showToast(`Report enqueued for ${'{'}domain{'}'}`, 'success');
              }}
            }} catch (err) {{
              showToast(type + ' failed: ' + err, 'error');
            }} finally {{
              target.disabled = false;
            }}
          }});

          // Health refresh (best effort)
          const healthPanel = document.getElementById('health-panel');
          if (healthPanel) {{
            const statusEl = document.getElementById('health-status');
            const detailsEl = document.getElementById('health-details');
            const url = healthPanel.dataset.url;
            async function refreshHealth() {{
              if (!url) return;
              try {{
                const res = await fetch(url);
                let payload = null;
                try {{ payload = await res.json(); }} catch (_e) {{ payload = {{ raw: await res.text() }}; }}
                const ok = res.ok;
                const data = payload || {{}};
                statusEl.innerHTML = '<b>' + (ok ? 'Healthy' : 'Unhealthy') + '</b>';
                const bits = [];
                ['discovery_queue_size','analysis_queue_size','pending_rescans','domains_tracked'].forEach(k => {{
                  if (data && typeof data === 'object' && k in data) bits.push(`${'{'}k.replace(/_/g, ' '){'}'}: ${'{'}data[k]{'}'}`);
                }});
                detailsEl.textContent = bits.join(' | ') || '';
              }} catch (err) {{
                statusEl.innerHTML = '<b>Unavailable</b>';
                detailsEl.textContent = 'Pipeline health endpoint not reachable (is the main pipeline running?)';
              }}
            }}
            refreshHealth();
            setInterval(refreshHealth, 30000);
          }}
        }})();
        </script>
        """
        return resp

    async def _admin_submit(self, request: web.Request) -> web.Response:
        data = await self._require_csrf(request)
        target = (data.get("target") or "").strip()
        domain = _extract_hostname(target)
        if not domain:
            raise web.HTTPSeeOther(location=_build_query_link("/admin", msg="Invalid domain/URL", error=1))

        existing = await self.database.get_domain(domain)
        if existing:
            if self.rescan_callback:
                self.rescan_callback(domain)
                raise web.HTTPSeeOther(
                    location=_build_query_link("/admin", msg=f"Rescan queued for {domain}")
                )
            raise web.HTTPSeeOther(
                location=_build_query_link("/admin", msg=f"Domain already exists: {domain}")
            )

        if not self.submit_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link("/admin", msg="Submit not configured", error=1)
            )
        self.submit_callback(domain)
        raise web.HTTPSeeOther(location=_build_query_link("/admin", msg=f"Submitted: {domain}"))

    async def _admin_domain(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")
        reports = await self.database.get_reports_for_domain(did)

        evidence_dir, evidence_base = self._resolve_evidence(domain)
        screenshots = self._get_screenshots(domain, evidence_dir)
        instruction_files = self._get_instruction_files(evidence_dir)

        # Get cluster info for this domain
        domain_name = domain.get("domain") or ""
        cluster = self._get_cluster_for_domain(domain_name)
        related_domains = self._get_related_domains(domain_name, cluster)
        related_domains = await self._enrich_related_domains_with_ids(related_domains)

        msg = request.query.get("msg")
        error = request.query.get("error") == "1"
        # Parse manual_pending platforms from query param (comma-separated)
        manual_pending_raw = request.query.get("manual_pending", "")
        manual_pending = [p.strip().lower() for p in manual_pending_raw.split(",") if p.strip()]

        resp = web.Response(
            text=_layout(
                title="SeedBuster Dashboard",
                body=_render_domain_detail(
                    domain,
                    reports,
                    evidence_dir=evidence_dir,
                    evidence_base_url=evidence_base,
                    screenshots=screenshots,
                    instruction_files=instruction_files,
                    admin=True,
                    csrf="__SET_COOKIE__",
                    msg=msg,
                    error=error,
                    available_platforms=self.get_available_platforms(),
                    platform_info=self.get_platform_info(),
                    cluster=cluster,
                    related_domains=related_domains,
                    manual_pending=manual_pending if manual_pending else None,
                ),
                admin=True,
            ),
            content_type="text/html",
        )
        csrf = self._get_or_set_csrf(request, resp)

        # Patch in csrf token without templating engine.
        resp.text = resp.text.replace("__SET_COOKIE__", csrf)

        # Inject Detail Page Scripts
        resp.text += """
        <script>
        (function() {
          const showToast = (message, type = 'info') => {
            if (window.sbToast) return window.sbToast(message, type);
            const t = document.createElement('div');
            t.className = `sb-toast sb-toast-${type}`;
            t.textContent = message;
            document.body.appendChild(t);
            setTimeout(() => t.classList.add('visible'), 10);
            setTimeout(() => {
              t.classList.remove('visible');
              setTimeout(() => t.remove(), 300);
            }, 3000);
          };

          window.copyFieldValue = (fieldId, btnId) => {
            const el = document.getElementById(fieldId);
            const btn = document.getElementById(btnId);
            if (!el || !btn) return;
            const text = el.textContent;
            navigator.clipboard.writeText(text).then(() => {
              const orig = btn.textContent;
              btn.textContent = 'Copied!';
              btn.classList.add('copied');
              setTimeout(() => {
                btn.textContent = orig;
                btn.classList.remove('copied');
              }, 2000);
            }).catch(err => showToast('Copy failed: ' + err, 'error'));
          };

          // Manual Modal Logic - uses functions defined in layout head (openManualModal, etc.)
          // These are already defined globally with correct 'open' class handling

          let currentConfirm = null;
          window.showConfirmDialog = (platformId, platformName, domainId) => {
             const panelId = `action_required_${domainId}`;
             const dialog = document.getElementById(panelId + '_confirm');
             if (!dialog) return;
             
             const platformSpan = document.getElementById(panelId + '_confirm_platform');
             if (platformSpan) platformSpan.textContent = platformName;
             dialog.classList.add('visible');
             
             currentConfirm = { platformId, domainId, panelId };
          };

          window.hideConfirmDialog = (panelId) => {
             const dialog = document.getElementById(panelId + '_confirm');
             if (dialog) dialog.classList.remove('visible');
             currentConfirm = null;
          };

          window.confirmMarkDone = async (panelId) => {
             if (!currentConfirm) return;
             const { domainId } = currentConfirm;
             const btn = document.querySelector(`#${currentConfirm.platformId}_detail .sb-detail-done-btn`);
             
             if (btn) {
                 btn.disabled = true;
                 btn.textContent = 'Marking...';
             }

             try {
               // Use FORM submission to match the existing handler expectation if needed, or stick to fetch
               // The handler _admin_manual_done reads from `await request.post()` or JSON?
               // It calls `_require_csrf` which reads `request.post()`. 
               // So we must send form-encoded data or use a hidden form submit.
               // Let's use a hidden form or fetch with body URLSearchParams.
               
               const formData = new URLSearchParams();
               formData.append('csrf', getCookie('sb_admin_csrf'));
               formData.append('note', 'Marked via modal');
               
               const res = await fetch(`/admin/domains/${domainId}/manual_done`, {
                 method: 'POST',
                 headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                 body: formData
               });
               
               if (res.ok || res.redirected) {
                 showToast('Marked as done', 'success');
                 window.location.reload();
               } else {
                 showToast('Failed to mark done', 'error');
                 if (btn) { btn.disabled = false; btn.textContent = 'Failed'; }
               }
             } catch (e) {
               showToast('Error: ' + e, 'error');
               if (btn) { btn.disabled = false; btn.textContent = 'Error'; }
             }
             
             hideConfirmDialog(panelId);
          };
          
          function getCookie(name) {
            const v = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
            return v ? v[2] : null;
          }

        })();
        </script>
        """
        return resp

    async def _admin_update_domain(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        data = await self._require_csrf(request)
        status = (data.get("status") or "").strip().lower()
        verdict = (data.get("verdict") or "").strip().lower()
        notes = (data.get("notes") or "").strip()

        if status and status not in {s.value for s in DomainStatus}:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Invalid status", error=1)
            )
        if verdict and verdict not in {v.value for v in Verdict}:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Invalid verdict", error=1)
            )

        await self.database.update_domain_admin_fields(
            did,
            status=status or None,
            verdict=verdict or None,
            operator_notes=notes,
        )
        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Saved"))

    async def _admin_report_domain(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        if not self.report_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Reporting not configured", error=1)
            )

        data = await self._require_csrf(request)
        platforms = list({p.strip().lower() for p in data.getall("platform", []) if p.strip()})
        force = (data.get("force") or "") in {"1", "true", "on", "yes"}

        domain_name = str(domain.get("domain") or "")
        try:
            await self.report_callback(did, domain_name, platforms or None, force)
        except Exception as e:
            raise web.HTTPSeeOther(
                location=_build_query_link(
                    f"/admin/domains/{did}", msg=f"Report failed: {e}", error=1
                )
            )

        # Determine which selected platforms are manual-only
        platform_info = self.get_platform_info() if self.get_platform_info else {}
        manual_platforms = [
            p for p in platforms
            if platform_info.get(p, {}).get("manual_only", False)
        ]

        # Build redirect with manual_pending param if any manual platforms
        if manual_platforms:
            raise web.HTTPSeeOther(
                location=_build_query_link(
                    f"/admin/domains/{did}",
                    msg="Reports submitted - action required for manual platforms",
                    manual_pending=",".join(manual_platforms),
                )
            )
        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Reports submitted"))

    async def _admin_manual_done(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        if not self.mark_manual_done_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Not configured", error=1)
            )

        data = await self._require_csrf(request)
        note = (data.get("note") or "").strip() or "Manual submission marked complete"
        domain_name = str(domain.get("domain") or "")
        try:
            await self.mark_manual_done_callback(did, domain_name, None, note)
        except Exception as e:
            raise web.HTTPSeeOther(
                location=_build_query_link(
                    f"/admin/domains/{did}", msg=f"Failed: {e}", error=1
                )
            )
        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Updated"))

    async def _admin_rescan(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")
        await self._require_csrf(request)

        domain_name = str(domain.get("domain") or "")
        if self.rescan_callback:
            self.rescan_callback(domain_name)
            raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Rescan queued"))
        raise web.HTTPSeeOther(
            location=_build_query_link(f"/admin/domains/{did}", msg="Rescan not configured", error=1)
        )

    async def _admin_false_positive(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")
        await self._require_csrf(request)

        await self.database.update_domain_admin_fields(
            did,
            status=DomainStatus.FALSE_POSITIVE.value,
            verdict=Verdict.BENIGN.value,
            operator_notes=(domain.get("operator_notes") or ""),
        )
        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Marked false positive"))

    def _resolve_evidence(self, domain: dict) -> tuple[Path | None, str | None]:
        raw = (domain.get("evidence_path") or "").strip()
        if not raw:
            return None, None
        evidence_dir = Path(raw)

        # Evidence is served from /evidence (mounted to EVIDENCE_DIR). We expect each domain dir
        # to be a direct child; fall back to basename if paths are odd.
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
        # Prefer the main screenshot first.
        priority = {"screenshot.png": 0, "screenshot_early.png": 1, "screenshot_final.png": 2}
        return sorted(shots, key=lambda p: (priority.get(p.name, 50), p.name))

    def _get_instruction_files(self, evidence_dir: Path | None) -> list[Path]:
        if not evidence_dir:
            return []
        try:
            return sorted(evidence_dir.glob("report_instructions_*.txt"))
        except Exception:
            return []

    # -------------------------------------------------------------------------
    # Domain PDF/Package/Preview Routes
    # -------------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Admin API (JSON) endpoints for web-first interactions
    # ------------------------------------------------------------------
    async def _admin_api_stats(self, request: web.Request) -> web.Response:
        stats = await self.database.get_stats()
        stats["evidence_bytes"] = self._compute_evidence_bytes()
        stats["public_submissions_pending"] = await self.database.count_public_submissions(status="pending_review")
        pending_reports = await self.database.get_pending_reports()
        health_status = await self._fetch_health_status()
        return web.json_response(
            {"stats": stats, "pending_reports": pending_reports, "health": health_status}
        )

    async def _admin_api_domains(self, request: web.Request) -> web.Response:
        status = (request.query.get("status") or "").strip().lower()
        verdict = (request.query.get("verdict") or "").strip().lower()
        q = (request.query.get("q") or "").strip().lower()
        exclude_statuses_raw = (request.query.get("exclude_statuses") or "").strip().lower()
        limit = _coerce_int(request.query.get("limit"), default=50, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        # Parse comma-separated exclude_statuses (only used if status is not set)
        exclude_statuses = None
        if exclude_statuses_raw and not status:
            exclude_statuses = [s.strip() for s in exclude_statuses_raw.split(",") if s.strip()]

        domains = await self.database.list_domains(
            limit=limit,
            offset=offset,
            status=status or None,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
        )
        total = await self.database.count_domains(
            status=status or None,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
        )
        return web.json_response(
            {
                "domains": domains,
                "page": page,
                "limit": limit,
                "count": len(domains),
                "total": total,
            }
        )


    async def _admin_api_domain(self, request: web.Request) -> web.Response:
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")
        row = await self.database.get_domain_by_id(domain_id)
        if not row:
            raise web.HTTPNotFound(text="Domain not found")

        reports = await self.database.get_reports_for_domain(domain_id)
        evidence = {}
        infrastructure = {}
        instruction_files: list[str] = []
        cluster = self._get_cluster_for_domain(row["domain"])
        filtered_cluster = None
        if cluster:
            filtered = await self._filter_clusters([cluster])
            filtered_cluster = filtered[0] if filtered else None
        related_domains = await self._enrich_related_domains_with_ids(
            self._get_related_domains(row["domain"], filtered_cluster)
        )
        try:
            domain_dir = self.evidence_dir / _domain_dir_name(row["domain"])
            evidence["html"] = f"/evidence/{domain_dir.name}/page.html" if (domain_dir / "page.html").exists() else None
            evidence["analysis"] = f"/evidence/{domain_dir.name}/analysis.json" if (domain_dir / "analysis.json").exists() else None
            evidence["screenshots"] = [
                f"/evidence/{domain_dir.name}/{p.name}"
                for p in sorted(domain_dir.glob("screenshot*.png"))
            ]
            instruction_files = [
                f"/evidence/{domain_dir.name}/{p.name}"
                for p in self._get_instruction_files(domain_dir)
            ]
            analysis_path = domain_dir / "analysis.json"
            if analysis_path.exists():
                import json

                try:
                    data = json.loads(analysis_path.read_text())
                    infra = data.get("infrastructure") or {}
                    infrastructure = {
                        "hosting_provider": data.get("hosting_provider") or infra.get("hosting_provider"),
                        "registrar": infra.get("registrar") or data.get("registrar"),
                        "nameservers": infra.get("nameservers") or [],
                        "tls_age_days": infra.get("tls_age_days"),
                        "domain_age_days": infra.get("domain_age_days"),
                    }
                except Exception:
                    infrastructure = {}
        except Exception:
            evidence = {}

        return web.json_response(
            {
                "domain": row,
                "reports": reports,
                "evidence": evidence,
                "infrastructure": infrastructure,
                "cluster": filtered_cluster,
                "related_domains": related_domains,
                "instruction_files": instruction_files,
            }
        )

    async def _admin_api_submit(self, request: web.Request) -> web.Response:
        data = await request.json()
        target = (data.get("target") or data.get("domain") or "").strip()
        domain = _extract_hostname(target)
        if not domain:
            return web.json_response({"error": "Invalid domain/URL"}, status=400)

        existing = await self.database.get_domain(domain)
        if existing:
            if self.rescan_callback:
                self.rescan_callback(domain)
            return web.json_response({"status": "rescan_queued", "domain": domain})

        if not self.submit_callback:
            raise web.HTTPServiceUnavailable(text="Submit not configured")

        self.submit_callback(domain)
        return web.json_response({"status": "submitted", "domain": domain})

    async def _admin_api_rescan(self, request: web.Request) -> web.Response:
        domain_id = int(request.match_info.get("domain_id") or 0)
        domain = (request.match_info.get("domain") or "").strip()
        if not domain and domain_id:
            row = await self.database.get_domain_by_id(domain_id)
            domain = str(row.get("domain") or "") if row else ""
        if not domain:
            raise web.HTTPBadRequest(text="domain not found")

        if not self.rescan_callback:
            raise web.HTTPServiceUnavailable(text="Rescan not configured")
        self.rescan_callback(domain)
        return web.json_response({"status": "rescan_queued", "domain": domain})

    async def _admin_api_report(self, request: web.Request) -> web.Response:
        data = await request.json()
        domain_id = int(data.get("domain_id") or 0)
        domain = (data.get("domain") or "").strip()
        platforms_raw = data.get("platforms")
        platforms = [p.strip().lower() for p in platforms_raw] if isinstance(platforms_raw, list) else None
        force = bool(data.get("force", False))

        if not domain and domain_id:
            row = await self.database.get_domain_by_id(domain_id)
            domain = str(row.get("domain") or "") if row else ""
        if not domain_id and domain:
            row = await self.database.get_domain(domain)
            domain_id = int(row.get("id") or 0) if row else 0

        if not domain_id or not domain:
            raise web.HTTPBadRequest(text="domain_id/domain required")
        if not self.report_callback:
            raise web.HTTPServiceUnavailable(text="Report callback not configured")

        await self.report_callback(domain_id, domain, platforms, force)
        return web.json_response({"status": "report_enqueued", "domain": domain, "platforms": platforms})

    async def _admin_api_platforms(self, request: web.Request) -> web.Response:
        """Return available reporting platforms with their metadata."""
        platforms = self.get_available_platforms()
        info = self.get_platform_info()
        return web.json_response({"platforms": platforms, "info": info})

    async def _admin_api_analytics(self, request: web.Request) -> web.Response:
        """Return engagement + takedown analytics (admin-only)."""
        engagement = await self.database.get_engagement_summary()
        takedown = await self.database.get_takedown_metrics()
        return web.json_response({"engagement": engagement, "takedown": takedown})

    # -------------------------------------------------------------------------
    # Public submission + reporting APIs
    # -------------------------------------------------------------------------

    async def _public_api_submit(self, request: web.Request) -> web.Response:
        """Public endpoint to submit a suspicious domain for review."""
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON payload"}, status=400)

        # Honeypot to catch bots
        honeypot = (data.get("hp") or data.get("honeypot") or "").strip()
        if honeypot:
            return web.json_response({"status": "submitted", "message": "Thank you"})

        target = (data.get("domain") or data.get("target") or "").strip()
        if not target:
            return web.json_response({"error": "domain is required"}, status=400)

        domain = _extract_hostname(target)
        canonical = canonicalize_domain(domain)
        if not canonical:
            return web.json_response({"error": "Invalid domain/URL"}, status=400)

        if self._is_disallowed_public_host(canonical):
            return web.json_response({"error": "Local/private hosts are not allowed"}, status=400)

        client_ip = self._client_ip(request)
        if not self._rate_limit_allowed(client_ip, limit=10, window_seconds=3600):
            return web.json_response(
                {"error": "Too many submissions. Please try again later."},
                status=429,
            )

        source_url = str(data.get("source_url") or "").strip() or None
        if source_url:
            if len(source_url) > 2048:
                return web.json_response({"error": "Source URL too long"}, status=400)
            parsed = urlparse(source_url if "://" in source_url else f"https://{source_url}")
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return web.json_response({"error": "Source URL must be http(s)"}, status=400)
        reporter_notes = (data.get("notes") or "").strip()
        if reporter_notes and len(reporter_notes) > 1000:
            reporter_notes = reporter_notes[:1000]

        submission_id, duplicate = await self.database.add_public_submission(
            domain=canonical,
            canonical_domain=canonical,
            source_url=source_url,
            reporter_notes=reporter_notes or None,
        )

        message = (
            "Thank you for your submission. It will be reviewed by our team."
            if not duplicate
            else "This domain was already submitted. We've updated the count."
        )

        return web.json_response(
            {
                "status": "submitted",
                "domain": canonical,
                "submission_id": submission_id,
                "duplicate": duplicate,
                "message": message,
            }
        )

    async def _public_api_report_options(self, request: web.Request) -> web.Response:
        """Return manual report options + counters for a domain."""
        domain_id = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain = await self.database.get_domain_by_id(domain_id)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found")

        platform_info = self.get_platform_info()
        available_platforms = self.get_available_platforms()
        if not available_platforms:
            return web.json_response({"error": "No reporting platforms configured"}, status=503)

        manual_data: dict[str, dict] = {}
        if self.get_manual_report_options:
            try:
                manual_data = await self.get_manual_report_options(
                    domain_id,
                    domain.get("domain", ""),
                    available_platforms,
                )
            except Exception as e:
                raise web.HTTPServiceUnavailable(text=f"Manual instructions unavailable: {e}")
        else:
            raise web.HTTPServiceUnavailable(text="Manual instructions not configured")

        engagement_counts = await self.database.get_report_engagement_counts(domain_id)
        total_engagements = sum(engagement_counts.get(p, 0) for p in manual_data.keys())

        entries = []
        for platform in manual_data.keys():
            info = platform_info.get(platform, {}) if isinstance(platform_info, dict) else {}
            raw_instruction = manual_data.get(platform)
            instructions = None
            error = None
            if isinstance(raw_instruction, dict):
                if set(raw_instruction.keys()) == {"error"}:
                    error = str(raw_instruction.get("error"))
                else:
                    instructions = raw_instruction
            entries.append(
                {
                    "id": platform,
                    "name": info.get("name") or " ".join(part.capitalize() for part in platform.split("_")),
                    "manual_only": bool(info.get("manual_only", True)),
                    "url": info.get("url", ""),
                    "engagement_count": engagement_counts.get(platform, 0),
                    "instructions": instructions,
                    "error": error,
                }
            )

        return web.json_response(
            {
                "domain": domain.get("domain"),
                "domain_id": domain_id,
                "platforms": entries,
                "total_engagements": total_engagements,
            }
        )

    async def _public_api_report_engagement(self, request: web.Request) -> web.Response:
        """Record a public report click/engagement with cooldown."""
        domain_id = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain = await self.database.get_domain_by_id(domain_id)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found")

        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON payload"}, status=400)

        platform = (data.get("platform") or "").strip().lower()
        if not platform:
            return web.json_response({"error": "platform is required"}, status=400)

        available_platforms = {p.strip().lower() for p in self.get_available_platforms()}
        if platform not in available_platforms:
            return web.json_response({"error": "Unknown platform"}, status=400)

        session_hash = self._session_hash(request)
        count, cooldown = await self.database.record_report_engagement(
            domain_id=domain_id,
            platform=platform,
            session_hash=session_hash,
            cooldown_hours=24,
        )

        return web.json_response(
            {
                "status": "cooldown" if cooldown else "recorded",
                "platform": platform,
                "new_count": count,
                "message": "You've already reported recently." if cooldown else "Thank you for reporting!",
            }
        )

    # -------------------------------------------------------------------------
    # Admin submission review APIs
    # -------------------------------------------------------------------------

    async def _admin_api_submissions(self, request: web.Request) -> web.Response:
        status = (request.query.get("status") or "pending_review").strip() or None
        limit = _coerce_int(request.query.get("limit"), default=100, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        submissions = await self.database.get_public_submissions(status=status, limit=limit, offset=offset)
        total = await self.database.count_public_submissions(status=status)
        total_pending = await self.database.count_public_submissions(status="pending_review")

        return web.json_response(
            {
                "submissions": submissions,
                "page": page,
                "limit": limit,
                "count": len(submissions),
                "total": total,
                "total_pending": total_pending,
            }
        )

    async def _admin_api_submission(self, request: web.Request) -> web.Response:
        submission_id = _coerce_int(request.match_info.get("submission_id"), default=0, min_value=1)
        if not submission_id:
            raise web.HTTPBadRequest(text="submission_id required")
        submission = await self.database.get_public_submission(submission_id)
        if not submission:
            raise web.HTTPNotFound(text="Submission not found")
        return web.json_response({"submission": submission})

    async def _admin_api_approve_submission(self, request: web.Request) -> web.Response:
        submission_id = _coerce_int(request.match_info.get("submission_id"), default=0, min_value=1)
        if not submission_id:
            raise web.HTTPBadRequest(text="submission_id required")

        submission = await self.database.get_public_submission(submission_id)
        if not submission:
            raise web.HTTPNotFound(text="Submission not found")

        if str(submission.get("status") or "").strip().lower() != "pending_review":
            return web.json_response({"error": "Submission already reviewed"}, status=400)

        try:
            data = await request.json()
        except Exception:
            data = {}
        reviewer_notes = (data.get("notes") or "").strip()
        if reviewer_notes and len(reviewer_notes) > 1000:
            reviewer_notes = reviewer_notes[:1000]

        domain_value = (submission.get("canonical_domain") or submission.get("domain") or "").strip()
        canonical = canonicalize_domain(domain_value)
        if not canonical:
            return web.json_response({"error": "Invalid domain"}, status=400)

        existing = await self.database.get_domain_by_canonical(canonical)
        if existing:
            await self.database.update_public_submission_status(
                submission_id=submission_id,
                status="duplicate",
                reviewer_notes=reviewer_notes or "Already tracked",
                promoted_domain_id=int(existing.get("id") or 0),
            )
            return web.json_response(
                {
                    "status": "duplicate",
                    "domain": existing.get("domain"),
                    "domain_id": existing.get("id"),
                }
            )

        # Create domain and queue for analysis
        domain_id = await self.database.add_domain(
            domain=canonical,
            source="public_submission",
            domain_score=0,
        )

        if not domain_id:
            existing = await self.database.get_domain_by_canonical(canonical)
            domain_id = int(existing.get("id") or 0) if existing else 0

        if not domain_id:
            return web.json_response({"error": "Failed to create domain"}, status=500)

        if not self.submit_callback:
            raise web.HTTPServiceUnavailable(text="Submit callback not configured")

        self.submit_callback(canonical)
        await self.database.update_public_submission_status(
            submission_id=submission_id,
            status="approved",
            reviewer_notes=reviewer_notes or None,
            promoted_domain_id=domain_id,
        )

        return web.json_response(
            {"status": "approved", "domain": canonical, "domain_id": domain_id}
        )

    async def _admin_api_reject_submission(self, request: web.Request) -> web.Response:
        submission_id = _coerce_int(request.match_info.get("submission_id"), default=0, min_value=1)
        if not submission_id:
            raise web.HTTPBadRequest(text="submission_id required")

        submission = await self.database.get_public_submission(submission_id)
        if not submission:
            raise web.HTTPNotFound(text="Submission not found")

        if str(submission.get("status") or "").strip().lower() != "pending_review":
            return web.json_response({"error": "Submission already reviewed"}, status=400)

        try:
            data = await request.json()
        except Exception:
            data = {}

        reason = (data.get("reason") or "rejected").strip().lower()
        notes = (data.get("notes") or "").strip()
        if notes and len(notes) > 1000:
            notes = notes[:1000]

        await self.database.update_public_submission_status(
            submission_id=submission_id,
            status=reason or "rejected",
            reviewer_notes=notes or None,
            promoted_domain_id=None,
        )
        return web.json_response({"status": "rejected", "reason": reason})

    async def _admin_api_false_positive(self, request: web.Request) -> web.Response:
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")
        await self.database.mark_false_positive(domain_id)
        return web.json_response({"status": "ok"})

    async def _admin_api_update_domain_status(self, request: web.Request) -> web.Response:
        """Update domain status (PATCH /admin/api/domains/{domain_id}/status)."""
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        data = await request.json()
        new_status = (data.get("status") or "").strip().lower()

        # Validate status
        valid_statuses = {s.value for s in DomainStatus}
        if new_status not in valid_statuses:
            return web.json_response(
                {"error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"},
                status=400,
            )

        # Update via database
        await self.database.update_domain_status(domain_id, DomainStatus(new_status))
        return web.json_response({"status": "ok", "new_status": new_status})

    async def _admin_api_update_baseline(self, request: web.Request) -> web.Response:
        """Update watchlist baseline to current snapshot (POST /admin/api/domains/{domain_id}/baseline)."""
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        # Get domain record
        domain_record = await self.database.get_domain_by_id(domain_id)
        if not domain_record:
            return web.json_response(
                {"error": "Domain not found"},
                status=404
            )

        # Verify domain is watchlist status
        if domain_record.get("status") != "watchlist":
            return web.json_response(
                {"error": "Domain must be in watchlist status to update baseline"},
                status=400
            )

        # Update baseline
        new_baseline = await self.database.update_watchlist_baseline(domain_id)

        if not new_baseline:
            return web.json_response(
                {"error": "Failed to update baseline"},
                status=500
            )

        # Get latest snapshot for response
        domain_name = domain_record.get("domain")
        latest_snapshot = self.temporal.get_latest_snapshot(domain_name)

        response_data = {
            "status": "ok",
            "baseline_timestamp": new_baseline,
        }

        if latest_snapshot:
            response_data["snapshot"] = {
                "score": latest_snapshot.score,
                "verdict": latest_snapshot.verdict,
                "timestamp": latest_snapshot.timestamp.isoformat(),
            }

        return web.json_response(response_data)

    async def _admin_api_evidence(self, request: web.Request) -> web.Response:
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")
        row = await self.database.get_domain_by_id(domain_id)
        if not row:
            raise web.HTTPNotFound(text="Domain not found")

        domain_dir = self.evidence_dir / _domain_dir_name(row["domain"])
        files: list[dict] = []
        if domain_dir.exists():
            for p in sorted(domain_dir.glob("**/*")):
                if p.is_file():
                    files.append({
                        "path": f"/evidence/{_domain_dir_name(row['domain'])}/{p.relative_to(domain_dir)}",
                        "size": p.stat().st_size,
                    })
        return web.json_response({"files": files})

    async def _admin_api_clusters(self, request: web.Request) -> web.Response:
        clusters = await self._filter_clusters(self._load_clusters())
        return web.json_response({"clusters": clusters})

    async def _admin_api_cluster(self, request: web.Request) -> web.Response:
        cluster_id = (request.match_info.get("cluster_id") or "").strip()
        if not cluster_id:
            raise web.HTTPBadRequest(text="campaign_id required")
        clusters = await self._filter_clusters(self._load_clusters())
        cluster = next((c for c in clusters if str(c.get("cluster_id")) == cluster_id), None)
        if not cluster:
            raise web.HTTPNotFound(text="Campaign not found")
        enriched = await self._enrich_related_domains_with_ids(cluster.get("members", []))
        return web.json_response({"cluster": cluster, "domains": enriched})

    async def _admin_api_update_notes(self, request: web.Request) -> web.Response:
        """Update operator notes for a domain (PATCH /admin/api/domains/{domain_id}/notes)."""
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain = await self.database.get_domain_by_id(domain_id)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found")

        data = await request.json()
        notes = data.get("notes", "")

        # Update notes via database
        await self.database.update_domain_admin_fields(
            domain_id,
            operator_notes=notes,
        )
        return web.json_response({"status": "ok"})

    async def _admin_api_update_cluster_name(self, request: web.Request) -> web.Response:
        """Update campaign name (PATCH /admin/api/clusters/{cluster_id}/name)."""
        cluster_id = (request.match_info.get("cluster_id") or "").strip()
        if not cluster_id:
            raise web.HTTPBadRequest(text="campaign_id required")

        data = await request.json()
        new_name = (data.get("name") or "").strip()
        if not new_name:
            return web.json_response({"error": "Name cannot be empty"}, status=400)

        # Load clusters, update, and save
        if not self.clusters_dir:
            return web.json_response({"error": "Campaigns not configured"}, status=500)

        clusters_file = self.clusters_dir / "clusters.json"
        if not clusters_file.exists():
            raise web.HTTPNotFound(text="Campaign file not found")

        try:
            with open(clusters_file, "r") as f:
                data_file = json.load(f)

            clusters = data_file.get("clusters", [])
            found = False
            for cluster in clusters:
                if str(cluster.get("cluster_id")) == cluster_id or str(cluster.get("cluster_id", "")).startswith(cluster_id):
                    cluster["name"] = new_name
                    cluster["updated_at"] = datetime.now().isoformat()
                    found = True
                    break

            if not found:
                raise web.HTTPNotFound(text="Campaign not found")

            # Save back
            data_file["saved_at"] = datetime.now().isoformat()
            with open(clusters_file, "w") as f:
                json.dump(data_file, f, indent=2)

            return web.json_response({"status": "ok", "name": new_name})
        except web.HTTPNotFound:
            raise
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def _admin_domain_pdf(self, request: web.Request) -> web.Response:
        """Generate and download PDF report for a domain."""
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        if not self.generate_domain_pdf_callback:
            raise web.HTTPServiceUnavailable(text="PDF generation not configured.")

        domain_name = str(domain.get("domain") or "")
        try:
            report_path = await self.generate_domain_pdf_callback(domain_name, did)
            if not report_path or not report_path.exists():
                raise web.HTTPServiceUnavailable(text="PDF generation failed or unavailable.")

            return web.FileResponse(
                report_path,
                headers={
                    "Content-Disposition": (
                        f'attachment; filename="{domain_name.replace(".", "_")}_report{report_path.suffix}"'
                    )
                },
            )
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"PDF generation failed: {e}")

    async def _admin_domain_package(self, request: web.Request) -> web.Response:
        """Generate and download evidence archive for a domain."""
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        if not self.generate_domain_package_callback:
            raise web.HTTPServiceUnavailable(text="Package generation not configured.")

        domain_name = str(domain.get("domain") or "")
        try:
            archive_path = await self.generate_domain_package_callback(domain_name, did)
            if not archive_path or not archive_path.exists():
                raise web.HTTPServiceUnavailable(text="Archive generation failed.")

            return web.FileResponse(
                archive_path,
                headers={
                    "Content-Disposition": f'attachment; filename="{archive_path.name}"'
                },
            )
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"Package generation failed: {e}")

    async def _admin_domain_preview(self, request: web.Request) -> web.Response:
        """Dry-run report submission for a domain (sends to operator's email)."""
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        await self._require_csrf(request)

        if not self.preview_domain_report_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Preview not configured", error=1)
            )

        domain_name = str(domain.get("domain") or "")
        try:
            await self.preview_domain_report_callback(did, domain_name)
        except Exception as e:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg=f"Preview failed: {e}", error=1)
            )

        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Preview sent to your email"))

    # -------------------------------------------------------------------------
    # Campaign Detail and Reporting Routes
    # -------------------------------------------------------------------------

    def _get_cluster_by_id(self, cluster_id: str) -> dict | None:
        """Get a specific campaign by ID (supports prefix matching)."""
        clusters = self._load_clusters()
        for cluster in clusters:
            cid = cluster.get("cluster_id", "")
            if cid == cluster_id or cid.startswith(cluster_id):
                return cluster
        return None

    async def _admin_cluster_detail(self, request: web.Request) -> web.Response:
        """Show detailed threat campaign view with action buttons."""
        cluster_id = request.match_info.get("cluster_id", "")
        clusters = await self._filter_clusters(self._load_clusters())
        cluster = next(
            (
                c for c in clusters
                if str(c.get("cluster_id")) == cluster_id or str(c.get("cluster_id", "")).startswith(cluster_id)
            ),
            None,
        )
        if not cluster:
            raise web.HTTPNotFound(text="Campaign not found.")

        enriched_members = await self._enrich_related_domains_with_ids(cluster.get("members", []))
        cluster = dict(cluster)
        cluster["members"] = enriched_members

        msg = request.query.get("msg")
        error = request.query.get("error") == "1"

        body = _render_cluster_detail(cluster, admin=True)
        html_out = _layout(
            title=f"Campaign: {cluster.get('name', 'Unknown')}",
            body=_flash(msg, error=error) + body,
            admin=True,
        )

        resp = web.Response(text=html_out, content_type="text/html")
        csrf = self._get_or_set_csrf(request, resp)
        resp.text = resp.text.replace("__SET_COOKIE__", csrf)
        return resp

    async def _admin_cluster_pdf(self, request: web.Request) -> web.Response:
        """Generate and download PDF report for a campaign."""
        cluster_id = request.match_info.get("cluster_id", "")
        cluster = self._get_cluster_by_id(cluster_id)
        if not cluster:
            raise web.HTTPNotFound(text="Campaign not found.")

        if not self.generate_campaign_pdf_callback:
            raise web.HTTPServiceUnavailable(text="PDF generation not configured.")

        full_cluster_id = cluster.get("cluster_id", cluster_id)
        try:
            report_path = await self.generate_campaign_pdf_callback(full_cluster_id)
            if not report_path or not report_path.exists():
                raise web.HTTPServiceUnavailable(text="PDF generation failed or unavailable.")

            cluster_name = cluster.get("name", "campaign").replace(" ", "_")
            return web.FileResponse(
                report_path,
                headers={
                    "Content-Disposition": f'attachment; filename="{cluster_name}_report{report_path.suffix}"'
                },
            )
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"PDF generation failed: {e}")

    async def _admin_cluster_package(self, request: web.Request) -> web.Response:
        """Generate and download evidence archive for a campaign."""
        cluster_id = request.match_info.get("cluster_id", "")
        cluster = self._get_cluster_by_id(cluster_id)
        if not cluster:
            raise web.HTTPNotFound(text="Campaign not found.")

        if not self.generate_campaign_package_callback:
            raise web.HTTPServiceUnavailable(text="Package generation not configured.")

        full_cluster_id = cluster.get("cluster_id", cluster_id)
        try:
            archive_path = await self.generate_campaign_package_callback(full_cluster_id)
            if not archive_path or not archive_path.exists():
                raise web.HTTPServiceUnavailable(text="Archive generation failed.")

            return web.FileResponse(
                archive_path,
                headers={
                    "Content-Disposition": f'attachment; filename="{archive_path.name}"'
                },
            )
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"Package generation failed: {e}")

    async def _admin_cluster_preview(self, request: web.Request) -> web.Response:
        """Dry-run campaign report submission (sends to operator's email)."""
        cluster_id = request.match_info.get("cluster_id", "")
        cluster = self._get_cluster_by_id(cluster_id)
        if not cluster:
            raise web.HTTPNotFound(text="Campaign not found.")

        await self._require_csrf(request)

        if not self.preview_campaign_report_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/clusters/{cluster_id}", msg="Preview not configured", error=1)
            )

        full_cluster_id = cluster.get("cluster_id", cluster_id)
        try:
            await self.preview_campaign_report_callback(full_cluster_id)
        except Exception as e:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/clusters/{cluster_id}", msg=f"Preview failed: {e}", error=1)
            )

        raise web.HTTPSeeOther(
            location=_build_query_link(f"/admin/clusters/{cluster_id}", msg="Preview sent to your email")
        )

    async def _admin_cluster_submit(self, request: web.Request) -> web.Response:
        """Submit campaign reports to all platforms."""
        cluster_id = request.match_info.get("cluster_id", "")
        cluster = self._get_cluster_by_id(cluster_id)
        if not cluster:
            raise web.HTTPNotFound(text="Campaign not found.")

        await self._require_csrf(request)

        if not self.submit_campaign_report_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/clusters/{cluster_id}", msg="Submit not configured", error=1)
            )

        full_cluster_id = cluster.get("cluster_id", cluster_id)
        try:
            await self.submit_campaign_report_callback(full_cluster_id)
        except Exception as e:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/clusters/{cluster_id}", msg=f"Submit failed: {e}", error=1)
            )

        raise web.HTTPSeeOther(
            location=_build_query_link(f"/admin/clusters/{cluster_id}", msg="Reports submitted to all platforms")
        )
