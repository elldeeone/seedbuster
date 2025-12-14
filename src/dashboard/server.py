"""A tiny aiohttp-powered dashboard (public + admin views).

This is intentionally simple: server-rendered HTML, SQLite-backed, no JS framework.
"""

from __future__ import annotations

import base64
import html
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import quote, urlencode, urlparse

from aiohttp import web

from ..storage.database import Database, DomainStatus, Verdict


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


def _layout(*, title: str, body: str, admin: bool) -> str:
    # Only show navigation toggle in admin view - public view has no admin reference
    nav = ""
    if admin:
        nav = '<a class="nav-link" href="/">Public View</a>'

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
        --text-secondary: #8b949e;
        --text-tertiary: #6e7681;
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
        --accent-gray: #6e7681;
        --accent-gray-subtle: rgba(110, 118, 129, 0.15);

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
      .sb-badge-deferred {{ background: var(--accent-orange-subtle); color: var(--accent-orange); }}
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
        content: '✓';
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
  </head>
  <body>
    <div class="sb-container">
      <header class="sb-header">
        <div class="sb-brand">
          <div class="sb-logo">
            <div class="sb-logo-icon">SB</div>
            <span class="sb-logo-text">SeedBuster</span>
          </div>
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
    icon = "✕" if error else "✓"
    return f'<div class="{cls}"><span>{icon}</span><span>{_escape(msg)}</span></div>'


def _build_query_link(base: str, **params: object) -> str:
    clean = {k: v for k, v in params.items() if v not in (None, "", [], False)}
    if not clean:
        return base
    return f"{base}?{urlencode(clean, doseq=True)}"


def _render_stats(stats: dict) -> str:
    by_status = stats.get("by_status") or {}
    by_verdict = stats.get("by_verdict") or {}

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
      </div>
    """


def _render_domains_table(domains: list[dict], *, admin: bool) -> str:
    if not domains:
        return '''
          <div class="sb-panel">
            <div class="sb-muted" style="text-align: center; padding: 32px;">
              No domains found matching your criteria.
            </div>
          </div>
        '''

    rows = []
    for d in domains:
        did = d.get("id")
        domain = d.get("domain") or ""
        href = f"/admin/domains/{did}" if admin else f"/domains/{did}"
        domain_score = d.get("domain_score")
        analysis_score = d.get("analysis_score")

        rows.append(
            "<tr>"
            f'<td class="domain-cell" title="{_escape(domain)}"><a class="domain-link" href="{_escape(href)}">{_escape(domain)}</a></td>'
            f"<td>{_status_badge(str(d.get('status') or ''))}</td>"
            f"<td>{_verdict_badge(d.get('verdict'))}</td>"
            f'<td><span class="sb-score">{_escape(domain_score) if domain_score is not None else "—"}</span></td>'
            f'<td><span class="sb-score">{_escape(analysis_score) if analysis_score is not None else "—"}</span></td>'
            f'<td class="sb-muted">{_escape(d.get("source") or "—")}</td>'
            f'<td class="sb-muted">{_escape(d.get("first_seen") or "—")}</td>'
            "</tr>"
        )

    return f"""
      <div class="sb-panel">
        <div class="sb-panel-header">
          <span class="sb-panel-title">Tracked Domains</span>
          <span class="sb-muted">{len(domains)} results</span>
        </div>
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
              </tr>
            </thead>
            <tbody>
              {''.join(rows)}
            </tbody>
          </table>
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
            f'<td class="sb-muted">{_escape(next_attempt_at) or "—"}</td>'
            "</tr>"
        )

    return f"""
      <div class="sb-panel" style="border-color: rgba(240, 136, 62, 0.3); margin-bottom: 24px;">
        <div class="sb-panel-header" style="border-color: rgba(240, 136, 62, 0.2);">
          <span class="sb-panel-title" style="color: var(--accent-orange);">⚠ Reports Needing Attention</span>
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


def _render_filters(*, status: str, verdict: str, q: str, admin: bool, limit: int, page: int) -> str:
    action = "/admin" if admin else "/"
    return f"""
      <div class="sb-panel" style="margin-bottom: 16px;">
        <div class="sb-panel-header">
          <span class="sb-panel-title">Filters</span>
        </div>
        <form method="get" action="{_escape(action)}">
          <div class="sb-grid">
            <div class="col-3">
              <label class="sb-label">Status</label>
              <select class="sb-select" name="status">
                <option value="" {"selected" if not status else ""}>All Statuses</option>
                {''.join(
                    f'<option value="{_escape(s.value)}" {"selected" if status == s.value else ""}>{_escape(s.value)}</option>'
                    for s in DomainStatus
                )}
              </select>
            </div>
            <div class="col-3">
              <label class="sb-label">Verdict</label>
              <select class="sb-select" name="verdict">
                <option value="" {"selected" if not verdict else ""}>All Verdicts</option>
                {''.join(
                    f'<option value="{_escape(v.value)}" {"selected" if verdict == v.value else ""}>{_escape(v.value)}</option>'
                    for v in Verdict
                )}
              </select>
            </div>
            <div class="col-3">
              <label class="sb-label">Search</label>
              <input class="sb-input" type="text" name="q" value="{_escape(q)}" placeholder="domain contains…" />
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
      </div>
    """


def _render_pagination(*, status: str, verdict: str, q: str, limit: int, page: int, got: int, admin: bool) -> str:
    if page < 1:
        page = 1
    prev_link = ""
    if page > 1:
        prev_link = _build_query_link(
            "/admin" if admin else "/",
            status=status,
            verdict=verdict,
            q=q,
            limit=limit,
            page=page - 1,
        )
        prev_link = f'<a class="sb-btn" href="{_escape(prev_link)}">← Previous</a>'

    next_link = ""
    if got >= limit:
        next_link = _build_query_link(
            "/admin" if admin else "/",
            status=status,
            verdict=verdict,
            q=q,
            limit=limit,
            page=page + 1,
        )
        next_link = f'<a class="sb-btn" href="{_escape(next_link)}">Next →</a>'

    if not prev_link and not next_link:
        return ""

    return f"""
      <div class="sb-pagination">
        <div class="sb-page-info">Page {page}</div>
        <div class="sb-row">{prev_link}{next_link}</div>
      </div>
    """


def _render_kv_table(items: Iterable[tuple[str, object]]) -> str:
    rows = []
    for k, v in items:
        value = "" if v is None else str(v)
        rows.append(f"<tr><th>{_escape(k)}</th><td>{_escape(value) or '—'}</td></tr>")
    return f"""
      <div class="sb-panel">
        <table class="sb-kv-table" style="width: 100%;">
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    """


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
) -> str:
    did = domain.get("id")
    domain_name = domain.get("domain") or ""

    # Header action buttons - no admin link in public view
    header_links = []
    header_links.append(f'<a class="sb-btn" href="{_escape("/admin" if admin else "/")}">← Back</a>')
    if admin:
        header_links.append(f'<a class="sb-btn" href="{_escape(f"/domains/{did}")}">Public View</a>')

    open_url = f"https://{domain_name}"
    header_links.append(f'<a class="sb-btn" href="{_escape(open_url)}" target="_blank" rel="noreferrer">Visit Site ↗</a>')

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
              <span class="sb-muted"><code class="sb-code">{_escape(str(evidence_dir) if evidence_dir else "—")}</code></span>
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
    for r in reports:
        reports_rows.append(
            "<tr>"
            f"<td>{_escape(r.get('platform') or '')}</td>"
            f"<td>{_report_badge(r.get('status'))}</td>"
            f'<td class="sb-muted">{_escape(r.get("attempts") or 0)}</td>'
            f'<td class="sb-muted">{_escape(r.get("attempted_at") or "—")}</td>'
            f'<td class="sb-muted">{_escape(r.get("submitted_at") or "—")}</td>'
            f'<td class="sb-muted">{_escape(r.get("next_attempt_at") or "—")}</td>'
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

        platform_checks = []
        for p in available_platforms:
            platform_checks.append(
                f'<label style="display:flex;gap:10px;align-items:center;padding:8px 0;font-family:var(--font-mono);font-size:12px;color:var(--text-secondary);cursor:pointer;">'
                f'<input type="checkbox" name="platform" value="{_escape(p)}" checked />'
                f'<span>{_escape(p)}</span>'
                f"</label>"
            )

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
                  <div class="sb-row" style="margin-bottom: 12px;">
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
                  <div class="sb-action-card-title">Submit Reports</div>
                  <form method="post" action="/admin/domains/{_escape(did)}/report">
                    <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                    <div style="max-height:140px;overflow:auto;border:1px solid var(--border-default);border-radius:var(--radius-md);padding:4px 12px;margin-bottom:12px;background:var(--bg-elevated);">
                      {''.join(platform_checks) if platform_checks else '<div class="sb-muted" style="padding: 12px 0;">No configured reporters.</div>'}
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
    reasons_html = f'<pre class="sb-pre">{_escape(reasons)}</pre>' if reasons else '<div class="sb-muted">—</div>'
    notes_html = f'<pre class="sb-pre">{_escape(notes)}</pre>' if notes else '<div class="sb-muted">—</div>'

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


class DashboardServer:
    """Runs a small aiohttp server with public and admin dashboards."""

    def __init__(
        self,
        *,
        config: DashboardConfig,
        database: Database,
        evidence_dir: Path,
        submit_callback: Callable[[str], None] | None = None,
        rescan_callback: Callable[[str], None] | None = None,
        report_callback: Callable[[int, str, Optional[list[str]], bool], object] | None = None,
        mark_manual_done_callback: Callable[[int, str, Optional[list[str]], str], object] | None = None,
        get_available_platforms: Callable[[], list[str]] | None = None,
    ):
        self.config = config
        self.database = database
        self.evidence_dir = evidence_dir
        self.submit_callback = submit_callback
        self.rescan_callback = rescan_callback
        self.report_callback = report_callback
        self.mark_manual_done_callback = mark_manual_done_callback
        self.get_available_platforms = get_available_platforms or (lambda: [])

        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

        self._app = web.Application(middlewares=[self._admin_auth_middleware])
        self._register_routes()

    def _register_routes(self) -> None:
        self._app.router.add_get("/", self._public_index)
        self._app.router.add_get("/domains/{domain_id}", self._public_domain)
        self._app.router.add_get("/healthz", self._healthz)

        # Evidence directory is public by design for transparency.
        self._app.router.add_static("/evidence", str(self.evidence_dir), show_index=False)

        # Admin
        self._app.router.add_get("/admin", self._admin_index)
        self._app.router.add_post("/admin/submit", self._admin_submit)
        self._app.router.add_get("/admin/domains/{domain_id}", self._admin_domain)
        self._app.router.add_post("/admin/domains/{domain_id}/update", self._admin_update_domain)
        self._app.router.add_post("/admin/domains/{domain_id}/report", self._admin_report_domain)
        self._app.router.add_post("/admin/domains/{domain_id}/manual_done", self._admin_manual_done)
        self._app.router.add_post("/admin/domains/{domain_id}/rescan", self._admin_rescan)
        self._app.router.add_post("/admin/domains/{domain_id}/false_positive", self._admin_false_positive)

    @web.middleware
    async def _admin_auth_middleware(self, request: web.Request, handler):  # type: ignore[override]
        if not request.path.startswith("/admin"):
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
        status = (request.query.get("status") or "").strip().lower()
        verdict = (request.query.get("verdict") or "").strip().lower()
        q = (request.query.get("q") or "").strip().lower()
        limit = _coerce_int(request.query.get("limit"), default=100, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        stats = await self.database.get_stats()
        domains = await self.database.list_domains(
            limit=limit,
            offset=offset,
            status=status or None,
            verdict=verdict or None,
            query=q or None,
        )
        pending_reports = await self.database.get_pending_reports()

        body = (
            _flash(request.query.get("msg"))
            + _render_stats(stats)
            + _render_pending_reports(pending_reports, admin=False)
            + _render_filters(status=status, verdict=verdict, q=q, admin=False, limit=limit, page=page)
            + _render_domains_table(domains, admin=False)
            + _render_pagination(
                status=status,
                verdict=verdict,
                q=q,
                limit=limit,
                page=page,
                got=len(domains),
                admin=False,
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
        )
        html_out = _layout(title="SeedBuster Dashboard", body=body, admin=False)
        return web.Response(text=html_out, content_type="text/html")

    async def _admin_index(self, request: web.Request) -> web.Response:
        status = (request.query.get("status") or "").strip().lower()
        verdict = (request.query.get("verdict") or "").strip().lower()
        q = (request.query.get("q") or "").strip().lower()
        limit = _coerce_int(request.query.get("limit"), default=100, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        stats = await self.database.get_stats()
        domains = await self.database.list_domains(
            limit=limit,
            offset=offset,
            status=status or None,
            verdict=verdict or None,
            query=q or None,
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
            <form method="post" action="/admin/submit">
              <input type="hidden" name="csrf" value="__SET_COOKIE__" />
              <div class="sb-row">
                <input class="sb-input" type="text" name="target" placeholder="example.com or https://example.com/path" style="flex: 1;" />
                <button class="sb-btn sb-btn-primary" type="submit">Submit / Rescan</button>
              </div>
            </form>
          </div>
        """

        html_out = _layout(
            title="SeedBuster Dashboard",
            body=(
                _flash(msg, error=error)
                + _render_stats(stats)
                + submit_panel
                + _render_pending_reports(pending_reports, admin=True)
                + _render_filters(status=status, verdict=verdict, q=q, admin=True, limit=limit, page=page)
                + _render_domains_table(domains, admin=True)
                + _render_pagination(
                    status=status,
                    verdict=verdict,
                    q=q,
                    limit=limit,
                    page=page,
                    got=len(domains),
                    admin=True,
                )
            ),
            admin=True,
        )
        resp = web.Response(text=html_out, content_type="text/html")
        csrf = self._get_or_set_csrf(request, resp)
        resp.text = resp.text.replace("__SET_COOKIE__", csrf)
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

        msg = request.query.get("msg")
        error = request.query.get("error") == "1"

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
                ),
                admin=True,
            ),
            content_type="text/html",
        )
        csrf = self._get_or_set_csrf(request, resp)

        # Patch in csrf token without templating engine.
        resp.text = resp.text.replace("__SET_COOKIE__", csrf)
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

        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Report submitted"))

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
