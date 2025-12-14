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
    color = {
        DomainStatus.PENDING.value: "#f59e0b",
        DomainStatus.ANALYZING.value: "#3b82f6",
        DomainStatus.ANALYZED.value: "#64748b",
        DomainStatus.DEFERRED.value: "#f97316",
        DomainStatus.REPORTED.value: "#22c55e",
        DomainStatus.FALSE_POSITIVE.value: "#94a3b8",
        DomainStatus.ALLOWLISTED.value: "#14b8a6",
    }.get(status, "#9ca3af")
    return f'<span class="badge" style="background:{color}">{_escape(status)}</span>'


def _verdict_badge(value: str | None) -> str:
    verdict = (value or "").strip().lower()
    if not verdict:
        return '<span class="badge" style="background:#9ca3af">unknown</span>'
    color = {
        Verdict.HIGH.value: "#ef4444",
        Verdict.MEDIUM.value: "#f97316",
        Verdict.LOW.value: "#eab308",
        Verdict.BENIGN.value: "#22c55e",
    }.get(verdict, "#9ca3af")
    return f'<span class="badge" style="background:{color}">{_escape(verdict)}</span>'


def _report_badge(value: str | None) -> str:
    status = (value or "").strip().lower() or "unknown"
    color = {
        "submitted": "#22c55e",
        "confirmed": "#22c55e",
        "duplicate": "#22c55e",
        "pending": "#f59e0b",
        "manual_required": "#f97316",
        "rate_limited": "#3b82f6",
        "failed": "#ef4444",
        "skipped": "#94a3b8",
        "rejected": "#64748b",
    }.get(status, "#9ca3af")
    return f'<span class="badge" style="background:{color}">{_escape(status)}</span>'


def _layout(*, title: str, body: str, admin: bool) -> str:
    nav = (
        '<a href="/">Public</a>'
        + '<span class="sep">·</span>'
        + ('<a class="active" href="/admin">Admin</a>' if admin else '<a href="/admin">Admin</a>')
    )
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>{_escape(title)}</title>
    <style>
      :root {{
        --bg: #0b1220;
        --panel: #101a2e;
        --text: #e5e7eb;
        --muted: #94a3b8;
        --border: #22314d;
        --link: #93c5fd;
      }}
      body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; background: var(--bg); color: var(--text); }}
      a {{ color: var(--link); text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}
      .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
      header {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 16px; }}
      .title {{ font-weight: 700; letter-spacing: 0.2px; }}
      .nav a {{ padding: 6px 10px; border-radius: 10px; border: 1px solid transparent; }}
      .nav a.active {{ background: rgba(147, 197, 253, 0.12); border-color: rgba(147, 197, 253, 0.35); }}
      .sep {{ margin: 0 6px; color: var(--muted); }}
      .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 14px; margin: 14px 0; }}
      .grid {{ display: grid; grid-template-columns: repeat(12, 1fr); gap: 12px; }}
      .col-12 {{ grid-column: span 12; }}
      .col-8 {{ grid-column: span 8; }}
      .col-6 {{ grid-column: span 6; }}
      .col-4 {{ grid-column: span 4; }}
      .col-3 {{ grid-column: span 3; }}
      @media (max-width: 980px) {{
        .col-8, .col-6, .col-4, .col-3 {{ grid-column: span 12; }}
      }}
      table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 10px; }}
      th, td {{ text-align: left; padding: 10px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
      th {{ color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
      tr:hover td {{ background: rgba(148, 163, 184, 0.06); }}
      .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; color: #0b1220; font-weight: 700; }}
      .muted {{ color: var(--muted); }}
      .row {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
      .row > * {{ flex: 0 0 auto; }}
      input[type="text"], input[type="password"], select, textarea {{
        width: 100%;
        padding: 9px 10px;
        border-radius: 10px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,0.03);
        color: var(--text);
        outline: none;
      }}
      textarea {{ min-height: 90px; resize: vertical; }}
      label {{ display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }}
      .btn {{
        display: inline-block;
        padding: 9px 12px;
        border-radius: 10px;
        border: 1px solid rgba(255,255,255,0.12);
        background: rgba(255,255,255,0.06);
        color: var(--text);
        cursor: pointer;
        font-weight: 600;
      }}
      .btn:hover {{ background: rgba(255,255,255,0.10); }}
      .btn.danger {{ border-color: rgba(239, 68, 68, 0.5); background: rgba(239, 68, 68, 0.14); }}
      .btn.primary {{ border-color: rgba(147, 197, 253, 0.5); background: rgba(147, 197, 253, 0.14); }}
      code {{ background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 8px; }}
      .flash {{ padding: 10px 12px; border-radius: 12px; border: 1px solid rgba(34,197,94,0.35); background: rgba(34,197,94,0.08); }}
      .flash.error {{ border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.08); }}
      .images {{ display: grid; grid-template-columns: repeat(12, 1fr); gap: 10px; }}
      .shot {{ grid-column: span 6; background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 12px; padding: 10px; }}
      .shot img {{ width: 100%; border-radius: 10px; border: 1px solid rgba(255,255,255,0.08); }}
      .shot .cap {{ margin-top: 8px; font-size: 12px; color: var(--muted); }}
      @media (max-width: 980px) {{
        .shot {{ grid-column: span 12; }}
      }}
    </style>
  </head>
  <body>
    <div class="container">
      <header>
        <div class="title">{_escape(title)}</div>
        <div class="nav">{nav}</div>
      </header>
      {body}
      <div class="muted" style="margin-top:16px;font-size:12px;">
        SeedBuster dashboard · server-rendered · {("admin" if admin else "public")} view
      </div>
    </div>
  </body>
</html>
"""


def _flash(msg: str | None, *, error: bool = False) -> str:
    if not msg:
        return ""
    cls = "flash error" if error else "flash"
    return f'<div class="{cls}">{_escape(msg)}</div>'


def _build_query_link(base: str, **params: object) -> str:
    clean = {k: v for k, v in params.items() if v not in (None, "", [], False)}
    if not clean:
        return base
    return f"{base}?{urlencode(clean, doseq=True)}"


def _render_stats(stats: dict) -> str:
    by_status = stats.get("by_status") or {}
    by_verdict = stats.get("by_verdict") or {}

    def _kv(items: dict) -> str:
        parts = []
        for k in sorted(items.keys()):
            parts.append(f"<div><span class='muted'>{_escape(k)}:</span> <b>{_escape(items[k])}</b></div>")
        return "\n".join(parts) or "<div class='muted'>No data</div>"

    return f"""
      <div class="grid">
        <div class="panel col-4">
          <div class="muted">Total</div>
          <div style="font-size:28px;font-weight:800;margin-top:4px;">{_escape(stats.get("total", 0))}</div>
          <div class="muted" style="margin-top:8px;">Last 24h: <b>{_escape(stats.get("last_24h", 0))}</b></div>
        </div>
        <div class="panel col-4">
          <div class="muted" style="margin-bottom:8px;">By Status</div>
          {_kv(by_status)}
        </div>
        <div class="panel col-4">
          <div class="muted" style="margin-bottom:8px;">By Verdict</div>
          {_kv(by_verdict)}
        </div>
      </div>
    """


def _render_domains_table(domains: list[dict], *, admin: bool) -> str:
    if not domains:
        return '<div class="panel"><div class="muted">No domains found.</div></div>'

    rows = []
    for d in domains:
        did = d.get("id")
        domain = d.get("domain") or ""
        href = f"/admin/domains/{did}" if admin else f"/domains/{did}"
        rows.append(
            "<tr>"
            f"<td><a href=\"{_escape(href)}\">{_escape(domain)}</a></td>"
            f"<td>{_status_badge(str(d.get('status') or ''))}</td>"
            f"<td>{_verdict_badge(d.get('verdict'))}</td>"
            f"<td><code>{_escape(d.get('domain_score'))}</code></td>"
            f"<td><code>{_escape(d.get('analysis_score') if d.get('analysis_score') is not None else '')}</code></td>"
            f"<td class=\"muted\">{_escape(d.get('source') or '')}</td>"
            f"<td class=\"muted\">{_escape(d.get('first_seen') or '')}</td>"
            f"<td class=\"muted\">{_escape(d.get('updated_at') or '')}</td>"
            "</tr>"
        )

    return f"""
      <div class="panel">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Status</th>
              <th>Verdict</th>
              <th>Domain Score</th>
              <th>Analysis Score</th>
              <th>Source</th>
              <th>First Seen</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
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
            f"<td><a href=\"{_escape(href)}\">{_escape(domain)}</a></td>"
            f"<td>{_escape(platform)}</td>"
            f"<td>{_report_badge(str(status))}</td>"
            f"<td class=\"muted\">{_escape(next_attempt_at)}</td>"
            "</tr>"
        )

    return f"""
      <div class="panel">
        <div class="row" style="justify-content:space-between;margin-bottom:10px;">
          <div><b>Reports Needing Attention</b> <span class="muted">(pending/manual/rate-limited)</span></div>
          <div class="muted">showing {min(len(pending), limit)} of {len(pending)}</div>
        </div>
        <table>
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
    """


def _render_filters(*, status: str, verdict: str, q: str, admin: bool, limit: int, page: int) -> str:
    action = "/admin" if admin else "/"
    return f"""
      <div class="panel">
        <form method="get" action="{_escape(action)}">
          <div class="grid">
            <div class="col-4">
              <label>Status</label>
              <select name="status">
                <option value="" {"selected" if not status else ""}>All</option>
                {''.join(
                    f'<option value="{_escape(s.value)}" {"selected" if status == s.value else ""}>{_escape(s.value)}</option>'
                    for s in DomainStatus
                )}
              </select>
            </div>
            <div class="col-4">
              <label>Verdict</label>
              <select name="verdict">
                <option value="" {"selected" if not verdict else ""}>All</option>
                {''.join(
                    f'<option value="{_escape(v.value)}" {"selected" if verdict == v.value else ""}>{_escape(v.value)}</option>'
                    for v in Verdict
                )}
              </select>
            </div>
            <div class="col-4">
              <label>Search</label>
              <input type="text" name="q" value="{_escape(q)}" placeholder="domain contains…" />
            </div>
            <div class="col-3">
              <label>Limit</label>
              <select name="limit">
                {''.join(
                    f'<option value="{n}" {"selected" if limit == n else ""}>{n}</option>'
                    for n in (25, 50, 100, 200, 500)
                )}
              </select>
            </div>
            <div class="col-3">
              <label>Page</label>
              <input type="text" name="page" value="{_escape(page)}" />
            </div>
            <div class="col-6" style="display:flex;align-items:flex-end;gap:10px;">
              <button class="btn primary" type="submit">Apply</button>
              <a class="btn" href="{_escape(action)}">Reset</a>
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
        prev_link = f'<a class="btn" href="{_escape(prev_link)}">← Prev</a>'

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
        next_link = f'<a class="btn" href="{_escape(next_link)}">Next →</a>'

    if not prev_link and not next_link:
        return ""

    return f"""
      <div class="panel">
        <div class="row" style="justify-content:space-between;">
          <div class="muted">Page {page}</div>
          <div class="row">{prev_link}{next_link}</div>
        </div>
      </div>
    """


def _render_kv_table(items: Iterable[tuple[str, object]]) -> str:
    rows = []
    for k, v in items:
        value = "" if v is None else str(v)
        rows.append(f"<tr><th>{_escape(k)}</th><td>{_escape(value)}</td></tr>")
    return f"""
      <div class="panel">
        <table>
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

    header_links = []
    header_links.append(f'<a class="btn" href="{_escape("/admin" if admin else "/")}">← Back</a>')
    if admin:
        header_links.append(f'<a class="btn" href="{_escape(f"/domains/{did}")}">Public view</a>')
    else:
        header_links.append(f'<a class="btn" href="{_escape(f"/admin/domains/{did}")}">Admin view</a>')

    open_url = f"https://{domain_name}"
    header_links.append(f'<a class="btn" href="{_escape(open_url)}" target="_blank" rel="noreferrer">Open</a>')

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
                    f'<div><a href="{_escape(evidence_base_url + "/" + quote(filename))}" target="_blank" rel="noreferrer">{_escape(label)}</a></div>'
                )
        for p in instruction_files:
            files.append(
                f'<div><a href="{_escape(evidence_base_url + "/" + quote(p.name))}" target="_blank" rel="noreferrer">{_escape(p.name)}</a></div>'
            )

        images = []
        for p in screenshots:
            images.append(
                f'<div class="shot"><a href="{_escape(evidence_base_url + "/" + quote(p.name))}" target="_blank" rel="noreferrer">'
                f'<img src="{_escape(evidence_base_url + "/" + quote(p.name))}" loading="lazy" alt="{_escape(p.name)}" />'
                f"</a><div class=\"cap\">{_escape(p.name)}</div></div>"
            )

        evidence_bits = f"""
          <div class="panel">
            <div class="grid">
              <div class="col-6">
                <div style="margin-bottom:8px;"><b>Evidence Files</b></div>
                {''.join(files) if files else '<div class="muted">No evidence files found.</div>'}
              </div>
              <div class="col-6">
                <div style="margin-bottom:8px;"><b>Evidence Path</b></div>
                <div class="muted"><code>{_escape(str(evidence_dir) if evidence_dir else '')}</code></div>
              </div>
            </div>
          </div>
          <div class="panel">
            <div style="margin-bottom:10px;"><b>Screenshots</b></div>
            <div class="images">{''.join(images) if images else '<div class="muted">No screenshots.</div>'}</div>
          </div>
        """

    reports_rows = []
    for r in reports:
        reports_rows.append(
            "<tr>"
            f"<td>{_escape(r.get('platform') or '')}</td>"
            f"<td>{_report_badge(r.get('status'))}</td>"
            f"<td class=\"muted\">{_escape(r.get('attempts') or 0)}</td>"
            f"<td class=\"muted\">{_escape(r.get('attempted_at') or '')}</td>"
            f"<td class=\"muted\">{_escape(r.get('submitted_at') or '')}</td>"
            f"<td class=\"muted\">{_escape(r.get('next_attempt_at') or '')}</td>"
            f"<td class=\"muted\">{_escape((r.get('response') or '')[:180])}</td>"
            "</tr>"
        )

    reports_table = f"""
      <div class="panel">
        <div class="row" style="justify-content:space-between;margin-bottom:10px;">
          <div><b>Reports</b></div>
          <div class="muted">{len(reports)} records</div>
        </div>
        <table>
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
            {''.join(reports_rows) if reports_rows else '<tr><td class="muted" colspan="7">No reports yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    """

    notes = domain.get("operator_notes") or ""

    admin_forms = ""
    if admin and csrf:
        status_val = (domain.get("status") or "").strip().lower()
        verdict_val = (domain.get("verdict") or "").strip().lower()

        platform_checks = []
        for p in available_platforms:
            platform_checks.append(
                f'<label style="display:flex;gap:8px;align-items:center;margin:6px 0;">'
                f'<input type="checkbox" name="platform" value="{_escape(p)}" checked />'
                f'<span>{_escape(p)}</span>'
                f"</label>"
            )

        admin_forms = f"""
          <div class="panel">
            <div class="grid">
              <div class="col-6">
                <div style="margin-bottom:10px;"><b>Update Domain</b></div>
                <form method="post" action="/admin/domains/{_escape(did)}/update">
                  <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                  <div class="grid">
                    <div class="col-6">
                      <label>Status</label>
                      <select name="status">
                        {''.join(
                            f'<option value="{_escape(s.value)}" {"selected" if status_val == s.value else ""}>{_escape(s.value)}</option>'
                            for s in DomainStatus
                        )}
                      </select>
                    </div>
                    <div class="col-6">
                      <label>Verdict</label>
                      <select name="verdict">
                        <option value="" {"selected" if not verdict_val else ""}>unknown</option>
                        {''.join(
                            f'<option value="{_escape(v.value)}" {"selected" if verdict_val == v.value else ""}>{_escape(v.value)}</option>'
                            for v in Verdict
                        )}
                      </select>
                    </div>
                    <div class="col-12">
                      <label>Notes (public)</label>
                      <textarea name="notes" placeholder="what’s the current state / next step?">{_escape(notes)}</textarea>
                    </div>
                    <div class="col-12">
                      <button class="btn primary" type="submit">Save</button>
                    </div>
                  </div>
                </form>
              </div>

              <div class="col-6">
                <div style="margin-bottom:10px;"><b>Actions</b></div>

                <form method="post" action="/admin/domains/{_escape(did)}/rescan" style="margin-bottom:10px;">
                  <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                  <button class="btn" type="submit">Queue Rescan</button>
                </form>

                <form method="post" action="/admin/domains/{_escape(did)}/false_positive" style="margin-bottom:10px;">
                  <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                  <button class="btn danger" type="submit">Mark False Positive</button>
                </form>

                <div class="panel" style="padding:12px;margin:0 0 12px 0;">
                  <div style="margin-bottom:8px;"><b>Report Now</b></div>
                  <form method="post" action="/admin/domains/{_escape(did)}/report">
                    <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                    <div class="grid">
                      <div class="col-6">
                        <label>Platforms</label>
                        <div style="max-height:160px;overflow:auto;border:1px solid var(--border);border-radius:10px;padding:8px;">
                          {''.join(platform_checks) if platform_checks else '<div class="muted">No configured reporters.</div>'}
                        </div>
                      </div>
                      <div class="col-6">
                        <label>&nbsp;</label>
                        <label style="display:flex;gap:8px;align-items:center;margin-top:8px;">
                          <input type="checkbox" name="force" value="1" />
                          <span>Force (ignore rate-limit schedule)</span>
                        </label>
                        <button class="btn primary" type="submit" style="margin-top:10px;">Submit Reports</button>
                      </div>
                    </div>
                  </form>
                </div>

                <div class="panel" style="padding:12px;margin:0;">
                  <div style="margin-bottom:8px;"><b>Mark Manual Done</b></div>
                  <form method="post" action="/admin/domains/{_escape(did)}/manual_done">
                    <input type="hidden" name="csrf" value="{_escape(csrf)}" />
                    <label>Note</label>
                    <input type="text" name="note" placeholder="optional note" />
                    <button class="btn" type="submit" style="margin-top:10px;">Mark manual-required as submitted</button>
                  </form>
                </div>
              </div>
            </div>
          </div>
        """

    reasons = domain.get("verdict_reasons") or ""
    reasons_html = f"<pre style='white-space:pre-wrap;margin:0;'>{_escape(reasons)}</pre>" if reasons else "<div class='muted'>—</div>"
    notes_html = f"<pre style='white-space:pre-wrap;margin:0;'>{_escape(notes)}</pre>" if notes else "<div class='muted'>—</div>"

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
      <div class="row" style="justify-content:space-between;margin-bottom:12px;">
        <div>
          <div style="font-size:22px;font-weight:800;">{_escape(domain_name)}</div>
          <div class="row" style="margin-top:6px;">
            {_status_badge(str(domain.get("status") or ""))}
            {_verdict_badge(domain.get("verdict"))}
            <span class="muted">id <code>{_escape(did)}</code></span>
          </div>
        </div>
        <div class="row">{''.join(header_links)}</div>
      </div>
      {_flash(msg, error=error)}
      <div class="grid">
        <div class="col-6">{info}</div>
        <div class="col-6">
          <div class="panel">
            <div style="margin-bottom:8px;"><b>Reasons</b></div>
            {reasons_html}
          </div>
          <div class="panel">
            <div style="margin-bottom:8px;"><b>Notes</b></div>
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
          <div class="panel">
            <div style="margin-bottom:10px;"><b>Manual Entry</b> <span class="muted">(submit a domain or URL)</span></div>
            <form method="post" action="/admin/submit">
              <input type="hidden" name="csrf" value="__SET_COOKIE__" />
              <div class="grid">
                <div class="col-8">
                  <label>Domain / URL</label>
                  <input type="text" name="target" placeholder="example.com or https://example.com/path" />
                </div>
                <div class="col-4" style="display:flex;align-items:flex-end;">
                  <button class="btn primary" type="submit" style="width:100%;">Submit / Rescan</button>
                </div>
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
