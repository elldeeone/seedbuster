"""Renderers for dashboard summary sections."""

from __future__ import annotations

from urllib.parse import urlencode

from .server_helpers import (
    STATUS_FILTER_OPTIONS,
    VERDICT_FILTER_OPTIONS,
    _display_domain,
    _escape,
    _format_bytes,
    _report_badge,
    _status_badge,
    _verdict_badge,
)


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
                f"</div>"
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
            label = "All Statuses" if value == "" else (
                "Dangerous Only" if value == "dangerous" else value
            )
            selected = "selected" if status == value else ""
            options.append(
                f'<option value="{_escape(value)}" {selected}>{_escape(label)}</option>'
            )
        return "".join(options)

    def _render_verdict_options() -> str:
        options: list[str] = []
        for value in VERDICT_FILTER_OPTIONS:
            label = "All Verdicts" if value == "" else value
            selected = "selected" if verdict == value else ""
            options.append(
                f'<option value="{_escape(value)}" {selected}>{_escape(label)}</option>'
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
            display_domain = _display_domain(domain)
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
                f'<td class="domain-cell" title="{_escape(display_domain)}"><a class="domain-link" href="{_escape(href)}">{_escape(display_domain)}</a></td>'
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
        prev_link = _build_query_link(
            action,
            status=status,
            verdict=verdict,
            q=q,
            limit=limit,
            page=page_display - 1,
        )
        prev_link = f'<a class="sb-btn" href="{_escape(prev_link)}">&larr; Previous</a>'

    next_link = ""
    if can_next:
        next_link = _build_query_link(
            action,
            status=status,
            verdict=verdict,
            q=q,
            limit=limit,
            page=page_display + 1,
        )
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
