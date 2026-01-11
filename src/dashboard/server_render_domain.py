"""Domain detail renderers for the dashboard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

from ..storage.database import DomainStatus, Verdict
from .server_helpers import _escape, _report_badge, _status_badge, _verdict_badge
from .server_render_campaigns import _render_campaign_info
from .server_render_sections import _flash


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
        msg = report.get("response") or report.get("message") or ""
        import re

        url_match = re.search(r"https?://[^\s<>\"']+", msg)
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

    is_email = form_url.startswith("mailto:")
    open_btn_text = "Open Email Client" if is_email else "Open Abuse Form"
    open_btn_icon = "&#9993;" if is_email else "&nearr;"

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
    response_data = report.get("response_data")
    if isinstance(response_data, str):
        try:
            response_data = json.loads(response_data)
        except (json.JSONDecodeError, TypeError):
            response_data = {}
    response_data = response_data or {}

    manual_fields = response_data.get("manual_fields")
    platform = report.get("platform", "unknown")

    if manual_fields:
        form_url = manual_fields.get("form_url", "")
        fields = manual_fields.get("fields", [])
        notes = manual_fields.get("notes", [])
    else:
        msg = report.get("response") or report.get("message") or ""
        import re

        url_match = re.search(r"https?://[^\s<>\"']+", msg)
        form_url = url_match.group(0) if url_match else ""
        fields = [{"label": "Report Details", "value": msg, "multiline": True}] if msg else []
        notes = []

    is_email = form_url.startswith("mailto:") if form_url else False
    open_btn_text = "Open Email Client" if is_email else "Open Abuse Form"
    open_btn_icon = "&#9993;" if is_email else "&nearr;"

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

    reports_by_platform: dict[str, dict] = {}
    for r in reports:
        platform = (r.get("platform") or "").lower()
        if platform in manual_pending:
            existing = reports_by_platform.get(platform)
            if not existing or (r.get("status") or "").lower() == "manual_required":
                reports_by_platform[platform] = r

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

    platform_icons = {
        "cloudflare": "&#9729;",
        "google": "\U0001f50d",
        "microsoft": "\U0001fa9f",
        "netcraft": "\U0001f6e1",
        "apwg": "\U0001f3a3",
        "registrar": "\U0001f4dd",
        "hosting_provider": "\U0001f5a5",
        "edge_provider": "\U0001f310",
        "dns_provider": "\U0001f4e1",
        "digitalocean": "\U0001f30a",
    }

    list_items = []
    detail_views = []

    for i, r in enumerate(manual_reports):
        platform = (r.get("platform") or "unknown").lower()
        platform_display = platform.upper()
        platform_id = f"{panel_id}_platform_{i}"
        icon = platform_icons.get(platform, "\U0001f4cb")

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

        detail_views.append(_render_platform_detail(
            r, platform_id, domain_id, panel_id, evidence_base_url
        ))

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
    evidence_cache_buster: str | None = None,
    screenshots: list[Path],
    instruction_files: list[Path],
    admin: bool,
    csrf: str | None,
    msg: str | None,
    error: bool,
    available_platforms: list[str],
    platform_info: dict[str, dict] | None = None,
    campaign: dict | None = None,
    related_domains: list[dict] | None = None,
    manual_pending: list[str] | None = None,
) -> str:
    did = domain.get("id")
    domain_name = domain.get("domain") or ""

    header_links = []
    header_links.append(f'<a class="sb-btn" href="{_escape("/admin" if admin else "/")}">&larr; Back</a>')
    if admin:
        header_links.append(f'<a class="sb-btn" href="{_escape(f"/domains/{did}")}">Public View</a>')

    open_url = f"https://{domain_name}"
    header_links.append(
        f'<a class="sb-btn" href="{_escape(open_url)}" target="_blank" rel="noreferrer">Visit Site &nearr;</a>'
    )

    evidence_bits = ""
    if evidence_base_url and (screenshots or instruction_files or evidence_dir):
        files = []
        cache_suffix = f"?v={evidence_cache_buster}" if evidence_cache_buster else ""
        for label, filename in (
            ("analysis.json", "analysis.json"),
            ("page.html", "page.html"),
            ("console.log", "console.log"),
            ("network.har", "network.har"),
        ):
            if evidence_dir and (evidence_dir / filename).exists():
                files.append(
                    f'<a class="sb-btn" style="font-size: 11px; padding: 6px 12px;" href="{_escape(evidence_base_url + "/" + quote(filename) + cache_suffix)}" target="_blank" rel="noreferrer">{_escape(label)}</a>'
                )
        for p in instruction_files:
            files.append(
                f'<a class="sb-btn" style="font-size: 11px; padding: 6px 12px;" href="{_escape(evidence_base_url + "/" + quote(p.name) + cache_suffix)}" target="_blank" rel="noreferrer">{_escape(p.name)}</a>'
            )

        images = []
        for p in screenshots:
            images.append(
                f'<div class="sb-screenshot"><a href="{_escape(evidence_base_url + "/" + quote(p.name) + cache_suffix)}" target="_blank" rel="noreferrer">'
                f'<img src="{_escape(evidence_base_url + "/" + quote(p.name) + cache_suffix)}" loading="lazy" alt="{_escape(p.name)}" />'
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

    reports_rows = []
    for idx, r in enumerate(reports):
        status = (r.get("status") or "").lower()
        platform = r.get("platform") or ""

        if status == "manual_required":
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

    admin_forms = ""
    if admin and csrf:
        status_val = (domain.get("status") or "").strip().lower()
        verdict_val = (domain.get("verdict") or "").strip().lower()

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
    reasons_html = (
        f'<pre class="sb-pre">{_escape(reasons)}</pre>'
        if reasons
        else '<div class="sb-muted">&mdash;</div>'
    )
    notes_html = f'<pre class="sb-pre">{_escape(notes)}</pre>' if notes else '<div class="sb-muted">&mdash;</div>'

    info = _render_kv_table(
        [
            ("domain", domain_name),
            ("source", domain.get("source") or ""),
            ("status", domain.get("status") or ""),
            ("verdict", domain.get("verdict") or ""),
            ("domain_score", domain.get("domain_score") or 0),
            (
                "analysis_score",
                domain.get("analysis_score") if domain.get("analysis_score") is not None else "",
            ),
            ("first_seen", domain.get("first_seen") or ""),
            ("analyzed_at", domain.get("analyzed_at") or ""),
            ("reported_at", domain.get("reported_at") or ""),
            ("updated_at", domain.get("updated_at") or ""),
        ]
    )

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
      {_render_campaign_info(campaign, related_domains or [], admin)}
      {admin_forms}
      {evidence_bits}
      {reports_table}
    """
