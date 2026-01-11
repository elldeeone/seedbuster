"""Campaign renderers for the dashboard."""

from __future__ import annotations

from urllib.parse import quote

from .server_helpers import _escape, _status_badge, _verdict_badge


def _render_campaign_info(campaign: dict | None, related_domains: list[dict], admin: bool) -> str:
    """Render threat campaign info panel for domain detail page."""
    if not campaign:
        return ""

    campaign_name = campaign.get("name", "Unknown Campaign")
    campaign_id = campaign.get("campaign_id", "")
    confidence = campaign.get("confidence", 0)
    shared_backends = list(campaign.get("shared_backends", []))
    shared_kits = list(campaign.get("shared_kits", []))
    shared_nameservers = list(campaign.get("shared_nameservers", []))

    related_html = ""
    if related_domains:
        base_url = "/admin/domains" if admin else "/domains"
        visible_items = []
        hidden_items = []

        for i, member in enumerate(related_domains):
            domain = member.get("domain", "")
            domain_id = member.get("id")
            score = member.get("score", 0)
            if domain_id:
                href = f"{base_url}/{domain_id}"
            else:
                fallback_url = "/admin" if admin else "/"
                href = f"{fallback_url}?q={quote(domain)}"
            item_html = (
                f'<div class="sb-breakdown-item">'
                f'<a href="{_escape(href)}" class="sb-breakdown-key" style="color: var(--text-link);">{_escape(domain)}</a>'
                f'<span class="sb-score">{_escape(score)}</span>'
                f"</div>"
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

    if confidence >= 70:
        conf_class = "sb-badge-high"
    elif confidence >= 40:
        conf_class = "sb-badge-medium"
    else:
        conf_class = "sb-badge-low"

    campaigns_link = "/admin/campaigns" if admin else "/campaigns"
    confidence_display = f"{confidence:.0f}% confidence"

    return f"""
      <div class="sb-panel" style="border-color: rgba(163, 113, 247, 0.3); margin-bottom: 16px;">
        <div class="sb-panel-header" style="border-color: rgba(163, 113, 247, 0.2);">
          <div>
            <span class="sb-panel-title" style="color: var(--accent-purple);">Threat Campaign</span>
            <a href="{_escape(campaigns_link)}" class="sb-muted" style="margin-left: 12px; font-size: 12px;">View all campaigns &rarr;</a>
          </div>
          <span class="sb-badge {conf_class}">{_escape(confidence_display)}</span>
        </div>
        <div class="sb-grid">
          <div class="col-6">
            <div style="margin-bottom: 16px;">
              <div class="sb-label">Campaign Name</div>
              <div style="font-size: 16px; font-weight: 600; color: var(--text-primary);">{_escape(campaign_name)}</div>
              <div class="sb-muted" style="font-size: 12px; margin-top: 4px;">ID: <code class="sb-code">{_escape(campaign_id)}</code></div>
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


def _render_campaigns_list(campaigns: list[dict], admin: bool, q: str = "") -> str:
    """Render the threat campaigns listing page."""
    search = (q or "").strip().lower()
    filtered: list[dict] = []
    for campaign in campaigns:
        if not search:
            filtered.append(campaign)
            continue
        name = str(campaign.get("name") or campaign.get("campaign_id") or "").lower()
        cid = str(campaign.get("campaign_id") or "").lower()
        member_hit = any(search in (m.get("domain", "").lower()) for m in campaign.get("members", []))
        if search in name or search in cid or member_hit:
            filtered.append(campaign)

    total_count = len(campaigns)
    display_count = len(filtered)
    action_href = "/admin/campaigns" if admin else "/campaigns"

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

    campaign_cards = []
    for campaign in filtered:
        campaign_id = campaign.get("campaign_id", "")
        campaign_name = campaign.get("name", "") or campaign_id or "Unknown Campaign"
        members = campaign.get("members", []) or []
        member_count = len(members)
        shared_backends = campaign.get("shared_backends", []) or []
        shared_kits = campaign.get("shared_kits", []) or []
        shared_nameservers = campaign.get("shared_nameservers", []) or []

        detail_href = f"/admin/campaigns/{campaign_id}" if admin else f"/campaigns/{campaign_id}"

        member_items: list[str] = []
        for member in members[:3]:
            domain = member.get("domain", "")
            added_at = (member.get("added_at") or "")[:10]
            domain_id = member.get("id")
            href = (
                f"/admin/domains/{domain_id}"
                if (admin and domain_id)
                else (f"/domains/{domain_id}" if domain_id else "")
            )
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

        campaign_cards.append(f"""
          <div class="col-6">
            <div class="sb-panel" style="border-color: rgba(163, 113, 247, 0.25); margin: 0;">
              <div class="sb-panel-header" style="border-color: rgba(163, 113, 247, 0.18);">
                <div>
                  <div class="sb-panel-title" style="color: var(--accent-purple);">{_escape(campaign_name)}</div>
                  <div class="sb-muted" style="font-size: 12px;">Campaign ID: <code class="sb-code">{_escape(campaign_id)}</code></div>
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
        {"".join(campaign_cards)}
      </div>
    """


def _render_campaign_detail(campaign: dict, admin: bool) -> str:
    """Render the detailed threat campaign page with action buttons."""
    campaign_id = campaign.get("campaign_id", "")
    campaign_name = campaign.get("name", "Unknown Campaign")
    members = campaign.get("members", []) or []
    shared_backends = campaign.get("shared_backends", []) or []
    shared_kits = campaign.get("shared_kits", []) or []
    shared_nameservers = campaign.get("shared_nameservers", []) or []
    shared_asns = campaign.get("shared_asns", []) or []
    actor_id = campaign.get("actor_id", "")
    actor_notes = campaign.get("actor_notes", "")

    back_href = "/admin/campaigns" if admin else "/campaigns"

    action_buttons = ""
    if admin:
        action_buttons = f"""
          <div class="sb-row" style="flex-wrap: wrap; gap: 8px; margin-top: 8px;">
            <a class="sb-btn" href="/admin/campaigns/{_escape(campaign_id)}/pdf">Campaign PDF</a>
            <a class="sb-btn" href="/admin/campaigns/{_escape(campaign_id)}/package">Campaign Package</a>
            <form method="post" action="/admin/campaigns/{_escape(campaign_id)}/preview" style="display: inline;">
              <input type="hidden" name="csrf" value="__SET_COOKIE__" />
              <button type="submit" class="sb-btn">Preview Reports</button>
            </form>
            <form method="post" action="/admin/campaigns/{_escape(campaign_id)}/submit" style="display: inline;">
              <input type="hidden" name="csrf" value="__SET_COOKIE__" />
              <button type="submit" class="sb-btn sb-btn-danger">Submit All Reports</button>
            </form>
          </div>
        """

    actor_html = ""
    if actor_id or actor_notes:
        actor_html = f"""
          <div class="sb-panel" style="margin-bottom: 16px; border-color: rgba(245, 158, 11, 0.3);">
            <div class="sb-label" style="color: var(--accent-yellow);">Threat Actor Attribution</div>
            <div class="sb-code" style="margin-bottom: 8px;">{_escape(actor_id) if actor_id else '(unattributed)'}</div>
            <div class="sb-muted">{_escape(actor_notes)}</div>
          </div>
        """

    def render_indicator(label: str, values: list[str]) -> str:
        if not values:
            return ""
        visible = values[:6]
        chips = "".join(
            f'<code class="sb-code" style="display: inline-block; margin: 2px 4px 2px 0;">{_escape(v)}</code>'
            for v in visible
        )
        remainder = len(values) - len(visible)
        more = (
            f'<span class="sb-muted" style="font-size: 12px;">+{remainder} more</span>'
            if remainder > 0
            else ""
        )
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
        href = (
            f"/admin/domains/{domain_id}"
            if (admin and domain_id)
            else (f"/domains/{domain_id}" if domain_id else "")
        )
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
            footer_parts.append(f'<span class="sb-muted">Added {_escape(added)}</span>')
        if ip:
            footer_parts.append(f'<span class="sb-muted">IP {_escape(ip)}</span>')
        footer = " \u2022 ".join(footer_parts) if footer_parts else ""
        meta_display = meta if meta else '<span class="sb-muted">&mdash;</span>'
        footer_html = (
            f'<div class="sb-muted" style="font-size: 12px; margin-top: 2px;">{footer}</div>'
            if footer
            else ""
        )
        member_items.append(
            f'<div class="sb-breakdown-item">'
            f'<a href="{_escape(href)}" class="sb-breakdown-key" style="color: var(--text-link);">{_escape(domain)}</a>'
            f'<div class="sb-row" style="gap: 8px; flex-wrap: wrap; align-items: center;">{meta_display}</div>'
            f'{footer_html}'
            f"</div>"
        )

    related_html = (
        f'<div class="sb-breakdown">{"".join(member_items)}</div>'
        if member_items
        else '<div class="sb-muted">No related domains yet.</div>'
    )
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

    table_rows = []
    for member in members:
        domain = member.get("domain", "")
        status = member.get("status")
        verdict = member.get("verdict")
        score = member.get("score")
        added = (member.get("added_at") or "")[:10] or "&mdash;"
        ip = member.get("ip_address") or "&mdash;"
        domain_id = member.get("id")
        href = (
            f"/admin/domains/{domain_id}"
            if (admin and domain_id)
            else (f"/domains/{domain_id}" if domain_id else "")
        )
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
        <h1 style="flex: 1; margin: 0 0 0 12px; font-size: 24px;">{_escape(campaign_name)}</h1>
      </div>

      <div class="sb-panel" style="border-color: rgba(163, 113, 247, 0.3); margin-bottom: 16px;">
        <div class="sb-panel-header" style="border-color: rgba(163, 113, 247, 0.2);">
          <div>
            <span class="sb-panel-title" style="color: var(--accent-purple);">Threat Campaign</span>
            <span class="sb-muted" style="margin-left: 10px; font-size: 12px;">ID: <code class="sb-code">{_escape(campaign_id)}</code></span>
          </div>
          {action_buttons}
        </div>
        <div class="sb-grid" style="align-items: flex-start;">
          <div class="col-8">
            <div class="sb-label">Campaign Name</div>
            <div style="font-size: 20px; font-weight: 700; margin-top: 4px;">{_escape(campaign_name)}</div>
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
