"""Admin dashboard page handlers."""

from __future__ import annotations

from aiohttp import web

from ..utils.domains import canonicalize_domain
from .server_helpers import DANGEROUS_EXCLUDE_STATUSES, _coerce_int, _extract_hostname
from .server_layout import _layout
from .server_render_campaigns import _render_campaigns_list
from .server_render_sections import (
    _build_query_link,
    _flash,
    _render_domains_section,
    _render_health,
    _render_pending_reports,
    _render_stats,
)


class DashboardServerAdminDashboardMixin:
    """Admin dashboard pages."""

    async def _admin_campaigns(self, request: web.Request) -> web.Response:
        search = (request.query.get("q") or "").strip()
        campaigns = await self._filter_campaigns(self._load_campaigns())
        body = _render_campaigns_list(campaigns, admin=True, q=search)
        html_out = _layout(title="SeedBuster - Threat Campaigns", body=body, admin=True)
        return web.Response(text=html_out, content_type="text/html")

    async def _admin_index(self, request: web.Request) -> web.Response:
        status = (request.query.get("status") or "").strip().lower()
        verdict = (request.query.get("verdict") or "").strip().lower()
        q = (request.query.get("q") or "").strip().lower()
        exclude_takedowns = (request.query.get("exclude_takedowns") or "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        limit = _coerce_int(request.query.get("limit"), default=100, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        stats = await self._get_stats_cached(include_evidence=True)
        health_status = await self._fetch_health_status()

        status_filter = None if status == "dangerous" else (status or None)
        exclude_statuses = DANGEROUS_EXCLUDE_STATUSES if status == "dangerous" else None
        total_count = await self.database.count_domains(
            status=status_filter,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
            exclude_takedowns=exclude_takedowns,
        )
        domains = await self.database.list_domains(
            limit=limit,
            offset=offset,
            status=status_filter,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
            exclude_takedowns=exclude_takedowns,
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
        resp.text += f"""
        <script>
        (function() {{
          const showToast = (message, type = 'info') => {{
            if (window.sbToast) return window.sbToast(message, type);
            if (type === 'error') {{ console.error(message); }} else {{ console.log(message); }}
          }};
          const csrfToken = (document.querySelector('input[name="csrf"]') || {{}}).value || '';

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
                  headers: {{ 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }},
                  body: JSON.stringify({{ days }}),
                }});
                const data = await res.json();
                if (res.ok) {{
                  cleanupResult.textContent = `Removed ${{data.removed_dirs || 0}} directories older than ${{days}} days.`;
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
                  headers: {{ 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }},
                  body: JSON.stringify({{ target }}),
                }});
                const data = await res.json();
                const msg = data.status === 'rescan_queued'
                  ? `Rescan queued for ${{data.domain}}`
                  : `Submitted ${{data.domain || target}}`;
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
              headers: {{ 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }},
              body: JSON.stringify(payload || {{}}),
            }});
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || res.statusText);
            return data;
          }}

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
                await postJSON(`/admin/api/domains/${{domainId}}/rescan`, {{ domain }});
                showToast(`Rescan queued for ${{domain}}`, 'success');
              }} else {{
                await postJSON('/admin/api/report', {{ domain_id: parseInt(domainId, 10), domain }});
                showToast(`Report enqueued for ${{domain}}`, 'success');
              }}
            }} catch (err) {{
              showToast(type + ' failed: ' + err, 'error');
            }} finally {{
              target.disabled = false;
            }}
          }});

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
                  if (data && typeof data === 'object' && k in data) bits.push(`${{k.replace(/_/g, ' ')}}: ${{data[k]}}`);
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
        {""}
        """
        return resp

    async def _admin_submit(self, request: web.Request) -> web.Response:
        data = await self._require_csrf(request)
        target = (data.get("target") or "").strip()
        domain = canonicalize_domain(target) or _extract_hostname(target)
        if not domain:
            raise web.HTTPSeeOther(location=_build_query_link("/admin", msg="Invalid domain/URL", error=1))
        source_url = None
        if "/" in target or target.startswith(("http://", "https://")):
            source_url = self._normalize_source_url(target, canonical=domain)

        existing = await self.database.get_domain(domain)
        if existing:
            if source_url and self.submit_callback:
                self._invoke_submit_callback(domain, source_url)
                raise web.HTTPSeeOther(
                    location=_build_query_link("/admin", msg=f"Rescan queued for {domain}")
                )
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
        self._invoke_submit_callback(domain, source_url)
        raise web.HTTPSeeOther(location=_build_query_link("/admin", msg=f"Submitted: {domain}"))
