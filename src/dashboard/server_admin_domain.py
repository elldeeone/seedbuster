"""Admin domain detail page handler."""

from __future__ import annotations

from aiohttp import web

from .server_helpers import _coerce_int, _domain_dir_name
from .server_layout import _layout
from .server_render_domain import _render_domain_detail


class DashboardServerAdminDomainMixin:
    """Admin domain detail handler."""

    async def _admin_domain(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")
        reports = await self.database.get_reports_for_domain(did)

        snapshot_param = (request.query.get("snapshot") or "").strip()
        domain_dir = self.evidence_dir / _domain_dir_name(domain["domain"])
        snapshots, latest_id = self._list_snapshots(domain_dir)
        snapshot_dir, resolved_snapshot_id, is_latest = self._resolve_snapshot_dir(
            domain_dir, snapshot_param, latest_id
        )
        if snapshot_param and not snapshot_dir and domain_dir.exists():
            snapshot_dir = domain_dir
            resolved_snapshot_id = latest_id
            is_latest = True

        evidence_base = None
        evidence_cache_buster = resolved_snapshot_id or latest_id
        if snapshot_dir:
            evidence_base = f"/evidence/{domain_dir.name}"
            if not is_latest and resolved_snapshot_id:
                evidence_base = f"/evidence/{domain_dir.name}/runs/{resolved_snapshot_id}"
        screenshots = self._get_screenshots(domain, snapshot_dir)
        instruction_files = self._get_instruction_files(domain_dir) if is_latest else []

        domain_name = domain.get("domain") or ""
        campaign = self._get_campaign_for_domain(domain_name)
        related_domains = self._get_related_domains(domain_name, campaign)
        related_domains = await self._enrich_related_domains_with_ids(related_domains)

        msg = request.query.get("msg")
        error = request.query.get("error") == "1"
        manual_pending_raw = request.query.get("manual_pending", "")
        manual_pending = [p.strip().lower() for p in manual_pending_raw.split(",") if p.strip()]

        resp = web.Response(
            text=_layout(
                title="SeedBuster Dashboard",
                body=_render_domain_detail(
                    domain,
                    self._filter_reports_for_snapshot(reports, snapshots, resolved_snapshot_id or latest_id),
                    evidence_dir=snapshot_dir,
                    evidence_base_url=evidence_base,
                    evidence_cache_buster=evidence_cache_buster,
                    screenshots=screenshots,
                    instruction_files=instruction_files,
                    admin=True,
                    csrf="__SET_COOKIE__",
                    msg=msg,
                    error=error,
                    available_platforms=self.get_available_platforms(),
                    platform_info=self.get_platform_info(),
                    campaign=campaign,
                    related_domains=related_domains,
                    manual_pending=manual_pending if manual_pending else None,
                ),
                admin=True,
            ),
            content_type="text/html",
        )
        csrf = self._get_or_set_csrf(request, resp)

        resp.text = resp.text.replace("__SET_COOKIE__", csrf)

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
