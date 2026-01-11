"""Report preview template builder."""

from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from .base import ReportEvidence


class ReportManagerPreviewTemplateMixin:
    """Preview template helper."""

    def _build_platform_report_preview(self, platform: str, evidence: ReportEvidence) -> str:
        """Build preview of what would be sent to a platform."""
        from .templates import ReportTemplates

        reporter_email = (self.resend_from_email or self.reporter_email or "").strip()
        reporter_email_addr = reporter_email
        if "<" in reporter_email_addr and ">" in reporter_email_addr:
            reporter_email_addr = reporter_email_addr.split("<")[-1].rstrip(">").strip()

        if platform == "digitalocean":
            all_domains = (evidence.backend_domains or []) + (evidence.suspicious_endpoints or [])
            do_apps: list[str] = []
            for d in all_domains:
                if not isinstance(d, str):
                    continue
                if "ondigitalocean.app" not in d.lower():
                    continue
                if "://" in d:
                    parsed = urlparse(d)
                    if parsed.netloc:
                        do_apps.append(parsed.netloc)
                else:
                    do_apps.append(d)
            do_apps = sorted(set(do_apps))

            scam_type = ReportTemplates._resolve_scam_type(evidence)
            if scam_type == "crypto_doubler":
                scam_header = "CRYPTOCURRENCY FRAUD - Apps to suspend:"
            elif scam_type == "fake_airdrop":
                scam_header = "CRYPTOCURRENCY FRAUD (FAKE AIRDROP) - Apps to suspend:"
            elif scam_type == "seed_phishing":
                scam_header = "CRYPTOCURRENCY PHISHING - Apps to suspend:"
            else:
                scam_header = "CRYPTOCURRENCY FRAUD - Apps to suspend:"
            observed_line = ReportTemplates._observed_summary_line(evidence)
            highlights = ReportTemplates._summarize_reasons(evidence.detection_reasons, max_items=4)
            impersonation = evidence.get_impersonation_lines()

            description = f"""{scam_header}
{chr(10).join(f'- {app}' for app in do_apps)}

Reported URL: {evidence.url}
Observed: {observed_line}

"""

            if impersonation:
                description += f"""Impersonation indicators:
{chr(10).join(f'- {r}' for r in impersonation)}

"""

            description += f"""Key evidence from our review:
{chr(10).join(f'- {r}' for r in highlights)}

Captured evidence (screenshot + HTML) available on request.

"""

            return f"""
DIGITALOCEAN ABUSE REPORT PREVIEW
=================================

Form URL: https://www.digitalocean.com/company/contact/abuse#phishing

Field: name
Value: Kaspa Security

Field: email
Value: {reporter_email_addr or "(not set)"}

Field: target
Value: Kaspa cryptocurrency wallet users

Field: evidence_url
Value: {evidence.url}

Field: description
Value:
{description}
"""
        if platform == "cloudflare":
            reporter_name = ""
            reporter_identity = (self.resend_from_email or self.reporter_email or "").strip()
            if "<" in reporter_identity and ">" in reporter_identity:
                reporter_name = reporter_identity.split("<", 1)[0].strip().strip('"')
            reporter_name = reporter_name or os.environ.get("CLOUDFLARE_REPORTER_NAME", "").strip() or "SeedBuster"

            cf_title = os.environ.get("CLOUDFLARE_REPORTER_TITLE", "").strip()
            cf_company = os.environ.get("CLOUDFLARE_REPORTER_COMPANY", "").strip()
            cf_tele = os.environ.get("CLOUDFLARE_REPORTER_TELEPHONE", "").strip()
            cf_brand = os.environ.get("CLOUDFLARE_TARGETED_BRAND", "").strip()
            cf_country = os.environ.get("CLOUDFLARE_REPORTED_COUNTRY", "").strip()
            cf_user_agent = os.environ.get("CLOUDFLARE_REPORTED_USER_AGENT", "").strip()

            template_data = ReportTemplates.cloudflare(evidence, reporter_email_addr or "")

            internal_lines: list[str] = []
            if evidence.backend_domains:
                internal_lines.append("Backend infrastructure (hostnames observed):")
                internal_lines.extend(f"- {b}" for b in evidence.backend_domains[:10])
                internal_lines.append("")
            if evidence.suspicious_endpoints:
                internal_lines.append("Observed data collection endpoints:")
                internal_lines.extend(f"- {u}" for u in evidence.suspicious_endpoints[:10])
                internal_lines.append("")
            if evidence.screenshot_path or evidence.html_path:
                internal_lines.append("Captured evidence (screenshot + HTML) available on request.")
            internal_comments = "\n".join(internal_lines).strip() or "(optional)"

            return f"""
CLOUDFLARE ABUSE REPORT PREVIEW
===============================

Form URL: https://abuse.cloudflare.com/

Abuse type: Phishing & Malware

Field: name
Value: {reporter_name}

Field: email
Value: {reporter_email_addr or "(not set)"}

Field: email2
Value: {reporter_email_addr or "(not set)"}

Field: title (optional)
Value: {cf_title or "(blank)"}

Field: company (optional)
Value: {cf_company or "(blank)"}

Field: telephone (optional)
Value: {cf_tele or "(blank)"}

Field: urls
Value:
{evidence.url}

Field: justification (may be released publicly)
Value:
{template_data.get('body', 'N/A')}

Field: original_work / targeted_brand (optional)
Value:
{cf_brand or "(blank)"}

Field: reported_country (optional)
Value: {cf_country or "(blank)"}

Field: reported_user_agent (optional)
Value: {cf_user_agent or "(blank)"}

Field: comments (internal to Cloudflare)
Value:
{internal_comments}

Note: Cloudflare uses Turnstile; submission is typically manual.
"""
        if platform == "google":
            additional_info = ReportTemplates.google_safebrowsing_comment(evidence)
            form_url = "https://safebrowsing.google.com/safebrowsing/report_phish/"
            reporter = self.reporters.get("google")
            if reporter and hasattr(reporter, "get_form_url"):
                try:
                    form_url = reporter.get_form_url(evidence)
                except Exception:
                    pass
            return f"""
GOOGLE SAFE BROWSING REPORT PREVIEW
===================================

Form URL: {form_url}

Field: url
Value: {evidence.url}

Field: dq (additional details)
Value:
{additional_info}

Note: Google's form includes dynamic hidden fields; SeedBuster auto-discovers them at submit time.
"""
        if platform == "netcraft":
            reason = evidence.to_summary().strip()

            payload: dict[str, object] = {
                "urls": [
                    {
                        "url": evidence.url,
                        "reason": reason,
                    }
                ]
            }
            if reporter_email_addr:
                payload["email"] = reporter_email_addr

            return f"""
NETCRAFT REPORT PREVIEW
======================

Endpoint: https://report.netcraft.com/api/v3/report/urls
Method: POST
Body (JSON):
{json.dumps(payload, indent=2)}
"""
        if platform in ("registrar", "resend", "smtp"):
            template_data = ReportTemplates.generic_email(evidence, reporter_email or reporter_email_addr or "")
            return f"""
EMAIL REPORT PREVIEW
====================

Would send to: [Registrar abuse contact via RDAP lookup]

Subject: {template_data.get('subject', 'N/A')}

Body:
{template_data.get('body', 'N/A')}
"""
        return f"""
{platform.upper()} REPORT PREVIEW
{'=' * (len(platform) + 16)}

Platform: {platform}
Domain: {evidence.domain}
URL: {evidence.url}

Evidence Summary:
{evidence.to_summary()}
"""
