"""Report template generation for abuse reports."""

from datetime import datetime, timezone
from typing import Optional

from .base import ReportEvidence


class ReportTemplates:
    """Generates formatted abuse reports for various platforms."""

    @classmethod
    def generic_email(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """
        Generate a generic abuse report email.
        Action-first format optimized for busy abuse teams.
        """
        subject = f"Phishing Report: {evidence.domain}"

        body = f"""
================================================================================
                         PHISHING ABUSE REPORT
================================================================================

ACTION REQUESTED
----------------
Please investigate and take down the following phishing infrastructure.

REPORTED SITE
-------------
  Domain:     {evidence.domain}
  URL:        {evidence.url}
  Detected:   {evidence.detected_at.strftime('%Y-%m-%d %H:%M UTC')}
  Confidence: {evidence.confidence_score}%

--------------------------------------------------------------------------------
                              EVIDENCE
--------------------------------------------------------------------------------

DETECTION REASONS
{cls._format_list(evidence.detection_reasons)}

"""

        if evidence.backend_domains:
            body += f"""BACKEND INFRASTRUCTURE
The phishing site sends stolen data to these servers:
{cls._format_list(evidence.backend_domains)}

"""

        if evidence.suspicious_endpoints:
            body += f"""DATA EXFILTRATION ENDPOINTS
{cls._format_list(evidence.suspicious_endpoints[:5])}

"""

        if evidence.api_keys_found:
            body += f"""API KEYS FOUND IN MALICIOUS CODE
(useful for tracking this threat actor)
{cls._format_list(evidence.api_keys_found)}

"""

        body += """--------------------------------------------------------------------------------
                           ABOUT THIS THREAT
--------------------------------------------------------------------------------

WHAT IS SEED PHRASE PHISHING?
Cryptocurrency wallets use a 12 or 24-word "seed phrase" as a master key.
Anyone with these words has COMPLETE control over the wallet and can steal
all funds instantly and irreversibly.

This phishing site impersonates a legitimate wallet and tricks users into
entering their seed phrase, which is then sent to the attacker's servers.

IMPACT
- Victims lose all cryptocurrency in their wallet
- Theft is immediate and irreversible
- No bank or authority can recover the funds

--------------------------------------------------------------------------------

Reporter: {}
Tool: SeedBuster - Automated Cryptocurrency Phishing Detection
Source: https://github.com/elldeeone/seedbuster
""".format(reporter_email)

        return {"subject": subject, "body": body}

    @classmethod
    def digitalocean(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """
        Generate a DigitalOcean-specific abuse report.
        Optimized for their abuse team with clear action items.
        """
        subject = f"URGENT: Phishing Backend on App Platform - {evidence.domain}"

        # Extract DO apps
        do_apps = [d for d in (evidence.backend_domains or []) if "ondigitalocean.app" in d]

        body = """
================================================================================
              URGENT: CRYPTOCURRENCY PHISHING INFRASTRUCTURE
                    DigitalOcean App Platform Abuse Report
================================================================================

ACTION REQUESTED
----------------
Please IMMEDIATELY suspend the following App Platform applications.
They are actively receiving stolen cryptocurrency seed phrases.

"""

        if do_apps:
            body += """APPS TO SUSPEND
---------------
"""
            for i, app in enumerate(do_apps, 1):
                body += f"  {i}. {app}\n"
            body += "\n"

        body += f"""================================================================================
                              INCIDENT DETAILS
================================================================================

PHISHING SITE (FRONTEND)
------------------------
  Domain:     {evidence.domain}
  URL:        {evidence.url}
  Detected:   {evidence.detected_at.strftime('%Y-%m-%d %H:%M UTC')}
  Confidence: {evidence.confidence_score}%

HOW THE ATTACK WORKS
--------------------
  1. Victim visits {evidence.domain} (fake cryptocurrency wallet)
  2. Site displays fake "restore wallet" form requesting 12-word seed phrase
  3. Victim enters their seed phrase thinking it's legitimate
  4. Data is POST'd to DigitalOcean App Platform backends (listed above)
  5. Attacker uses seed phrase to steal all cryptocurrency from victim's wallet

"""

        if evidence.suspicious_endpoints:
            body += """DATA EXFILTRATION ENDPOINTS
---------------------------
"""
            for endpoint in evidence.suspicious_endpoints[:5]:
                body += f"  - {endpoint}\n"
            body += "\n"

        body += f"""================================================================================
                              EVIDENCE
================================================================================

DETECTION INDICATORS
--------------------
{cls._format_list(evidence.detection_reasons)}

"""

        if evidence.api_keys_found:
            body += f"""API KEYS IN MALICIOUS CODE
--------------------------
(May help identify threat actor across incidents)
{cls._format_list(evidence.api_keys_found)}

"""

        body += f"""================================================================================
                           RECOMMENDED ACTIONS
================================================================================

1. IMMEDIATE: Suspend/terminate the App Platform applications listed above
2. Preserve application logs for potential law enforcement referral
3. Consider sharing threat indicators with security community

================================================================================

ABOUT THIS REPORT
-----------------
This report was generated by SeedBuster, an automated system that monitors
for cryptocurrency phishing sites targeting the Kaspa ecosystem.

Reporter:    {reporter_email}
Tool:        SeedBuster - Cryptocurrency Phishing Detection
Source:      https://github.com/elldeeone/seedbuster
Report Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

We are happy to provide additional evidence (screenshots, HTML captures,
network logs) upon request.
"""

        return {"subject": subject, "body": body}

    @classmethod
    def cloudflare(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """Generate a Cloudflare abuse report."""
        subject = f"Phishing Report: {evidence.domain}"

        body = f"""CRYPTOCURRENCY PHISHING SITE

ACTION REQUESTED: Block/flag this domain for phishing

REPORTED SITE
  Domain:     {evidence.domain}
  URL:        {evidence.url}
  Confidence: {evidence.confidence_score}%

WHAT IT DOES
This site impersonates a legitimate cryptocurrency wallet. It tricks users
into entering their 12-word seed phrase, which gives attackers complete
control over the victim's wallet and all funds.

DETECTION EVIDENCE
{cls._format_list(evidence.detection_reasons)}

"""
        if evidence.backend_domains:
            body += f"""BACKEND SERVERS (receiving stolen data)
{cls._format_list(evidence.backend_domains)}

"""

        body += f"""---
Reporter: {reporter_email}
Detection: SeedBuster (automated phishing detection)
"""

        return {
            "subject": subject,
            "body": body,
            "abuse_type": "phishing",
            "url": evidence.url,
        }

    @classmethod
    def registrar(
        cls,
        evidence: ReportEvidence,
        reporter_email: str,
        registrar_name: Optional[str] = None,
    ) -> dict:
        """Generate a domain registrar abuse report."""
        registrar_str = f" - {registrar_name}" if registrar_name else ""
        subject = f"Domain Abuse Report: {evidence.domain}"

        body = f"""
================================================================================
                    DOMAIN ABUSE REPORT{registrar_str}
================================================================================

ACTION REQUESTED
----------------
Please investigate and consider suspending this domain for phishing.

REPORTED DOMAIN
---------------
  Domain:     {evidence.domain}
  URL:        {evidence.url}
  Abuse Type: Phishing / Cryptocurrency Theft
  Detected:   {evidence.detected_at.strftime('%Y-%m-%d %H:%M UTC')}
  Confidence: {evidence.confidence_score}%

DESCRIPTION
-----------
This domain hosts a phishing site impersonating a legitimate cryptocurrency
wallet. It collects victims' seed phrases (12/24-word recovery phrases),
which provide complete control over cryptocurrency wallets and enable
immediate, irreversible theft of funds.

EVIDENCE
--------
{cls._format_list(evidence.detection_reasons)}

"""

        if evidence.backend_domains:
            body += f"""BACKEND INFRASTRUCTURE
{cls._format_list(evidence.backend_domains)}

"""

        if evidence.suspicious_endpoints:
            body += f"""MALICIOUS ENDPOINTS
{cls._format_list(evidence.suspicious_endpoints[:5])}

"""

        body += f"""================================================================================

Reporter: {reporter_email}
Tool:     SeedBuster - Automated Phishing Detection
Source:   https://github.com/elldeeone/seedbuster
"""

        return {"subject": subject, "body": body}

    @classmethod
    def phishtank_comment(cls, evidence: ReportEvidence) -> str:
        """Generate a comment for PhishTank submission."""
        lines = [
            "Cryptocurrency seed phrase phishing site.",
            f"Confidence: {evidence.confidence_score}%",
            "",
            "Detection reasons:",
        ]
        for reason in evidence.detection_reasons[:5]:
            lines.append(f"- {reason}")

        if evidence.backend_domains:
            lines.append("")
            lines.append("Backend infrastructure:")
            for backend in evidence.backend_domains[:3]:
                lines.append(f"- {backend}")

        lines.append("")
        lines.append("Detected by SeedBuster")

        return "\n".join(lines)

    @classmethod
    def google_safebrowsing_comment(cls, evidence: ReportEvidence) -> str:
        """Generate additional info for Google Safe Browsing report."""
        lines = [
            "Cryptocurrency wallet phishing - steals seed phrases",
            "",
            "Evidence:",
        ]
        for reason in evidence.detection_reasons[:5]:
            lines.append(f"- {reason}")

        return "\n".join(lines)

    @staticmethod
    def _format_list(items: list[str], prefix: str = "  - ") -> str:
        """Format a list of items with prefix."""
        if not items:
            return "  (none)"
        return "\n".join(f"{prefix}{item}" for item in items)
