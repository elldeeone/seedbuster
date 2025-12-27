"""Report template generation for abuse reports."""

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from .base import ReportEvidence

if TYPE_CHECKING:
    from ..analyzer.clustering import ThreatCluster


class ReportTemplates:
    """Generates formatted abuse reports for various platforms."""

    @staticmethod
    def _extract_seed_phrase_indicator(reasons: list[str]) -> str | None:
        for reason in reasons or []:
            text = (reason or "").strip()
            if not text:
                continue
            lower = text.lower()
            if "seed phrase" not in lower and "mnemonic" not in lower:
                continue
            match = re.search(r"'([^']+)'", text)
            if match:
                return match.group(1).strip() or None
        return None

    @classmethod
    def _summarize_reasons(cls, reasons: list[str], *, max_items: int = 5) -> list[str]:
        cleaned: list[str] = []
        for r in reasons or []:
            text = (r or "").strip()
            if text:
                cleaned.append(text)

        if not cleaned:
            return []

        drop_substrings = (
            "suspicion score",
            "domain suspicion",
            "keyword",
            "tld",
            "kaspa-related title",
            "wallet-related title",
            "known malicious domain",
        )

        keep_substrings = (
            "seed phrase",
            "mnemonic",
            "recovery phrase",
            "private key",
            "walletconnect",
            "cloaking detected",
            "ondigitalocean.app",
            "workers.dev",
        )

        def humanize(text: str) -> str:
            out = (text or "").strip()
            lower = out.lower()
            if lower.startswith("temporal:"):
                out = out.split(":", 1)[1].strip()
            out = out.replace("Seed phrase form found via exploration:", "Seed phrase form detected:")
            out = out.replace("Seed phrase form found:", "Seed phrase form detected:")
            out = out.replace(" via exploration", "")
            out = out.replace("Cloaking detected", "Cloaking detected (content varied across scans)")
            return out

        high_signal: list[str] = []
        other: list[str] = []
        for text in cleaned:
            lower = text.lower()
            if lower.startswith("temporal:") and "cloaking" not in lower:
                # "Temporal" heuristics are noisy; keep only explicit cloaking.
                continue
            if any(s in lower for s in drop_substrings):
                continue
            if any(s in lower for s in keep_substrings):
                high_signal.append(humanize(text))
            else:
                other.append(humanize(text))

        out = high_signal[: max_items]
        if len(out) < max_items:
            out.extend(other[: max_items - len(out)])

        if not out:
            out = cleaned[: max_items]

        return out

    @classmethod
    def generic_email(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """
        Generate a generic abuse report email.
        Action-first format optimized for busy abuse teams.
        Routes to appropriate template based on scam_type.
        """
        # Route to crypto doubler template if applicable
        if evidence.scam_type == "crypto_doubler":
            return cls.crypto_doubler_generic(evidence, reporter_email)

        subject = f"Phishing Takedown Request (Seed Phrase Theft): {evidence.domain}"

        seed_hint = cls._extract_seed_phrase_indicator(evidence.detection_reasons)
        seed_line = f"Observed seed phrase field: '{seed_hint}'" if seed_hint else "Observed seed phrase theft flow"
        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=5)
        if seed_hint:
            seed_lower = seed_hint.lower()
            highlights = [
                h
                for h in highlights
                if "seed phrase form detected" not in h.lower() and seed_lower not in h.lower()
            ]
        observations = [seed_line, *highlights]

        body = f"""Cryptocurrency phishing / seed phrase theft

Action requested:
- Please suspend/disable the phishing content for the URL below.

{cls._build_target_section(evidence)}

What we observed:
{cls._format_list(observations, prefix='- ')}

Impact:
- A seed phrase is the master key for a crypto wallet; theft enables immediate, irreversible loss of funds.

"""
        body += cls._build_backend_section(evidence)
        body += cls._build_endpoints_section(evidence)
        body += cls._build_api_keys_section(evidence)
        body += cls._build_attachments_section(evidence)
        body += cls._build_footer(reporter_email)

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
        # Route to crypto doubler template if applicable
        if evidence.scam_type == "crypto_doubler":
            return cls.crypto_doubler_cloudflare(evidence, reporter_email)

        subject = f"Phishing report: {evidence.domain}"

        seed_hint = cls._extract_seed_phrase_indicator(evidence.detection_reasons)
        seed_line = f"Requests seed phrase ('{seed_hint}')" if seed_hint else "Requests cryptocurrency seed phrase"
        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=4)

        body = f"""Cryptocurrency phishing (seed phrase theft)

Evidence URL: {evidence.url}
Observed: {seed_line}
Confidence: {evidence.confidence_score}%

Key evidence (automated capture):
{cls._format_list(highlights, prefix='- ')}

Steps to reproduce:
1) Open the evidence URL above.
2) The page presents a wallet/recovery flow.
3) It prompts the user to enter their seed phrase/mnemonic.

Captured evidence (screenshot + HTML) available on request.
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
        # Route to crypto doubler template if applicable
        if evidence.scam_type == "crypto_doubler":
            return cls.crypto_doubler_registrar(evidence, reporter_email, registrar_name)

        registrar_str = f" - {registrar_name}" if registrar_name else ""
        subject = f"Domain Abuse Report (phishing / seed phrase theft): {evidence.domain}"

        seed_hint = cls._extract_seed_phrase_indicator(evidence.detection_reasons)
        seed_line = f"Observed seed phrase field: '{seed_hint}'" if seed_hint else "Observed seed phrase theft flow"
        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=5)
        if seed_hint:
            seed_lower = seed_hint.lower()
            highlights = [
                h
                for h in highlights
                if "seed phrase form detected" not in h.lower() and seed_lower not in h.lower()
            ]
        observations = [seed_line, *highlights]

        body = f"""Registrar abuse report{registrar_str}

Action requested:
- Please suspend/disable this domain for phishing / cryptocurrency theft.

{cls._build_target_section(evidence)}

What we observed:
{cls._format_list(observations, prefix='- ')}

"""
        body += cls._build_backend_section(evidence)
        body += cls._build_endpoints_section(evidence)
        body += cls._build_attachments_section(evidence)
        body += cls._build_footer(reporter_email)

        return {"subject": subject, "body": body}

    @classmethod
    def google_safebrowsing_comment(cls, evidence: ReportEvidence) -> str:
        """Generate additional info for Google Safe Browsing report."""
        # Use appropriate comment based on scam type
        if evidence.scam_type == "crypto_doubler":
            return cls._google_safebrowsing_doubler_comment(evidence)
        # Default to seed phishing
        seed_hint = cls._extract_seed_phrase_indicator(evidence.detection_reasons)
        seed_line = f"Requests seed phrase ('{seed_hint}')." if seed_hint else "Requests cryptocurrency seed phrase."
        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=4)
        lines = [
            "Cryptocurrency wallet phishing (seed phrase theft).",
            seed_line,
            "",
            "Key evidence (automated capture):",
        ]
        for reason in highlights:
            lines.append(f"- {reason}")
        lines.extend(["", "Captured evidence (screenshot + HTML) available on request."])
        return "\n".join(lines)

    @classmethod
    def _google_safebrowsing_doubler_comment(cls, evidence: ReportEvidence) -> str:
        """Generate Google Safe Browsing comment for crypto doubler scams."""
        lines = [
            "Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam).",
            "Impersonates official project to steal cryptocurrency.",
            "",
        ]
        if evidence.scammer_wallets:
            lines.append(f"Scammer wallet: {evidence.scammer_wallets[0]}")
            lines.append("")
        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=4)
        lines.append("Key evidence (automated capture):")
        for reason in highlights:
            lines.append(f"- {reason}")
        lines.extend(["", "Captured evidence (screenshot + HTML) available on request."])
        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Crypto Doubler / Fake Giveaway Templates
    # -------------------------------------------------------------------------

    @classmethod
    def crypto_doubler_generic(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """Generate a generic abuse report for crypto doubler scams."""
        subject = f"Fraud Report (Crypto Doubler/Giveaway Scam): {evidence.domain}"

        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=5)

        body = f"""Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam)

Action requested:
- Please suspend/disable this fraudulent site.

{cls._build_target_section(evidence, include_scam_type=True, scam_type_label="Crypto Doubler / Fake Giveaway")}

What we observed:
{cls._format_list(highlights, prefix='- ')}

"""
        body += cls._build_scammer_wallets_section(evidence)
        body += """How this scam works:
- Site impersonates official Kaspa project (kaspa.org)
- Claims users will receive 3X back if they send cryptocurrency
- Shows fake transaction history and countdown timers
- Victim sends crypto to scammer's wallet; receives nothing back

Impact:
- This is advance-fee fraud. Victims lose all cryptocurrency sent.

"""
        body += cls._build_attachments_section(evidence)
        body += cls._build_footer(reporter_email)

        return {"subject": subject, "body": body}

    @classmethod
    def crypto_doubler_registrar(
        cls,
        evidence: ReportEvidence,
        reporter_email: str,
        registrar_name: Optional[str] = None,
    ) -> dict:
        """Generate a domain registrar abuse report for crypto doubler scams."""
        registrar_str = f" - {registrar_name}" if registrar_name else ""
        subject = f"Domain Abuse Report (crypto fraud): {evidence.domain}"

        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=5)

        body = f"""Registrar abuse report{registrar_str}

Action requested:
- Please suspend/disable this domain for advance-fee fraud / cryptocurrency scam.

{cls._build_target_section(evidence, include_scam_type=True, scam_type_label="Crypto Doubler / Fake Giveaway")}

What we observed:
{cls._format_list(highlights, prefix='- ')}

"""
        # Custom scammer wallet section with different label
        if evidence.scammer_wallets:
            body += f"Scammer wallet addresses (crypto sent here is stolen):\n{cls._format_list(evidence.scammer_wallets, prefix='- ')}\n\n"

        body += """How this scam works:
- Site clones official cryptocurrency project branding (kaspa.org)
- Promotes fake "airdrop" or "giveaway event"
- Claims users will receive 3X returns if they send cryptocurrency
- Shows fabricated transaction history to build false trust
- Victim sends crypto to scammer's wallet address
- Scammer keeps the funds; victim receives nothing

This is advance-fee fraud targeting cryptocurrency users.

"""
        body += cls._build_attachments_section(evidence)
        body += cls._build_footer(reporter_email)

        return {"subject": subject, "body": body}

    @classmethod
    def crypto_doubler_cloudflare(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """Generate a Cloudflare abuse report for crypto doubler scams."""
        subject = f"Fraud report: {evidence.domain}"

        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=4)

        body = f"""Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam)

Evidence URL: {evidence.url}
Scam type: Fake crypto giveaway promising 3X returns
Confidence: {evidence.confidence_score}%

"""

        if evidence.scammer_wallets:
            body += f"""Scammer wallet: {evidence.scammer_wallets[0]}

"""

        body += f"""Key evidence (automated capture):
{cls._format_list(highlights, prefix='- ')}

Steps to reproduce:
1) Open the evidence URL above.
2) The page impersonates kaspa.org with a "Join Event" button.
3) Clicking leads to a page promising 3X returns on sent crypto.
4) A wallet address is displayed for victims to send funds.

Captured evidence (screenshot + HTML) available on request.
"""

        return {
            "subject": subject,
            "body": body,
            "abuse_type": "phishing",
            "url": evidence.url,
        }

    @staticmethod
    def _format_list(items: list[str], prefix: str = "  - ") -> str:
        """Format a list of items with prefix."""
        if not items:
            return "  (none)"
        return "\n".join(f"{prefix}{item}" for item in items)

    # -------------------------------------------------------------------------
    # Shared Section Builders (reduce duplication across templates)
    # -------------------------------------------------------------------------

    @classmethod
    def _build_target_section(
        cls,
        evidence: ReportEvidence,
        *,
        include_scam_type: bool = False,
        scam_type_label: str = "",
    ) -> str:
        """Build the common 'Target:' section used in most templates."""
        lines = [
            "Target:",
            f"- Domain: {evidence.domain}",
            f"- URL: {evidence.url}",
            f"- Detected: {evidence.detected_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"- Confidence: {evidence.confidence_score}%",
        ]
        if include_scam_type and scam_type_label:
            lines.append(f"- Scam type: {scam_type_label}")
        return "\n".join(lines)

    @classmethod
    def _build_attachments_section(cls, evidence: ReportEvidence) -> str:
        """Build the attachments section if evidence files exist."""
        attachments: list[str] = []
        if evidence.screenshot_path and evidence.screenshot_path.exists():
            attachments.append(f"{evidence.screenshot_path.name} (screenshot)")
        if evidence.html_path and evidence.html_path.exists():
            attachments.append(f"{evidence.html_path.name} (HTML capture)")
        if not attachments:
            return ""
        return f"Attachments:\n{cls._format_list(attachments, prefix='- ')}\n\n"

    @staticmethod
    def _build_footer(reporter_email: str) -> str:
        """Build the common footer with reporter info."""
        return f"""Reporter: {reporter_email}
Tool: SeedBuster (automated phishing detection)
Source: https://github.com/elldeeone/seedbuster
"""

    @classmethod
    def _build_backend_section(cls, evidence: ReportEvidence) -> str:
        """Build backend infrastructure section if applicable."""
        if not evidence.backend_domains:
            return ""
        return f"Backend infrastructure (if applicable):\n{cls._format_list(evidence.backend_domains, prefix='- ')}\n\n"

    @classmethod
    def _build_endpoints_section(cls, evidence: ReportEvidence, max_items: int = 5) -> str:
        """Build suspicious endpoints section if applicable."""
        if not evidence.suspicious_endpoints:
            return ""
        return f"Observed data collection endpoints:\n{cls._format_list(evidence.suspicious_endpoints[:max_items], prefix='- ')}\n\n"

    @classmethod
    def _build_api_keys_section(cls, evidence: ReportEvidence) -> str:
        """Build API keys section if applicable."""
        if not evidence.api_keys_found:
            return ""
        return f"API keys found in malicious code:\n{cls._format_list(evidence.api_keys_found, prefix='- ')}\n\n"

    @classmethod
    def _build_scammer_wallets_section(cls, evidence: ReportEvidence) -> str:
        """Build scammer wallet addresses section if applicable."""
        if not evidence.scammer_wallets:
            return ""
        return f"Scammer wallet addresses:\n{cls._format_list(evidence.scammer_wallets, prefix='- ')}\n\n"

    # -------------------------------------------------------------------------
    # Campaign-Level Templates
    # -------------------------------------------------------------------------

    @classmethod
    def campaign_digitalocean(
        cls,
        cluster: "ThreatCluster",
        reporter_email: str,
    ) -> dict:
        """
        Generate a DigitalOcean abuse report for an entire campaign.
        Lists ALL backend apps and ALL frontends using them.
        """
        # Extract all DO apps from cluster backends
        do_apps = [
            backend for backend in cluster.shared_backends
            if "ondigitalocean.app" in backend.lower()
        ]

        if not do_apps:
            return {"subject": "", "body": "No DigitalOcean apps found in cluster"}

        subject = f"URGENT: {len(do_apps)} App Platform Apps Used in Coordinated Phishing Campaign - {cluster.name}"

        body = f"""
================================================================================
      URGENT: COORDINATED CRYPTOCURRENCY PHISHING CAMPAIGN
           DigitalOcean App Platform - Multiple Apps Involved
================================================================================

ACTION REQUESTED
----------------
Please IMMEDIATELY suspend ALL of the following App Platform applications.
This is a coordinated campaign with {len(cluster.members)} phishing domains
all using these backends to receive stolen cryptocurrency seed phrases.

"""

        body += """APPS TO SUSPEND (PRIORITY - DISABLES ALL PHISHING SITES)
=========================================================
"""
        for i, app in enumerate(do_apps, 1):
            # Count how many frontends use this backend
            using_count = sum(1 for m in cluster.members if app in m.backends)
            body += f"  {i}. {app}\n"
            body += f"     Used by {using_count} phishing domain(s)\n\n"

        body += f"""
================================================================================
                         CAMPAIGN OVERVIEW
================================================================================

Campaign Name:   {cluster.name}
Campaign ID:     {cluster.cluster_id}
Total Domains:   {len(cluster.members)}
Shared Backends: {len(do_apps)} DigitalOcean apps
Confidence:      {cluster.confidence:.0f}%
First Detected:  {cluster.created_at.strftime('%Y-%m-%d')}
Last Updated:    {cluster.updated_at.strftime('%Y-%m-%d')}

PHISHING DOMAINS IN THIS CAMPAIGN
----------------------------------
"""
        for i, member in enumerate(cluster.members, 1):
            body += f"  {i}. {member.domain} (score: {member.score}%)\n"

        body += f"""
================================================================================
                         HOW THE ATTACK WORKS
================================================================================

  1. Victim visits one of {len(cluster.members)} fake wallet sites (listed above)
  2. Site displays fake "restore wallet" form requesting 12-word seed phrase
  3. Victim enters their seed phrase thinking it's legitimate
  4. Data is POST'd to DigitalOcean App Platform backends (listed above)
  5. Attacker uses seed phrase to steal all cryptocurrency from victim's wallet

WHY THIS IS HIGH PRIORITY
-------------------------
- The backend apps are the CHOKEPOINT for the entire campaign
- Suspending {len(do_apps)} apps immediately disables {len(cluster.members)} phishing sites
- This is more efficient than reporting each phishing domain individually
- The attacker is actively stealing cryptocurrency through these backends

"""

        if cluster.shared_kits:
            body += f"""PHISHING KIT SIGNATURES DETECTED
---------------------------------
{cls._format_list(list(cluster.shared_kits))}

"""

        body += f"""================================================================================
                         RECOMMENDED ACTIONS
================================================================================

1. IMMEDIATE: Suspend all {len(do_apps)} App Platform applications listed above
2. Preserve application logs for law enforcement
3. Check for other apps by same owner (likely same threat actor)
4. Consider sharing threat indicators with security community

================================================================================

ABOUT THIS REPORT
-----------------
This report was generated by SeedBuster, an automated system that monitors
for cryptocurrency phishing campaigns. This is a CAMPAIGN report showing
the full scope of coordinated phishing infrastructure.

Reporter:    {reporter_email}
Tool:        SeedBuster - Cryptocurrency Phishing Detection
Source:      https://github.com/elldeeone/seedbuster
Report Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

We are happy to provide additional evidence (screenshots, HAR files,
analysis data) upon request.
"""

        return {"subject": subject, "body": body}

    @classmethod
    def campaign_registrar(
        cls,
        cluster: "ThreatCluster",
        registrar_name: str,
        domains: List[str],
        reporter_email: str,
    ) -> dict:
        """
        Generate a bulk registrar abuse report for all domains at one registrar.
        """
        subject = f"Bulk Abuse Report: {len(domains)} Phishing Domains - {cluster.name}"

        body = f"""
================================================================================
              BULK DOMAIN ABUSE REPORT - {registrar_name.upper()}
================================================================================

ACTION REQUESTED
----------------
Please investigate and suspend the following {len(domains)} domain(s).
These are part of a coordinated phishing campaign targeting cryptocurrency users.

DOMAINS REGISTERED WITH {registrar_name.upper()}
{"=" * (35 + len(registrar_name))}
"""
        for i, domain in enumerate(domains, 1):
            body += f"  {i}. {domain}\n"

        body += f"""
================================================================================
                         CAMPAIGN CONTEXT
================================================================================

This is not an isolated incident. These domains are part of the
"{cluster.name}" phishing campaign with {len(cluster.members)} total domains.

Campaign ID:     {cluster.cluster_id}
Total Domains:   {len(cluster.members)} (across all registrars)
Your Domains:    {len(domains)}
Confidence:      {cluster.confidence:.0f}%
First Detected:  {cluster.created_at.strftime('%Y-%m-%d')}

SHARED INFRASTRUCTURE (proves coordination)
-------------------------------------------
All domains in this campaign share:
"""

        if cluster.shared_backends:
            body += f"""
Backend Servers:
{cls._format_list(list(cluster.shared_backends)[:5])}
"""

        if cluster.shared_nameservers:
            body += f"""
Nameservers:
{cls._format_list(list(cluster.shared_nameservers))}
"""

        body += f"""
================================================================================
                         ABUSE DESCRIPTION
================================================================================

These domains host phishing sites impersonating legitimate cryptocurrency
wallets. They trick users into entering their seed phrases (12/24-word
recovery phrases), which provide complete control over cryptocurrency
wallets and enable immediate, irreversible theft of funds.

================================================================================

Reporter: {reporter_email}
Tool:     SeedBuster - Automated Phishing Detection
Source:   https://github.com/elldeeone/seedbuster
"""

        return {"subject": subject, "body": body}

    @classmethod
    def campaign_dns_provider(
        cls,
        cluster: "ThreatCluster",
        provider_name: str,
        reporter_email: str,
    ) -> dict:
        """
        Generate a DNS provider abuse report for domains using their nameservers.
        """
        # Find domains using this provider's nameservers
        provider_lower = provider_name.lower()
        affected_domains = []
        for member in cluster.members:
            for ns in member.nameservers:
                if provider_lower in ns.lower():
                    affected_domains.append(member.domain)
                    break

        subject = f"DNS Abuse Report: {len(affected_domains)} Phishing Domains - {provider_name}"

        body = f"""
================================================================================
                 DNS ABUSE REPORT - {provider_name.upper()}
================================================================================

ACTION REQUESTED
----------------
Please investigate the following domains using your DNS services.
They are part of a coordinated phishing campaign targeting cryptocurrency users.

AFFECTED DOMAINS
----------------
"""
        for i, domain in enumerate(affected_domains, 1):
            body += f"  {i}. {domain}\n"

        body += f"""
================================================================================
                         CAMPAIGN CONTEXT
================================================================================

Campaign Name:   {cluster.name}
Total Domains:   {len(cluster.members)}
Using Your DNS:  {len(affected_domains)}
Confidence:      {cluster.confidence:.0f}%

EVIDENCE OF COORDINATION
------------------------
"""

        if cluster.shared_backends:
            body += f"""Shared Backend Servers:
{cls._format_list(list(cluster.shared_backends)[:3])}

"""

        body += f"""================================================================================

Reporter: {reporter_email}
Tool:     SeedBuster - Automated Phishing Detection
"""

        return {"subject": subject, "body": body}
