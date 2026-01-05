"""Report template generation for abuse reports."""

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from .base import ReportEvidence

if TYPE_CHECKING:
    from ..analyzer.campaigns import ThreatCampaign


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
    def _resolve_scam_type(cls, evidence: ReportEvidence) -> str:
        return evidence.resolve_scam_type()

    @classmethod
    def _scam_headline(cls, evidence: ReportEvidence) -> str:
        scam_type = cls._resolve_scam_type(evidence)
        if scam_type == "crypto_doubler":
            return "Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam)"
        if scam_type == "fake_airdrop":
            return "Cryptocurrency fraud (fake airdrop/claim)"
        if scam_type == "seed_phishing":
            return "Cryptocurrency phishing (seed phrase theft)"
        return "Cryptocurrency fraud / phishing"

    @classmethod
    def _observed_summary_line(cls, evidence: ReportEvidence) -> str:
        scam_type = cls._resolve_scam_type(evidence)
        if scam_type == "crypto_doubler":
            return "Observed crypto giveaway / doubler fraud"
        if scam_type == "fake_airdrop":
            return "Observed fake airdrop / claim flow"
        if scam_type == "seed_phishing":
            seed_hint = cls._extract_seed_phrase_indicator(evidence.detection_reasons)
            if seed_hint:
                return f"Requests seed phrase ('{seed_hint}')"
            return "Requests cryptocurrency seed phrase"
        return "Observed cryptocurrency fraud / phishing content"

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
            "kaspa",
            "airdrop",
            "giveaway",
            "claim",
            "support",
            "doubler",
        )

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
                high_signal.append(ReportEvidence.humanize_reason(text))
            else:
                other.append(ReportEvidence.humanize_reason(text))

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
        Uses the standardized evidence summary for consistency across platforms.
        """
        scam_type = cls._resolve_scam_type(evidence)
        if scam_type == "crypto_doubler":
            subject = f"Fraud Report (Crypto Doubler/Giveaway Scam): {evidence.domain}"
        elif scam_type == "seed_phishing":
            subject = f"Phishing Takedown Request (Seed Phrase Theft): {evidence.domain}"
        elif scam_type == "fake_airdrop":
            subject = f"Fraudulent Airdrop Takedown Request: {evidence.domain}"
        else:
            subject = f"Fraud/Phishing Takedown Request: {evidence.domain}"

        body = evidence.to_summary().strip()
        return {"subject": subject, "body": body}

    @classmethod
    def digitalocean(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """
        Generate a DigitalOcean-specific abuse report.
        Optimized for their abuse team with clear action items.
        """
        scam_type = cls._resolve_scam_type(evidence)
        if scam_type == "seed_phishing":
            subject = f"URGENT: Phishing Backend on App Platform - {evidence.domain}"
            header_label = "CRYPTOCURRENCY PHISHING INFRASTRUCTURE"
            action_detail = "They are actively receiving stolen cryptocurrency seed phrases."
            attack_steps = [
                f"  1. Victim visits {evidence.domain} (fake cryptocurrency wallet)",
                "  2. Site displays fake \"restore wallet\" form requesting 12-word seed phrase",
                "  3. Victim enters their seed phrase thinking it's legitimate",
                "  4. Data is POST'd to DigitalOcean App Platform backends (listed above)",
                "  5. Attacker uses seed phrase to steal all cryptocurrency from victim's wallet",
            ]
        elif scam_type == "fake_airdrop":
            subject = f"URGENT: Fraudulent Airdrop Backend on App Platform - {evidence.domain}"
            header_label = "CRYPTOCURRENCY FRAUD INFRASTRUCTURE"
            action_detail = "They are supporting a fraudulent airdrop/claim flow."
            attack_steps = [
                f"  1. Victim visits {evidence.domain} (fake airdrop/claim page)",
                "  2. Site presents a fake airdrop/claim flow",
                "  3. User is prompted to proceed with claim steps",
                "  4. Any submitted data/actions are sent to DigitalOcean App Platform backends",
                "  5. Victims may lose funds or expose sensitive details",
            ]
        else:
            subject = f"URGENT: Fraudulent Crypto Backend on App Platform - {evidence.domain}"
            header_label = "CRYPTOCURRENCY FRAUD INFRASTRUCTURE"
            action_detail = "They are supporting a cryptocurrency fraud/phishing flow."
            attack_steps = [
                f"  1. Victim visits {evidence.domain} (fraudulent crypto-themed site)",
                "  2. Site presents malicious or misleading content",
                "  3. User is prompted to proceed with unsafe actions",
                "  4. Any submitted data/actions are sent to DigitalOcean App Platform backends",
                "  5. Victims may lose funds or expose sensitive details",
            ]

        # Extract DO apps
        do_apps = [d for d in (evidence.backend_domains or []) if "ondigitalocean.app" in d]

        body = f"""
================================================================================
              URGENT: {header_label}
                    DigitalOcean App Platform Abuse Report
================================================================================

ACTION REQUESTED
----------------
Please IMMEDIATELY suspend the following App Platform applications.
{action_detail}

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

HOW THE ATTACK WORKS
--------------------
{chr(10).join(attack_steps)}

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
Reporter:    {reporter_email}
Report Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

We can provide additional evidence (screenshots, HTML captures, network logs)
upon request.
"""

        return {"subject": subject, "body": body}

    @classmethod
    def cloudflare(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """Generate a Cloudflare abuse report."""
        # Route to crypto doubler template if applicable
        scam_type = cls._resolve_scam_type(evidence)
        if scam_type == "crypto_doubler":
            return cls.crypto_doubler_cloudflare(evidence, reporter_email)

        subject = f"Phishing report: {evidence.domain}"

        headline = cls._scam_headline(evidence)
        observed_line = cls._observed_summary_line(evidence)
        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=4)
        impersonation = evidence.get_impersonation_lines()

        if scam_type == "seed_phishing":
            steps = [
                "1) Open the evidence URL above.",
                "2) The page presents a wallet/recovery flow.",
                "3) It prompts the user to enter their seed phrase/mnemonic.",
            ]
        elif scam_type == "fake_airdrop":
            steps = [
                "1) Open the evidence URL above.",
                "2) The page presents a fake airdrop/claim flow.",
                "3) The user is prompted to proceed with claim steps.",
            ]
        else:
            steps = [
                "1) Open the evidence URL above.",
                "2) The page presents fraudulent content.",
                "3) The user is prompted to proceed with unsafe actions.",
            ]

        body = f"""{headline}

Evidence URL: {evidence.url}
Observed: {observed_line}

Key evidence from our review:
{cls._format_list(highlights, prefix='- ')}

Steps to reproduce:
{cls._format_list(steps, prefix='')}

Captured evidence (screenshot + HTML) available on request.
"""

        if impersonation:
            body = body.replace(
                "Key evidence from our review:",
                "Impersonation indicators:\n"
                f"{cls._format_list(impersonation, prefix='- ')}\n\n"
                "Key evidence from our review:",
            )

        body = cls._append_public_entry(body, evidence)

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
        scam_type = cls._resolve_scam_type(evidence)
        if scam_type == "seed_phishing":
            subject = f"Domain Abuse Report (phishing / seed phrase theft): {evidence.domain}"
        elif scam_type == "fake_airdrop":
            subject = f"Domain Abuse Report (fake airdrop/fraud): {evidence.domain}"
        elif scam_type == "crypto_doubler":
            subject = f"Domain Abuse Report (crypto fraud): {evidence.domain}"
        else:
            subject = f"Domain Abuse Report (cryptocurrency fraud): {evidence.domain}"

        body = evidence.to_summary().strip()
        return {"subject": subject, "body": body}

    @classmethod
    def google_safebrowsing_comment(cls, evidence: ReportEvidence) -> str:
        """Generate additional info for Google Safe Browsing report."""
        return evidence.to_summary().strip()

    @classmethod
    def _google_safebrowsing_doubler_comment(cls, evidence: ReportEvidence) -> str:
        """Generate Google Safe Browsing comment for crypto doubler scams."""
        headline = cls._scam_headline(evidence)
        impersonation = evidence.get_impersonation_lines()
        lines = [f"{headline}."]
        if impersonation:
            lines.append("")
            lines.append("Impersonation indicators:")
            lines.extend(f"- {line}" for line in impersonation)
        lines.append("")
        lines.append("What a visitor sees:")
        lines.extend([
            "- A giveaway page promising 2X/3X returns.",
            "- Instructions to send cryptocurrency to a displayed address.",
            "- Urgency cues such as countdowns or fake confirmations.",
        ])
        lines.append("")
        lines.append("Why this is harmful:")
        lines.extend([
            "- Victims send funds to the attacker and receive nothing back.",
        ])
        if evidence.scammer_wallets:
            lines.append("")
            lines.append("Scammer wallet addresses observed:")
            for wallet in evidence.scammer_wallets[:3]:
                lines.append(f"- {wallet}")
        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=4)
        lines.append("")
        lines.append("Key evidence from our review:")
        for reason in highlights:
            lines.append(f"- {reason}")
        lines.extend(["", "We captured a screenshot and HTML during the scan and can provide them on request."])
        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Crypto Doubler / Fake Giveaway Templates
    # -------------------------------------------------------------------------

    @classmethod
    def crypto_doubler_generic(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """Generate a generic abuse report for crypto doubler scams."""
        subject = f"Fraud Report (Crypto Doubler/Giveaway Scam): {evidence.domain}"

        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=5)
        impersonation = evidence.get_impersonation_lines()
        observations = [*impersonation, *highlights] if impersonation else highlights

        body = f"""Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam)

Action requested:
- Please suspend/disable this fraudulent site.

{cls._build_target_section(evidence, include_scam_type=True, scam_type_label="Crypto Doubler / Fake Giveaway")}

What we observed:
{cls._format_list(observations, prefix='- ')}

"""
        body += cls._build_scammer_wallets_section(evidence)
        body += """How this scam works:
- Site advertises a fake giveaway promising 2X/3X returns
- Displays a deposit address and urgency cues to push action
- Victim sends crypto to the scammer's wallet; receives nothing back

Impact:
- This is advance-fee fraud. Victims lose all cryptocurrency sent.

"""
        body += cls._build_attachments_section(evidence)
        body += cls._build_footer(reporter_email)

        body = cls._append_public_entry(body, evidence)

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
        impersonation = evidence.get_impersonation_lines()
        observations = [*impersonation, *highlights] if impersonation else highlights

        body = f"""Registrar abuse report{registrar_str}

Action requested:
- Please suspend/disable this domain for advance-fee fraud / cryptocurrency scam.

{cls._build_target_section(evidence, include_scam_type=True, scam_type_label="Crypto Doubler / Fake Giveaway")}

What we observed:
{cls._format_list(observations, prefix='- ')}

"""
        # Custom scammer wallet section with different label
        if evidence.scammer_wallets:
            body += f"Scammer wallet addresses (crypto sent here is stolen):\n{cls._format_list(evidence.scammer_wallets, prefix='- ')}\n\n"

        body += """How this scam works:
- Site advertises a fake giveaway or "event"
- Claims users will receive 2X/3X returns if they send cryptocurrency
- Displays fabricated transaction history or countdown timers to build false trust
- Victim sends crypto to scammer's wallet address
- Scammer keeps the funds; victim receives nothing

This is advance-fee fraud targeting cryptocurrency users.

"""
        body += cls._build_attachments_section(evidence)
        body += cls._build_footer(reporter_email)

        body = cls._append_public_entry(body, evidence)

        return {"subject": subject, "body": body}

    @classmethod
    def crypto_doubler_cloudflare(cls, evidence: ReportEvidence, reporter_email: str) -> dict:
        """Generate a Cloudflare abuse report for crypto doubler scams."""
        subject = f"Fraud report: {evidence.domain}"

        highlights = cls._summarize_reasons(evidence.detection_reasons, max_items=4)
        impersonation = evidence.get_impersonation_lines()

        body = f"""Cryptocurrency advance-fee fraud (crypto doubler/giveaway scam)

Evidence URL: {evidence.url}
Scam type: Fake crypto giveaway promising 2X/3X returns

"""

        if evidence.scammer_wallets:
            body += f"""Scammer wallet: {evidence.scammer_wallets[0]}

"""

        if impersonation:
            body += f"""Impersonation indicators:
{cls._format_list(impersonation, prefix='- ')}

"""

        body += f"""Key evidence from our review:
{cls._format_list(highlights, prefix='- ')}

Steps to reproduce:
1) Open the evidence URL above.
2) The page presents a giveaway claiming 2X/3X returns.
3) A wallet address is displayed for victims to send funds.
4) Urgency cues (countdowns/limited time) are used to pressure action.

Captured evidence (screenshot + HTML) available on request.
"""

        body = cls._append_public_entry(body, evidence)

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
    def _append_public_entry(body: str, evidence: ReportEvidence) -> str:
        return body

    @staticmethod
    def _build_footer(reporter_email: str) -> str:
        """Build the common footer with reporter info."""
        return f"""Reporter: {reporter_email}\n"""

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
        campaign: "ThreatCampaign",
        reporter_email: str,
    ) -> dict:
        """
        Generate a DigitalOcean abuse report for an entire campaign.
        Lists ALL backend apps and ALL frontends using them.
        """
        # Extract all DO apps from campaign backends
        do_apps = [
            backend for backend in campaign.shared_backends
            if "ondigitalocean.app" in backend.lower()
        ]

        if not do_apps:
            return {"subject": "", "body": "No DigitalOcean apps found in campaign"}

        subject = f"URGENT: {len(do_apps)} App Platform Apps Used in Coordinated Phishing Campaign - {campaign.name}"

        body = f"""
================================================================================
      URGENT: COORDINATED CRYPTOCURRENCY PHISHING CAMPAIGN
           DigitalOcean App Platform - Multiple Apps Involved
================================================================================

ACTION REQUESTED
----------------
Please IMMEDIATELY suspend ALL of the following App Platform applications.
This is a coordinated campaign with {len(campaign.members)} phishing domains
all using these backends to receive stolen cryptocurrency seed phrases.

"""

        body += """APPS TO SUSPEND (PRIORITY - DISABLES ALL PHISHING SITES)
=========================================================
"""
        for i, app in enumerate(do_apps, 1):
            # Count how many frontends use this backend
            using_count = sum(1 for m in campaign.members if app in m.backends)
            body += f"  {i}. {app}\n"
            body += f"     Used by {using_count} phishing domain(s)\n\n"

        body += f"""
================================================================================
                         CAMPAIGN OVERVIEW
================================================================================

Campaign Name:   {campaign.name}
Campaign ID:     {campaign.campaign_id}
Total Domains:   {len(campaign.members)}
Shared Backends: {len(do_apps)} DigitalOcean apps
First Detected:  {campaign.created_at.strftime('%Y-%m-%d')}
Last Updated:    {campaign.updated_at.strftime('%Y-%m-%d')}

PHISHING DOMAINS IN THIS CAMPAIGN
----------------------------------
"""
        for i, member in enumerate(campaign.members, 1):
            body += f"  {i}. {member.domain} (score: {member.score}%)\n"

        body += f"""
================================================================================
                         HOW THE ATTACK WORKS
================================================================================

  1. Victim visits one of {len(campaign.members)} fake wallet sites (listed above)
  2. Site displays fake "restore wallet" form requesting 12-word seed phrase
  3. Victim enters their seed phrase thinking it's legitimate
  4. Data is POST'd to DigitalOcean App Platform backends (listed above)
  5. Attacker uses seed phrase to steal all cryptocurrency from victim's wallet

WHY THIS IS HIGH PRIORITY
-------------------------
- The backend apps are the CHOKEPOINT for the entire campaign
- Suspending {len(do_apps)} apps immediately disables {len(campaign.members)} phishing sites
- This is more efficient than reporting each phishing domain individually
- The attacker is actively stealing cryptocurrency through these backends

"""

        if campaign.shared_kits:
            body += f"""PHISHING KIT SIGNATURES DETECTED
---------------------------------
{cls._format_list(list(campaign.shared_kits))}

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
Reporter:    {reporter_email}
Report Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

We can provide additional evidence (screenshots, HAR files, analysis data)
upon request.
"""

        return {"subject": subject, "body": body}

    @classmethod
    def campaign_registrar(
        cls,
        campaign: "ThreatCampaign",
        registrar_name: str,
        domains: List[str],
        reporter_email: str,
    ) -> dict:
        """
        Generate a bulk registrar abuse report for all domains at one registrar.
        """
        subject = f"Bulk Abuse Report: {len(domains)} Phishing Domains - {campaign.name}"

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
"{campaign.name}" phishing campaign with {len(campaign.members)} total domains.

Campaign ID:     {campaign.campaign_id}
Total Domains:   {len(campaign.members)} (across all registrars)
Your Domains:    {len(domains)}
First Detected:  {campaign.created_at.strftime('%Y-%m-%d')}

SHARED INFRASTRUCTURE (proves coordination)
-------------------------------------------
All domains in this campaign share:
"""

        if campaign.shared_backends:
            body += f"""
Backend Servers:
{cls._format_list(list(campaign.shared_backends)[:5])}
"""

        if campaign.shared_nameservers:
            body += f"""
Nameservers:
{cls._format_list(list(campaign.shared_nameservers))}
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
"""

        return {"subject": subject, "body": body}

    @classmethod
    def campaign_dns_provider(
        cls,
        campaign: "ThreatCampaign",
        provider_name: str,
        reporter_email: str,
    ) -> dict:
        """
        Generate a DNS provider abuse report for domains using their nameservers.
        """
        # Find domains using this provider's nameservers
        provider_lower = provider_name.lower()
        affected_domains = []
        for member in campaign.members:
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

Campaign Name:   {campaign.name}
Total Domains:   {len(campaign.members)}
Using Your DNS:  {len(affected_domains)}

EVIDENCE OF COORDINATION
------------------------
"""

        if campaign.shared_backends:
            body += f"""Shared Backend Servers:
{cls._format_list(list(campaign.shared_backends)[:3])}

"""

        body += f"""================================================================================

Reporter: {reporter_email}
"""

        return {"subject": subject, "body": body}
