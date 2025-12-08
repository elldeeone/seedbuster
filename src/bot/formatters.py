"""Message formatters for Telegram alerts."""

import re
from dataclasses import dataclass
from typing import Optional


def escape_markdown(text: str) -> str:
    """Escape special characters for Telegram Markdown."""
    # Characters that need escaping in Telegram Markdown
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text


@dataclass
class AlertData:
    """Data for a phishing alert."""

    domain: str
    domain_id: str  # Short ID for commands
    verdict: str
    score: int
    reasons: list[str]
    screenshot_path: Optional[str] = None
    evidence_path: Optional[str] = None


class AlertFormatter:
    """Formats alert messages for Telegram."""

    VERDICT_EMOJI = {
        "high": "\u26a0\ufe0f",     # Warning sign
        "medium": "\u2753",         # Question mark
        "low": "\u2139\ufe0f",      # Info
        "benign": "\u2705",         # Check mark
    }

    VERDICT_LABEL = {
        "high": "HIGH CONFIDENCE",
        "medium": "NEEDS REVIEW",
        "low": "LOW SUSPICION",
        "benign": "LIKELY BENIGN",
    }

    @classmethod
    def format_alert(cls, data: AlertData) -> str:
        """Format a phishing detection alert."""
        emoji = cls.VERDICT_EMOJI.get(data.verdict, "\u2753")
        label = cls.VERDICT_LABEL.get(data.verdict, "UNKNOWN")

        lines = [
            f"{emoji} SUSPICIOUS DOMAIN DETECTED",
            "",
            f"Domain: {data.domain}",
            f"Confidence: {label} ({data.score}/100)",
            "",
            "Detection signals:",
        ]

        for reason in data.reasons[:8]:  # Limit reasons shown
            # Escape any special characters in reasons
            safe_reason = reason.replace('_', ' ').replace('*', '')
            lines.append(f"  - {safe_reason}")

        lines.extend([
            "",
            "Actions:",
            f"/ack {data.domain_id} - Mark reviewed",
            f"/fp {data.domain_id} - False positive",
            f"/report {data.domain_id} - Submit to blocklists",
            f"/evidence {data.domain_id} - Get evidence files",
        ])

        return "\n".join(lines)

    @classmethod
    def format_status(
        cls,
        stats: dict,
        queue_size: int = 0,
        is_running: bool = True,
    ) -> str:
        """Format system status message."""
        status_emoji = "\u2705" if is_running else "\u274c"

        by_status = stats.get("by_status", {})
        by_verdict = stats.get("by_verdict", {})

        lines = [
            f"{status_emoji} *SeedBuster Status*",
            "",
            f"*Pipeline:* {'Running' if is_running else 'Stopped'}",
            f"*Queue depth:* {queue_size}",
            "",
            "*Domains tracked:*",
            f"  - Total: {stats.get('total', 0)}",
            f"  - Last 24h: {stats.get('last_24h', 0)}",
            f"  - Pending: {by_status.get('pending', 0)}",
            f"  - Analyzed: {by_status.get('analyzed', 0)}",
            "",
            "*By verdict:*",
            f"  - High: {by_verdict.get('high', 0)}",
            f"  - Medium: {by_verdict.get('medium', 0)}",
            f"  - Low: {by_verdict.get('low', 0)}",
            f"  - Benign: {by_verdict.get('benign', 0)}",
        ]

        return "\n".join(lines)

    @classmethod
    def format_recent(cls, domains: list[dict], limit: int = 10) -> str:
        """Format list of recent domains."""
        if not domains:
            return "No recent domains found."

        lines = [f"*Recent {min(len(domains), limit)} domains:*", ""]

        for domain in domains[:limit]:
            verdict = domain.get("verdict", "pending")
            emoji = cls.VERDICT_EMOJI.get(verdict, "\u23f3")  # Hourglass for pending
            score = domain.get("analysis_score", domain.get("domain_score", 0)) or 0
            lines.append(f"{emoji} `{domain['domain']}` ({score})")

        return "\n".join(lines)

    @classmethod
    def format_domain_details(cls, domain: dict) -> str:
        """Format detailed domain information."""
        lines = [
            f"*Domain:* `{domain['domain']}`",
            "",
            f"*Status:* {domain.get('status', 'unknown')}",
            f"*Verdict:* {domain.get('verdict', 'pending')}",
            f"*Domain Score:* {domain.get('domain_score', 0)}",
            f"*Analysis Score:* {domain.get('analysis_score', 'N/A')}",
            "",
            f"*First seen:* {domain.get('first_seen', 'unknown')}",
            f"*Source:* {domain.get('source', 'unknown')}",
        ]

        if domain.get("verdict_reasons"):
            lines.extend(["", "*Reasons:*", domain["verdict_reasons"]])

        return "\n".join(lines)

    @classmethod
    def format_help(cls) -> str:
        """Format help message."""
        return """*SeedBuster Commands:*

*Monitoring:*
`/status` - System health and stats
`/recent [n]` - Show last N domains (default 10)
`/stats` - Detailed statistics

*Domain Management:*
`/submit <url>` - Submit domain for analysis
`/ack <id>` - Acknowledge alert
`/fp <id>` - Mark as false positive
`/evidence <id>` - Get evidence files

*Reporting:*
`/report <id>` - Submit to blocklists

*Configuration:*
`/threshold <n>` - Set analysis threshold
`/allowlist` - View allowlist
`/allowlist add <domain>` - Add to allowlist

*Help:*
`/help` - Show this message
"""
