"""Message formatters for Telegram alerts."""

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
class TemporalInfo:
    """Temporal analysis information for alerts."""
    is_initial_scan: bool = True
    scan_number: int = 1
    total_scans: int = 1
    rescans_scheduled: bool = False
    cloaking_suspected: bool = False  # Anti-bot detected on initial scan
    cloaking_confirmed: bool = False  # Cloaking pattern detected from rescans
    cloaking_confidence: float = 0.0
    previous_score: Optional[int] = None  # For rescan comparisons


@dataclass
class ClusterInfo:
    """Threat cluster information for alerts."""
    cluster_id: Optional[str] = None
    cluster_name: Optional[str] = None
    is_new_cluster: bool = True
    related_domains: list[str] = None
    confidence: float = 0.0

    def __post_init__(self):
        if self.related_domains is None:
            self.related_domains = []


@dataclass
class LearningInfo:
    """Auto-learning information for alerts."""
    learned: bool = False
    version: str = ""
    added_to_frontends: list[str] = None
    added_to_api_keys: list[str] = None

    def __post_init__(self):
        if self.added_to_frontends is None:
            self.added_to_frontends = []
        if self.added_to_api_keys is None:
            self.added_to_api_keys = []


@dataclass
class AlertData:
    """Data for a phishing alert."""

    domain: str
    domain_id: str  # Short ID for commands
    verdict: str
    score: int
    reasons: list[str]
    screenshot_path: Optional[str] = None
    screenshot_paths: Optional[list[str]] = None  # Multiple screenshots (early, final)
    evidence_path: Optional[str] = None
    urlscan_result_url: Optional[str] = None
    temporal: Optional[TemporalInfo] = None  # Temporal analysis info
    cluster: Optional[ClusterInfo] = None  # Threat cluster info
    seed_form_found: bool = False  # True if seed phrase entry form was discovered
    learning: Optional[LearningInfo] = None  # Auto-learning info


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

        # Determine header based on temporal status
        temporal = data.temporal
        if temporal and not temporal.is_initial_scan:
            # This is a rescan update
            header = f"\U0001F504 RESCAN UPDATE (Scan {temporal.scan_number}/{temporal.total_scans})"
            if temporal.previous_score is not None:
                score_change = data.score - temporal.previous_score
                if score_change < 0:
                    header += f"\nScore: {temporal.previous_score} \u2192 {data.score} (\u2193{abs(score_change)})"
                elif score_change > 0:
                    header += f"\nScore: {temporal.previous_score} \u2192 {data.score} (\u2191{score_change})"
        elif temporal and temporal.is_initial_scan:
            header = f"{emoji} SUSPICIOUS DOMAIN DETECTED (INITIAL SCAN)"
        else:
            header = f"{emoji} SUSPICIOUS DOMAIN DETECTED"

        lines = [
            header,
            "",
            f"Domain: {data.domain}",
            f"Confidence: {label} ({data.score}/100)",
        ]

        # SEED FORM FOUND - the definitive indicator (show first!)
        if data.seed_form_found:
            lines.append("")
            lines.append("\U0001F3AF SEED FORM FOUND - CONFIRMED PHISHING")
            lines.append("Exploration discovered seed phrase entry form")

        # Add temporal status section for initial scans
        if temporal and temporal.is_initial_scan:
            lines.append("")
            if temporal.rescans_scheduled:
                lines.append("\U0001F551 Rescans scheduled: 6h / 12h / 24h / 48h")
            if temporal.cloaking_suspected:
                lines.append("\u26A0\uFE0F Cloaking suspected: Anti-bot service detected")

        # Add cloaking confirmation for rescans
        if temporal and temporal.cloaking_confirmed:
            lines.append("")
            lines.append(f"\U0001F6A8 CLOAKING CONFIRMED ({temporal.cloaking_confidence:.0%} confidence)")
            lines.append("Site showed different content to rescan - evidence of intentional evasion")

        # Add threat cluster info if linked to other domains
        cluster = data.cluster
        if cluster and cluster.related_domains:
            lines.append("")
            lines.append(f"\U0001F517 LINKED CAMPAIGN: {cluster.cluster_name}")
            related_list = ", ".join(cluster.related_domains[:3])
            if len(cluster.related_domains) > 3:
                related_list += f" (+{len(cluster.related_domains) - 3} more)"
            lines.append(f"Related: {related_list}")

        # De-duplicate reasons (keep first occurrence, normalize for comparison)
        seen_normalized = set()
        unique_reasons = []
        for r in data.reasons:
            # Normalize for dedup: lowercase, remove common variations
            normalized = r.lower().replace("known malicious domain:", "known malicious:").replace("_", " ")
            # Extract core identifier (domain name) for matching
            if "walrus-app" in normalized or "whale-app" in normalized or "kaspa-backend" in normalized:
                # For backend domains, use domain as key
                for pattern in ["walrus-app", "whale-app", "kaspa-backend"]:
                    if pattern in normalized:
                        key = f"{pattern}_malicious"
                        if key not in seen_normalized:
                            seen_normalized.add(key)
                            unique_reasons.append(r)
                        break
            else:
                if normalized not in seen_normalized:
                    seen_normalized.add(normalized)
                    unique_reasons.append(r)

        # Categorize reasons by type
        infra_reasons = [r for r in unique_reasons if r.startswith("INFRA:")]
        code_reasons = [r for r in unique_reasons if r.startswith("CODE:")]
        temporal_reasons = [r for r in unique_reasons if r.startswith("TEMPORAL:")]
        external_reasons = [r for r in unique_reasons if r.startswith("EXTERNAL:")]

        # Categorize other reasons
        threat_intel = []
        antibot = []
        domain_signals = []
        other = []

        for r in unique_reasons:
            if r.startswith(("INFRA:", "CODE:", "TEMPORAL:", "EXTERNAL:")):
                continue
            elif "KNOWN MALICIOUS" in r or "Malicious URL" in r:
                threat_intel.append(r)
            elif "Anti-bot" in r or "blocked" in r.lower():
                antibot.append(r)
            elif "domain" in r.lower() or "title" in r.lower() or "suspicion score" in r.lower():
                domain_signals.append(r)
            else:
                other.append(r)

        # Build organized signal sections
        lines.append("")

        # Threat Intelligence section
        if threat_intel:
            lines.append("\U0001F6A8 Threat Intel:")
            for r in threat_intel[:6]:
                safe_reason = r.replace('_', ' ').replace('*', '')
                lines.append(f"  • {safe_reason}")

        # Anti-bot/Evasion section
        if antibot:
            lines.append("\U0001F575 Evasion:")
            for r in antibot:
                safe_reason = r.replace('_', ' ').replace('*', '')
                lines.append(f"  • {safe_reason}")

        # Infrastructure section
        if infra_reasons:
            lines.append("\U0001F5A7 Infrastructure:")
            for r in infra_reasons:
                # Remove "INFRA: " prefix for cleaner display
                clean = r.replace("INFRA: ", "")
                safe_reason = clean.replace('_', ' ').replace('*', '')
                lines.append(f"  • {safe_reason}")

        # Code Analysis section
        if code_reasons:
            lines.append("\U0001F4BB Code Analysis:")
            for r in code_reasons:
                clean = r.replace("CODE: ", "")
                safe_reason = clean.replace('_', ' ').replace('*', '')
                lines.append(f"  • {safe_reason}")

        # Temporal section (for rescans)
        if temporal_reasons:
            lines.append("\U0001F551 Temporal:")
            for r in temporal_reasons:
                clean = r.replace("TEMPORAL: ", "")
                safe_reason = clean.replace('_', ' ').replace('*', '')
                lines.append(f"  • {safe_reason}")

        # External Intelligence section
        if external_reasons:
            lines.append("\U0001F50D External Intel:")
            for r in external_reasons:
                clean = r.replace("EXTERNAL: ", "")
                safe_reason = clean.replace('_', ' ').replace('*', '')
                lines.append(f"  • {safe_reason}")

        # Domain signals section
        if domain_signals:
            lines.append("\U0001F310 Domain:")
            for r in domain_signals[:4]:
                safe_reason = r.replace('_', ' ').replace('*', '')
                lines.append(f"  • {safe_reason}")

        # Other signals (if any remaining)
        if other:
            lines.append("\U0001F50D Other:")
            for r in other[:3]:
                safe_reason = r.replace('_', ' ').replace('*', '')
                lines.append(f"  • {safe_reason}")

        # Auto-learning indicator (if learned)
        if data.learning and data.learning.learned:
            lines.append("")
            lines.append(f"\U0001F9E0 Auto-learned (v{data.learning.version})")

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
`/bulk <domains...>` - Submit many domains (paste list)
`/ack <id>` - Acknowledge alert
`/fp <id>` - Mark as false positive
`/defer <id>` - Wait for rescans (suspected cloaking)
`/evidence <id>` - Get evidence files

*Reporting:*
`/report <id>` - Submit to all enabled platforms
`/report <id> status` - Show per-platform report status
`/report <id> <platform>` - Submit to a specific platform
`/report <id> done [platform|all]` - Mark manual submissions complete
`/reports [filter] [n]` - Show reporting queue (filters: pending/manual/rate)
`/platforms` - Show enabled/available reporting platforms

*Configuration:*
`/threshold <n>` - Set analysis threshold
`/allowlist` - View allowlist
`/allowlist add <domain>` - Add to allowlist

*Help:*
`/help` - Show this message
"""
