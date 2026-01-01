"""
Report generator for SeedBuster - creates PDF/HTML reports for domains and campaigns.

Supports two scopes:
- Single domain reports with campaign context
- Campaign reports showing all linked domains
"""

import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from ..analyzer.campaigns import ThreatCampaignManager
    from ..storage.database import Database
    from ..storage.evidence import EvidenceStore

logger = logging.getLogger(__name__)


@dataclass
class DomainReportData:
    """Data for a single domain report."""

    domain: str
    url: str
    detected_at: datetime
    confidence_score: int
    detection_reasons: List[str]
    suspicious_endpoints: List[str]
    backend_domains: List[str]
    api_keys_found: List[str]
    hosting_provider: Optional[str]
    edge_provider: Optional[str]
    screenshots: List[Path]
    analysis_json: dict
    # Campaign context (if part of a campaign)
    campaign_id: Optional[str] = None
    campaign_name: Optional[str] = None
    related_domains: List[str] = field(default_factory=list)


@dataclass
class CampaignReportData:
    """Data for a campaign report."""

    campaign_id: str
    campaign_name: str
    confidence: float
    created_at: datetime
    updated_at: datetime
    # All member domains
    members: List[DomainReportData]
    # Shared infrastructure
    shared_backends: List[str]
    shared_nameservers: List[str]
    shared_kits: List[str]
    shared_asns: List[str]
    # Summary stats
    total_domains: int
    active_domains: int


class ReportGenerator:
    """Generates PDF/HTML reports for domains and campaigns."""

    def __init__(
        self,
        database: "Database",
        evidence_store: "EvidenceStore",
        campaign_manager: "ThreatCampaignManager",
        output_dir: Optional[Path] = None,
    ):
        self.database = database
        self.evidence_store = evidence_store
        self.campaign_manager = campaign_manager
        self.output_dir = output_dir or Path("data/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # Single Domain Reports
    # -------------------------------------------------------------------------

    async def generate_domain_html(
        self,
        domain: str,
        domain_id: Optional[int] = None,
        snapshot_id: Optional[str] = None,
    ) -> Path:
        """Generate HTML report for a single domain."""
        data = await self._gather_domain_data(domain, domain_id, snapshot_id)
        html = self._render_domain_html(data)

        output_path = self.output_dir / f"report_{self._safe_filename(domain)}.html"
        output_path.write_text(html, encoding="utf-8")
        logger.info(f"Generated HTML report: {output_path}")
        return output_path

    async def generate_domain_pdf(
        self,
        domain: str,
        domain_id: Optional[int] = None,
        snapshot_id: Optional[str] = None,
    ) -> Path:
        """Generate PDF report for a single domain."""
        html_path = await self.generate_domain_html(domain, domain_id, snapshot_id)
        pdf_path = html_path.with_suffix(".pdf")

        try:
            from weasyprint import HTML

            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info(f"Generated PDF report: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning("weasyprint not installed - PDF generation unavailable")
            raise ImportError(
                "PDF generation requires weasyprint. Install with: pip install weasyprint"
            )

    async def _gather_domain_data(
        self,
        domain: str,
        domain_id: Optional[int] = None,
        snapshot_id: Optional[str] = None,
    ) -> DomainReportData:
        """Gather all data needed for a domain report."""
        # Load analysis data
        analysis = self.evidence_store.load_analysis(domain, snapshot_id) or {}
        infra = analysis.get("infrastructure") or {}

        # Get screenshots
        screenshots = self.evidence_store.get_all_screenshot_paths(domain, snapshot_id)

        # Get campaign context
        campaign = self.campaign_manager.get_campaign_for_domain(domain)
        campaign_id = campaign.campaign_id if campaign else None
        campaign_name = campaign.name if campaign else None
        related_domains = (
            [m.domain for m in campaign.members if m.domain != domain] if campaign else []
        )

        # Get domain data from database if available
        domain_data = {}
        if domain_id:
            domain_data = await self.database.get_domain_by_id(domain_id) or {}

        return DomainReportData(
            domain=domain,
            url=analysis.get("final_url") or f"https://{domain}",
            detected_at=datetime.fromisoformat(
                domain_data.get("first_seen") or analysis.get("saved_at") or datetime.now().isoformat()
            ),
            confidence_score=analysis.get("score") or domain_data.get("analysis_score") or 0,
            detection_reasons=analysis.get("reasons") or [],
            suspicious_endpoints=analysis.get("suspicious_endpoints") or [],
            backend_domains=analysis.get("backend_domains") or [],
            api_keys_found=analysis.get("api_keys_found") or [],
            hosting_provider=analysis.get("hosting_provider") or infra.get("hosting_provider"),
            edge_provider=analysis.get("edge_provider") or infra.get("edge_provider"),
            screenshots=screenshots,
            analysis_json=analysis,
            campaign_id=campaign_id,
            campaign_name=campaign_name,
            related_domains=related_domains,
        )

    def _render_domain_html(self, data: DomainReportData) -> str:
        """Render HTML for a single domain report."""
        # Embed screenshots as base64
        screenshot_html = self._render_screenshots(data.screenshots[:5])

        # Build campaign context section
        campaign_section = ""
        if data.campaign_id:
            related_list = ", ".join(data.related_domains[:10]) or "None"
            if len(data.related_domains) > 10:
                related_list += f" (+{len(data.related_domains) - 10} more)"
            campaign_section = f"""
            <div class="section campaign-context">
                <h2>Campaign Context</h2>
                <p class="warning">This domain is part of a coordinated phishing campaign.</p>
                <table>
                    <tr><td><strong>Campaign:</strong></td><td>{data.campaign_name}</td></tr>
                    <tr><td><strong>Campaign ID:</strong></td><td><code>{data.campaign_id}</code></td></tr>
                    <tr><td><strong>Related Domains:</strong></td><td>{len(data.related_domains)} domains</td></tr>
                </table>
                <p><strong>Related domains:</strong> {related_list}</p>
            </div>
            """

        # Build detection reasons
        reasons_html = "\n".join(f"<li>{r}</li>" for r in data.detection_reasons)

        # Build backend infrastructure
        backends_html = ""
        if data.backend_domains:
            backends_list = "\n".join(f"<li><code>{b}</code></li>" for b in data.backend_domains)
            backends_html = f"""
            <div class="section backends">
                <h2>Backend Infrastructure (C2)</h2>
                <p>Stolen data is sent to these servers:</p>
                <ul>{backends_list}</ul>
            </div>
            """

        # Build API keys section
        api_keys_html = ""
        if data.api_keys_found:
            keys_list = "\n".join(f"<li><code>{k}</code></li>" for k in data.api_keys_found)
            api_keys_html = f"""
            <div class="section api-keys">
                <h2>API Keys Found</h2>
                <p>These API keys can be used to track the threat actor:</p>
                <ul>{keys_list}</ul>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Report: {data.domain}</title>
    <style>
        {self._get_report_css()}
    </style>
</head>
<body>
    <header>
        <h1>Phishing Abuse Report</h1>
        <p class="subtitle">Generated by SeedBuster</p>
    </header>

    <div class="section summary">
        <h2>Summary</h2>
        <table>
            <tr><td><strong>Domain:</strong></td><td><code>{data.domain}</code></td></tr>
            <tr><td><strong>URL:</strong></td><td><a href="{data.url}">{data.url}</a></td></tr>
            <tr><td><strong>Detected:</strong></td><td>{data.detected_at.strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
            <tr><td><strong>Confidence:</strong></td><td><span class="score score-{self._score_class(data.confidence_score)}">{data.confidence_score}%</span></td></tr>
            <tr><td><strong>Origin Hosting:</strong></td><td>{data.hosting_provider or 'Unknown'}</td></tr>
            <tr><td><strong>Edge/CDN:</strong></td><td>{data.edge_provider or 'Unknown'}</td></tr>
        </table>
    </div>

    {campaign_section}

    <div class="section reasons">
        <h2>Detection Reasons</h2>
        <ul>
            {reasons_html}
        </ul>
    </div>

    {backends_html}
    {api_keys_html}

    <div class="section screenshots">
        <h2>Visual Evidence</h2>
        {screenshot_html}
    </div>

    <div class="section about">
        <h2>About This Report</h2>
        <p>This report was generated by <strong>SeedBuster</strong>, an automated cryptocurrency
        phishing detection system. The domain above was identified as hosting a phishing site
        that attempts to steal cryptocurrency wallet seed phrases.</p>
        <p><strong>What is seed phrase phishing?</strong> Cryptocurrency wallets use a 12 or 24-word
        "seed phrase" as a master key. Anyone with these words has complete control over the wallet
        and can steal all funds instantly and irreversibly.</p>
    </div>

    <footer>
        <p>Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p>SeedBuster - Cryptocurrency Phishing Detection</p>
    </footer>
</body>
</html>"""

    # -------------------------------------------------------------------------
    # Campaign Reports
    # -------------------------------------------------------------------------

    async def generate_campaign_html(self, campaign_id: str) -> Path:
        """Generate HTML report for an entire campaign."""
        data = await self._gather_campaign_data(campaign_id)
        html = self._render_campaign_html(data)

        safe_name = self._safe_filename(data.campaign_name)
        output_path = self.output_dir / f"campaign_{safe_name}_{campaign_id[:8]}.html"
        output_path.write_text(html, encoding="utf-8")
        logger.info(f"Generated campaign HTML report: {output_path}")
        return output_path

    async def generate_campaign_pdf(self, campaign_id: str) -> Path:
        """Generate PDF report for an entire campaign."""
        html_path = await self.generate_campaign_html(campaign_id)
        pdf_path = html_path.with_suffix(".pdf")

        try:
            from weasyprint import HTML

            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info(f"Generated campaign PDF report: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning("weasyprint not installed - PDF generation unavailable")
            raise ImportError(
                "PDF generation requires weasyprint. Install with: pip install weasyprint"
            )

    async def _gather_campaign_data(self, campaign_id: str) -> CampaignReportData:
        """Gather all data needed for a campaign report."""
        campaign = self.campaign_manager.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign not found: {campaign_id}")

        # Gather data for each member domain
        members = []
        for member in campaign.members:
            try:
                domain_data = await self._gather_domain_data(member.domain)
                members.append(domain_data)
            except Exception as e:
                logger.warning(f"Failed to gather data for {member.domain}: {e}")

        return CampaignReportData(
            campaign_id=campaign.campaign_id,
            campaign_name=campaign.name,
            confidence=campaign.confidence,
            created_at=campaign.created_at,
            updated_at=campaign.updated_at,
            members=members,
            shared_backends=list(campaign.shared_backends),
            shared_nameservers=list(campaign.shared_nameservers),
            shared_kits=list(campaign.shared_kits),
            shared_asns=list(campaign.shared_asns),
            total_domains=len(campaign.members),
            active_domains=len([m for m in members if m.confidence_score > 0]),
        )

    def _render_campaign_html(self, data: CampaignReportData) -> str:
        """Render HTML for a campaign report."""
        # Domain inventory table
        domain_rows = []
        for m in data.members:
            score_class = self._score_class(m.confidence_score)
            domain_rows.append(f"""
                <tr>
                    <td><code>{m.domain}</code></td>
                    <td>{m.detected_at.strftime('%Y-%m-%d')}</td>
                    <td><span class="score score-{score_class}">{m.confidence_score}%</span></td>
                    <td>{m.hosting_provider or 'Unknown'}</td>
                    <td>{len(m.backend_domains)} backends</td>
                </tr>
            """)
        domain_table = "\n".join(domain_rows)

        # Shared backends
        backends_html = ""
        if data.shared_backends:
            backends_list = "\n".join(f"<li><code>{b}</code></li>" for b in data.shared_backends)
            backends_html = f"""
            <div class="section backends">
                <h2>Shared Backend Infrastructure (C2)</h2>
                <p>All phishing sites in this campaign send stolen data to these servers:</p>
                <ul class="ioc-list">{backends_list}</ul>
                <p class="action"><strong>Recommended action:</strong> Suspend these backend applications immediately.
                This will disable data exfiltration for ALL {data.total_domains} phishing domains.</p>
            </div>
            """

        # Shared nameservers
        nameservers_html = ""
        if data.shared_nameservers:
            ns_list = "\n".join(f"<li><code>{ns}</code></li>" for ns in data.shared_nameservers)
            nameservers_html = f"""
            <div class="section nameservers">
                <h2>Shared DNS Infrastructure</h2>
                <p>These nameservers are used by domains in this campaign:</p>
                <ul class="ioc-list">{ns_list}</ul>
            </div>
            """

        # Evidence gallery - one key screenshot per domain
        gallery_html = ""
        gallery_items = []
        for m in data.members[:10]:  # Limit to 10 to keep report manageable
            if m.screenshots:
                img_data = self._embed_image(m.screenshots[0])
                gallery_items.append(f"""
                    <div class="gallery-item">
                        <img src="{img_data}" alt="{m.domain}">
                        <p><code>{m.domain}</code></p>
                    </div>
                """)
        if gallery_items:
            gallery_html = f"""
            <div class="section gallery">
                <h2>Evidence Gallery</h2>
                <p>Key screenshots from each phishing domain:</p>
                <div class="gallery-grid">
                    {"".join(gallery_items)}
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Campaign Report: {data.campaign_name}</title>
    <style>
        {self._get_report_css()}
        {self._get_campaign_css()}
    </style>
</head>
<body>
    <header>
        <h1>Phishing Campaign Report</h1>
        <p class="subtitle">{data.campaign_name}</p>
    </header>

    <div class="section executive-summary">
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat">
                <div class="stat-value">{data.total_domains}</div>
                <div class="stat-label">Phishing Domains</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(data.shared_backends)}</div>
                <div class="stat-label">Backend Servers</div>
            </div>
            <div class="stat">
                <div class="stat-value">{data.confidence:.0f}%</div>
                <div class="stat-label">Confidence</div>
            </div>
        </div>
        <table>
            <tr><td><strong>Campaign ID:</strong></td><td><code>{data.campaign_id}</code></td></tr>
            <tr><td><strong>First Detected:</strong></td><td>{data.created_at.strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
            <tr><td><strong>Last Updated:</strong></td><td>{data.updated_at.strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
            <tr><td><strong>Phishing Kits:</strong></td><td>{', '.join(data.shared_kits) or 'Unknown'}</td></tr>
        </table>
    </div>

    {backends_html}
    {nameservers_html}

    <div class="section domain-inventory">
        <h2>Domain Inventory</h2>
        <p>All {data.total_domains} domains identified as part of this campaign:</p>
        <table class="domain-table">
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>First Seen</th>
                    <th>Score</th>
                    <th>Origin Hosting</th>
                    <th>Backends</th>
                </tr>
            </thead>
            <tbody>
                {domain_table}
            </tbody>
        </table>
    </div>

    {gallery_html}

    <div class="section recommended-actions">
        <h2>Recommended Actions</h2>
        <ol>
            <li><strong>Backend Takedown (Highest Priority):</strong> Suspend the {len(data.shared_backends)} backend
            server(s) listed above. This immediately disables data exfiltration for all phishing domains.</li>
            <li><strong>Domain Suspension:</strong> Report all {data.total_domains} domains to their respective registrars.</li>
            <li><strong>DNS Provider Report:</strong> Report abuse to nameserver providers.</li>
            <li><strong>Blocklist Submission:</strong> Submit all domains to Google Safe Browsing, Netcraft, etc.</li>
        </ol>
    </div>

    <div class="section about">
        <h2>About This Report</h2>
        <p>This report was generated by <strong>SeedBuster</strong>, an automated cryptocurrency
        phishing detection system. These domains were identified as part of a coordinated phishing
        campaign targeting cryptocurrency wallet users.</p>
    </div>

    <footer>
        <p>Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p>SeedBuster - Cryptocurrency Phishing Detection</p>
    </footer>
</body>
</html>"""

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def _render_screenshots(self, screenshots: List[Path]) -> str:
        """Render screenshots as HTML with embedded base64 images."""
        if not screenshots:
            return "<p>No screenshots available.</p>"

        items = []
        for i, path in enumerate(screenshots):
            img_data = self._embed_image(path)
            label = path.stem.replace("screenshot_", "").replace("_", " ").title() or f"Screenshot {i+1}"
            items.append(f"""
                <div class="screenshot">
                    <img src="{img_data}" alt="{label}">
                    <p class="caption">{label}</p>
                </div>
            """)

        return f'<div class="screenshot-grid">{"".join(items)}</div>'

    def _embed_image(self, path: Path) -> str:
        """Embed an image as base64 data URI."""
        if not path.exists():
            return ""
        try:
            data = base64.b64encode(path.read_bytes()).decode("utf-8")
            suffix = path.suffix.lower()
            mime = "image/png" if suffix == ".png" else "image/jpeg"
            return f"data:{mime};base64,{data}"
        except Exception as e:
            logger.warning(f"Failed to embed image {path}: {e}")
            return ""

    def _safe_filename(self, name: str) -> str:
        """Convert a string to a safe filename."""
        return "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)[:50]

    def _score_class(self, score: int) -> str:
        """Get CSS class for confidence score."""
        if score >= 80:
            return "high"
        elif score >= 50:
            return "medium"
        return "low"

    def _get_report_css(self) -> str:
        """Get base CSS for reports."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #1a1a2e;
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 20px;
            background: #f8f9fa;
        }
        header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e74c3c;
        }
        header h1 {
            font-size: 2em;
            color: #e74c3c;
            margin-bottom: 5px;
        }
        header .subtitle {
            color: #666;
            font-size: 1.1em;
        }
        .section {
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #2c3e50;
            font-size: 1.4em;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table td {
            padding: 8px 0;
            vertical-align: top;
        }
        table td:first-child {
            width: 150px;
            color: #666;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        ul, ol {
            margin-left: 20px;
        }
        li {
            margin-bottom: 8px;
        }
        .score {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .score-high {
            background: #fee;
            color: #c0392b;
        }
        .score-medium {
            background: #fff3cd;
            color: #856404;
        }
        .score-low {
            background: #d4edda;
            color: #155724;
        }
        .warning {
            background: #fff3cd;
            color: #856404;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .campaign-context {
            border-left: 4px solid #e74c3c;
        }
        .backends, .api-keys {
            border-left: 4px solid #f39c12;
        }
        @media screen {
            .screenshot-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
            }
        }
        .screenshot img {
            width: 100%;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .screenshot .caption {
            text-align: center;
            color: #666;
            font-size: 0.9em;
            margin-top: 8px;
        }
        footer {
            text-align: center;
            color: #999;
            font-size: 0.85em;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        a {
            color: #3498db;
        }
        @media print {
            body {
                background: white;
            }
            .section {
                box-shadow: none;
                border: 1px solid #ddd;
            }
            .screenshot-grid {
                display: block;
            }
            .screenshot {
                break-inside: avoid;
                margin-bottom: 16px;
            }
        }
        """

    def _get_campaign_css(self) -> str:
        """Get additional CSS for campaign reports."""
        return """
        @media screen {
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 20px;
                margin-bottom: 20px;
            }
        }
        .stat {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #e74c3c;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .domain-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .domain-table th, .domain-table td {
            padding: 12px 8px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        .domain-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        .domain-table tr:hover {
            background: #f8f9fa;
        }
        .ioc-list {
            background: #f8f9fa;
            padding: 15px 15px 15px 35px;
            border-radius: 5px;
        }
        .ioc-list li {
            margin-bottom: 5px;
        }
        .action {
            background: #e8f4fd;
            color: #0c5460;
            padding: 10px 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        @media screen {
            .gallery-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
            }
        }
        .gallery-item {
            text-align: center;
        }
        .gallery-item img {
            width: 100%;
            height: 150px;
            object-fit: cover;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .gallery-item p {
            font-size: 0.8em;
            color: #666;
            margin-top: 5px;
        }
        .recommended-actions ol {
            margin-left: 20px;
        }
        .recommended-actions li {
            margin-bottom: 15px;
        }
        @media print {
            .stats-grid,
            .gallery-grid {
                display: block;
            }
            .stat,
            .gallery-item {
                break-inside: avoid;
                margin-bottom: 16px;
            }
        }
        """
