"""
Evidence packager for SeedBuster - prepares evidence for submission and archival.

Two modes:
1. Submission mode: Direct PDF/screenshot attachments for abuse teams (no ZIP)
2. Archive mode: Full ZIP files for internal records
"""

import json
import logging
import shutil
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from ..analyzer.campaigns import ThreatCampaignManager
    from ..storage.database import Database
    from ..storage.evidence import EvidenceStore

from .report_generator import ReportGenerator
from ..utils.files import safe_filename_component

logger = logging.getLogger(__name__)


@dataclass
class SubmissionAttachments:
    """Attachments prepared for email submission to abuse teams."""

    domain: str
    pdf_path: Optional[Path]  # PDF report (if weasyprint available)
    html_path: Path  # HTML report (always available)
    best_screenshot: Optional[Path]  # Most damning screenshot
    all_screenshots: List[Path]  # All available screenshots
    # Metadata
    report_generated_at: datetime
    campaign_context: Optional[str]  # If part of campaign


@dataclass
class CampaignSubmissionAttachments:
    """Attachments for campaign-level submission."""

    campaign_id: str
    campaign_name: str
    pdf_path: Optional[Path]
    html_path: Path
    domain_count: int
    # Per-domain attachments for platforms that need individual reports
    domain_attachments: Dict[str, SubmissionAttachments]


class EvidencePackager:
    """
    Handles evidence packaging for both submission and archival.

    - For abuse team submissions: Direct attachments (PDF, screenshots), no ZIP
    - For internal records: Full ZIP archives with all evidence
    """

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
        self.output_dir = output_dir or Path("data/packages")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.report_generator = ReportGenerator(
            database=database,
            evidence_store=evidence_store,
            campaign_manager=campaign_manager,
            output_dir=self.output_dir / "reports",
        )

    # -------------------------------------------------------------------------
    # Submission Mode - Direct attachments for abuse teams
    # -------------------------------------------------------------------------

    async def prepare_domain_submission(
        self,
        domain: str,
        domain_id: Optional[int] = None,
        snapshot_id: Optional[str] = None,
    ) -> SubmissionAttachments:
        """
        Prepare attachments for submitting a single domain report.

        Returns direct file paths (PDF, screenshot) suitable for email attachment.
        Does NOT create a ZIP file.
        """
        # Generate HTML report (always)
        html_path = await self.report_generator.generate_domain_html(
            domain, domain_id, snapshot_id
        )

        # Try to generate PDF (may fail if weasyprint not installed)
        pdf_path = None
        try:
            pdf_path = await self.report_generator.generate_domain_pdf(
                domain, domain_id, snapshot_id
            )
        except ImportError:
            logger.info("PDF generation unavailable - using HTML only")

        # Get screenshots
        screenshots = self.evidence_store.get_all_screenshot_paths(domain, snapshot_id)
        best_screenshot = screenshots[0] if screenshots else None

        # Get campaign context
        campaign = self.campaign_manager.get_campaign_for_domain(domain)
        campaign_context = None
        if campaign:
            campaign_context = (
                f"Part of '{campaign.name}' campaign with "
                f"{len(campaign.members)} domains"
            )

        return SubmissionAttachments(
            domain=domain,
            pdf_path=pdf_path,
            html_path=html_path,
            best_screenshot=best_screenshot,
            all_screenshots=screenshots,
            report_generated_at=datetime.now(),
            campaign_context=campaign_context,
        )

    async def prepare_campaign_submission(
        self, campaign_id: str
    ) -> CampaignSubmissionAttachments:
        """
        Prepare attachments for submitting a campaign-level report.

        Returns campaign PDF plus individual domain attachments.
        """
        campaign = self.campaign_manager.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign not found: {campaign_id}")

        # Generate campaign HTML report (always)
        html_path = await self.report_generator.generate_campaign_html(campaign_id)

        # Try to generate PDF
        pdf_path = None
        try:
            pdf_path = await self.report_generator.generate_campaign_pdf(campaign_id)
        except ImportError:
            logger.info("PDF generation unavailable - using HTML only")

        # Prepare individual domain attachments (for platforms that need them)
        domain_attachments = {}
        for member in campaign.members:
            try:
                attachments = await self.prepare_domain_submission(member.domain)
                domain_attachments[member.domain] = attachments
            except Exception as e:
                logger.warning(f"Failed to prepare attachments for {member.domain}: {e}")

        return CampaignSubmissionAttachments(
            campaign_id=campaign_id,
            campaign_name=campaign.name,
            pdf_path=pdf_path,
            html_path=html_path,
            domain_count=len(campaign.members),
            domain_attachments=domain_attachments,
        )

    def get_best_screenshot(self, domain: str) -> Optional[Path]:
        """Get the single best screenshot for a domain (for email attachment)."""
        screenshots = self.evidence_store.get_all_screenshot_paths(domain)
        return screenshots[0] if screenshots else None

    # -------------------------------------------------------------------------
    # Archive Mode - Full ZIP files for internal records
    # -------------------------------------------------------------------------

    async def create_domain_archive(
        self,
        domain: str,
        domain_id: Optional[int] = None,
        include_report: bool = True,
        snapshot_id: Optional[str] = None,
    ) -> Path:
        """
        Create a ZIP archive of all evidence for a single domain.

        This is for INTERNAL use - not for sending to abuse teams.
        """
        timestamp = datetime.now().strftime("%Y%m%d")
        safe_domain = safe_filename_component(domain, max_length=50, default="")
        archive_name = f"archive_{safe_domain}_{timestamp}"
        archive_dir = self.output_dir / "archives" / archive_name
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Copy evidence files
        evidence_dir = self.evidence_store.get_evidence_path(domain, snapshot_id)
        if evidence_dir.exists():
            # Copy screenshots
            screenshots_dir = archive_dir / "screenshots"
            screenshots_dir.mkdir(exist_ok=True)
            for screenshot in evidence_dir.glob("screenshot*.png"):
                shutil.copy2(screenshot, screenshots_dir / screenshot.name)

            # Copy HAR file
            har_path = evidence_dir / "network.har"
            if har_path.exists():
                shutil.copy2(har_path, archive_dir / "network.har")

            # Copy analysis.json
            analysis_path = evidence_dir / "analysis.json"
            if analysis_path.exists():
                shutil.copy2(analysis_path, archive_dir / "analysis.json")

            # Copy console.log
            console_path = evidence_dir / "console.log"
            if console_path.exists():
                shutil.copy2(console_path, archive_dir / "console.log")

            # Copy HTML snapshot
            html_path = evidence_dir / "page.html"
            if html_path.exists():
                shutil.copy2(html_path, archive_dir / "page.html")

        # Generate and include report
        if include_report:
            try:
                html_path = await self.report_generator.generate_domain_html(
                    domain, domain_id, snapshot_id
                )
                shutil.copy2(html_path, archive_dir / "report.html")

                try:
                    pdf_path = await self.report_generator.generate_domain_pdf(
                        domain, domain_id, snapshot_id
                    )
                    shutil.copy2(pdf_path, archive_dir / "report.pdf")
                except ImportError:
                    pass
            except Exception as e:
                logger.warning(f"Failed to generate report for archive: {e}")

        # Add campaign context if applicable
        campaign = self.campaign_manager.get_campaign_for_domain(domain)
        if campaign:
            campaign_info = {
                "campaign_id": campaign.campaign_id,
                "campaign_name": campaign.name,
                "related_domains": [m.domain for m in campaign.members if m.domain != domain],
                "shared_backends": list(campaign.shared_backends),
                "shared_nameservers": list(campaign.shared_nameservers),
                "shared_asns": list(campaign.shared_asns),
                "confidence": campaign.confidence,
            }
            (archive_dir / "campaign_info.json").write_text(
                json.dumps(campaign_info, indent=2), encoding="utf-8"
            )

        # Create submission log placeholder
        submission_log = {
            "domain": domain,
            "archive_created": datetime.now().isoformat(),
            "submissions": [],  # Will be filled when reports are submitted
        }
        (archive_dir / "submission_log.json").write_text(
            json.dumps(submission_log, indent=2), encoding="utf-8"
        )

        # Create ZIP
        zip_path = self.output_dir / "archives" / f"{archive_name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in archive_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(archive_dir)
                    zf.write(file_path, arcname)

        # Clean up directory (keep only ZIP)
        shutil.rmtree(archive_dir)

        logger.info(f"Created domain archive: {zip_path}")
        return zip_path

    async def create_campaign_archive(
        self,
        campaign_id: str,
        include_reports: bool = True,
    ) -> Path:
        """
        Create a ZIP archive of all evidence for an entire campaign.

        This is for INTERNAL use - not for sending to abuse teams.
        """
        campaign = self.campaign_manager.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign not found: {campaign_id}")

        timestamp = datetime.now().strftime("%Y%m%d")
        safe_name = safe_filename_component(campaign.name, max_length=50, default="")
        archive_name = f"archive_campaign_{safe_name}_{timestamp}"
        archive_dir = self.output_dir / "archives" / archive_name
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Create evidence directory for each domain
        evidence_root = archive_dir / "evidence"
        evidence_root.mkdir(exist_ok=True)

        for member in campaign.members:
            domain_evidence_dir = evidence_root / safe_filename_component(
                member.domain, max_length=50, default=""
            )
            domain_evidence_dir.mkdir(exist_ok=True)

            # Copy evidence files
            src_evidence = self.evidence_store.get_evidence_path(member.domain)
            if src_evidence.exists():
                # Screenshots
                screenshots_dir = domain_evidence_dir / "screenshots"
                screenshots_dir.mkdir(exist_ok=True)
                for screenshot in src_evidence.glob("screenshot*.png"):
                    shutil.copy2(screenshot, screenshots_dir / screenshot.name)

                # HAR
                har_path = src_evidence / "network.har"
                if har_path.exists():
                    shutil.copy2(har_path, domain_evidence_dir / "network.har")

                # Analysis
                analysis_path = src_evidence / "analysis.json"
                if analysis_path.exists():
                    shutil.copy2(analysis_path, domain_evidence_dir / "analysis.json")

        # Generate and include campaign report
        if include_reports:
            try:
                html_path = await self.report_generator.generate_campaign_html(campaign_id)
                shutil.copy2(html_path, archive_dir / "campaign_report.html")

                try:
                    pdf_path = await self.report_generator.generate_campaign_pdf(campaign_id)
                    shutil.copy2(pdf_path, archive_dir / "campaign_report.pdf")
                except ImportError:
                    pass
            except Exception as e:
                logger.warning(f"Failed to generate campaign report for archive: {e}")

        # Create IOCs directory
        iocs_dir = archive_dir / "iocs"
        iocs_dir.mkdir(exist_ok=True)

        # domains.txt
        domains = [m.domain for m in campaign.members]
        (iocs_dir / "domains.txt").write_text("\n".join(domains), encoding="utf-8")

        # backends.txt
        backends = list(campaign.shared_backends)
        (iocs_dir / "backends.txt").write_text("\n".join(backends), encoding="utf-8")

        # Gather all API keys from member analyses
        all_api_keys = set()
        for member in campaign.members:
            analysis = self.evidence_store.load_analysis(member.domain)
            if analysis:
                all_api_keys.update(analysis.get("api_keys_found", []))
        if all_api_keys:
            (iocs_dir / "api_keys.txt").write_text("\n".join(all_api_keys), encoding="utf-8")

        # Create submission log
        submission_log = {
            "campaign_id": campaign_id,
            "campaign_name": campaign.name,
            "archive_created": datetime.now().isoformat(),
            "domain_count": len(campaign.members),
            "submissions": [],
        }
        (archive_dir / "submission_log.json").write_text(
            json.dumps(submission_log, indent=2), encoding="utf-8"
        )

        # Create ZIP
        zip_path = self.output_dir / "archives" / f"{archive_name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in archive_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(archive_dir)
                    zf.write(file_path, arcname)

        # Clean up directory
        shutil.rmtree(archive_dir)

        logger.info(f"Created campaign archive: {zip_path}")
        return zip_path

    # -------------------------------------------------------------------------
    # HAR Processing - Extract backend requests
    # -------------------------------------------------------------------------

    def extract_backend_requests(self, domain: str) -> List[dict]:
        """
        Extract requests to backend/C2 servers from a domain's HAR file.

        Returns a list of simplified request objects showing data exfiltration.
        """
        evidence_dir = self.evidence_store.get_evidence_path(domain)
        har_path = evidence_dir / "network.har"

        if not har_path.exists():
            return []

        try:
            har_data = json.loads(har_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"Failed to read HAR file for {domain}: {e}")
            return []

        # Get known backend domains from analysis
        analysis = self.evidence_store.load_analysis(domain)
        backend_domains = set(analysis.get("backend_domains", [])) if analysis else set()

        # Also check campaign's shared backends
        campaign = self.campaign_manager.get_campaign_for_domain(domain)
        if campaign:
            backend_domains.update(campaign.shared_backends)

        # Extract matching requests
        backend_requests = []
        for entry in har_data.get("log", {}).get("entries", []):
            request = entry.get("request", {})
            url = request.get("url", "")

            # Check if request is to a backend domain
            is_backend = any(bd in url for bd in backend_domains)

            # Also flag POST requests to external domains
            method = request.get("method", "")
            if method == "POST" or is_backend:
                backend_requests.append({
                    "url": url,
                    "method": method,
                    "is_backend": is_backend,
                    "time": entry.get("startedDateTime"),
                    "status": entry.get("response", {}).get("status"),
                })

        return backend_requests

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------
