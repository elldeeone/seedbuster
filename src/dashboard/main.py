"""Standalone dashboard process (run separately from the pipeline).

Run:
  python -m src.dashboard.main
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

from ..analyzer.clustering import ThreatClusterManager
from ..config import load_config
from ..reporter import ReportManager
from ..reporter.evidence_packager import EvidencePackager
from ..storage import Database, EvidenceStore
from .server import DashboardConfig, DashboardServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def _spawn(coro: Coroutine[Any, Any, Any]) -> None:
    """Fire-and-forget helper that logs exceptions."""
    task = asyncio.create_task(coro)

    def _done(t: asyncio.Task) -> None:
        try:
            exc = t.exception()
        except asyncio.CancelledError:
            return
        except Exception as e:  # pragma: no cover - extremely defensive
            logger.warning("Background task error: %s", e)
            return
        if exc:
            logger.warning("Background task error: %s", exc)

    task.add_done_callback(_done)


async def run_dashboard() -> None:
    config = load_config()

    db = Database(config.data_dir / "seedbuster.db")
    await db.connect()

    evidence_store = EvidenceStore(config.evidence_dir)
    report_manager = ReportManager(
        database=db,
        evidence_store=evidence_store,
        smtp_config={
            "host": config.smtp_host,
            "port": config.smtp_port,
            "username": config.smtp_username,
            "password": config.smtp_password,
            "from_email": config.smtp_from_email or config.resend_from_email,
        },
        phishtank_api_key=config.phishtank_api_key or None,
        resend_api_key=config.resend_api_key,
        resend_from_email=config.resend_from_email,
        reporter_email=config.smtp_from_email or config.resend_from_email,
        enabled_platforms=config.report_platforms,
    )

    # Initialize cluster manager and evidence packager
    cluster_manager = ThreatClusterManager(config.data_dir / "clusters")
    evidence_packager = EvidencePackager(
        database=db,
        evidence_store=evidence_store,
        cluster_manager=cluster_manager,
        output_dir=config.data_dir / "packages",
    )

    def submit_callback(domain: str) -> None:
        _spawn(db.enqueue_dashboard_action("submit_domain", {"domain": domain}))

    def rescan_callback(domain: str) -> None:
        _spawn(db.enqueue_dashboard_action("rescan_domain", {"domain": domain}))

    async def report_callback(
        domain_id: int,
        domain: str,
        platforms: list[str] | None,
        force: bool,
    ) -> None:
        await db.enqueue_dashboard_action(
            "report_domain",
            {
                "domain_id": int(domain_id),
                "domain": domain,
                "platforms": platforms,
                "force": bool(force),
            },
        )

    async def manual_done_callback(
        domain_id: int,
        domain: str,
        platforms: list[str] | None,
        note: str,
    ) -> None:
        await db.enqueue_dashboard_action(
            "manual_done",
            {
                "domain_id": int(domain_id),
                "domain": domain,
                "platforms": platforms,
                "note": note,
            },
        )

    # -------------------------------------------------------------------------
    # New callbacks for PDF/evidence generation
    # -------------------------------------------------------------------------

    async def generate_domain_pdf_callback(domain: str, domain_id: int | None) -> Path | None:
        """Generate PDF report for a domain."""
        attachments = await evidence_packager.prepare_domain_submission(domain, domain_id)
        return attachments.pdf_path or attachments.html_path

    async def generate_domain_package_callback(domain: str, domain_id: int | None) -> Path | None:
        """Generate evidence archive for a domain."""
        return await evidence_packager.create_domain_archive(domain, domain_id)

    async def preview_domain_report_callback(domain_id: int, domain: str) -> dict:
        """Send dry-run reports to operator's email."""
        dry_run_email = os.environ.get("DRY_RUN_EMAIL")
        if not dry_run_email:
            raise ValueError("DRY_RUN_EMAIL not configured")
        return await report_manager.report_domain(
            domain_id=domain_id,
            domain=domain,
            dry_run=True,
            dry_run_email=dry_run_email,
        )

    async def generate_campaign_pdf_callback(cluster_id: str) -> Path | None:
        """Generate PDF report for a campaign."""
        attachments = await evidence_packager.prepare_campaign_submission(cluster_id)
        return attachments.pdf_path or attachments.html_path

    async def generate_campaign_package_callback(cluster_id: str) -> Path | None:
        """Generate evidence archive for a campaign."""
        return await evidence_packager.create_campaign_archive(cluster_id)

    async def preview_campaign_report_callback(cluster_id: str) -> dict:
        """Send dry-run campaign reports to operator's email."""
        dry_run_email = os.environ.get("DRY_RUN_EMAIL")
        if not dry_run_email:
            raise ValueError("DRY_RUN_EMAIL not configured")
        return await report_manager.report_campaign(
            cluster_id=cluster_id,
            cluster_manager=cluster_manager,
            dry_run=True,
            dry_run_email=dry_run_email,
        )

    async def submit_campaign_report_callback(cluster_id: str) -> dict:
        """Submit campaign reports to all platforms."""
        return await report_manager.report_campaign(cluster_id=cluster_id, cluster_manager=cluster_manager)

    server = DashboardServer(
        config=DashboardConfig(
            enabled=True,
            host=config.dashboard_host,
            port=config.dashboard_port,
            admin_user=config.dashboard_admin_user,
            admin_password=config.dashboard_admin_password,
        ),
        database=db,
        evidence_dir=config.evidence_dir,
        clusters_dir=config.data_dir / "clusters",
        submit_callback=submit_callback,
        rescan_callback=rescan_callback,
        report_callback=report_callback,
        mark_manual_done_callback=manual_done_callback,
        get_available_platforms=report_manager.get_available_platforms,
        # New callbacks for enhanced reporting
        generate_domain_pdf_callback=generate_domain_pdf_callback,
        generate_domain_package_callback=generate_domain_package_callback,
        preview_domain_report_callback=preview_domain_report_callback,
        generate_campaign_pdf_callback=generate_campaign_pdf_callback,
        generate_campaign_package_callback=generate_campaign_package_callback,
        preview_campaign_report_callback=preview_campaign_report_callback,
        submit_campaign_report_callback=submit_campaign_report_callback,
    )

    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            # Windows event loop does not support add_signal_handler.
            pass

    await server.start()
    logger.info("Dashboard running on http://%s:%s", config.dashboard_host, config.dashboard_port)
    try:
        await stop_event.wait()
    finally:
        await server.stop()
        await db.close()


def main() -> None:
    asyncio.run(run_dashboard())


if __name__ == "__main__":
    main()
