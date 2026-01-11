"""Core pipeline setup and lifecycle."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from ..analyzer import BrowserAnalyzer, PhishingDetector, ThreatIntelUpdater
from ..analyzer.campaigns import ThreatCampaignManager
from ..analyzer.external_intel import ExternalIntelligence
from ..analyzer.infrastructure import InfrastructureAnalyzer
from ..analyzer.takedown_checker import TakedownChecker
from ..analyzer.temporal import ScanReason, TemporalTracker
from ..bot import SeedBusterBot
from ..config import Config
from ..discovery import (
    AsyncCertstreamListener,
    BingWebSearchProvider,
    DomainScorer,
    GoogleCSEProvider,
    SearchDiscovery,
)
from ..monitoring.health import HealthServer
from ..reporter import ReportManager
from ..reporter.evidence_packager import EvidencePackager
from ..storage import Database, EvidenceStore
from ..storage.database import DomainStatus
from ..utils.domains import canonicalize_domain, normalize_allowlist_domain
from .analysis import AnalysisEngine

logger = logging.getLogger(__name__)


class SeedBusterPipelineCoreMixin:
    """Core lifecycle and wiring for the pipeline."""

    def __init__(self, config: Config):
        self.config = config
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._stop_lock = asyncio.Lock()
        self._stop_task: asyncio.Task | None = None
        self._started_at = datetime.now(timezone.utc)

        self._discovery_queue: asyncio.Queue[object] = asyncio.Queue(maxsize=1000)
        self._analysis_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=100)
        self._rescan_pending: set[str] = set()

        self.database = Database(config.data_dir / "seedbuster.db")
        self.evidence_store = EvidenceStore(config.evidence_dir)
        self.scorer = DomainScorer(
            target_patterns=config.target_patterns,
            allowlist=config.allowlist,
            denylist=config.denylist,
            suspicious_tlds=config.suspicious_tlds,
            min_score_to_analyze=config.domain_score_threshold,
            keyword_weights=config.domain_keyword_weights,
            substitutions=config.substitutions,
        )
        self.browser = BrowserAnalyzer(
            timeout=config.analysis_timeout,
            exploration_targets=config.exploration_targets,
        )
        self.infrastructure = InfrastructureAnalyzer(timeout=10)
        self.temporal = TemporalTracker(config.data_dir / "temporal")
        self.campaign_manager = ThreatCampaignManager(config.data_dir / "campaigns")
        self.external_intel = ExternalIntelligence(
            urlscan_api_key=config.urlscan_api_key or None,
            virustotal_api_key=config.virustotal_api_key or None,
            cache_dir=config.data_dir / "intel_cache",
            scoring_weights=config.scoring_weights,
        )
        self.detector = PhishingDetector(
            fingerprints_dir=config.data_dir / "fingerprints",
            config_dir=config.config_dir,
            keywords=config.keywords,
            analysis_threshold=config.analysis_score_threshold,
            seed_keywords=config.seed_keywords,
            title_keywords=config.title_keywords,
            pattern_categories=config.pattern_categories,
            infrastructure_thresholds=config.infrastructure_thresholds,
            scoring_weights=config.scoring_weights,
        )
        self.threat_intel_updater = ThreatIntelUpdater(config.config_dir)
        self.takedown_checker = TakedownChecker(
            backend_probe_paths=config.takedown_backend_probe_paths,
            backend_status_weight=config.takedown_backend_status_weight,
            backend_error_weight=config.takedown_backend_error_weight,
        )

        self.report_manager = ReportManager(
            database=self.database,
            evidence_store=self.evidence_store,
            smtp_config={
                "host": config.smtp_host,
                "port": config.smtp_port,
                "username": config.smtp_username,
                "password": config.smtp_password,
                "from_email": config.smtp_from_email or config.resend_from_email,
            },
            resend_api_key=config.resend_api_key,
            resend_from_email=config.resend_from_email,
            reporter_email=config.smtp_from_email or config.resend_from_email,
            enabled_platforms=config.report_platforms,
        )

        self.evidence_packager = EvidencePackager(
            database=self.database,
            evidence_store=self.evidence_store,
            campaign_manager=self.campaign_manager,
            output_dir=config.data_dir / "packages",
        )

        self.bot = SeedBusterBot(
            token=config.telegram_bot_token,
            chat_id=config.telegram_chat_id,
            database=self.database,
            evidence_store=self.evidence_store,
            allowlist_path=config.config_dir / "allowlist.txt",
            submit_callback=self._manual_submit,
            report_manager=self.report_manager,
            report_require_approval=config.report_require_approval,
            report_min_score=config.report_min_score,
            campaign_manager=self.campaign_manager,
            evidence_packager=self.evidence_packager,
        )
        self.analysis_engine = AnalysisEngine(
            config=config,
            database=self.database,
            evidence_store=self.evidence_store,
            browser=self.browser,
            infrastructure=self.infrastructure,
            temporal=self.temporal,
            external_intel=self.external_intel,
            detector=self.detector,
            campaign_manager=self.campaign_manager,
            threat_intel_updater=self.threat_intel_updater,
            report_manager=self.report_manager,
            bot=self.bot,
        )
        self.health_server = HealthServer(
            host=config.health_host,
            port=config.health_port,
            status_provider=self._health_snapshot,
            enabled=config.health_enabled,
        )
        self.ct_listener: AsyncCertstreamListener = None
        self.search_discovery: SearchDiscovery | None = None

    def _manual_submit(self, target: str):
        """Handle manual domain submission from Telegram/dashboard."""
        raw = str(target or "").strip()
        if not raw:
            return
        domain = canonicalize_domain(raw) or raw.split("/")[0]
        source_url = raw if ("/" in raw or raw.startswith(("http://", "https://"))) else None
        if source_url and not source_url.startswith(("http://", "https://")):
            source_url = f"https://{source_url}"
        try:
            self._discovery_queue.put_nowait({
                "domain": domain,
                "source": "manual",
                "force": True,
                "source_url": source_url,
            })
            logger.info("Manual submission queued: %s (forced)", domain)
        except asyncio.QueueFull:
            logger.warning("Queue full, could not submit: %s", domain)

    def _manual_rescan(self, domain: str, source_url: str | None = None):
        """Handle manual rescan request from Telegram."""
        try:
            asyncio.create_task(
                self._handle_rescan(domain, ScanReason.MANUAL, source_url=source_url)
            )
            logger.info("Manual rescan queued: %s", domain)
        except Exception as exc:
            logger.error("Failed to queue manual rescan for %s: %s", domain, exc)

    def _allowlist_add(self, domain: str) -> None:
        """Sync allowlist updates to the in-memory scorer and database."""
        value = normalize_allowlist_domain(domain)
        if not value:
            return
        self.scorer.allowlist.add(value)
        self.config.allowlist.add(value)
        self.temporal.cancel_rescans(value)
        logger.info("Allowlisted via Telegram: %s", value)
        try:
            asyncio.create_task(self._apply_allowlist_entry(value))
        except Exception as exc:
            logger.warning("Failed to schedule allowlist update for %s: %s", value, exc)

    def _allowlist_remove(self, domain: str) -> None:
        """Sync allowlist removals to the in-memory scorer."""
        value = normalize_allowlist_domain(domain)
        if not value:
            return
        self.scorer.allowlist.discard(value)
        self.config.allowlist.discard(value)
        logger.info("Removed from allowlist via Telegram: %s", value)

    async def _apply_allowlist_entry(self, domain: str) -> None:
        """Mark matching domains allowlisted in the database."""
        try:
            await self.database.apply_allowlist_entry(domain)
        except Exception as exc:
            logger.warning("Failed to apply allowlist entry %s: %s", domain, exc)

    async def _resume_pending_domains(self) -> None:
        """Resume any pending domains from previous runs."""
        try:
            pending = await self.database.get_pending_domains(limit=None)
        except Exception as exc:
            logger.warning("Failed to load pending domains on startup: %s", exc)
            return

        if not pending:
            return

        resumed = 0
        for row in pending:
            try:
                domain_id = int(row.get("id") or 0)
                domain = str(row.get("domain") or "").strip()
                domain_score = int(row.get("domain_score") or 0)
                if not domain or not domain_id:
                    continue
                await self._analysis_queue.put({
                    "id": domain_id,
                    "domain": domain,
                    "domain_score": domain_score,
                    "reasons": [],
                })
                resumed += 1
            except asyncio.QueueFull:
                logger.warning("Analysis queue full while resuming pending domains")
                break
            except Exception:
                continue

        if resumed:
            logger.info("Re-queued %s pending domains from previous run", resumed)

    async def _resume_stuck_analyzing_domains(self) -> None:
        """Reset domains stuck in analyzing status and requeue them."""
        try:
            analyzing = await self.database.get_analyzing_domains(limit=None)
        except Exception as exc:
            logger.warning("Failed to load analyzing domains on startup: %s", exc)
            return

        if not analyzing:
            return

        resumed = 0
        for row in analyzing:
            try:
                domain_id = int(row.get("id") or 0)
                domain = str(row.get("domain") or "").strip()
                domain_score = int(row.get("domain_score") or 0)
                if not domain or not domain_id:
                    continue
                await self.database.update_domain_status(domain_id, DomainStatus.PENDING)
                await self._analysis_queue.put({
                    "id": domain_id,
                    "domain": domain,
                    "domain_score": domain_score,
                    "reasons": [],
                })
                resumed += 1
            except asyncio.QueueFull:
                logger.warning("Analysis queue full while resuming analyzing domains")
                break
            except Exception:
                continue

        if resumed:
            logger.info("Re-queued %s analyzing domains from previous run", resumed)

    async def _apply_allowlist_entries(self) -> None:
        """Mark existing domains allowlisted based on configured entries."""
        if not self.config.allowlist:
            return
        total = 0
        for entry in sorted(self.config.allowlist):
            self.temporal.cancel_rescans(entry)
            total += await self.database.apply_allowlist_entry(entry)
        if total:
            logger.info("Allowlisted %s existing domains from config", total)

    def _health_snapshot(self) -> dict:
        """Provide a lightweight status dict for health endpoints."""
        uptime = (datetime.now(timezone.utc) - self._started_at).total_seconds()
        temporal_stats = self.temporal.get_stats()
        return {
            "status": "ok" if self._running else "stopped",
            "uptime_seconds": round(uptime, 1),
            "discovery_queue_size": self._discovery_queue.qsize(),
            "analysis_queue_size": self._analysis_queue.qsize(),
            "pending_rescans": temporal_stats.get("pending_rescans", 0),
            "domains_tracked": temporal_stats.get("domains_tracked", 0),
        }

    async def start(self):
        """Start all pipeline components."""
        logger.info("Starting SeedBuster pipeline...")
        self._running = True

        await self.database.connect()
        logger.info("Database connected")

        await self._apply_allowlist_entries()
        await self._resume_stuck_analyzing_domains()
        await self._resume_pending_domains()

        await self.browser.start()
        logger.info("Browser started")

        self.bot.set_queue_size_callback(lambda: self._discovery_queue.qsize() + self._analysis_queue.qsize())
        self.bot.set_rescan_callback(self._manual_rescan)
        self.bot.set_reload_callback(self.detector.reload_threat_intel)
        self.bot.set_allowlist_callbacks(self._allowlist_add, self._allowlist_remove)
        await self.bot.start()
        logger.info("Telegram bot started")

        self.ct_listener = AsyncCertstreamListener(
            queue=self._discovery_queue,
            quick_filter=self.scorer.quick_filter,
        )
        await self.ct_listener.start()
        logger.info("CT stream listener started")

        if self.config.search_discovery_enabled:
            provider = None
            match (self.config.search_discovery_provider or "").lower():
                case "google":
                    if not (self.config.google_cse_api_key and self.config.google_cse_id):
                        logger.error(
                            "Search discovery enabled but GOOGLE_CSE_API_KEY/GOOGLE_CSE_ID not set; skipping"
                        )
                    else:
                        provider = GoogleCSEProvider(
                            api_key=self.config.google_cse_api_key,
                            cse_id=self.config.google_cse_id,
                            gl=self.config.google_cse_gl,
                            hl=self.config.google_cse_hl,
                        )
                case "bing":
                    if not self.config.bing_search_api_key:
                        logger.error("Search discovery enabled but BING_SEARCH_API_KEY not set; skipping")
                    else:
                        provider = BingWebSearchProvider(
                            api_key=self.config.bing_search_api_key,
                            endpoint=self.config.bing_search_endpoint,
                            market=self.config.bing_search_market,
                        )
                case other:
                    logger.error("Unknown SEARCH_DISCOVERY_PROVIDER=%r; expected 'google' or 'bing'", other)

            if provider:
                self.search_discovery = SearchDiscovery(
                    queue=self._discovery_queue,
                    provider=provider,
                    queries=self.config.search_discovery_queries,
                    interval_seconds=self.config.search_discovery_interval_minutes * 60,
                    results_per_query=self.config.search_discovery_results_per_query,
                    force_analyze=self.config.search_discovery_force_analyze,
                    exclude_domains=self.config.search_discovery_exclude_domains,
                    rotate_pages=self.config.search_discovery_rotate_pages,
                    state_path=self.config.data_dir / "search_discovery_state.json",
                )
                logger.info("Search discovery enabled")

        self.temporal.set_rescan_callback(self._handle_rescan)
        logger.info("Temporal tracker initialized")

        analysis_worker_count = max(1, int(self.config.max_concurrent_analyses or 1))
        self._tasks = [
            asyncio.create_task(self._discovery_worker()),
            *[
                asyncio.create_task(self._analysis_worker(worker_id=i + 1))
                for i in range(analysis_worker_count)
            ],
            asyncio.create_task(self._dashboard_actions_worker()),
            asyncio.create_task(self.temporal.run_rescan_loop()),
            asyncio.create_task(self._report_retry_worker()),
            asyncio.create_task(self._watchlist_rescan_worker()),
            asyncio.create_task(self._takedown_worker()),
        ]
        if self.search_discovery:
            self._tasks.append(asyncio.create_task(self.search_discovery.run_loop()))

        await self.health_server.start()
        logger.info("Health server started")

        startup_note = "Monitoring CT logs for suspicious domains..."
        if self.search_discovery:
            startup_note = "Monitoring CT logs and search results for suspicious domains..."
        await self.bot.send_message(f"*SeedBuster started*\n{startup_note}")

        logger.info("Pipeline running")

        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            logger.info("Pipeline tasks cancelled")

    async def stop(self):
        """Stop all pipeline components."""
        async with self._stop_lock:
            if self._stop_task is None:
                self._stop_task = asyncio.create_task(self._stop_impl())
            stop_task = self._stop_task
        await stop_task

    async def _stop_impl(self):
        """One-shot shutdown implementation (idempotent via stop())."""
        logger.info("Stopping SeedBuster pipeline...")
        self._running = False

        if self.ct_listener:
            await self.ct_listener.stop()
            self.ct_listener = None

        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        self.search_discovery = None

        await self.bot.send_message("*SeedBuster stopping*...")
        await self.bot.stop()
        await self.health_server.stop()
        await self.browser.stop()
        await self.infrastructure.close()
        await self.database.close()

        logger.info("Pipeline stopped")
