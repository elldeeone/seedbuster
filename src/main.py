"""Main entry point for SeedBuster phishing detection pipeline."""

import asyncio
import json
import logging
import signal
import sys
from pathlib import Path
from datetime import datetime, timezone

from .config import load_config, Config, validate_config
from .discovery import (
    DomainScorer,
    AsyncCertstreamListener,
    SearchDiscovery,
    GoogleCSEProvider,
    BingWebSearchProvider,
)
from .analyzer import BrowserAnalyzer, PhishingDetector, ThreatIntelUpdater
from .analyzer.infrastructure import InfrastructureAnalyzer
from .analyzer.temporal import TemporalTracker, ScanReason
from .analyzer.campaigns import ThreatCampaignManager
from .analyzer.external_intel import ExternalIntelligence
from .analyzer.takedown_checker import TakedownChecker, TakedownStatus
from .storage import Database, EvidenceStore
from .storage.database import DomainStatus
from .bot import SeedBusterBot
from .reporter import ReportManager
from .reporter.evidence_packager import EvidencePackager
from .monitoring.health import HealthServer
from .pipeline.analysis import AnalysisEngine
from .utils.domains import canonicalize_domain, normalize_allowlist_domain

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


class SeedBusterPipeline:
    """Main orchestrator for the phishing detection pipeline."""

    def __init__(self, config: Config):
        self.config = config
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._stop_lock = asyncio.Lock()
        self._stop_task: asyncio.Task | None = None
        self._started_at = datetime.now(timezone.utc)

        # Queues for pipeline stages
        # Discovery queue items can be a domain string or a dict with metadata:
        # { "domain": "...", "source": "...", "force": bool }
        self._discovery_queue: asyncio.Queue[object] = asyncio.Queue(maxsize=1000)
        self._analysis_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=100)
        self._rescan_pending: set[str] = set()

        # Components
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

        # Initialize report manager
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

        # Evidence packager for report generation
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
            # Force analysis even if the domain scorer would normally drop it.
            self._discovery_queue.put_nowait({
                "domain": domain,
                "source": "manual",
                "force": True,
                "source_url": source_url,
            })
            logger.info(f"Manual submission queued: {domain} (forced)")
        except asyncio.QueueFull:
            logger.warning(f"Queue full, could not submit: {domain}")

    async def _handle_rescan(self, domain: str, reason: ScanReason):
        """Handle scheduled rescan - re-analyze domain and send update if changed."""
        logger.info(f"Rescan triggered for {domain} (reason: {reason.value})")

        rescan_key = (domain or "").strip().lower()
        if rescan_key in self._rescan_pending:
            logger.info("Rescan already queued for %s; skipping duplicate.", domain)
            return

        domain_record = await self.database.get_domain(domain)
        if domain_record:
            status = str(domain_record.get("status") or "").strip().lower()
            benign_statuses = {
                DomainStatus.FALSE_POSITIVE.value,
                DomainStatus.ALLOWLISTED.value,
            }
            if status in benign_statuses and reason != ScanReason.MANUAL:
                canceled = self.temporal.cancel_rescans(domain)
                logger.info(
                    f"Skipping scheduled rescan for {domain} (status={status}); "
                    f"canceled {canceled} remaining rescans"
                )
                return
            domain = str(domain_record.get("domain") or domain)
            rescan_key = (domain or "").strip().lower() or rescan_key

        # Queue the domain for re-analysis with rescan flag
        # We store the reason in a dict to track rescan context
        if rescan_key:
            self._rescan_pending.add(rescan_key)
        try:
            await self._analysis_queue.put((domain, reason))
        except Exception:
            if rescan_key:
                self._rescan_pending.discard(rescan_key)
            raise

    def _manual_rescan(self, domain: str):
        """Handle manual rescan request from Telegram."""
        import asyncio
        try:
            # Create task to handle async rescan
            asyncio.create_task(self._handle_rescan(domain, ScanReason.MANUAL))
            logger.info(f"Manual rescan queued: {domain}")
        except Exception as e:
            logger.error(f"Failed to queue manual rescan for {domain}: {e}")

    def _allowlist_add(self, domain: str) -> None:
        """Sync allowlist updates to the in-memory scorer and database."""
        value = normalize_allowlist_domain(domain)
        if not value:
            return
        self.scorer.allowlist.add(value)
        self.config.allowlist.add(value)
        self.temporal.cancel_rescans(value)
        logger.info(f"Allowlisted via Telegram: {value}")
        try:
            asyncio.create_task(self._apply_allowlist_entry(value))
        except Exception as e:
            logger.warning("Failed to schedule allowlist update for %s: %s", value, e)

    def _allowlist_remove(self, domain: str) -> None:
        """Sync allowlist removals to the in-memory scorer."""
        value = normalize_allowlist_domain(domain)
        if not value:
            return
        self.scorer.allowlist.discard(value)
        self.config.allowlist.discard(value)
        logger.info(f"Removed from allowlist via Telegram: {value}")

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

        # Connect to database
        await self.database.connect()
        logger.info("Database connected")

        await self._apply_allowlist_entries()
        await self._resume_stuck_analyzing_domains()
        await self._resume_pending_domains()

        # Start browser
        await self.browser.start()
        logger.info("Browser started")

        # Start Telegram bot
        self.bot.set_queue_size_callback(lambda: self._discovery_queue.qsize() + self._analysis_queue.qsize())
        self.bot.set_rescan_callback(self._manual_rescan)
        self.bot.set_reload_callback(self.detector.reload_threat_intel)
        self.bot.set_allowlist_callbacks(self._allowlist_add, self._allowlist_remove)
        await self.bot.start()
        logger.info("Telegram bot started")

        # Start CT listener
        self.ct_listener = AsyncCertstreamListener(
            queue=self._discovery_queue,
            quick_filter=self.scorer.quick_filter,
        )
        await self.ct_listener.start()
        logger.info("CT stream listener started")

        # Optional: search-engine discovery via official APIs (Google CSE / Bing).
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

        # Set up temporal rescan callback and start rescan loop
        self.temporal.set_rescan_callback(self._handle_rescan)
        logger.info("Temporal tracker initialized")

        # Start worker tasks
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

        # Send startup notification
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

        # Stop components in reverse order
        if self.ct_listener:
            await self.ct_listener.stop()
            self.ct_listener = None

        # Stop worker tasks (including infinite rescan loop)
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

    async def _discovery_worker(self):
        """Process discovered domains from CT stream."""
        logger.info("Discovery worker started")

        while self._running:
            try:
                # Get domain from queue with timeout
                try:
                    item = await asyncio.wait_for(
                        self._discovery_queue.get(),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    continue

                source = "certstream"
                force = False
                source_url = None
                if isinstance(item, dict):
                    domain = (item.get("domain") or "").strip()
                    source = (item.get("source") or source).strip() or source
                    force = bool(item.get("force", False))
                    source_url = (item.get("source_url") or "").strip() or None
                else:
                    domain = str(item).strip()

                if not domain:
                    continue

                # Check if already seen
                if await self.database.domain_exists(domain):
                    logger.debug(f"Already seen: {domain}")
                    continue

                # Score the domain
                score_result = self.scorer.score_domain(domain)

                if score_result.is_allowlisted:
                    logger.debug(f"Allowlisted: {domain}")
                    continue

                if not force and not score_result.should_analyze:
                    logger.debug(f"Below threshold: {domain} (score={score_result.score})")
                    continue

                # Add to database
                domain_id = await self.database.add_domain(
                    domain=domain,
                    source=source,
                    domain_score=score_result.score,
                    source_url=source_url,
                )

                if domain_id:
                    logger.info(
                        f"Queued for analysis: {domain} "
                        f"(score={score_result.score}, reasons={score_result.reasons})"
                    )
                    # Queue for analysis
                    await self._analysis_queue.put({
                        "id": domain_id,
                        "domain": domain,
                        "domain_score": score_result.score,
                        "reasons": score_result.reasons,
                        "source_url": source_url,
                    })

            except Exception as e:
                logger.error(f"Discovery worker error: {e}")
                await asyncio.sleep(1)

    async def _dashboard_actions_worker(self):
        """Process dashboard admin actions (submit/rescan/report) from SQLite queue."""
        logger.info("Dashboard actions worker started")

        while self._running:
            try:
                actions = await self.database.claim_dashboard_actions(limit=20)
                if not actions:
                    await asyncio.sleep(1.0)
                    continue

                for action in actions:
                    action_id = int(action.get("id") or 0)
                    kind = str(action.get("kind") or "").strip().lower()
                    payload_raw = action.get("payload") or "{}"

                    try:
                        payload = (
                            json.loads(payload_raw)
                            if isinstance(payload_raw, str) and payload_raw.strip()
                            else {}
                        )
                    except Exception:
                        payload = {}

                    try:
                        await self._handle_dashboard_action(kind, payload)
                        await self.database.finish_dashboard_action(action_id, status="done")
                    except Exception as e:
                        logger.warning(
                            "Dashboard action failed (id=%s kind=%s): %s",
                            action_id,
                            kind,
                            e,
                        )
                        await self.database.finish_dashboard_action(
                            action_id,
                            status="failed",
                            error=str(e),
                        )

            except Exception as e:
                logger.error(f"Dashboard actions worker error: {e}")
                await asyncio.sleep(1.0)

    async def _handle_dashboard_action(self, kind: str, payload: dict) -> None:
        """Handle a single dashboard action payload."""
        action = str(kind or "").strip().lower()

        if action == "submit_domain":
            domain = str(payload.get("domain") or "").strip().lower()
            if not domain:
                raise ValueError("domain is required")

            # If it already exists, treat it as a rescan request.
            if await self.database.domain_exists(domain):
                self._manual_rescan(domain)
                return

            try:
                self._discovery_queue.put_nowait({
                    "domain": domain,
                    "source": "manual",
                    "force": True,
                })
            except asyncio.QueueFull:
                raise RuntimeError("discovery queue full")

            return

        if action == "rescan_domain":
            domain = str(payload.get("domain") or "").strip().lower()
            if not domain:
                raise ValueError("domain is required")
            self._manual_rescan(domain)
            return

        if action == "report_domain":
            domain_id = int(payload.get("domain_id") or 0)
            domain = str(payload.get("domain") or "").strip()
            force = bool(payload.get("force", False))
            platforms = payload.get("platforms")
            platforms_list: list[str] | None = None
            if isinstance(platforms, list):
                platforms_list = [str(p).strip().lower() for p in platforms if str(p).strip()]

            if not domain and domain_id:
                row = await self.database.get_domain_by_id(domain_id)
                domain = str(row.get("domain") or "").strip() if row else ""
            if not domain_id and domain:
                row = await self.database.get_domain(domain)
                domain_id = int(row.get("id") or 0) if row else 0

            if not domain_id or not domain:
                raise ValueError("domain_id/domain required")

            await self.report_manager.report_domain(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms_list,
                force=force,
            )
            return

        if action == "manual_done":
            domain_id = int(payload.get("domain_id") or 0)
            domain = str(payload.get("domain") or "").strip()
            platforms = payload.get("platforms")
            platforms_list: list[str] | None = None
            if isinstance(platforms, list):
                platforms_list = [str(p).strip().lower() for p in platforms if str(p).strip()]
            note = str(payload.get("note") or "Manual submission marked complete").strip()

            if not domain and domain_id:
                row = await self.database.get_domain_by_id(domain_id)
                domain = str(row.get("domain") or "").strip() if row else ""
            if not domain_id and domain:
                row = await self.database.get_domain(domain)
                domain_id = int(row.get("id") or 0) if row else 0

            if not domain_id or not domain:
                raise ValueError("domain_id/domain required")

            await self.report_manager.mark_manual_done(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms_list,
                note=note,
            )
            return

        if action == "allowlist_add":
            domain = str(payload.get("domain") or "").strip().lower()
            if not domain:
                raise ValueError("domain is required")
            self._allowlist_add(domain)
            return

        if action == "allowlist_remove":
            domain = str(payload.get("domain") or "").strip().lower()
            if not domain:
                raise ValueError("domain is required")
            self._allowlist_remove(domain)
            return

        raise ValueError(f"unknown action kind: {action}")

    async def _analysis_worker(self, worker_id: int | None = None):
        """Analyze queued domains for phishing signals."""
        label = f"Analysis worker {worker_id}" if worker_id else "Analysis worker"
        logger.info("%s started", label)

        while self._running:
            try:
                # Get domain from queue
                try:
                    task = await asyncio.wait_for(
                        self._analysis_queue.get(),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    continue

                # Handle rescan tasks (tuple) vs regular tasks (dict)
                if isinstance(task, tuple):
                    # Rescan task: (domain, ScanReason)
                    domain, scan_reason = task
                    # Get domain record from database
                    domain_record = await self.database.get_domain(domain)

                    try:
                        if domain_record:
                            domain_id = int(domain_record.get("id") or 0)
                            score_result = self.scorer.score_domain(domain)
                            domain_score = score_result.score
                            domain_reasons = score_result.reasons
                            if domain_id:
                                current_score = int(domain_record.get("domain_score") or 0)
                                if domain_score != current_score:
                                    await self.database.update_domain_score(domain_id, domain_score)
                            domain_record["domain_score"] = domain_score
                            domain_record["reasons"] = domain_reasons
                            await self.analysis_engine.analyze(domain_record, scan_reason=scan_reason)
                        else:
                            logger.warning(f"Rescan: domain not found in DB: {domain}")
                    finally:
                        key = (domain or "").strip().lower()
                        if key:
                            self._rescan_pending.discard(key)
                else:
                    # Regular task from discovery
                    await self.analysis_engine.analyze(task)

            except Exception as e:
                logger.error(f"Analysis worker error: {e}")
                await asyncio.sleep(1)

    async def _report_retry_worker(self):
        """Retry rate-limited reports in the background."""
        logger.info("Report retry worker started")

        # Poll interval (seconds). Keep this conservative to avoid hammering web forms/APIs.
        interval_seconds = 300

        while self._running:
            try:
                # Best-effort retry; this only touches `rate_limited` reports that are due.
                results = await self.report_manager.retry_due_reports(limit=20)
                if results:
                    # Log summary only; user can check `/report <id> status` for details.
                    by_status: dict[str, int] = {}
                    for r in results:
                        by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
                    logger.info(f"Report retry pass: {by_status}")

                    # Notify on progress (avoid spamming on pure rate-limit churn).
                    notify_statuses = {"submitted", "confirmed", "duplicate", "manual_required"}
                    notify = [r for r in results if r.status.value in notify_statuses]
                    if notify:
                        lines = ["*Report retry updates:*"]
                        max_items = 10
                        for r in notify[:max_items]:
                            domain = (r.response_data or {}).get("domain") or "unknown"
                            line = f"- `{domain}`: `{r.platform}` `{r.status.value}`"
                            if r.status.value == "manual_required" and r.message:
                                manual_url = self.bot._extract_first_url(r.message)
                                if manual_url:
                                    line += f" (manual: `{manual_url}`)"
                                try:
                                    short_id = self.evidence_store.get_domain_id(domain)
                                    line += f" (instructions: `/evidence {short_id}`)"
                                except Exception:
                                    pass
                            lines.append(line)
                        extra = len(notify) - max_items
                        if extra > 0:
                            lines.append(f"...and {extra} more")
                        await self.bot.send_message("\n".join(lines))

                await asyncio.sleep(interval_seconds)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Report retry worker error: {e}")
                await asyncio.sleep(60)

        logger.info("Report retry worker stopped")

    async def _watchlist_rescan_worker(self):
        """Periodically rescan watchlist domains.

        Checks for domains with status='watchlist' that haven't been updated
        in WATCHLIST_RESCAN_DAYS (default 30). Triggers rescans so we can
        detect if suspicious domains become more malicious over time.
        """
        import os
        logger.info("Watchlist rescan worker started")

        # Configurable via environment variable
        rescan_days = int(os.environ.get("WATCHLIST_RESCAN_DAYS", "30"))
        # Check once every 6 hours
        check_interval_seconds = 6 * 60 * 60

        while self._running:
            try:
                domains = await self.database.get_watchlist_domains_due_rescan(
                    days_since_update=rescan_days,
                    limit=10,
                )

                if domains:
                    logger.info(f"Found {len(domains)} watchlist domains due for rescan")

                for row in domains:
                    domain = str(row.get("domain") or "").strip()
                    if not domain:
                        continue

                    logger.info(f"Queueing monthly rescan for watchlist domain: {domain}")
                    await self._handle_rescan(domain, ScanReason.RESCAN_MONTHLY)

                await asyncio.sleep(check_interval_seconds)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Watchlist rescan worker error: {e}")
                await asyncio.sleep(60)

        logger.info("Watchlist rescan worker stopped")

    @staticmethod
    def _parse_timestamp(value: str | None):
        if not value:
            return None
        try:
            # SQLite may store without timezone; assume UTC.
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def _takedown_interval_seconds(self, row: dict, now: datetime) -> int:
        """Compute how often to check based on age/status."""
        status = str(row.get("takedown_status") or "active").lower()
        reported_at = self._parse_timestamp(row.get("reported_at")) or self._parse_timestamp(row.get("created_at")) or now
        age_hours = max(0.0, (now - reported_at).total_seconds() / 3600.0)

        if status == TakedownStatus.CONFIRMED_DOWN.value:
            hours = max(1, int(self.config.takedown_interval_confirmed_down_hours or 6))
            return hours * 60 * 60
        if status == TakedownStatus.LIKELY_DOWN.value:
            minutes = max(1, int(self.config.takedown_interval_likely_down_minutes or 30))
            return minutes * 60
        if age_hours < 24:
            minutes = max(1, int(self.config.takedown_interval_new_minutes or 15))
            return minutes * 60
        if age_hours < 24 * 7:
            hours = max(1, int(self.config.takedown_interval_week_hours or 1))
            return hours * 60 * 60
        hours = max(1, int(self.config.takedown_interval_older_hours or 3))
        return hours * 60 * 60

    @staticmethod
    def _takedown_recovered(
        previous_status: str | None,
        current_status: TakedownStatus,
    ) -> bool:
        prev = str(previous_status or "").strip().lower()
        if not prev:
            return False
        if current_status != TakedownStatus.ACTIVE:
            return False
        return prev in {
            TakedownStatus.LIKELY_DOWN.value,
            TakedownStatus.CONFIRMED_DOWN.value,
        }

    async def _takedown_worker(self):
        """Monitor domains for takedown signals (DNS/HTTP)."""
        logger.info("Takedown monitor worker started")
        while self._running:
            try:
                batch_size = max(1, int(self.config.takedown_check_batch_size or 200))
                concurrency = max(1, int(self.config.takedown_check_concurrency or 10))
                domains = await self.database.get_domains_for_takedown_check(limit=batch_size)
                now = datetime.now(timezone.utc)
                due_rows = []
                for row in domains:
                    domain = str(row.get("domain") or "").strip()
                    if not domain:
                        continue

                    last_checked = self._parse_timestamp(row.get("last_checked_at"))
                    interval = self._takedown_interval_seconds(row, now)
                    if last_checked and (now - last_checked).total_seconds() < interval:
                        continue
                    due_rows.append(row)

                if not due_rows:
                    await asyncio.sleep(300)
                    continue

                semaphore = asyncio.Semaphore(concurrency)

                async def _check_row(row: dict) -> int:
                    async with semaphore:
                        domain = str(row.get("domain") or "").strip()
                        if not domain:
                            return 0
                        try:
                            check_time = datetime.now(timezone.utc)
                            analysis = None
                            evidence_path = row.get("evidence_path")
                            analysis_path = None
                            if evidence_path:
                                analysis_path = Path(str(evidence_path)) / "analysis.json"
                            if not analysis_path or not analysis_path.exists():
                                analysis_path = self.evidence_store.get_analysis_path(domain)
                            if analysis_path and analysis_path.exists():
                                try:
                                    analysis = json.loads(
                                        analysis_path.read_text(encoding="utf-8")
                                    )
                                except Exception:
                                    analysis = None
                            result = await self.takedown_checker.check_domain(
                                domain,
                                previous_status=row.get("takedown_status"),
                                analysis=analysis,
                            )
                            await self.database.add_takedown_check(
                                domain_id=int(row.get("id") or 0),
                                http_status=result.http_status,
                                http_error=result.http_error,
                                dns_resolves=result.dns_resolves,
                                dns_result=result.dns_result,
                                is_sinkholed=result.is_sinkholed,
                                domain_status=result.domain_status,
                                content_hash=result.content_hash,
                                still_phishing=None,
                                takedown_status=result.status.value,
                                confidence=result.confidence,
                                provider_signal=result.provider_signal,
                                backend_status=result.backend_status,
                                backend_error=result.backend_error,
                                backend_target=result.backend_target,
                            )
                            if self._takedown_recovered(row.get("takedown_status"), result.status):
                                await self._handle_rescan(domain, ScanReason.CONTENT_CHANGE)
                                logger.info(
                                    "Takedown recovery detected for %s; rescan queued",
                                    domain,
                                )
                            if bool(row.get("takedown_override")):
                                return 1

                            detected_at = None
                            confirmed_at = None
                            if result.status in {TakedownStatus.LIKELY_DOWN, TakedownStatus.CONFIRMED_DOWN}:
                                detected_at = check_time.isoformat()
                            if result.status == TakedownStatus.CONFIRMED_DOWN:
                                confirmed_at = check_time.isoformat()

                            await self.database.update_domain_takedown_status(
                                int(row.get("id") or 0),
                                result.status.value,
                                detected_at=detected_at,
                                confirmed_at=confirmed_at,
                            )
                            return 1
                        except Exception as exc:
                            logger.error(f"Takedown check failed for {domain}: {exc}")
                            return 0

                results = await asyncio.gather(*[_check_row(row) for row in due_rows])
                checked = sum(results)
                await asyncio.sleep(60 if checked else 300)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Takedown worker error: {e}")
                await asyncio.sleep(120)

        logger.info("Takedown monitor worker stopped")

    async def _analyze_domain(self, task: dict, scan_reason: ScanReason = ScanReason.INITIAL):
        """Delegate to AnalysisEngine (moved to pipeline.analysis)."""
        await self.analysis_engine.analyze(task, scan_reason=scan_reason)

async def run_pipeline():
    """Run the SeedBuster pipeline."""
    config = load_config()

    validation_errors = validate_config(config)
    if validation_errors:
        for err in validation_errors:
            logger.error(err)
        sys.exit(1)

    pipeline = SeedBusterPipeline(config)

    # Handle shutdown signals
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(pipeline.stop()))

    try:
        await pipeline.start()
    except KeyboardInterrupt:
        pass
    finally:
        await pipeline.stop()


def main():
    """Entry point."""
    asyncio.run(run_pipeline())


if __name__ == "__main__":
    main()
