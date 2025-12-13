"""Main entry point for SeedBuster phishing detection pipeline."""

import asyncio
import logging
import signal
import sys
from pathlib import Path

from .config import load_config, Config
from .discovery import DomainScorer, AsyncCertstreamListener
from .analyzer import BrowserAnalyzer, PhishingDetector, ThreatIntelUpdater
from .analyzer.infrastructure import InfrastructureAnalyzer
from .analyzer.temporal import TemporalTracker, ScanReason
from .analyzer.clustering import ThreatClusterManager, analyze_for_clustering
from .analyzer.external_intel import ExternalIntelligence
from .storage import Database, EvidenceStore
from .storage.database import DomainStatus, Verdict
from .bot import SeedBusterBot, AlertFormatter
from .bot.formatters import AlertData, TemporalInfo, ClusterInfo, LearningInfo
from .reporter import ReportManager

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

        # Queues for pipeline stages
        self._discovery_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
        self._analysis_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=100)

        # Components
        self.database = Database(config.data_dir / "seedbuster.db")
        self.evidence_store = EvidenceStore(config.evidence_dir)
        self.scorer = DomainScorer(
            target_patterns=config.target_patterns,
            allowlist=config.allowlist,
            denylist=config.denylist,
            suspicious_tlds=config.suspicious_tlds,
        )
        self.browser = BrowserAnalyzer(timeout=config.analysis_timeout)
        self.infrastructure = InfrastructureAnalyzer(timeout=10)
        self.temporal = TemporalTracker(config.data_dir / "temporal")
        self.cluster_manager = ThreatClusterManager(config.data_dir / "clusters")
        self.external_intel = ExternalIntelligence(
            urlscan_api_key=config.urlscan_api_key or None,
            virustotal_api_key=config.virustotal_api_key or None,
            cache_dir=config.data_dir / "intel_cache",
        )
        self.detector = PhishingDetector(
            fingerprints_dir=config.data_dir / "fingerprints",
            keywords=config.keywords,
            analysis_threshold=config.analysis_score_threshold,
        )
        self.threat_intel_updater = ThreatIntelUpdater(config.config_dir)

        # Initialize report manager
        self.report_manager = ReportManager(
            database=self.database,
            evidence_store=self.evidence_store,
            resend_api_key=config.resend_api_key,
            resend_from_email=config.resend_from_email,
            reporter_email=config.resend_from_email,
        )

        self.bot = SeedBusterBot(
            token=config.telegram_bot_token,
            chat_id=config.telegram_chat_id,
            database=self.database,
            evidence_store=self.evidence_store,
            submit_callback=self._manual_submit,
            report_manager=self.report_manager,
        )
        self.ct_listener: AsyncCertstreamListener = None

    def _manual_submit(self, domain: str):
        """Handle manual domain submission from Telegram."""
        try:
            self._discovery_queue.put_nowait(domain)
            logger.info(f"Manual submission queued: {domain}")
        except asyncio.QueueFull:
            logger.warning(f"Queue full, could not submit: {domain}")

    async def _handle_rescan(self, domain: str, reason: ScanReason):
        """Handle scheduled rescan - re-analyze domain and send update if changed."""
        logger.info(f"Rescan triggered for {domain} (reason: {reason.value})")

        # Queue the domain for re-analysis with rescan flag
        # We store the reason in a dict to track rescan context
        await self._analysis_queue.put((domain, reason))

    def _manual_rescan(self, domain: str):
        """Handle manual rescan request from Telegram."""
        import asyncio
        try:
            # Create task to handle async rescan
            asyncio.create_task(self._handle_rescan(domain, ScanReason.MANUAL))
            logger.info(f"Manual rescan queued: {domain}")
        except Exception as e:
            logger.error(f"Failed to queue manual rescan for {domain}: {e}")

    async def start(self):
        """Start all pipeline components."""
        logger.info("Starting SeedBuster pipeline...")
        self._running = True

        # Connect to database
        await self.database.connect()
        logger.info("Database connected")

        # Start browser
        await self.browser.start()
        logger.info("Browser started")

        # Start Telegram bot
        self.bot.set_queue_size_callback(lambda: self._discovery_queue.qsize())
        self.bot.set_rescan_callback(self._manual_rescan)
        self.bot.set_reload_callback(self.detector.reload_threat_intel)
        await self.bot.start()
        logger.info("Telegram bot started")

        # Start CT listener
        self.ct_listener = AsyncCertstreamListener(
            queue=self._discovery_queue,
            quick_filter=self.scorer.quick_filter,
        )
        await self.ct_listener.start()
        logger.info("CT stream listener started")

        # Set up temporal rescan callback and start rescan loop
        self.temporal.set_rescan_callback(self._handle_rescan)
        logger.info("Temporal tracker initialized")

        # Start worker tasks
        tasks = [
            asyncio.create_task(self._discovery_worker()),
            asyncio.create_task(self._analysis_worker()),
            asyncio.create_task(self.temporal.run_rescan_loop()),
        ]

        # Send startup notification
        await self.bot.send_message("*SeedBuster started*\nMonitoring CT logs for suspicious domains...")

        logger.info("Pipeline running")

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Pipeline tasks cancelled")

    async def stop(self):
        """Stop all pipeline components."""
        logger.info("Stopping SeedBuster pipeline...")
        self._running = False

        # Stop components in reverse order
        if self.ct_listener:
            await self.ct_listener.stop()

        await self.bot.send_message("*SeedBuster stopping*...")
        await self.bot.stop()
        await self.browser.stop()
        await self.database.close()

        logger.info("Pipeline stopped")

    async def _discovery_worker(self):
        """Process discovered domains from CT stream."""
        logger.info("Discovery worker started")

        while self._running:
            try:
                # Get domain from queue with timeout
                try:
                    domain = await asyncio.wait_for(
                        self._discovery_queue.get(),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
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

                if not score_result.should_analyze:
                    logger.debug(f"Below threshold: {domain} (score={score_result.score})")
                    continue

                # Add to database
                domain_id = await self.database.add_domain(
                    domain=domain,
                    source="certstream",
                    domain_score=score_result.score,
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
                    })

            except Exception as e:
                logger.error(f"Discovery worker error: {e}")
                await asyncio.sleep(1)

    async def _analysis_worker(self):
        """Analyze queued domains for phishing signals."""
        logger.info("Analysis worker started")

        # Semaphore for concurrent analysis limit
        sem = asyncio.Semaphore(self.config.max_concurrent_analyses)

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
                    domains = await self.database.get_recent_domains(limit=100)
                    domain_record = None
                    for d in domains:
                        if d["domain"] == domain:
                            domain_record = d
                            break

                    if domain_record:
                        async with sem:
                            await self._analyze_domain(domain_record, scan_reason=scan_reason)
                    else:
                        logger.warning(f"Rescan: domain not found in DB: {domain}")
                else:
                    # Regular task from discovery
                    async with sem:
                        await self._analyze_domain(task)

            except Exception as e:
                logger.error(f"Analysis worker error: {e}")
                await asyncio.sleep(1)

    async def _analyze_domain(self, task: dict, scan_reason: ScanReason = ScanReason.INITIAL):
        """Analyze a single domain."""
        import socket

        domain_id = task["id"]
        domain = task["domain"]
        is_rescan = scan_reason != ScanReason.INITIAL
        domain_score = task["domain_score"]
        domain_reasons = task.get("reasons", [])

        logger.info(f"Analyzing: {domain}")

        try:
            # Update status
            await self.database.update_domain_status(domain_id, DomainStatus.ANALYZING)

            # Quick DNS check first (extract hostname only, ignore path)
            hostname = domain.split("/")[0]
            dns_resolves = True
            try:
                socket.gethostbyname(hostname)
            except socket.gaierror:
                dns_resolves = False
                logger.info(f"Domain does not resolve: {hostname}")

            if not dns_resolves:
                # Domain doesn't exist - report based on domain score alone
                verdict = Verdict.MEDIUM if domain_score >= 50 else Verdict.LOW
                analysis_score = domain_score
                reasons = domain_reasons + ["Domain does not resolve (not registered or offline)"]

                # Save analysis
                await self.evidence_store.save_analysis(domain, {
                    "domain": domain,
                    "score": analysis_score,
                    "verdict": verdict.value,
                    "reasons": reasons,
                    "dns_resolves": False,
                })
            else:
                # Run browser, infrastructure, and external intel in PARALLEL
                browser_task = asyncio.create_task(self.browser.analyze(domain))
                infra_task = asyncio.create_task(self.infrastructure.analyze(domain))
                external_task = asyncio.create_task(self.external_intel.query_all(domain))

                browser_result = await browser_task
                infra_result = await infra_task
                external_result = await external_task

                logger.info(
                    f"Infrastructure analysis for {domain}: "
                    f"score={infra_result.risk_score}, "
                    f"reasons={len(infra_result.risk_reasons)}"
                )
                if external_result.score > 0:
                    logger.info(
                        f"External intel for {domain}: "
                        f"score={external_result.score}, "
                        f"reasons={len(external_result.reasons)}"
                    )

                if not browser_result.success:
                    logger.warning(f"Failed to analyze {domain}: {browser_result.error}")
                    verdict = Verdict.LOW
                    analysis_score = domain_score
                    reasons = domain_reasons + [browser_result.error or "Analysis failed"]
                else:
                    # Save all screenshots for comparison
                    has_early = (
                        hasattr(browser_result, 'screenshot_early') and
                        browser_result.screenshot_early
                    )
                    has_blocked = (
                        hasattr(browser_result, 'blocked_requests') and
                        browser_result.blocked_requests
                    )

                    if has_early:
                        # Save early screenshot (before JS-based evasion)
                        await self.evidence_store.save_screenshot(domain, browser_result.screenshot_early, suffix="_early")
                        if has_blocked:
                            logger.info(f"Saved early screenshot for {domain} (anti-bot blocked)")

                    if browser_result.screenshot:
                        # Save final screenshot
                        await self.evidence_store.save_screenshot(domain, browser_result.screenshot)

                    # Save exploration screenshots (especially ones with suspicious content)
                    # Note: Check exploration_steps directly, not 'explored' flag
                    # Steps are captured incrementally, but 'explored' is only set at the end
                    # If exploration fails partway through, we still want to save captured steps
                    if browser_result.exploration_steps:
                        for i, step in enumerate(browser_result.exploration_steps):
                            if step.screenshot and step.success:
                                # Check if browser detected this as a seed form
                                # (includes textarea with mnemonic text, not just 12+ inputs)
                                if getattr(step, "is_seed_form", False):
                                    suffix = f"_exploration_seedform_{i+1}"
                                    logger.info(f"Saving seed form screenshot: {step.button_text} (mnemonic form detected)")
                                else:
                                    # Fallback: count text inputs
                                    text_inputs = [
                                        inp for inp in step.input_fields
                                        if inp.get("type") in ("text", "password", "")
                                    ]
                                    if len(text_inputs) >= 12:
                                        suffix = f"_exploration_seedform_{i+1}"
                                        logger.info(f"Saving seed form screenshot: {step.button_text} ({len(text_inputs)} inputs)")
                                    elif len(text_inputs) >= 6:
                                        suffix = f"_exploration_suspicious_{i+1}"
                                    else:
                                        suffix = f"_exploration_{i+1}"
                                await self.evidence_store.save_screenshot(domain, step.screenshot, suffix=suffix)

                    if browser_result.html:
                        await self.evidence_store.save_html(domain, browser_result.html)

                    # Get temporal analysis (if we have previous snapshots)
                    temporal_analysis = self.temporal.analyze(domain)

                    # Detect phishing signals (including all intelligence layers)
                    detection = self.detector.detect(
                        browser_result,
                        domain_score,
                        infrastructure=infra_result,
                        temporal=temporal_analysis,
                    )

                    # Add external intelligence results
                    analysis_score = min(100, detection.score + external_result.score)
                    reasons = detection.reasons + external_result.reasons

                    # Save temporal snapshot for future comparisons
                    self.temporal.add_snapshot(
                        domain=domain,
                        html=browser_result.html,
                        title=browser_result.title or "",
                        screenshot=browser_result.screenshot,
                        score=analysis_score,
                        verdict=detection.verdict,
                        reasons=reasons,
                        external_domains=browser_result.external_requests,
                        blocked_requests=len(getattr(browser_result, 'blocked_requests', []) or []),
                        tls_age_days=infra_result.tls.age_days if infra_result.tls else -1,
                        hosting_provider=infra_result.hosting.hosting_provider if infra_result.hosting else "",
                        scan_reason=scan_reason,
                    )

                    # Cluster analysis - link related phishing sites
                    cluster_result = analyze_for_clustering(
                        manager=self.cluster_manager,
                        domain=domain,
                        detection_result={
                            "score": analysis_score,
                            "suspicious_endpoints": detection.suspicious_endpoints,
                            "kit_matches": detection.kit_matches,
                        },
                        infrastructure={
                            "nameservers": infra_result.domain_info.nameservers if infra_result.domain_info else [],
                            "asn": str(infra_result.hosting.asn) if infra_result.hosting else None,
                            "ip": infra_result.hosting.ip_address if infra_result.hosting else None,
                        } if infra_result else None,
                    )
                    if cluster_result.related_domains:
                        logger.info(f"Clustering: {domain} linked to {len(cluster_result.related_domains)} related sites")

                    # Convert verdict string to enum
                    verdict = Verdict(detection.verdict)

                    # Save analysis results
                    await self.evidence_store.save_analysis(domain, {
                        "domain": domain,
                        "score": analysis_score,
                        "verdict": verdict.value,
                        "reasons": reasons,
                        "visual_match": detection.visual_match_score,
                        "seed_form": detection.seed_form_detected,
                        "suspicious_endpoints": detection.suspicious_endpoints,
                        "infrastructure": {
                            "score": detection.infrastructure_score,
                            "reasons": detection.infrastructure_reasons,
                            "tls_age_days": infra_result.tls.age_days if infra_result.tls else None,
                            "domain_age_days": infra_result.domain_info.age_days if infra_result.domain_info else None,
                            "hosting_provider": infra_result.hosting.hosting_provider if infra_result.hosting else None,
                            "uses_privacy_dns": infra_result.domain_info.uses_privacy_dns if infra_result.domain_info else False,
                        },
                        "code_analysis": {
                            "score": detection.code_score,
                            "reasons": detection.code_reasons,
                            "kit_matches": detection.kit_matches,
                        },
                        "temporal": {
                            "score": detection.temporal_score,
                            "reasons": detection.temporal_reasons,
                            "cloaking_detected": detection.cloaking_detected,
                            "snapshots_count": temporal_analysis.snapshots_count,
                        },
                        "cluster": {
                            "cluster_id": cluster_result.cluster_id,
                            "cluster_name": cluster_result.cluster_name,
                            "is_new_cluster": cluster_result.is_new_cluster,
                            "related_domains": cluster_result.related_domains,
                            "confidence": cluster_result.confidence,
                        },
                        "external_intel": external_result.to_dict(),
                    })

            # Update database
            evidence_path = str(self.evidence_store.get_evidence_path(domain))
            await self.database.update_domain_analysis(
                domain_id=domain_id,
                analysis_score=analysis_score,
                verdict=verdict,
                verdict_reasons="\n".join(reasons),
                evidence_path=evidence_path,
            )

            # Send alert if suspicious
            if analysis_score >= self.config.analysis_score_threshold:
                screenshot_path = self.evidence_store.get_screenshot_path(domain)
                screenshot_paths = self.evidence_store.get_all_screenshot_paths(domain)

                # Determine if cloaking is suspected (anti-bot service blocked)
                blocked_requests = getattr(browser_result, 'blocked_requests', []) or []
                cloaking_suspected = len(blocked_requests) > 0

                # Create temporal info for alert
                # Note: After add_snapshot, snapshots_count is already incremented
                # So we check > 1 (not <= 1) for initial scan determination
                snapshots = self.temporal.get_snapshots(domain)
                snapshot_count = len(snapshots)

                temporal_info = TemporalInfo(
                    is_initial_scan=not is_rescan,
                    scan_number=snapshot_count,
                    total_scans=5,  # Initial + 4 rescans
                    rescans_scheduled=True,
                    cloaking_suspected=cloaking_suspected,
                    cloaking_confirmed=temporal_analysis.cloaking_detected,
                    cloaking_confidence=temporal_analysis.cloaking_confidence,
                    previous_score=None,  # Will be set on rescans
                )

                # Get previous score for rescans
                if is_rescan and len(snapshots) >= 2:
                    temporal_info.previous_score = snapshots[-2].score

                # Create cluster info for alert
                cluster_info = ClusterInfo(
                    cluster_id=cluster_result.cluster_id,
                    cluster_name=cluster_result.cluster_name,
                    is_new_cluster=cluster_result.is_new_cluster,
                    related_domains=cluster_result.related_domains,
                    confidence=cluster_result.confidence,
                )

                # Auto-learn BEFORE sending alert (so we can include status in alert)
                learning_info = None
                matched_backends = self.threat_intel_updater.extract_matched_backends(
                    detection.suspicious_endpoints
                )
                matched_api_keys = self.threat_intel_updater.extract_matched_api_keys(reasons)

                if self.threat_intel_updater.should_learn(
                    domain=domain,
                    analysis_score=analysis_score,
                    cluster_confidence=cluster_result.confidence,
                    cluster_name=cluster_result.cluster_name,
                    matched_backends=matched_backends,
                    matched_api_keys=matched_api_keys,
                ):
                    learning_result = self.threat_intel_updater.learn(
                        domain=domain,
                        analysis_score=analysis_score,
                        cluster_confidence=cluster_result.confidence,
                        cluster_name=cluster_result.cluster_name,
                        matched_backends=matched_backends,
                        matched_api_keys=matched_api_keys,
                    )
                    if learning_result.updated:
                        logger.info(f"Threat intel auto-updated: {learning_result.message}")
                        self.detector.reload_threat_intel()
                        learning_info = LearningInfo(
                            learned=True,
                            version=learning_result.version,
                            added_to_frontends=learning_result.added_to_frontends,
                            added_to_api_keys=learning_result.added_to_api_keys,
                        )

                await self.bot.send_alert(AlertData(
                    domain=domain,
                    domain_id=self.evidence_store.get_domain_id(domain),
                    verdict=verdict.value,
                    score=analysis_score,
                    reasons=reasons,
                    screenshot_path=str(screenshot_path) if screenshot_path else None,
                    screenshot_paths=[str(p) for p in screenshot_paths] if screenshot_paths else None,
                    evidence_path=evidence_path,
                    temporal=temporal_info,
                    cluster=cluster_info,
                    seed_form_found=detection.seed_form_detected,
                    learning=learning_info,
                ))

            logger.info(f"Completed: {domain} (verdict={verdict.value}, score={analysis_score})")

        except Exception as e:
            logger.error(f"Error analyzing {domain}: {e}")
            await self.database.update_domain_status(domain_id, DomainStatus.PENDING)


async def run_pipeline():
    """Run the SeedBuster pipeline."""
    config = load_config()

    # Validate config
    if not config.telegram_bot_token:
        logger.error("TELEGRAM_BOT_TOKEN not set")
        sys.exit(1)
    if not config.telegram_chat_id:
        logger.error("TELEGRAM_CHAT_ID not set")
        sys.exit(1)

    pipeline = SeedBusterPipeline(config)

    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(pipeline.stop()))

    try:
        await pipeline.start()
    except KeyboardInterrupt:
        await pipeline.stop()


def main():
    """Entry point."""
    asyncio.run(run_pipeline())


if __name__ == "__main__":
    main()
