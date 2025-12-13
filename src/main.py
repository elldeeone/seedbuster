"""Main entry point for SeedBuster phishing detection pipeline."""

import asyncio
import logging
import signal
import sys

from .config import load_config, Config
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
from .analyzer.clustering import ThreatClusterManager, analyze_for_clustering
from .analyzer.external_intel import ExternalIntelligence
from .storage import Database, EvidenceStore
from .storage.database import DomainStatus, Verdict
from .bot import SeedBusterBot
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
        self._tasks: list[asyncio.Task] = []
        self._stop_lock = asyncio.Lock()
        self._stop_task: asyncio.Task | None = None

        # Queues for pipeline stages
        # Discovery queue items can be a domain string or a dict with metadata:
        # { "domain": "...", "source": "...", "force": bool }
        self._discovery_queue: asyncio.Queue[object] = asyncio.Queue(maxsize=1000)
        self._analysis_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=100)

        # Components
        self.database = Database(config.data_dir / "seedbuster.db")
        self.evidence_store = EvidenceStore(config.evidence_dir)
        self.scorer = DomainScorer(
            target_patterns=config.target_patterns,
            allowlist=config.allowlist,
            denylist=config.denylist,
            suspicious_tlds=config.suspicious_tlds,
            min_score_to_analyze=config.domain_score_threshold,
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

        self.bot = SeedBusterBot(
            token=config.telegram_bot_token,
            chat_id=config.telegram_chat_id,
            database=self.database,
            evidence_store=self.evidence_store,
            submit_callback=self._manual_submit,
            report_manager=self.report_manager,
            report_require_approval=config.report_require_approval,
            report_min_score=config.report_min_score,
        )
        self.ct_listener: AsyncCertstreamListener = None
        self.search_discovery: SearchDiscovery | None = None

    def _manual_submit(self, domain: str):
        """Handle manual domain submission from Telegram."""
        try:
            # Force analysis even if the domain scorer would normally drop it.
            self._discovery_queue.put_nowait({
                "domain": domain,
                "source": "manual",
                "force": True,
            })
            logger.info(f"Manual submission queued: {domain} (forced)")
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
        self.bot.set_queue_size_callback(lambda: self._discovery_queue.qsize() + self._analysis_queue.qsize())
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
                )
                logger.info("Search discovery enabled")

        # Set up temporal rescan callback and start rescan loop
        self.temporal.set_rescan_callback(self._handle_rescan)
        logger.info("Temporal tracker initialized")

        # Start worker tasks
        self._tasks = [
            asyncio.create_task(self._discovery_worker()),
            asyncio.create_task(self._analysis_worker()),
            asyncio.create_task(self.temporal.run_rescan_loop()),
        ]
        if self.search_discovery:
            self._tasks.append(asyncio.create_task(self.search_discovery.run_loop()))

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
                if isinstance(item, dict):
                    domain = (item.get("domain") or "").strip()
                    source = (item.get("source") or source).strip() or source
                    force = bool(item.get("force", False))
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
                    domain_record = await self.database.get_domain(domain)

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
        import ipaddress
        import socket
        from urllib.parse import urlparse

        domain_id = task["id"]
        domain = task["domain"]
        is_rescan = scan_reason != ScanReason.INITIAL
        domain_score = task["domain_score"]
        domain_reasons = task.get("reasons", [])

        logger.info(f"Analyzing: {domain}")

        browser_result = None
        infra_result = None
        external_result = None
        detection = None
        cluster_result = None
        urlscan_result_url: str | None = None

        try:
            # Update status
            await self.database.update_domain_status(domain_id, DomainStatus.ANALYZING)

            # Quick DNS check first (extract hostname only, ignore path/scheme)
            raw_target = (domain or "").strip()
            parsed_target = urlparse(raw_target if "://" in raw_target else f"http://{raw_target}")
            hostname = (parsed_target.hostname or raw_target.split("/")[0]).strip()

            dns_resolves = True
            resolved_ips: set[str] = set()
            non_global_ips: set[str] = set()

            try:
                # IP literal
                ip_obj = ipaddress.ip_address(hostname)
                resolved_ips.add(str(ip_obj))
            except ValueError:
                try:
                    addrinfos = await asyncio.to_thread(
                        socket.getaddrinfo,
                        hostname,
                        None,
                        socket.AF_UNSPEC,
                        socket.SOCK_STREAM,
                    )
                    resolved_ips = {sockaddr[0] for *_rest, sockaddr in addrinfos}
                except socket.gaierror:
                    dns_resolves = False
            except socket.gaierror:
                dns_resolves = False
                logger.info(f"Domain does not resolve: {hostname}")

            if dns_resolves and resolved_ips:
                for ip in resolved_ips:
                    try:
                        if not ipaddress.ip_address(ip).is_global:
                            non_global_ips.add(ip)
                    except ValueError:
                        continue

            if not dns_resolves or not resolved_ips:
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
                self.temporal.add_snapshot(
                    domain=domain,
                    score=analysis_score,
                    verdict=verdict.value,
                    reasons=reasons,
                    scan_reason=scan_reason,
                )
            elif non_global_ips:
                # SSRF hardening: never browse or connect to private/local targets.
                verdict = Verdict.MEDIUM if domain_score >= 50 else Verdict.LOW
                analysis_score = domain_score
                reasons = domain_reasons + [
                    (
                        "Analysis blocked (SSRF guard): "
                        f"{hostname} resolves to private/local IP(s): {', '.join(sorted(non_global_ips))}"
                    )
                ]

                await self.evidence_store.save_analysis(domain, {
                    "domain": domain,
                    "score": analysis_score,
                    "verdict": verdict.value,
                    "reasons": reasons,
                    "dns_resolves": True,
                    "resolved_ips": sorted(resolved_ips),
                    "blocked_for_ssrf": True,
                })
                self.temporal.add_snapshot(
                    domain=domain,
                    score=analysis_score,
                    verdict=verdict.value,
                    reasons=reasons,
                    scan_reason=scan_reason,
                )
            else:
                # Run browser, infrastructure, and external intel in PARALLEL
                browser_result, infra_result, external_result = await asyncio.gather(
                    self.browser.analyze(domain),
                    self.infrastructure.analyze(domain),
                    self.external_intel.query_all(domain),
                    return_exceptions=True,
                )

                if isinstance(browser_result, Exception):
                    browser_result = None
                if isinstance(infra_result, Exception):
                    logger.warning(f"Infrastructure analysis failed for {domain}: {infra_result}")
                    infra_result = None
                if isinstance(external_result, Exception):
                    logger.warning(f"External intel query failed for {domain}: {external_result}")
                    external_result = None

                if infra_result:
                    logger.info(
                        f"Infrastructure analysis for {domain}: "
                        f"score={infra_result.risk_score}, "
                        f"reasons={len(infra_result.risk_reasons)}"
                    )
                if external_result and external_result.score > 0:
                    logger.info(
                        f"External intel for {domain}: "
                        f"score={external_result.score}, "
                        f"reasons={len(external_result.reasons)}"
                    )
                if external_result and external_result.urlscan and external_result.urlscan.result_url:
                    urlscan_result_url = external_result.urlscan.result_url

                if not browser_result or not browser_result.success:
                    error = getattr(browser_result, "error", None) or "Analysis failed"
                    logger.warning(f"Failed to analyze {domain}: {error}")
                    verdict = Verdict.LOW
                    analysis_score = min(
                        100,
                        domain_score + (external_result.score if external_result else 0),
                    )
                    reasons = domain_reasons + [error] + (external_result.reasons if external_result else [])

                    await self.evidence_store.save_analysis(domain, {
                        "domain": domain,
                        "score": analysis_score,
                        "verdict": verdict.value,
                        "reasons": reasons,
                        "dns_resolves": True,
                        "resolved_ips": sorted(resolved_ips),
                        "analysis_error": error,
                        "external_intel": external_result.to_dict() if external_result else None,
                    })
                    self.temporal.add_snapshot(
                        domain=domain,
                        html=getattr(browser_result, "html", None),
                        title=getattr(browser_result, "title", "") or "",
                        screenshot=getattr(browser_result, "screenshot", None),
                        score=analysis_score,
                        verdict=verdict.value,
                        reasons=reasons,
                        external_domains=getattr(browser_result, "external_requests", None) or [],
                        blocked_requests=len(getattr(browser_result, "blocked_requests", []) or []),
                        tls_age_days=infra_result.tls.age_days if infra_result and infra_result.tls else -1,
                        hosting_provider=(
                            infra_result.hosting.hosting_provider if infra_result and infra_result.hosting else ""
                        ),
                        scan_reason=scan_reason,
                    )
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

                    # Clear stale exploration screenshots from previous scans (directory is reused).
                    removed = self.evidence_store.clear_exploration_screenshots(domain)
                    if removed:
                        logger.info(f"Cleared {removed} old exploration screenshots for {domain}")

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
                    external_score = external_result.score if external_result else 0
                    external_reasons = external_result.reasons if external_result else []
                    analysis_score = min(100, detection.score + external_score)
                    reasons = detection.reasons + external_reasons

                    # Optional: submit a fresh urlscan.io scan when cloaking is suspected/confirmed.
                    # This provides a different scanner vantage point, which can help validate
                    # what content is being served when our own IP/browser fingerprint is burned.
                    urlscan_submission = None
                    blocked_requests = getattr(browser_result, "blocked_requests", []) or []
                    cloaking_suspected = len(blocked_requests) > 0
                    if (
                        self.config.urlscan_submit_enabled
                        and self.config.urlscan_api_key
                        and analysis_score >= self.config.analysis_score_threshold
                        and (cloaking_suspected or temporal_analysis.cloaking_detected)
                    ):
                        target_url = domain if "://" in domain else f"https://{domain}"
                        urlscan_submission = await self.external_intel.submit_urlscan_scan(
                            target_url,
                            visibility=self.config.urlscan_submit_visibility,
                            tags=["seedbuster", "cloaking"],
                        )
                        if urlscan_submission.submitted and urlscan_submission.result_url:
                            reasons.append(
                                f"EXTERNAL: urlscan.io active scan submitted: {urlscan_submission.result_url}"
                            )
                            urlscan_result_url = urlscan_submission.result_url

                    # If urlscan also saw a decoy, an older scan may have captured the wallet UI.
                    # Prefer the best historical scan that contains wallet/seed UI text.
                    if analysis_score >= self.config.analysis_score_threshold and (
                        cloaking_suspected or temporal_analysis.cloaking_detected
                    ):
                        best = await self.external_intel.query_urlscan_best(domain)
                        if best.found and best.result_url and best.result_url != urlscan_result_url:
                            reasons.append(
                                f"EXTERNAL: urlscan.io historical scan with wallet/seed UI: {best.result_url}"
                            )
                            urlscan_result_url = best.result_url

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
                        tls_age_days=infra_result.tls.age_days if infra_result and infra_result.tls else -1,
                        hosting_provider=(
                            infra_result.hosting.hosting_provider if infra_result and infra_result.hosting else ""
                        ),
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
                            "tls_age_days": infra_result.tls.age_days if infra_result and infra_result.tls else None,
                            "domain_age_days": (
                                infra_result.domain_info.age_days
                                if infra_result and infra_result.domain_info
                                else None
                            ),
                            "hosting_provider": (
                                infra_result.hosting.hosting_provider
                                if infra_result and infra_result.hosting
                                else None
                            ),
                            "uses_privacy_dns": (
                                infra_result.domain_info.uses_privacy_dns
                                if infra_result and infra_result.domain_info
                                else False
                            ),
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
                        "external_intel": external_result.to_dict() if external_result else None,
                        "urlscan_submission": (
                            {
                                "scan_id": urlscan_submission.scan_id,
                                "result_url": urlscan_submission.result_url,
                                "visibility": self.config.urlscan_submit_visibility,
                            }
                            if urlscan_submission and urlscan_submission.submitted
                            else None
                        ),
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

                temporal_analysis = self.temporal.analyze(domain)

                # Create temporal info for alert
                # Note: After add_snapshot, snapshots_count is already incremented
                # So we check > 1 (not <= 1) for initial scan determination
                snapshots = self.temporal.get_snapshots(domain)
                snapshot_count = len(snapshots)

                temporal_info = TemporalInfo(
                    is_initial_scan=not is_rescan,
                    scan_number=snapshot_count,
                    total_scans=5,  # Initial + 4 rescans
                    rescans_scheduled=not is_rescan,
                    cloaking_suspected=cloaking_suspected,
                    cloaking_confirmed=temporal_analysis.cloaking_detected,
                    cloaking_confidence=temporal_analysis.cloaking_confidence,
                    previous_score=None,  # Will be set on rescans
                )

                # Get previous score for rescans
                if is_rescan and len(snapshots) >= 2:
                    temporal_info.previous_score = snapshots[-2].score

                # Create cluster info for alert
                cluster_info = None
                if cluster_result:
                    cluster_info = ClusterInfo(
                        cluster_id=cluster_result.cluster_id,
                        cluster_name=cluster_result.cluster_name,
                        is_new_cluster=cluster_result.is_new_cluster,
                        related_domains=cluster_result.related_domains,
                        confidence=cluster_result.confidence,
                    )

                # Auto-learn BEFORE sending alert (so we can include status in alert)
                learning_info = None
                if detection and cluster_result:
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
                    urlscan_result_url=urlscan_result_url,
                    temporal=temporal_info,
                    cluster=cluster_info,
                    seed_form_found=detection.seed_form_detected if detection else False,
                    learning=learning_info,
                ))

            # Optional: auto-report when approval is disabled.
            if (
                not self.config.report_require_approval
                and scan_reason == ScanReason.INITIAL
                and analysis_score >= self.config.report_min_score
                and browser_result
                and getattr(browser_result, "success", False)
                and self.report_manager.get_available_platforms()
            ):
                results = await self.report_manager.report_domain(domain_id=domain_id, domain=domain)
                summary = self.report_manager.format_results_summary(results)
                await self.bot.send_message(f"Auto-report results for `{domain}`:\n\n{summary}")

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
