"""Main entry point for SeedBuster phishing detection pipeline."""

import asyncio
import logging
import signal
import sys
from pathlib import Path

from .config import load_config, Config
from .discovery import DomainScorer, AsyncCertstreamListener
from .analyzer import BrowserAnalyzer, PhishingDetector
from .storage import Database, EvidenceStore
from .storage.database import DomainStatus, Verdict
from .bot import SeedBusterBot, AlertFormatter
from .bot.formatters import AlertData

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
        self.detector = PhishingDetector(
            fingerprints_dir=config.data_dir / "fingerprints",
            keywords=config.keywords,
            analysis_threshold=config.analysis_score_threshold,
        )
        self.bot = SeedBusterBot(
            token=config.telegram_bot_token,
            chat_id=config.telegram_chat_id,
            database=self.database,
            evidence_store=self.evidence_store,
            submit_callback=self._manual_submit,
        )
        self.ct_listener: AsyncCertstreamListener = None

    def _manual_submit(self, domain: str):
        """Handle manual domain submission from Telegram."""
        try:
            self._discovery_queue.put_nowait(domain)
            logger.info(f"Manual submission queued: {domain}")
        except asyncio.QueueFull:
            logger.warning(f"Queue full, could not submit: {domain}")

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
        await self.bot.start()
        logger.info("Telegram bot started")

        # Start CT listener
        self.ct_listener = AsyncCertstreamListener(
            queue=self._discovery_queue,
            quick_filter=self.scorer.quick_filter,
        )
        await self.ct_listener.start()
        logger.info("CT stream listener started")

        # Start worker tasks
        tasks = [
            asyncio.create_task(self._discovery_worker()),
            asyncio.create_task(self._analysis_worker()),
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

                # Analyze with semaphore
                async with sem:
                    await self._analyze_domain(task)

            except Exception as e:
                logger.error(f"Analysis worker error: {e}")
                await asyncio.sleep(1)

    async def _analyze_domain(self, task: dict):
        """Analyze a single domain."""
        domain_id = task["id"]
        domain = task["domain"]
        domain_score = task["domain_score"]

        logger.info(f"Analyzing: {domain}")

        try:
            # Update status
            await self.database.update_domain_status(domain_id, DomainStatus.ANALYZING)

            # Browse the site
            browser_result = await self.browser.analyze(domain)

            if not browser_result.success:
                logger.warning(f"Failed to analyze {domain}: {browser_result.error}")
                # Still save what we have
                verdict = Verdict.LOW
                analysis_score = domain_score
                reasons = [browser_result.error or "Analysis failed"]
            else:
                # Save evidence
                if browser_result.screenshot:
                    await self.evidence_store.save_screenshot(domain, browser_result.screenshot)
                if browser_result.html:
                    await self.evidence_store.save_html(domain, browser_result.html)

                # Detect phishing signals
                detection = self.detector.detect(browser_result, domain_score)
                analysis_score = detection.score
                reasons = detection.reasons

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
                await self.bot.send_alert(AlertData(
                    domain=domain,
                    domain_id=self.evidence_store.get_domain_id(domain),
                    verdict=verdict.value,
                    score=analysis_score,
                    reasons=reasons,
                    screenshot_path=str(screenshot_path) if screenshot_path else None,
                    evidence_path=evidence_path,
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
