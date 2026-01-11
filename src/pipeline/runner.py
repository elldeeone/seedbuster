"""Main entry point for SeedBuster phishing detection pipeline."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

from ..config import load_config, validate_config
from .runner_analysis import SeedBusterPipelineAnalysisMixin
from .runner_core import SeedBusterPipelineCoreMixin
from .runner_discovery import SeedBusterPipelineDiscoveryMixin
from .runner_reporting import SeedBusterPipelineReportingMixin
from .runner_rescan import SeedBusterPipelineRescanMixin
from .runner_takedown import SeedBusterPipelineTakedownMixin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


class SeedBusterPipeline(
    SeedBusterPipelineCoreMixin,
    SeedBusterPipelineDiscoveryMixin,
    SeedBusterPipelineAnalysisMixin,
    SeedBusterPipelineReportingMixin,
    SeedBusterPipelineRescanMixin,
    SeedBusterPipelineTakedownMixin,
):
    """Main orchestrator for the phishing detection pipeline."""

    pass


async def run_pipeline():
    """Run the SeedBuster pipeline."""
    config = load_config()

    validation_errors = validate_config(config)
    if validation_errors:
        for err in validation_errors:
            logger.error(err)
        sys.exit(1)

    pipeline = SeedBusterPipeline(config)

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
