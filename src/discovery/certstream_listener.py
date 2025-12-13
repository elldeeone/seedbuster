"""Certificate Transparency log listener using certstream."""

import asyncio
import logging
from typing import Callable, Optional

import certstream

# Fix SSL certificate verification on some systems
import os
import certifi
os.environ['SSL_CERT_FILE'] = certifi.where()
os.environ['REQUESTS_CA_BUNDLE'] = certifi.where()

logger = logging.getLogger(__name__)


class CertstreamListener:
    """Listens to Certificate Transparency logs for new domains."""

    def __init__(
        self,
        on_domain: Callable[[str], None],
        quick_filter: Optional[Callable[[str], bool]] = None,
    ):
        """
        Initialize the CT log listener.

        Args:
            on_domain: Callback for each interesting domain found
            quick_filter: Optional quick filter function (returns True if interesting)
        """
        self.on_domain = on_domain
        self.quick_filter = quick_filter or (lambda d: True)
        self._running = False
        self._seen_domains: set[str] = set()  # Dedup within session
        self._max_seen = 100000  # Max domains to track for dedup

    def _handle_message(self, message: dict, context):
        """Handle incoming certstream message."""
        if message["message_type"] != "certificate_update":
            return

        try:
            # Extract domains from certificate
            data = message["data"]
            leaf_cert = data.get("leaf_cert", {})
            all_domains = leaf_cert.get("all_domains", [])

            for domain in all_domains:
                # Clean up domain
                domain = domain.lower().strip()
                if domain.startswith("*."):
                    domain = domain[2:]

                # Skip if we've seen this domain recently
                if domain in self._seen_domains:
                    continue

                # Quick filter
                if not self.quick_filter(domain):
                    continue

                # Track and emit
                self._seen_domains.add(domain)
                if len(self._seen_domains) > self._max_seen:
                    # Clear half when full
                    self._seen_domains = set(list(self._seen_domains)[self._max_seen // 2 :])

                # Call the callback
                try:
                    self.on_domain(domain)
                except Exception as e:
                    logger.error(f"Error in domain callback for {domain}: {e}")

        except Exception as e:
            logger.error(f"Error processing certstream message: {e}")

    def start(self):
        """Start listening to certstream (blocking)."""
        self._running = True
        logger.info("Starting certstream listener...")

        while self._running:
            try:
                certstream.listen_for_events(
                    self._handle_message,
                    url="wss://certstream.calidog.io/",
                )
            except Exception as e:
                if self._running:
                    logger.error(f"Certstream connection error: {e}")
                    logger.info("Reconnecting in 5 seconds...")
                    import time

                    time.sleep(5)

    def stop(self):
        """Stop the listener."""
        self._running = False
        logger.info("Stopping certstream listener...")


class AsyncCertstreamListener:
    """Async wrapper for certstream listener that queues domains."""

    def __init__(
        self,
        queue: asyncio.Queue,
        quick_filter: Optional[Callable[[str], bool]] = None,
    ):
        self.queue = queue
        self.quick_filter = quick_filter or (lambda d: True)
        self._listener: Optional[CertstreamListener] = None
        self._thread = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _enqueue_domain(self, domain: str) -> None:
        """Enqueue domain on the event loop thread."""
        try:
            self.queue.put_nowait(domain)
        except asyncio.QueueFull:
            logger.warning(f"Queue full, dropping domain: {domain}")

    def _on_domain(self, domain: str):
        """Queue domain for async processing (thread-safe)."""
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._enqueue_domain, domain)
        else:
            # Best-effort fallback (e.g., unit tests) if loop isn't available.
            self._enqueue_domain(domain)

    async def start(self):
        """Start listener in background thread."""
        import threading

        self._loop = asyncio.get_running_loop()
        self._listener = CertstreamListener(
            on_domain=self._on_domain,
            quick_filter=self.quick_filter,
        )

        self._thread = threading.Thread(target=self._listener.start, daemon=True)
        self._thread.start()
        logger.info("Async certstream listener started")

    async def stop(self):
        """Stop the listener."""
        if self._listener:
            self._listener.stop()
        if self._thread:
            self._thread.join(timeout=5)
        self._loop = None
        logger.info("Async certstream listener stopped")
