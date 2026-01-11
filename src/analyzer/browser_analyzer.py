"""Playwright-based browser analysis for phishing detection."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import random
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Browser, Response, Error as PlaywrightError

from ..utils.exploration_targets import DEFAULT_EXPLORATION_TARGETS
from .browser_constants import ANTIBOT_DOMAINS, REDIRECT_STATUS_CODES, STEALTH_SCRIPT, USER_AGENTS
from .browser_forms import BrowserFormsMixin
from .browser_interaction import BrowserInteractionMixin
from .browser_models import BrowserResult
from .browser_redirects import BrowserRedirectMixin
from .browser_fingerprint import BrowserFingerprintMixin

logger = logging.getLogger(__name__)


class BrowserAnalyzer(
    BrowserRedirectMixin,
    BrowserFormsMixin,
    BrowserInteractionMixin,
    BrowserFingerprintMixin,
):
    """Analyzes websites using headless Playwright browser."""

    def __init__(
        self,
        timeout: int = 30,
        headless: bool = True,
        exploration_targets: list[dict] | None = None,
    ):
        self.timeout = timeout * 1000  # Convert to ms
        self.headless = headless
        self._playwright = None
        self._browser: Optional[Browser] = None
        self.exploration_targets = exploration_targets or list(DEFAULT_EXPLORATION_TARGETS)

    async def start(self):
        """Start the browser instance."""
        self._playwright = await async_playwright().start()
        disable_sandbox = os.getenv("SEEDBUSTER_DISABLE_CHROMIUM_SANDBOX") == "1"
        sandbox_args: list[str] = []
        if disable_sandbox:
            sandbox_args = ["--no-sandbox", "--disable-setuid-sandbox"]
            logger.warning("Chromium sandbox disabled via SEEDBUSTER_DISABLE_CHROMIUM_SANDBOX=1")
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            chromium_sandbox=not disable_sandbox,
            args=[
                "--disable-dev-shm-usage",
                "--disable-gpu",
                *sandbox_args,
            ],
        )
        logger.info("Browser started")

    async def stop(self):
        """Stop the browser instance."""
        try:
            if self._browser:
                await self._browser.close()
        except PlaywrightError as exc:
            logger.warning("Browser close failed: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Browser close error: %s", exc)
        finally:
            self._browser = None

        try:
            if self._playwright:
                await self._playwright.stop()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Playwright stop error: %s", exc)
        finally:
            self._playwright = None

        logger.info("Browser stopped")

    async def analyze(self, domain: str, explore: bool = True) -> BrowserResult:
        """Analyze a domain and collect evidence."""
        if not self._browser:
            await self.start()

        raw_target = domain.strip()
        parsed_target = urlparse(raw_target if "://" in raw_target else f"https://{raw_target}")
        target_host = parsed_target.hostname or raw_target.split("/")[0]

        result = BrowserResult(domain=domain, success=False)
        context = None
        page = None

        try:
            user_agent = random.choice(USER_AGENTS)
            context = await self._browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=user_agent,
                ignore_https_errors=True,
                locale="en-US",
                timezone_id="America/New_York",
                geolocation={"latitude": 40.7128, "longitude": -74.0060},
                permissions=["geolocation"],
                color_scheme="light",
                device_scale_factor=1,
                is_mobile=False,
                has_touch=False,
            )

            page = await context.new_page()

            await page.add_init_script(STEALTH_SCRIPT)

            page.on("console", lambda msg: result.console_logs.append(f"[{msg.type}] {msg.text}"))

            external_domains = set()
            form_posts = []
            blocked_requests = []
            blocked_internal_requests = []
            host_safety_cache: dict[str, bool] = {}

            async def is_global_destination(hostname: str) -> bool:
                host_key = (hostname or "").strip().lower()
                if not host_key:
                    return True

                cached = host_safety_cache.get(host_key)
                if cached is not None:
                    if cached is False or host_key != (target_host or "").lower():
                        return cached

                try:
                    ip_obj = ipaddress.ip_address(host_key)
                    safe = ip_obj.is_global
                except ValueError:
                    try:
                        addrinfos = await asyncio.to_thread(
                            socket.getaddrinfo,
                            host_key,
                            None,
                            socket.AF_UNSPEC,
                            socket.SOCK_STREAM,
                        )
                        resolved_ips = {sockaddr[0] for *_rest, sockaddr in addrinfos}
                        safe = bool(resolved_ips) and all(
                            ipaddress.ip_address(ip).is_global for ip in resolved_ips
                        )
                    except Exception:
                        safe = False

                if safe is False or host_key != (target_host or "").lower():
                    host_safety_cache[host_key] = safe
                return safe

            async def handle_route(route):
                url = route.request.url

                url_lower = url.lower()
                if any(antibot in url_lower for antibot in ANTIBOT_DOMAINS):
                    blocked_requests.append(url)
                    logger.debug("Blocked anti-bot request: %s", url)
                    await route.abort()
                    return

                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if hostname and parsed.scheme in ("http", "https", "ws", "wss"):
                        if not await is_global_destination(hostname):
                            blocked_internal_requests.append(url)
                            logger.debug("Blocked private/local request (SSRF guard): %s", url)
                            await route.abort()
                            return
                except Exception:
                    ...
                await route.continue_()

            await page.route("**/*", handle_route)

            async def handle_request(request):
                try:
                    url = request.url
                    if not url.startswith("data:"):
                        parsed = urlparse(url)
                        request_host = parsed.hostname
                        if request_host and request_host != target_host:
                            external_domains.add(request_host)
                    if request.method == "POST":
                        form_posts.append(
                            {
                                "url": url,
                                "method": request.method,
                                "post_data": request.post_data[:500] if request.post_data else None,
                            }
                        )
                except Exception:
                    pass

            page.on("request", handle_request)

            redirect_events: list[dict] = []

            async def handle_response(response: Response):
                try:
                    if response.status not in REDIRECT_STATUS_CODES:
                        return
                    headers = response.headers or {}
                    location = headers.get("location")
                    header_subset = {}
                    for key in ("server", "x-powered-by", "x-vercel-id"):
                        value = headers.get(key)
                        if value:
                            header_subset[key] = value
                    to_url = urljoin(response.url, location) if location else None
                    redirect_events.append(
                        {
                            "type": "http",
                            "status": response.status,
                            "method": response.request.method,
                            "from_url": response.url,
                            "to_url": to_url,
                            "location": location,
                            "headers": header_subset or None,
                        }
                    )
                except Exception:
                    return

            page.on("response", handle_response)

            url = raw_target if raw_target.startswith(("http://", "https://")) else f"https://{raw_target}"
            try:
                response = await page.goto(
                    url,
                    timeout=self.timeout,
                    wait_until="domcontentloaded",
                )
                result.initial_url = url
                result.status_code = response.status if response else None
                chain = await self._build_redirect_chain(response)
                if redirect_events:
                    chain.extend(redirect_events)
                result.redirect_chain = self._dedupe_redirect_chain(chain)
                result.redirect_hops = len(result.redirect_chain)
                result.redirect_detected = result.redirect_hops > 0

                try:
                    await page.wait_for_selector("body", state="visible", timeout=3000)
                    await asyncio.sleep(1.5)
                except Exception:
                    await asyncio.sleep(2.0)
                result.early_url = page.url
                result.screenshot_early = await page.screenshot(full_page=True)
                result.html_early = await page.content()
                result.title_early = await page.title()

                try:
                    await page.wait_for_load_state("networkidle", timeout=self.timeout)
                except PlaywrightError as idle_err:
                    if "Timeout" in str(idle_err):
                        logger.warning("networkidle timeout for %s, continuing with DOM content", domain)
                    else:
                        raise

            except PlaywrightError as exc:
                if "ERR_" in str(exc) or "Timeout" in str(exc):
                    url = (
                        raw_target.replace("https://", "http://", 1)
                        if raw_target.startswith("https://")
                        else (
                            raw_target
                            if raw_target.startswith("http://")
                            else f"http://{raw_target}"
                        )
                    )
                    try:
                        response = await page.goto(
                            url,
                            timeout=self.timeout,
                            wait_until="domcontentloaded",
                        )
                        result.initial_url = url
                        result.status_code = response.status if response else None
                        chain = await self._build_redirect_chain(response)
                        if redirect_events:
                            chain.extend(redirect_events)
                        result.redirect_chain = self._dedupe_redirect_chain(chain)
                        result.redirect_hops = len(result.redirect_chain)
                        result.redirect_detected = result.redirect_hops > 0

                        try:
                            await page.wait_for_selector("body", state="visible", timeout=3000)
                            await asyncio.sleep(1.5)
                        except Exception:
                            await asyncio.sleep(2.0)
                        result.early_url = page.url
                        result.screenshot_early = await page.screenshot(full_page=True)
                        result.html_early = await page.content()
                        result.title_early = await page.title()

                        try:
                            await page.wait_for_load_state("networkidle", timeout=self.timeout)
                        except PlaywrightError as idle_err:
                            if "Timeout" in str(idle_err):
                                logger.warning(
                                    "networkidle timeout for %s (HTTP), continuing with DOM content",
                                    domain,
                                )
                            else:
                                raise
                    except PlaywrightError as exc2:
                        if "goto" in str(exc2).lower() or "ERR_" in str(exc2):
                            result.error = f"Failed to load: {str(exc2)[:200]}"
                            return result
                        logger.warning("HTTP fallback issue for %s: %s", domain, exc2)
                else:
                    result.error = f"Failed to load: {str(exc)[:200]}"
                    return result

            await self._simulate_human_behavior(page)

            result.final_url = page.url
            self._augment_redirect_chain(result)
            result.title = await page.title()
            result.html = await page.content()
            result.screenshot = await page.screenshot(full_page=True)
            result.external_requests = list(external_domains)
            result.form_submissions = form_posts
            result.blocked_requests = blocked_requests
            result.blocked_internal_requests = blocked_internal_requests

            if result.title_early and result.title:
                if result.title_early != result.title:
                    result.evasion_detected = True
                    logger.info(
                        "Evasion detected: title changed from '%s' to '%s'",
                        result.title_early,
                        result.title,
                    )

            result.forms = await self._extract_forms(page)
            result.input_fields = await self._extract_inputs(page)

            if explore:
                try:
                    await self._explore_navigation(page, result)
                except Exception as exc:
                    logger.warning("Exploration failed (non-fatal): %s", exc)

            result.success = True
            if blocked_requests:
                logger.info(
                    "Successfully analyzed %s (blocked %s anti-bot requests)",
                    domain,
                    len(blocked_requests),
                )
            else:
                logger.info("Successfully analyzed %s", domain)

        except Exception as exc:
            result.error = f"Analysis error: {str(exc)[:200]}"
            logger.error("Error analyzing %s: %s", domain, exc)

        finally:
            if page:
                await page.close()
            if context:
                await context.close()

        return result
