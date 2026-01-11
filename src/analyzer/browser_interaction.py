"""Browser analyzer interaction helpers."""

from __future__ import annotations

import asyncio
import logging
import random
import re
from typing import Optional
from urllib.parse import urljoin

from playwright.async_api import Page

from .browser_models import BrowserResult, ExplorationStep

logger = logging.getLogger(__name__)


class BrowserInteractionMixin:
    """Interaction and exploration helpers."""

    async def _simulate_human_behavior(self, page: Page) -> None:
        """Simulate human-like behavior to evade bot detection."""
        try:
            await asyncio.sleep(random.uniform(1.5, 3.0))

            viewport = page.viewport_size
            if not viewport:
                viewport = {"width": 1920, "height": 1080}

            for _ in range(random.randint(2, 4)):
                x = random.randint(100, viewport["width"] - 100)
                y = random.randint(100, viewport["height"] - 100)
                await page.mouse.move(x, y)
                await asyncio.sleep(random.uniform(0.1, 0.3))

            scroll_amount = random.randint(100, 300)
            await page.evaluate(f"window.scrollBy(0, {scroll_amount})")
            await asyncio.sleep(random.uniform(0.3, 0.6))

            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(random.uniform(0.3, 0.5))

        except Exception as exc:
            logger.debug("Human simulation error (non-fatal): %s", exc)

    async def _find_visible_buttons(self, page: Page) -> list[dict]:
        """Find all visible clickable elements on the page with their text."""
        try:
            buttons = await page.evaluate(
                """
                () => {
                    const clickables = document.querySelectorAll('button, a, [role="button"], [onclick]');
                    const results = [];
                    for (const el of clickables) {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        // Check if element is visible
                        if (rect.width > 10 && rect.height > 10 &&
                            style.display !== 'none' && style.visibility !== 'hidden' &&
                            style.opacity !== '0') {
                            const text = (el.textContent || el.innerText || '').trim();
                            if (text && text.length < 100) {
                                results.push({
                                    text: text.substring(0, 50),
                                    tag: el.tagName.toLowerCase(),
                                    id: el.id || null,
                                    class: el.className || null
                                });
                            }
                        }
                    }
                    return results;
                }
            """
            )
            return buttons
        except Exception as exc:
            logger.debug("Error finding visible buttons: %s", exc)
            return []

    async def _explore_navigation(self, page: Page, result: BrowserResult, max_clicks: int = 6) -> None:
        """Click through navigation elements to discover hidden phishing forms."""
        logger.info("Starting click-through exploration for %s", result.domain)

        visible_buttons = await self._find_visible_buttons(page)
        if visible_buttons:
            button_texts = [b["text"][:30] for b in visible_buttons[:8]]
            logger.info("Found %s buttons: %s", len(visible_buttons), button_texts)
        else:
            logger.info("No visible buttons found on page (will still try known targets)")

        explored_texts = set()
        clicks_made = 0

        high_priority_targets = [
            "12-word",
            "24-word",
            "12 word",
            "24 word",
            "12 words",
            "24 words",
            "mnemonic",
            "import mnemonic",
            "enter mnemonic",
            "seed phrase",
            "secret phrase",
            "recover",
            "restore",
            "import",
            "recovery",
        ]

        while clicks_made < max_clicks:
            found_target = False

            visible_buttons = await self._find_visible_buttons(page)
            button_texts = [b["text"] for b in visible_buttons[:10]]
            logger.debug("Visible buttons on page: %s", button_texts)

            for target_text in high_priority_targets:
                target_key = target_text.lower()
                if target_key in explored_texts:
                    continue

                element = await self._find_clickable_element(page, target_text)
                if element:
                    actual_text = await element.text_content()
                    actual_text = actual_text.strip()[:50] if actual_text else target_text

                    logger.info("Exploration: clicking HIGH PRIORITY '%s' on %s", actual_text, result.domain)

                    clicked = await self._click_element_resilient(page, element, label=actual_text)
                    explored_texts.add(target_key)
                    if not clicked:
                        logger.info(
                            "Exploration: failed to click HIGH PRIORITY '%s' on %s",
                            actual_text,
                            result.domain,
                        )
                        continue

                    clicks_made += 1

                    seed_found = await self._wait_and_capture_step(page, result, actual_text)
                    found_target = True
                    if seed_found:
                        logger.info("Stopping exploration - seed form found on %s", result.domain)
                        break
                    break

            if found_target and any(getattr(s, "is_seed_form", False) for s in result.exploration_steps):
                break
            if found_target:
                continue

            sorted_targets = sorted(self.exploration_targets, key=lambda x: x.get("priority", 1))
            for target in sorted_targets:
                target_text = str(target.get("text", "")).lower()
                if target_text in explored_texts:
                    continue

                element = await self._find_clickable_element(page, target_text)
                if element:
                    actual_text = await element.text_content()
                    actual_text = actual_text.strip()[:50] if actual_text else target_text

                    logger.info("Exploration: clicking '%s' on %s", actual_text, result.domain)

                    clicked = await self._click_element_resilient(page, element, label=actual_text)
                    explored_texts.add(target_text)
                    if not clicked:
                        logger.info("Exploration: failed to click '%s' on %s", actual_text, result.domain)
                        continue

                    clicks_made += 1

                    seed_found = await self._wait_and_capture_step(page, result, actual_text)
                    found_target = True
                    if seed_found:
                        logger.info("Stopping exploration - seed form found on %s", result.domain)
                    break

            if any(getattr(s, "is_seed_form", False) for s in result.exploration_steps):
                break
            if not found_target:
                break

        if clicks_made > 0:
            result.explored = True
            logger.info(
                "Exploration complete: %s clicks, %s steps captured",
                clicks_made,
                len(result.exploration_steps),
            )

    @staticmethod
    def _extract_navigation_target_from_onclick(onclick: str) -> Optional[str]:
        if not onclick:
            return None

        patterns = [
            r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, onclick, re.I)
            if match:
                target = match.group(1).strip()
                return target or None
        return None

    async def _get_element_navigation_target(self, page: Page, element) -> Optional[str]:
        try:
            href = await element.get_attribute("href")
            if href:
                return urljoin(page.url, href)
        except Exception:
            pass

        try:
            onclick = await element.get_attribute("onclick")
            target = self._extract_navigation_target_from_onclick(onclick or "")
            if target:
                return urljoin(page.url, target)
        except Exception:
            pass

        return None

    async def _click_element_resilient(self, page: Page, element, label: str) -> bool:
        """Click an element with fallbacks to avoid navigation timeouts/overlays."""
        last_error: Optional[Exception] = None

        try:
            await element.click(timeout=5000, no_wait_after=True)
            return True
        except Exception as exc:
            last_error = exc

        try:
            try:
                await element.scroll_into_view_if_needed()
            except Exception:
                pass
            await element.click(timeout=5000, force=True, no_wait_after=True)
            return True
        except Exception as exc:
            last_error = exc

        try:
            await page.evaluate("(el) => el.click()", element)
            return True
        except Exception as exc:
            last_error = exc

        try:
            target = await self._get_element_navigation_target(page, element)
            if target:
                await page.goto(target, wait_until="domcontentloaded", timeout=self.timeout)
                return True
        except Exception as exc:
            last_error = exc

        logger.debug("Exploration click failed for '%s': %s", label, str(last_error)[:200])
        return False

    async def _find_clickable_element(self, page: Page, target_text: str):
        """Find a clickable element containing the target text."""
        try:
            handle = await page.evaluate_handle(
                f"""
                () => {{
                    const targetText = '{target_text}'.toLowerCase();
                    // Check buttons first (most likely)
                    let firstMatch = null;
                    for (const el of document.querySelectorAll('button')) {{
                        const text = (el.textContent || '').toLowerCase();
                        if (text.includes(targetText)) {{
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 10 && rect.height > 10) return el;
                            if (!firstMatch) firstMatch = el;
                        }}
                    }}
                    // Then links
                    for (const el of document.querySelectorAll('a')) {{
                        const text = (el.textContent || '').toLowerCase();
                        if (text.includes(targetText)) {{
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 10 && rect.height > 10) return el;
                            if (!firstMatch) firstMatch = el;
                        }}
                    }}
                    // Then role=button
                    for (const el of document.querySelectorAll('[role="button"]')) {{
                        const text = (el.textContent || '').toLowerCase();
                        if (text.includes(targetText)) {{
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 10 && rect.height > 10) return el;
                            if (!firstMatch) firstMatch = el;
                        }}
                    }}
                    // Finally clickable divs (but NOT paragraphs/spans with lots of text)
                    for (const el of document.querySelectorAll('div[onclick], div.btn, div.button')) {{
                        const text = (el.textContent || '').toLowerCase();
                        if (text.includes(targetText) && text.length < 100) {{
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 10 && rect.height > 10) return el;
                            if (!firstMatch) firstMatch = el;
                        }}
                    }}
                    // Fallback: return first matching element even if hidden (UI cloaking often sets display:none).
                    return firstMatch;
                }}
            """
            )
            element = handle.as_element()
            if element is None:
                await handle.dispose()
                return None
            return element
        except Exception as exc:
            logger.debug("Fast element search failed for '%s': %s", target_text, exc)
        return None

    async def _wait_and_capture_step(self, page: Page, result: BrowserResult, button_text: str) -> bool:
        """Wait for page update and capture exploration step."""
        button_lower = button_text.lower()

        if any(kw in button_lower for kw in ["seed", "recover", "mnemonic", "import", "restore", "legacy"]):
            await asyncio.sleep(2.5)
            try:
                await page.wait_for_selector(
                    "input[type='text'], input[type='password'], textarea", timeout=3000
                )
            except Exception:
                pass
        else:
            await asyncio.sleep(1.5)

        try:
            await page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass

        step = ExplorationStep(button_text=button_text)
        try:
            step.screenshot = await page.screenshot()
            step.html = await page.content()
            step.title = await page.title()
            step.url = page.url
            step.input_fields = await self._extract_inputs(page)
            step.forms = await self._extract_forms(page)
            step.success = True

            page_text = await page.evaluate("() => document.body?.innerText || ''")

            if self._is_mnemonic_form(step.input_fields, page_text):
                step.is_seed_form = True
                logger.warning(
                    "SEED FORM FOUND after clicking '%s' - page contains mnemonic input form",
                    button_text,
                )

            seed_inputs = [
                inp
                for inp in step.input_fields
                if any(
                    kw in (inp.get("placeholder", "") + inp.get("name", "")).lower()
                    for kw in ["word", "seed", "phrase", "mnemonic"]
                )
            ]
            if seed_inputs and not getattr(step, "is_seed_form", False):
                logger.info(
                    "Exploration found %s seed-like inputs after clicking '%s'",
                    len(seed_inputs),
                    button_text,
                )

            if len(step.input_fields) > len(result.input_fields):
                logger.info(
                    "Exploration step '%s' has %s inputs (main page: %s)",
                    button_text,
                    len(step.input_fields),
                    len(result.input_fields),
                )

        except Exception as exc:
            step.error = str(exc)
            logger.debug("Error capturing exploration step: %s", exc)

        result.exploration_steps.append(step)

        return getattr(step, "is_seed_form", False)
