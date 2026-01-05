#!/usr/bin/env python3
"""Capture visual fingerprint packs for legitimate sites.

Usage:
    python scripts/capture_visual_fingerprints.py
"""

from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path

from PIL import Image
import yaml
from playwright.async_api import async_playwright

# Add src to path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer.visual_match import fingerprint_payload


DEFAULT_SITES = [
    {
        "group": "kaspa.org",
        "url": "https://kaspa.org/",
        "hints": ["kaspa.org"],
        "variants": [
            {"label": "base", "name": "kaspa.org", "viewport": (1280, 720), "full_page": True, "scroll": 0.0},
            {"label": "full", "viewport": (1280, 720), "full_page": True, "scroll": 0.0},
            {"label": "hero", "viewport": (1280, 720), "full_page": False, "scroll": 0.0},
            {"label": "mid", "viewport": (1280, 720), "full_page": False, "scroll": 0.4},
            {"label": "footer", "viewport": (1280, 720), "full_page": False, "scroll": 0.8},
            {"label": "mobile", "viewport": (390, 844), "full_page": False, "scroll": 0.0},
        ],
    },
    {
        "group": "wallet.kaspanet.io",
        "url": "https://wallet.kaspanet.io/",
        "hints": ["wallet.kaspanet.io", "kaspa-ng.org"],
        "variants": [
            {"label": "landing", "name": "kaspanet-wallet-landing", "viewport": (1280, 720), "full_page": True, "scroll": 0.0},
            {"label": "base", "name": "kaspanet-wallet", "viewport": (1280, 720), "full_page": True, "scroll": 0.0},
            {
                "label": "legacy",
                "name": "kaspanet-wallet-recovery",
                "viewport": (1280, 720),
                "full_page": True,
                "scroll": 0.0,
                "click_text": "Continue on Legacy Wallet",
            },
            {"label": "full", "viewport": (1280, 720), "full_page": True, "scroll": 0.0},
            {"label": "hero", "viewport": (1280, 720), "full_page": False, "scroll": 0.0},
            {"label": "mobile", "viewport": (390, 844), "full_page": False, "scroll": 0.0},
        ],
    },
    {
        "group": "kaspa-ng.org",
        "url": "https://kaspa-ng.org/",
        "hints": ["kaspa-ng.org", "kaspa ng"],
        "variants": [
            {"label": "full", "viewport": (1280, 720), "full_page": True, "scroll": 0.0},
            {"label": "hero", "viewport": (1280, 720), "full_page": False, "scroll": 0.0},
            {"label": "mid", "viewport": (1280, 720), "full_page": False, "scroll": 0.4},
            {"label": "mobile", "viewport": (390, 844), "full_page": False, "scroll": 0.0},
        ],
    },
]


async def _capture_variant(page, fingerprints_dir: Path, site: dict, variant: dict) -> None:
    viewport = variant["viewport"]
    await page.set_viewport_size({"width": viewport[0], "height": viewport[1]})
    await page.goto(site["url"], wait_until="networkidle", timeout=60000)
    await asyncio.sleep(2)

    scroll_ratio = float(variant.get("scroll", 0.0) or 0.0)
    if scroll_ratio:
        await page.evaluate(
            "ratio => window.scrollTo(0, Math.floor(document.body.scrollHeight * ratio))",
            scroll_ratio,
        )
        await asyncio.sleep(1)

    click_text = (variant.get("click_text") or "").strip()
    if click_text:
        try:
            await page.get_by_text(click_text, exact=False).first.click(timeout=5000)
            await page.wait_for_load_state("networkidle", timeout=30000)
            await asyncio.sleep(2)
        except Exception:
            pass

    html = ""
    try:
        html = await page.content()
    except Exception:
        html = ""

    text = ""
    try:
        text = await page.inner_text("body")
    except Exception:
        text = html

    screenshot = await page.screenshot(full_page=bool(variant.get("full_page", False)))
    image = Image.open(io.BytesIO(screenshot))

    name = variant.get("name") or f"{site['group']}__{variant['label']}"
    payload = fingerprint_payload(
        name=name,
        group=site["group"],
        variant=variant["label"],
        image=image,
        text=text,
        raw_html=html,
        url=site["url"],
        viewport=viewport,
        hints=site.get("hints"),
    )

    (fingerprints_dir / f"{name}.json").write_text(json.dumps(payload, indent=2, sort_keys=True))
    (fingerprints_dir / f"{name}.png").write_bytes(screenshot)
    print(f"Saved {name}")


def _load_sites(config_dir: Path) -> list[dict]:
    config_path = config_dir / "visual_fingerprints.yaml"
    if not config_path.exists():
        return list(DEFAULT_SITES)
    try:
        data = yaml.safe_load(config_path.read_text()) or {}
    except Exception:
        return list(DEFAULT_SITES)
    sites = data.get("sites")
    if not isinstance(sites, list):
        return list(DEFAULT_SITES)
    return sites


async def main() -> None:
    data_dir = Path(os.environ.get("DATA_DIR", "./data"))
    fingerprints_dir = data_dir / "fingerprints"
    fingerprints_dir.mkdir(parents=True, exist_ok=True)
    config_dir = Path(os.environ.get("CONFIG_DIR", "./config"))
    sites = _load_sites(config_dir)

    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=True)
    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()

    try:
        for site in sites:
            for variant in site["variants"]:
                await _capture_variant(page, fingerprints_dir, site, variant)
    finally:
        await browser.close()
        await playwright.stop()


if __name__ == "__main__":
    asyncio.run(main())
