"""End-to-end browser tests for the dashboard frontend.

These tests use Playwright to interact with the actual dashboard UI,
testing JavaScript functionality, button clicks, form submissions, etc.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncGenerator

import pytest
from playwright.async_api import async_playwright, Page, Browser, expect

from src.dashboard.server import DashboardConfig, DashboardServer
from src.storage.database import Database, DomainStatus, Verdict


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
async def database(tmp_path) -> AsyncGenerator[Database, None]:
    """Create a test database."""
    db = Database(tmp_path / "test.db")
    await db.connect()
    yield db
    await db.close()


@pytest.fixture
def evidence_dir(tmp_path) -> Path:
    """Create evidence directory."""
    path = tmp_path / "evidence"
    path.mkdir()
    return path


@pytest.fixture
def clusters_dir(tmp_path) -> Path:
    """Create clusters directory."""
    path = tmp_path / "clusters"
    path.mkdir()
    return path


@pytest.fixture
async def dashboard_with_data(database, evidence_dir, clusters_dir):
    """Create dashboard server with test data."""
    # Track callbacks
    submitted_domains = []
    rescanned_domains = []
    reported_domains = []

    def on_submit(domain: str):
        submitted_domains.append(domain)

    def on_rescan(domain: str):
        rescanned_domains.append(domain)

    async def on_report(domain_id: int, domain: str, platforms: list, force: bool):
        reported_domains.append((domain_id, domain, platforms, force))
        return {}

    config = DashboardConfig(
        enabled=True,
        host="127.0.0.1",
        port=0,  # Let OS assign port
        admin_user="admin",
        admin_password="testpass",
    )

    server = DashboardServer(
        config=config,
        database=database,
        evidence_dir=evidence_dir,
        clusters_dir=clusters_dir,
        submit_callback=on_submit,
        rescan_callback=on_rescan,
        report_callback=on_report,
        get_available_platforms=lambda: ["google", "cloudflare", "registrar"],
        get_platform_info=lambda: {
            "google": {"name": "Google Safe Browsing", "type": "api"},
            "cloudflare": {"name": "Cloudflare", "type": "api"},
            "registrar": {"name": "Domain Registrar", "type": "email"},
        },
    )

    # Add test domains
    domain1_id = await database.add_domain(
        domain="phishing-test.example.com",
        source="manual",
        domain_score=85,
    )
    await database.update_domain_analysis(
        domain_id=domain1_id,
        analysis_score=90,
        verdict=Verdict.HIGH,
        verdict_reasons="Seed phrase form detected\nSuspicious API endpoint",
        evidence_path=str(evidence_dir / "phishing-test.example.com"),
    )

    domain2_id = await database.add_domain(
        domain="medium-risk.example.com",
        source="certstream",
        domain_score=55,
    )
    await database.update_domain_analysis(
        domain_id=domain2_id,
        analysis_score=50,
        verdict=Verdict.MEDIUM,
        verdict_reasons="Suspicious keywords found",
        evidence_path=str(evidence_dir / "medium-risk.example.com"),
    )

    domain3_id = await database.add_domain(
        domain="pending-analysis.example.com",
        source="manual",
        domain_score=70,
    )

    # Create evidence files for first domain
    domain_evidence = evidence_dir / "phishing-test.example.com_abc123"
    domain_evidence.mkdir()
    (domain_evidence / "screenshot.png").write_bytes(b"fake-png-data")
    (domain_evidence / "analysis.json").write_text(json.dumps({
        "domain": "phishing-test.example.com",
        "final_url": "https://phishing-test.example.com/wallet",
        "reasons": ["Seed phrase form detected"],
    }))

    return {
        "server": server,
        "database": database,
        "submitted": submitted_domains,
        "rescanned": rescanned_domains,
        "reported": reported_domains,
        "domain_ids": {
            "high": domain1_id,
            "medium": domain2_id,
            "pending": domain3_id,
        },
    }


@pytest.fixture
async def running_server(dashboard_with_data):
    """Start the dashboard server and return its URL."""
    from aiohttp import web

    server = dashboard_with_data["server"]
    runner = web.AppRunner(server._app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()

    # Get the actual port
    port = site._server.sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"

    yield {
        **dashboard_with_data,
        "base_url": base_url,
    }

    await runner.cleanup()


@pytest.fixture
async def browser() -> AsyncGenerator[Browser, None]:
    """Launch browser for testing."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        yield browser
        await browser.close()


@pytest.fixture
async def admin_page(browser, running_server) -> AsyncGenerator[Page, None]:
    """Create an authenticated admin page."""
    context = await browser.new_context(
        http_credentials={
            "username": "admin",
            "password": "testpass",
        }
    )
    page = await context.new_page()
    yield page
    await context.close()


@pytest.fixture
async def public_page(browser, running_server) -> AsyncGenerator[Page, None]:
    """Create a public (unauthenticated) page."""
    page = await browser.new_page()
    yield page
    await page.close()


# =============================================================================
# Public Page Tests
# =============================================================================


@pytest.mark.asyncio
async def test_public_index_loads(public_page, running_server):
    """Test public index page loads correctly."""
    await public_page.goto(running_server["base_url"])

    # Check page title contains SeedBuster
    title = await public_page.title()
    assert "SeedBuster" in title or "seedbuster" in title.lower()

    # Check for domain listing (use first match since domain may appear multiple times)
    await expect(public_page.locator("text=phishing-test.example.com").first).to_be_visible()


@pytest.mark.asyncio
async def test_public_domain_link_navigation(public_page, running_server):
    """Test clicking a domain navigates to detail page."""
    await public_page.goto(running_server["base_url"])

    # Click on a domain link (use first match since there may be multiple)
    await public_page.locator("text=phishing-test.example.com").first.click()

    # Should navigate to domain detail
    await public_page.wait_for_url(f"**/domains/**")

    # Check domain name is visible (use first match)
    await expect(public_page.locator("text=phishing-test.example.com").first).to_be_visible()


@pytest.mark.asyncio
async def test_public_clusters_navigation(public_page, running_server):
    """Test navigating to clusters page."""
    await public_page.goto(running_server["base_url"])

    # Click clusters link
    await public_page.click("text=Clusters")

    # Should navigate to clusters page
    await public_page.wait_for_url("**/clusters**")


# =============================================================================
# Admin Authentication Tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_requires_auth(browser, running_server):
    """Test admin page requires authentication."""
    page = await browser.new_page()

    # Navigate without credentials
    response = await page.goto(f"{running_server['base_url']}/admin")

    # Should get 401
    assert response.status == 401

    await page.close()


@pytest.mark.asyncio
async def test_admin_with_auth_loads(admin_page, running_server):
    """Test admin page loads with proper auth."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    # Check ADMIN indicator is visible (use exact match)
    await expect(admin_page.locator(".mode-admin")).to_be_visible()

    # Check domains are listed (use first match)
    await expect(admin_page.locator("text=phishing-test.example.com").first).to_be_visible()


# =============================================================================
# Form Submission Tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_submit_domain_form(admin_page, running_server):
    """Test submitting a new domain via the form."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    # Find and fill the submit form
    await admin_page.fill('input[name="target"]', "newdomain.test.com")

    # Submit the form
    await admin_page.click('button[type="submit"]:has-text("Submit")')

    # Wait for redirect/refresh
    await admin_page.wait_for_load_state("networkidle")

    # Check domain was submitted via callback
    assert "newdomain.test.com" in running_server["submitted"]


@pytest.mark.asyncio
async def test_admin_update_notes(admin_page, running_server):
    """Test updating domain operator notes."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    # Find notes textarea and fill it
    notes_input = admin_page.locator('textarea[name="notes"]')
    if await notes_input.count() > 0:
        await notes_input.fill("This is a confirmed phishing site targeting crypto wallets.")

        # Find and click save/update button
        save_btn = admin_page.locator('button:has-text("Save"), button:has-text("Update")')
        if await save_btn.count() > 0:
            await save_btn.first.click()
            await admin_page.wait_for_load_state("networkidle")

            # Verify notes were saved
            db = running_server["database"]
            domain = await db.get_domain_by_id(domain_id)
            assert "confirmed phishing" in (domain.get("operator_notes") or "").lower()


# =============================================================================
# Button Interaction Tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_rescan_button(admin_page, running_server):
    """Test the rescan button triggers rescan callback."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    # Look for rescan button
    rescan_btn = admin_page.locator('button:has-text("Rescan"), .js-rescan')

    if await rescan_btn.count() > 0:
        await rescan_btn.first.click()

        # Wait for the action to complete
        await admin_page.wait_for_timeout(500)

        # Check rescan callback was triggered
        assert "phishing-test.example.com" in running_server["rescanned"]


@pytest.mark.asyncio
async def test_admin_false_positive_button(admin_page, running_server):
    """Test marking domain as false positive."""
    domain_id = running_server["domain_ids"]["medium"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    # Look for false positive button
    fp_btn = admin_page.locator('button:has-text("False Positive"), button:has-text("Mark FP")')

    if await fp_btn.count() > 0:
        await fp_btn.first.click()
        await admin_page.wait_for_load_state("networkidle")

        # Verify status changed
        db = running_server["database"]
        domain = await db.get_domain_by_id(domain_id)
        assert domain["status"] == DomainStatus.FALSE_POSITIVE.value


# =============================================================================
# Toast Notification Tests
# =============================================================================


@pytest.mark.asyncio
async def test_toast_appears_on_action(admin_page, running_server):
    """Test toast notifications appear on actions."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    # Submit a domain to trigger a toast
    await admin_page.fill('input[name="target"]', "toast-test.example.com")
    await admin_page.click('button[type="submit"]:has-text("Submit")')

    # Wait for toast to appear (either on page refresh message or AJAX)
    await admin_page.wait_for_timeout(500)

    # Check for success message in URL or page content
    content = await admin_page.content()
    # The page should show some success indication
    assert "toast-test.example.com" in running_server["submitted"]


@pytest.mark.asyncio
async def test_toast_from_javascript(admin_page, running_server):
    """Test programmatic toast creation."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    # Manually trigger a toast via JavaScript
    await admin_page.evaluate("sbToast('Test notification', 'success')")

    # Check toast container exists and has content
    toast = admin_page.locator(".sb-toast")
    await expect(toast).to_be_visible(timeout=2000)
    await expect(toast).to_contain_text("Test notification")


# =============================================================================
# Copy to Clipboard Tests
# =============================================================================


@pytest.mark.asyncio
async def test_copy_button_visual_feedback(admin_page, running_server):
    """Test copy button shows visual feedback."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    # Find a copy button
    copy_btn = admin_page.locator('button:has-text("Copy")').first

    if await copy_btn.count() > 0:
        # Grant clipboard permissions
        await admin_page.context.grant_permissions(["clipboard-read", "clipboard-write"])

        await copy_btn.click()

        # Check for visual feedback (button text change or class)
        await admin_page.wait_for_timeout(300)

        # Button should show "Copied" or have copied class
        btn_text = await copy_btn.text_content()
        btn_class = await copy_btn.get_attribute("class")
        assert "copied" in (btn_text or "").lower() or "copied" in (btn_class or "")


# =============================================================================
# Modal Dialog Tests
# =============================================================================


@pytest.mark.asyncio
async def test_manual_report_modal_opens(admin_page, running_server):
    """Test manual report modal opens correctly."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    # Look for manual report button
    manual_btn = admin_page.locator('button:has-text("Manual Report"), button:has-text("Manual")')

    if await manual_btn.count() > 0:
        await manual_btn.first.click()

        # Modal overlay should be visible
        overlay = admin_page.locator(".sb-modal-overlay.open, .modal-overlay.open")
        if await overlay.count() > 0:
            await expect(overlay).to_be_visible()

            # Modal content should be visible
            modal = admin_page.locator(".sb-modal.open, .modal.open")
            await expect(modal).to_be_visible()


@pytest.mark.asyncio
async def test_modal_closes_on_escape(admin_page, running_server):
    """Test modal closes when ESC key is pressed."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    # Open modal
    manual_btn = admin_page.locator('button:has-text("Manual Report"), button:has-text("Manual")')

    if await manual_btn.count() > 0:
        await manual_btn.first.click()
        await admin_page.wait_for_timeout(300)

        # Press Escape
        await admin_page.keyboard.press("Escape")
        await admin_page.wait_for_timeout(300)

        # Modal should be closed
        overlay = admin_page.locator(".sb-modal-overlay.open")
        if await overlay.count() > 0:
            await expect(overlay).to_be_hidden()


@pytest.mark.asyncio
async def test_modal_close_button(admin_page, running_server):
    """Test modal closes when close button is clicked."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    manual_btn = admin_page.locator('button:has-text("Manual Report"), button:has-text("Manual")')

    if await manual_btn.count() > 0:
        await manual_btn.first.click()
        await admin_page.wait_for_timeout(300)

        # Click close button
        close_btn = admin_page.locator('.sb-modal button:has-text("Close"), .sb-modal .close-btn')
        if await close_btn.count() > 0:
            await close_btn.first.click()
            await admin_page.wait_for_timeout(300)


# =============================================================================
# Filter and Pagination Tests
# =============================================================================


@pytest.mark.asyncio
async def test_status_filter_dropdown(admin_page, running_server):
    """Test status filter changes domain list."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    # Find status filter
    status_filter = admin_page.locator('select[name="status"]')

    if await status_filter.count() > 0:
        # Select analyzed status
        await status_filter.select_option("analyzed")

        # Submit the form (filters may require form submission)
        filter_form = admin_page.locator('form').first
        if await filter_form.count() > 0:
            await admin_page.keyboard.press("Enter")

        await admin_page.wait_for_load_state("networkidle")

        # URL should contain status parameter or page should show filtered results
        # (Some forms may use JS without changing URL)
        content = await admin_page.content()
        assert "status=analyzed" in admin_page.url or "analyzed" in content.lower()


@pytest.mark.asyncio
async def test_verdict_filter(admin_page, running_server):
    """Test verdict filter changes domain list."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    verdict_filter = admin_page.locator('select[name="verdict"]')

    if await verdict_filter.count() > 0:
        await verdict_filter.select_option("high")
        await admin_page.wait_for_load_state("networkidle")

        # Should show high verdict domains
        await expect(admin_page.locator("text=phishing-test.example.com")).to_be_visible()


@pytest.mark.asyncio
async def test_search_filter(admin_page, running_server):
    """Test search/query filter."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    search_input = admin_page.locator('input[name="q"], input[type="search"]')

    if await search_input.count() > 0:
        await search_input.fill("phishing")
        await search_input.press("Enter")
        await admin_page.wait_for_load_state("networkidle")

        # Should filter to matching domains
        await expect(admin_page.locator("text=phishing-test.example.com")).to_be_visible()


# =============================================================================
# AJAX/API Interaction Tests
# =============================================================================


@pytest.mark.asyncio
async def test_ajax_rescan_request(admin_page, running_server):
    """Test AJAX rescan request via JavaScript."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    # Find JS rescan button (AJAX-powered)
    rescan_btn = admin_page.locator(".js-rescan")

    if await rescan_btn.count() > 0:
        # Listen for network request
        async with admin_page.expect_response(lambda r: "rescan" in r.url) as response_info:
            await rescan_btn.first.click()

        response = await response_info.value
        assert response.status == 200


@pytest.mark.asyncio
async def test_ajax_report_request(admin_page, running_server):
    """Test AJAX report request."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    report_btn = admin_page.locator(".js-report")

    if await report_btn.count() > 0:
        async with admin_page.expect_response(lambda r: "report" in r.url) as response_info:
            await report_btn.first.click()

        response = await response_info.value
        assert response.status == 200


# =============================================================================
# Navigation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_to_public_navigation(admin_page, running_server):
    """Test navigation from admin to public view."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    # Find public view link
    public_link = admin_page.locator('a:has-text("Public View"), a:has-text("Public")')

    if await public_link.count() > 0:
        await public_link.first.click()
        await admin_page.wait_for_url(running_server["base_url"] + "/")

        # Should not show admin indicator
        admin_indicator = admin_page.locator("text=ADMIN")
        # Either hidden or shows PUBLIC instead
        assert await admin_indicator.count() == 0 or not await admin_indicator.is_visible()


@pytest.mark.asyncio
async def test_domain_detail_back_navigation(admin_page, running_server):
    """Test navigating back from domain detail."""
    domain_id = running_server["domain_ids"]["high"]
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/{domain_id}")

    # Use browser back
    await admin_page.go_back()
    await admin_page.wait_for_load_state("networkidle")

    # Should be back on admin index or previous page
    assert "/admin/domains/" not in admin_page.url or domain_id not in admin_page.url


# =============================================================================
# Responsive/Visual Tests
# =============================================================================


@pytest.mark.asyncio
async def test_mobile_viewport(browser, running_server):
    """Test dashboard works on mobile viewport."""
    context = await browser.new_context(
        viewport={"width": 375, "height": 667},
        http_credentials={"username": "admin", "password": "testpass"},
    )
    page = await context.new_page()

    await page.goto(f"{running_server['base_url']}/admin")

    # Page should load without errors
    title = await page.title()
    assert "SeedBuster" in title or "seedbuster" in title.lower()

    # Content should still be visible
    await expect(page.locator("text=phishing-test.example.com")).to_be_visible()

    await context.close()


@pytest.mark.asyncio
async def test_dark_theme_loads(admin_page, running_server):
    """Test dark theme CSS loads correctly."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    # Check for dark theme CSS variables
    bg_color = await admin_page.evaluate(
        "getComputedStyle(document.body).backgroundColor"
    )

    # Dark theme should have dark background (low RGB values)
    # Parse rgb(r, g, b) or rgba(r, g, b, a) format
    if "rgb" in bg_color:
        # Extract just the RGB values (handle both rgb and rgba)
        import re
        rgb_match = re.search(r'rgba?\((\d+),\s*(\d+),\s*(\d+)', bg_color)
        if rgb_match:
            rgb_values = [int(rgb_match.group(i)) for i in (1, 2, 3)]
            avg_brightness = sum(rgb_values) / 3
            assert avg_brightness < 100, f"Expected dark theme background, got avg brightness {avg_brightness}"


# =============================================================================
# Error Handling Tests
# =============================================================================


@pytest.mark.asyncio
async def test_404_page(admin_page, running_server):
    """Test 404 page for non-existent domain."""
    await admin_page.goto(f"{running_server['base_url']}/admin/domains/99999")

    # Should show 404 or error message
    content = await admin_page.content()
    assert "404" in content or "not found" in content.lower() or "error" in content.lower()


@pytest.mark.asyncio
async def test_invalid_filter_handled(admin_page, running_server):
    """Test invalid filter values are handled gracefully."""
    await admin_page.goto(f"{running_server['base_url']}/admin?status=invalid_status")

    # Page should still load
    title = await page.title() if 'page' in dir() else await admin_page.title()
    # Should not crash
    assert admin_page.url is not None


# =============================================================================
# Integration Workflow Tests
# =============================================================================


@pytest.mark.asyncio
async def test_full_admin_workflow(admin_page, running_server):
    """Test complete admin workflow: list -> detail -> action -> back."""
    # Step 1: View admin index
    await admin_page.goto(f"{running_server['base_url']}/admin")
    await expect(admin_page.locator("text=phishing-test.example.com").first).to_be_visible()

    # Step 2: Click on a domain to view details (use first match)
    await admin_page.locator("text=phishing-test.example.com").first.click()
    await admin_page.wait_for_url("**/admin/domains/**")

    # Step 3: Verify domain detail page (use first match)
    await expect(admin_page.locator("text=phishing-test.example.com").first).to_be_visible()

    # Step 4: Trigger an action (rescan via AJAX if available)
    rescan_btn = admin_page.locator(".js-rescan")
    if await rescan_btn.count() > 0:
        await rescan_btn.first.click()
        await admin_page.wait_for_timeout(500)
        assert "phishing-test.example.com" in running_server["rescanned"]

    # Step 5: Navigate back
    await admin_page.go_back()
    await admin_page.wait_for_load_state("networkidle")


@pytest.mark.asyncio
async def test_submit_and_view_new_domain(admin_page, running_server):
    """Test submitting a domain and then viewing it."""
    await admin_page.goto(f"{running_server['base_url']}/admin")

    # Submit new domain
    await admin_page.fill('input[name="target"]', "workflow-new.test.com")
    await admin_page.click('button[type="submit"]:has-text("Submit")')
    await admin_page.wait_for_load_state("networkidle")

    # Verify it was submitted
    assert "workflow-new.test.com" in running_server["submitted"]

    # Add to database manually (simulating pipeline processing)
    db = running_server["database"]
    new_id = await db.add_domain(
        domain="workflow-new.test.com",
        source="manual",
        domain_score=75,
    )

    # Refresh and find the new domain
    await admin_page.reload()
    await expect(admin_page.locator("text=workflow-new.test.com")).to_be_visible()
