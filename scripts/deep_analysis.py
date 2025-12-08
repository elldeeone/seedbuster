#!/usr/bin/env python3
"""Deep forensic analysis of a scam site - extract all intelligence."""

import asyncio
import json
import re
import socket
import ssl
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from playwright.async_api import async_playwright


async def main():
    """Deep analysis of scam site."""
    domain = "kaspa-wallet.co"

    print(f"Deep Forensic Analysis: {domain}")
    print("=" * 70)

    intel = {
        "domain": domain,
        "analysis_time": datetime.now().isoformat(),
        "dns": {},
        "ssl": {},
        "http": {},
        "content": {},
        "network": {},
        "scripts": {},
        "indicators": [],
    }

    # 1. DNS Analysis
    print("\n[1] DNS Analysis...")
    try:
        ip = socket.gethostbyname(domain)
        intel["dns"]["ip"] = ip
        intel["dns"]["resolves"] = True
        print(f"    IP: {ip}")

        # Reverse DNS
        try:
            reverse = socket.gethostbyaddr(ip)
            intel["dns"]["reverse"] = reverse[0]
            print(f"    Reverse DNS: {reverse[0]}")
        except:
            intel["dns"]["reverse"] = None

    except socket.gaierror:
        intel["dns"]["resolves"] = False
        print("    Does not resolve!")

    # 2. SSL Certificate Analysis
    print("\n[2] SSL Certificate Analysis...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                intel["ssl"]["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                intel["ssl"]["subject"] = dict(x[0] for x in cert.get("subject", []))
                intel["ssl"]["not_before"] = cert.get("notBefore")
                intel["ssl"]["not_after"] = cert.get("notAfter")
                intel["ssl"]["san"] = [x[1] for x in cert.get("subjectAltName", [])]

                print(f"    Issuer: {intel['ssl']['issuer'].get('organizationName', 'Unknown')}")
                print(f"    Valid from: {intel['ssl']['not_before']}")
                print(f"    Valid to: {intel['ssl']['not_after']}")
                print(f"    SANs: {intel['ssl']['san']}")

                # Check if recently issued (suspicious)
                if "Let's Encrypt" in str(intel["ssl"]["issuer"]):
                    intel["indicators"].append("Uses Let's Encrypt (common for scams)")

    except Exception as e:
        intel["ssl"]["error"] = str(e)
        print(f"    SSL Error: {e}")

    # 3. Browser-based analysis
    print("\n[3] Browser Analysis...")

    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=True)
    context = await browser.new_context(
        viewport={"width": 1920, "height": 1080},
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ignore_https_errors=True,
    )

    page = await context.new_page()

    # Track all network requests
    requests_log = []
    responses_log = []

    async def log_request(request):
        requests_log.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "headers": dict(request.headers) if request.headers else {},
        })

    async def log_response(response):
        responses_log.append({
            "url": response.url,
            "status": response.status,
            "headers": dict(response.headers) if response.headers else {},
        })

    page.on("request", log_request)
    page.on("response", log_response)

    try:
        response = await page.goto(f"https://{domain}", wait_until="networkidle", timeout=30000)
        await asyncio.sleep(3)

        # HTTP Response Analysis
        intel["http"]["status"] = response.status
        intel["http"]["headers"] = dict(response.headers) if response.headers else {}

        print(f"    Status: {response.status}")
        print(f"    Server: {intel['http']['headers'].get('server', 'Not disclosed')}")

        # Check security headers (lack of them is suspicious for a "wallet")
        security_headers = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security"]
        missing_security = [h for h in security_headers if h not in intel["http"]["headers"]]
        if missing_security:
            intel["indicators"].append(f"Missing security headers: {', '.join(missing_security)}")
            print(f"    Missing security headers: {missing_security}")

        # Content Analysis
        html = await page.content()
        intel["content"]["length"] = len(html)
        intel["content"]["title"] = await page.title()

        print(f"    Title: {intel['content']['title']}")
        print(f"    HTML size: {len(html)} bytes")

        # Extract all scripts
        scripts = await page.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script');
                return Array.from(scripts).map(s => ({
                    src: s.src || null,
                    inline_length: s.src ? 0 : s.textContent.length,
                    type: s.type || 'text/javascript',
                }));
            }
        """)
        intel["scripts"]["count"] = len(scripts)
        intel["scripts"]["external"] = [s["src"] for s in scripts if s["src"]]
        intel["scripts"]["inline_count"] = sum(1 for s in scripts if not s["src"])
        intel["scripts"]["total_inline_size"] = sum(s["inline_length"] for s in scripts)

        print(f"    Scripts: {len(scripts)} total ({len(intel['scripts']['external'])} external)")

        # Extract meta tags
        meta_tags = await page.evaluate("""
            () => {
                const metas = document.querySelectorAll('meta');
                return Array.from(metas).map(m => ({
                    name: m.name || m.getAttribute('property') || m.httpEquiv,
                    content: m.content,
                }));
            }
        """)
        intel["content"]["meta_tags"] = {m["name"]: m["content"] for m in meta_tags if m["name"]}

        # Check for copied/stolen content indicators
        if "kaspa" in html.lower() and "wallet" in html.lower():
            # Check if they're impersonating official site
            official_domains = ["kaspa.org", "kaspanet.io", "github.com/kaspanet"]
            for official in official_domains:
                if official in html:
                    intel["indicators"].append(f"References official domain: {official}")

        # Analyze external requests
        external_domains = set()
        for req in requests_log:
            parsed = urlparse(req["url"])
            if parsed.netloc and domain not in parsed.netloc:
                external_domains.add(parsed.netloc)

        intel["network"]["external_domains"] = list(external_domains)
        intel["network"]["total_requests"] = len(requests_log)

        print(f"\n    External domains contacted ({len(external_domains)}):")
        for ext_domain in sorted(external_domains):
            category = categorize_domain(ext_domain)
            print(f"      - {ext_domain} [{category}]")
            if category == "SUSPICIOUS":
                intel["indicators"].append(f"Suspicious external domain: {ext_domain}")

        # Look for data exfiltration patterns in JS
        print("\n[4] JavaScript Analysis...")

        # Get all inline script content
        inline_js = await page.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script:not([src])');
                return Array.from(scripts).map(s => s.textContent).join('\\n');
            }
        """)

        # Patterns that indicate malicious intent
        suspicious_patterns = {
            "fetch\\s*\\(": "Dynamic data fetching",
            "XMLHttpRequest": "XHR requests",
            "navigator\\.": "Browser fingerprinting",
            "localStorage": "Local storage access",
            "sessionStorage": "Session storage access",
            "document\\.cookie": "Cookie access",
            "eval\\s*\\(": "Dynamic code execution",
            "atob|btoa": "Base64 encoding (obfuscation)",
            "webhook": "Webhook endpoint",
            "telegram": "Telegram API",
            "discord": "Discord API",
            "\\.ondigitalocean\\.": "DigitalOcean backend",
            "fingerprint": "Fingerprinting",
            "canvas.*toDataURL": "Canvas fingerprinting",
            "webgl.*getParameter": "WebGL fingerprinting",
        }

        found_patterns = []
        for pattern, desc in suspicious_patterns.items():
            if re.search(pattern, inline_js, re.I):
                found_patterns.append(desc)

        intel["scripts"]["suspicious_patterns"] = found_patterns
        if found_patterns:
            print(f"    Suspicious JS patterns found:")
            for p in found_patterns:
                print(f"      - {p}")
                intel["indicators"].append(f"JS pattern: {p}")

        # Look for hardcoded endpoints
        endpoints = re.findall(r'https?://[^\s"\'<>]+', inline_js)
        external_endpoints = [e for e in endpoints if domain not in e]
        if external_endpoints:
            intel["scripts"]["external_endpoints"] = external_endpoints[:20]  # Limit
            print(f"\n    Hardcoded external endpoints:")
            for ep in external_endpoints[:10]:
                print(f"      - {ep[:80]}")

        # Extract form actions
        forms = await page.evaluate("""
            () => {
                const forms = document.querySelectorAll('form');
                return Array.from(forms).map(f => ({
                    action: f.action,
                    method: f.method,
                    id: f.id,
                }));
            }
        """)
        intel["content"]["forms"] = forms

        # Look for hidden iframes (common in phishing)
        iframes = await page.evaluate("""
            () => {
                const iframes = document.querySelectorAll('iframe');
                return Array.from(iframes).map(f => ({
                    src: f.src,
                    hidden: f.style.display === 'none' || f.hidden || f.width === '0' || f.height === '0',
                }));
            }
        """)
        if iframes:
            intel["content"]["iframes"] = iframes
            hidden_iframes = [i for i in iframes if i["hidden"]]
            if hidden_iframes:
                intel["indicators"].append(f"Hidden iframes detected: {len(hidden_iframes)}")
                print(f"\n    Hidden iframes: {len(hidden_iframes)}")

    finally:
        await browser.close()
        await playwright.stop()

    # Summary
    print("\n" + "=" * 70)
    print("INTELLIGENCE SUMMARY")
    print("=" * 70)

    print(f"\nDomain: {domain}")
    print(f"IP: {intel['dns'].get('ip', 'Unknown')}")
    print(f"SSL Issuer: {intel['ssl'].get('issuer', {}).get('organizationName', 'Unknown')}")

    print(f"\nIndicators of Compromise ({len(intel['indicators'])}):")
    for i, indicator in enumerate(intel["indicators"], 1):
        print(f"  {i}. {indicator}")

    # Save full intel
    output_path = Path("data/intel_report.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(intel, indent=2, default=str))
    print(f"\nFull report saved to: {output_path}")

    return intel


def categorize_domain(domain: str) -> str:
    """Categorize an external domain."""
    safe_patterns = [
        "google", "gstatic", "googleapis", "cloudflare", "cdnjs",
        "jsdelivr", "unpkg", "fontawesome", "fonts.gstatic",
    ]

    suspicious_patterns = [
        "digitalocean", "herokuapp", "vercel", "netlify", "railway",
        "webhook", "api.", "collect", "track", "log.",
    ]

    analytics_patterns = [
        "analytics", "gtag", "facebook", "twitter", "ipdata", "ipinfo",
    ]

    domain_lower = domain.lower()

    for pattern in safe_patterns:
        if pattern in domain_lower:
            return "CDN/SAFE"

    for pattern in analytics_patterns:
        if pattern in domain_lower:
            return "ANALYTICS/TRACKING"

    for pattern in suspicious_patterns:
        if pattern in domain_lower:
            return "SUSPICIOUS"

    return "UNKNOWN"


if __name__ == "__main__":
    asyncio.run(main())
