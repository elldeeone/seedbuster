#!/usr/bin/env python3
"""Deeper probe of scammer backend - mimicking actual frontend behavior."""

import asyncio
import json
import httpx

WHALE_BACKEND = "https://whale-app-poxe2.ondigitalocean.app"
WHALE_API_KEY = "e7a25d99-66d4-4a1b-a6e0-3f2e93f25f1b"


async def probe_whale_post_routes():
    """Try POST requests to likely form submission routes."""
    print("=" * 60)
    print("WHALE BACKEND - POST ROUTE DISCOVERY")
    print("=" * 60)

    headers = {
        "x-api-key": WHALE_API_KEY,
        "Content-Type": "application/json",
        "Origin": "https://kaspa-wallet.co",
        "Referer": "https://kaspa-wallet.co/",
    }

    async with httpx.AsyncClient(timeout=10) as client:
        # Try various POST routes with different payloads
        routes_to_try = [
            ("/api/form/", {}),
            ("/api/form/text", {}),
            ("/api/form/text", {"text": "test"}),
            ("/api/form/submit", {}),
            ("/api/submit", {}),
            ("/form", {}),
            ("/submit", {}),
            # Try with typical seed phrase form structure
            ("/api/form/", {"words": ["test"] * 12}),
            ("/api/form/text", {"phrase": "test phrase"}),
        ]

        for route, payload in routes_to_try:
            url = f"{WHALE_BACKEND}{route}"
            print(f"\n[POST] {route}")
            print(f"  Payload: {json.dumps(payload)[:50]}")

            try:
                resp = await client.post(url, headers=headers, json=payload)
                print(f"  Status: {resp.status_code}")
                print(f"  Response: {resp.text[:300] if resp.text else '(empty)'}")

                # Check response headers for clues
                if "x-powered-by" in resp.headers:
                    print(f"  X-Powered-By: {resp.headers['x-powered-by']}")

            except Exception as e:
                print(f"  ERROR: {e}")


async def probe_common_api_patterns():
    """Try common REST API patterns."""
    print("\n" + "=" * 60)
    print("COMMON API PATTERN DISCOVERY")
    print("=" * 60)

    headers = {
        "x-api-key": WHALE_API_KEY,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=10) as client:
        # Common REST patterns
        patterns = [
            ("GET", "/api/v1/"),
            ("GET", "/api/v1/forms"),
            ("GET", "/api/v1/submissions"),
            ("GET", "/v1/"),
            ("POST", "/api/v1/form"),
            ("POST", "/webhook"),
            ("POST", "/hook"),
            ("GET", "/admin"),
            ("GET", "/dashboard"),
            ("GET", "/.env"),  # Info disclosure check
            ("GET", "/config"),
            ("GET", "/api/config"),
        ]

        for method, route in patterns:
            url = f"{WHALE_BACKEND}{route}"
            print(f"\n[{method}] {route}")

            try:
                if method == "GET":
                    resp = await client.get(url, headers=headers)
                else:
                    resp = await client.post(url, headers=headers, json={})

                # Only show non-404 responses
                if resp.status_code != 404:
                    print(f"  Status: {resp.status_code} *** INTERESTING ***")
                    print(f"  Response: {resp.text[:300] if resp.text else '(empty)'}")
                else:
                    print(f"  Status: 404")

            except Exception as e:
                print(f"  ERROR: {e}")


async def check_cors_config():
    """Check CORS configuration for info disclosure."""
    print("\n" + "=" * 60)
    print("CORS CONFIGURATION CHECK")
    print("=" * 60)

    async with httpx.AsyncClient(timeout=10) as client:
        # OPTIONS request to check CORS
        try:
            resp = await client.options(
                f"{WHALE_BACKEND}/api/form/",
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                }
            )
            print(f"Status: {resp.status_code}")
            print(f"CORS Headers:")
            for h in ["access-control-allow-origin", "access-control-allow-methods",
                      "access-control-allow-headers", "access-control-allow-credentials"]:
                if h in resp.headers:
                    print(f"  {h}: {resp.headers[h]}")

        except Exception as e:
            print(f"ERROR: {e}")


async def enumerate_with_wordlist():
    """Quick wordlist-based endpoint enumeration."""
    print("\n" + "=" * 60)
    print("ENDPOINT ENUMERATION")
    print("=" * 60)

    # Common backend endpoints
    wordlist = [
        "api", "v1", "v2", "form", "forms", "submit", "data", "log", "logs",
        "user", "users", "admin", "login", "auth", "token", "webhook",
        "seed", "phrase", "wallet", "words", "mnemonic", "recovery",
        "telegram", "bot", "notify", "alert", "export", "dump", "backup",
        "db", "database", "mongo", "redis", "metrics", "stats", "analytics"
    ]

    headers = {"x-api-key": WHALE_API_KEY}
    found = []

    async with httpx.AsyncClient(timeout=5) as client:
        for word in wordlist:
            for prefix in ["", "api/", "api/v1/"]:
                route = f"/{prefix}{word}"
                url = f"{WHALE_BACKEND}{route}"

                try:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code != 404:
                        found.append((route, resp.status_code, resp.text[:100]))
                        print(f"  FOUND: {route} -> {resp.status_code}")
                except:
                    pass

                try:
                    resp = await client.post(url, headers=headers, json={})
                    if resp.status_code != 404:
                        found.append((f"POST {route}", resp.status_code, resp.text[:100]))
                        print(f"  FOUND: POST {route} -> {resp.status_code}")
                except:
                    pass

    print(f"\nTotal non-404 endpoints found: {len(found)}")
    for route, status, body in found:
        print(f"  {route}: {status} - {body[:50]}")


async def main():
    print("DEEP BACKEND PROBE - Threat Intelligence")
    print()

    await probe_whale_post_routes()
    await probe_common_api_patterns()
    await check_cors_config()
    await enumerate_with_wordlist()

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
