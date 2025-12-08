#!/usr/bin/env python3
"""Probe scammer backend infrastructure for threat intelligence."""

import asyncio
import json
import httpx

# Known endpoints from kaspa-wallet.co analysis
WHALE_BACKEND = "https://whale-app-poxe2.ondigitalocean.app"
WALRUS_BACKEND = "https://walrus-app-o5hvw.ondigitalocean.app"
WHALE_API_KEY = "e7a25d99-66d4-4a1b-a6e0-3f2e93f25f1b"


async def probe_whale():
    """Probe the whale backend (form exfiltration server)."""
    print("=" * 60)
    print("PROBING WHALE BACKEND (Form Exfiltration)")
    print("=" * 60)

    async with httpx.AsyncClient(timeout=10) as client:
        # Test various endpoints
        endpoints = [
            "/",
            "/api",
            "/api/form",
            "/api/form/",
            "/api/form/text",
            "/api/forms",
            "/api/data",
            "/api/submissions",
            "/api/logs",
            "/health",
            "/status",
        ]

        headers_with_key = {"x-api-key": WHALE_API_KEY}
        headers_without_key = {}

        for endpoint in endpoints:
            url = f"{WHALE_BACKEND}{endpoint}"
            print(f"\n[GET] {endpoint}")

            # Try without API key
            try:
                resp = await client.get(url, headers=headers_without_key)
                print(f"  No key: {resp.status_code} - {resp.text[:200] if resp.text else '(empty)'}")
            except Exception as e:
                print(f"  No key: ERROR - {e}")

            # Try with API key
            try:
                resp = await client.get(url, headers=headers_with_key)
                print(f"  With key: {resp.status_code} - {resp.text[:200] if resp.text else '(empty)'}")
            except Exception as e:
                print(f"  With key: ERROR - {e}")

        # Try POST to form endpoint (empty body, just to see response)
        print(f"\n[POST] /api/form/ (empty body)")
        try:
            resp = await client.post(
                f"{WHALE_BACKEND}/api/form/",
                headers=headers_with_key,
                json={}
            )
            print(f"  {resp.status_code} - {resp.text[:500] if resp.text else '(empty)'}")
        except Exception as e:
            print(f"  ERROR - {e}")


async def probe_walrus():
    """Probe the walrus backend (IP logging server)."""
    print("\n" + "=" * 60)
    print("PROBING WALRUS BACKEND (IP Logging)")
    print("=" * 60)

    async with httpx.AsyncClient(timeout=10) as client:
        endpoints = [
            "/",
            "/log-ip",
            "/logs",
            "/api",
            "/api/logs",
            "/api/ips",
            "/health",
            "/status",
        ]

        for endpoint in endpoints:
            url = f"{WALRUS_BACKEND}{endpoint}"
            print(f"\n[GET] {endpoint}")

            try:
                resp = await client.get(url)
                print(f"  {resp.status_code} - {resp.text[:200] if resp.text else '(empty)'}")
            except Exception as e:
                print(f"  ERROR - {e}")

        # Try POST to log-ip
        print(f"\n[POST] /log-ip")
        try:
            resp = await client.post(f"{WALRUS_BACKEND}/log-ip", json={"test": True})
            print(f"  {resp.status_code} - {resp.text[:200] if resp.text else '(empty)'}")
        except Exception as e:
            print(f"  ERROR - {e}")


async def check_ipdata_key():
    """Check if the ipdata.co API key is still active."""
    print("\n" + "=" * 60)
    print("CHECKING IPDATA.CO API KEY")
    print("=" * 60)

    IPDATA_KEY = "520a83d66268292f5b97ca64c496ef3b9cfb1bb1f85f2615b103f66f"

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            # Check our own IP to see if key works
            resp = await client.get(f"https://api.ipdata.co/?api-key={IPDATA_KEY}")
            print(f"Status: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                print(f"Key is ACTIVE")
                print(f"  Remaining requests: {resp.headers.get('x-ratelimit-remaining', 'unknown')}")
                # Don't print our actual IP data
            else:
                print(f"Key may be revoked or rate limited: {resp.text[:200]}")
        except Exception as e:
            print(f"ERROR - {e}")


async def main():
    print("SCAMMER BACKEND PROBE - For Threat Intelligence Only")
    print("This probes publicly exposed endpoints with publicly leaked credentials")
    print()

    await probe_whale()
    await probe_walrus()
    await check_ipdata_key()

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
