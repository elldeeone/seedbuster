"""
Refresh infrastructure/registrar intel for all domains without full browser rescans.

This script:
- Loads existing analysis.json (if present) for each domain
- Runs InfrastructureAnalyzer to enrich hosting provider, edge/CDN, ASN, registrar, nameservers
- Writes updated analysis.json (preserving existing fields)

Usage:
    python scripts/refresh_infra.py
    python scripts/refresh_infra.py --env-file /etc/seedbuster/seedbuster.env
"""

import asyncio
import argparse
import logging
import os
from pathlib import Path

from src.config import load_config
from src.analyzer.infrastructure import InfrastructureAnalyzer
from src.storage import Database, EvidenceStore


logger = logging.getLogger("refresh_infra")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def _load_env_file(path: str) -> None:
    """Load environment variables from a .env-style file."""
    try:
        from dotenv import dotenv_values
    except Exception as exc:
        raise RuntimeError("python-dotenv is required for --env-file") from exc

    values = dotenv_values(path)
    for key, value in values.items():
        if value is None:
            continue
        os.environ[key] = value


async def refresh_domain(
    analyzer: InfrastructureAnalyzer,
    evidence: EvidenceStore,
    domain: str,
) -> bool:
    """Refresh infra intel for a single domain."""
    try:
        infra_result = await analyzer.analyze(domain)
    except Exception as e:
        logger.warning("Infra analysis failed for %s: %s", domain, e)
        return False

    try:
        existing = evidence.load_analysis(domain) or {"domain": domain}
        origin_provider = (
            infra_result.hosting.hosting_provider if infra_result.hosting else existing.get("hosting_provider")
        )
        edge_provider = (
            infra_result.hosting.edge_provider if infra_result.hosting else existing.get("edge_provider")
        )
        existing["hosting_provider"] = origin_provider
        existing["edge_provider"] = edge_provider

        infra_block = existing.get("infrastructure") or {}
        infra_block.update(
            {
                "hosting_provider": origin_provider,
                "edge_provider": edge_provider,
                "tls_age_days": infra_result.tls.age_days if infra_result.tls else infra_block.get("tls_age_days"),
                "domain_age_days": infra_result.domain_info.age_days
                if infra_result.domain_info
                else infra_block.get("domain_age_days"),
                "uses_privacy_dns": infra_result.domain_info.uses_privacy_dns
                if infra_result.domain_info
                else infra_block.get("uses_privacy_dns", False),
                "nameservers": infra_result.domain_info.nameservers
                if infra_result.domain_info
                else infra_block.get("nameservers"),
                "registrar": infra_result.domain_info.registrar
                if infra_result.domain_info
                else infra_block.get("registrar"),
            }
        )
        ip_addresses = []
        if infra_result.hosting and infra_result.hosting.ip_address:
            ip_addresses.append(infra_result.hosting.ip_address)
        if infra_result.domain_info and infra_result.domain_info.a_records:
            ip_addresses.extend(infra_result.domain_info.a_records)
        infra_block["ip_addresses"] = sorted({ip for ip in ip_addresses if ip})
        if infra_block["ip_addresses"]:
            existing["resolved_ips"] = infra_block["ip_addresses"]
        existing["infrastructure"] = infra_block

        await evidence.save_analysis(domain, existing)
        return True
    except Exception as e:
        logger.warning("Failed to save analysis for %s: %s", domain, e)
        return False


async def main():
    parser = argparse.ArgumentParser(description="Refresh infrastructure/registrar intel.")
    parser.add_argument("--env-file", help="Load environment variables from a file before running.")
    args = parser.parse_args()

    if args.env_file:
        _load_env_file(args.env_file)

    config = load_config()
    db = Database(config.data_dir / "seedbuster.db")
    await db.connect()
    evidence = EvidenceStore(config.evidence_dir)
    analyzer = InfrastructureAnalyzer(timeout=10)

    # Fetch all domains
    async with db._lock:
        cursor = await db._connection.execute("SELECT domain FROM domains")
        rows = await cursor.fetchall()
    domains = [row["domain"] for row in rows if row["domain"]]
    logger.info("Refreshing infrastructure for %d domains", len(domains))

    successes = 0
    failures = 0
    for idx, domain in enumerate(domains, start=1):
        ok = await refresh_domain(analyzer, evidence, domain)
        if ok:
            successes += 1
        else:
            failures += 1
        if idx % 25 == 0:
            logger.info("Processed %d/%d (success=%d, failed=%d)", idx, len(domains), successes, failures)

    await analyzer.close()
    await db.close()
    logger.info("Done. success=%d failed=%d", successes, failures)


if __name__ == "__main__":
    asyncio.run(main())
