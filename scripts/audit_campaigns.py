#!/usr/bin/env python3
"""Audit threat campaigns against domain verdicts."""

import argparse
import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse


def normalize_domain_key(domain: str) -> str:
    raw = (domain or "").strip().lower()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        host = (parsed.hostname or raw.split("/")[0]).strip(".").lower()
        return host
    except Exception:
        return raw.split("/")[0].strip().lower()


def extract_path(domain: str) -> str:
    raw = (domain or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    path = parsed.path or ""
    if path and path != "/":
        return path
    return ""


def load_campaigns(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("campaigns", [])


def load_domains(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT domain, verdict, status FROM domains").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def print_section(title: str) -> None:
    print()
    print(f"== {title} ==")


def main() -> None:
    default_db = Path("/var/lib/seedbuster/data/seedbuster.db")
    default_campaigns = Path("/var/lib/seedbuster/data/campaigns/campaigns.json")

    parser = argparse.ArgumentParser(
        description="Audit threat campaigns against domain verdicts and indicators.",
    )
    parser.add_argument("--db", type=Path, default=default_db)
    parser.add_argument("--campaigns", type=Path, default=default_campaigns)
    args = parser.parse_args()

    campaigns = load_campaigns(args.campaigns)
    domains = load_domains(args.db)

    host_to_domains: dict[str, dict[str, str]] = {}
    for row in domains:
        host = normalize_domain_key(row.get("domain", ""))
        if not host:
            continue
        host_to_domains[host] = {
            "domain": row.get("domain", ""),
            "verdict": (row.get("verdict") or "").lower(),
            "status": (row.get("status") or "").lower(),
        }

    host_index: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for camp in campaigns:
        for member in camp.get("members", []):
            host = normalize_domain_key(member.get("domain", ""))
            if host:
                host_index[host].append((camp, member))

    print_section("Low/Medium/High Domain Mapping")
    verdict_set = {"low", "medium", "high"}
    lmh_domains = [
        d for d in domains if (d.get("verdict") or "").lower() in verdict_set
    ]
    print(f"Total domains (low/medium/high): {len(lmh_domains)}")

    missing = 0
    multi = 0
    for row in sorted(lmh_domains, key=lambda r: r.get("domain", "")):
        host = normalize_domain_key(row.get("domain", ""))
        matches = host_index.get(host, [])
        if not matches:
            missing += 1
            print(f"- NO CAMPAIGN: {row.get('domain')} ({row.get('verdict')})")
        elif len(matches) > 1:
            multi += 1
            ids = sorted({m[0].get("campaign_id") for m in matches})
            joined = ", ".join(ids)
            print(
                f"- MULTIPLE CAMPAIGNS: {row.get('domain')} "
                f"({row.get('verdict')}) -> {joined}"
            )
    print(f"Missing campaigns: {missing}")
    print(f"Multiple campaigns: {multi}")

    print_section("Campaign Members With Paths")
    path_members: list[tuple[str, str, str]] = []
    for camp in campaigns:
        for member in camp.get("members", []):
            path = extract_path(member.get("domain", ""))
            if path:
                path_members.append(
                    (camp.get("campaign_id", ""), camp.get("name", ""), member.get("domain", ""))
                )
    if path_members:
        for cid, name, domain in path_members:
            print(f"- {cid} {name}: {domain}")
    else:
        print("None")

    print_section("Duplicate Hosts Across Campaigns")
    host_map: dict[str, set[str]] = defaultdict(set)
    for camp in campaigns:
        for member in camp.get("members", []):
            host = normalize_domain_key(member.get("domain", ""))
            if host:
                host_map[host].add(camp.get("campaign_id", ""))

    duplicates = [
        (host, sorted(ids)) for host, ids in host_map.items() if len(ids) > 1
    ]
    if duplicates:
        for host, ids in sorted(duplicates):
            print(f"- {host}: {', '.join(ids)}")
    else:
        print("None")

    print_section("Members With No Indicator Overlap in Multi-Member Campaigns")
    weak_members: list[tuple[str, str, str]] = []
    for camp in campaigns:
        members = camp.get("members", [])
        if len(members) <= 1:
            continue
        shared_backends = {b.lower() for b in camp.get("shared_backends", [])}
        shared_ns = {n.lower() for n in camp.get("shared_nameservers", [])}
        shared_kits = {k.lower() for k in camp.get("shared_kits", [])}
        shared_asns = {a for a in camp.get("shared_asns", [])}
        for member in members:
            mb = {b.lower() for b in member.get("backends", [])}
            mns = {n.lower() for n in member.get("nameservers", [])}
            mk = {k.lower() for k in member.get("kit_matches", [])}
            masn = member.get("asn")
            overlap = (
                (mb & shared_backends)
                or (mns & shared_ns)
                or (mk & shared_kits)
                or (masn and masn in shared_asns)
            )
            if not overlap:
                weak_members.append(
                    (camp.get("campaign_id", ""), camp.get("name", ""), member.get("domain", ""))
                )
    if weak_members:
        for cid, name, domain in weak_members:
            print(f"- {cid} {name}: {domain}")
    else:
        print("None")

    print_section("Campaign Members Tied to Benign/Allowlisted/False Positive Domains")
    flagged: list[tuple[str, str, str, dict[str, str]]] = []
    for camp in campaigns:
        for member in camp.get("members", []):
            host = normalize_domain_key(member.get("domain", ""))
            info = host_to_domains.get(host)
            if not info:
                continue
            if info["verdict"] in {"benign", "false_positive"}:
                flagged.append((camp.get("campaign_id", ""), camp.get("name", ""), member.get("domain", ""), info))
                continue
            if info["status"] in {"allowlisted", "false_positive"}:
                flagged.append((camp.get("campaign_id", ""), camp.get("name", ""), member.get("domain", ""), info))

    if flagged:
        for cid, name, domain, info in flagged:
            print(
                f"- {cid} {name}: {domain} -> {info['verdict']} / {info['status']} "
                f"(db: {info['domain']})"
            )
    else:
        print("None")


if __name__ == "__main__":
    main()
