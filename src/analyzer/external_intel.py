"""
Layer 6: External Intelligence

Queries external threat intelligence services:
- urlscan.io: Check existing scans and verdicts
- VirusTotal: Domain/URL reputation from 70+ vendors
- abuse.ch URLhaus: Known malware/phishing URLs

All services have free tiers sufficient for moderate volume.
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import quote

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class URLScanResult:
    """Result from urlscan.io."""
    found: bool = False
    scan_id: Optional[str] = None
    verdict: Optional[str] = None  # malicious, suspicious, benign
    score: int = 0
    categories: List[str] = field(default_factory=list)
    brands_targeted: List[str] = field(default_factory=list)
    scan_date: Optional[datetime] = None
    screenshot_url: Optional[str] = None


@dataclass
class VirusTotalResult:
    """Result from VirusTotal."""
    found: bool = False
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    categories: List[str] = field(default_factory=list)
    reputation: int = 0  # -100 to 100
    last_analysis_date: Optional[datetime] = None


@dataclass
class URLhausResult:
    """Result from abuse.ch URLhaus."""
    found: bool = False
    threat_type: Optional[str] = None  # malware_download, phishing, etc.
    tags: List[str] = field(default_factory=list)
    url_status: Optional[str] = None  # online, offline
    date_added: Optional[datetime] = None


@dataclass
class ExternalIntelResult:
    """Combined result from all external intelligence sources."""
    urlscan: Optional[URLScanResult] = None
    virustotal: Optional[VirusTotalResult] = None
    urlhaus: Optional[URLhausResult] = None

    # Aggregated scores
    score: int = 0
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "reasons": self.reasons,
            "urlscan": {
                "found": self.urlscan.found if self.urlscan else False,
                "verdict": self.urlscan.verdict if self.urlscan else None,
                "score": self.urlscan.score if self.urlscan else 0,
            } if self.urlscan else None,
            "virustotal": {
                "found": self.virustotal.found if self.virustotal else False,
                "malicious": self.virustotal.malicious_count if self.virustotal else 0,
                "suspicious": self.virustotal.suspicious_count if self.virustotal else 0,
            } if self.virustotal else None,
            "urlhaus": {
                "found": self.urlhaus.found if self.urlhaus else False,
                "threat_type": self.urlhaus.threat_type if self.urlhaus else None,
            } if self.urlhaus else None,
        }


class ExternalIntelligence:
    """
    Queries external threat intelligence services.

    Rate limits (free tier):
    - urlscan.io: 50 scans/day, 5000 searches/month
    - VirusTotal: 4 req/min, 500 req/day
    - abuse.ch: No strict limits, be respectful

    All queries are search-only (no new scans submitted).
    """

    def __init__(
        self,
        urlscan_api_key: Optional[str] = None,
        virustotal_api_key: Optional[str] = None,
        cache_dir: Optional[Path] = None,
        cache_ttl_hours: int = 24,
    ):
        self.urlscan_api_key = urlscan_api_key
        self.virustotal_api_key = virustotal_api_key
        self.cache_dir = cache_dir
        self.cache_ttl = timedelta(hours=cache_ttl_hours)

        # Rate limiting
        self._last_vt_request = 0.0
        self._vt_min_interval = 15.0  # 4 req/min = 15s between requests

        # In-memory cache for session
        self._cache: Dict[str, tuple] = {}  # key -> (result, timestamp)

        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, service: str, domain: str) -> str:
        """Generate cache key."""
        return f"{service}:{domain}"

    def _get_cached(self, service: str, domain: str) -> Optional[Any]:
        """Get cached result if still valid."""
        key = self._get_cache_key(service, domain)

        # Check memory cache
        if key in self._cache:
            result, timestamp = self._cache[key]
            if datetime.now() - timestamp < self.cache_ttl:
                return result

        # Check disk cache
        if self.cache_dir:
            cache_file = self.cache_dir / f"{hashlib.md5(key.encode()).hexdigest()}.json"
            if cache_file.exists():
                try:
                    with open(cache_file, "r") as f:
                        data = json.load(f)
                    cached_at = datetime.fromisoformat(data["cached_at"])
                    if datetime.now() - cached_at < self.cache_ttl:
                        return data["result"]
                except Exception:
                    pass

        return None

    def _set_cached(self, service: str, domain: str, result: Any):
        """Cache result."""
        key = self._get_cache_key(service, domain)

        # Memory cache
        self._cache[key] = (result, datetime.now())

        # Disk cache
        if self.cache_dir:
            cache_file = self.cache_dir / f"{hashlib.md5(key.encode()).hexdigest()}.json"
            try:
                with open(cache_file, "w") as f:
                    json.dump({
                        "cached_at": datetime.now().isoformat(),
                        "service": service,
                        "domain": domain,
                        "result": result,
                    }, f)
            except Exception:
                pass

    async def query_urlscan(self, domain: str) -> URLScanResult:
        """
        Search urlscan.io for existing scans of domain.

        Free tier: 5000 searches/month (no API key needed for search).
        """
        result = URLScanResult()

        # Check cache
        cached = self._get_cached("urlscan", domain)
        if cached:
            return URLScanResult(**cached)

        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=1"
            headers = {}
            if self.urlscan_api_key:
                headers["API-Key"] = self.urlscan_api_key

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = data.get("results", [])

                        if results:
                            result.found = True
                            scan = results[0]

                            result.scan_id = scan.get("_id")
                            result.screenshot_url = scan.get("screenshot")

                            # Get verdict from verdicts object
                            verdicts = scan.get("verdicts", {})
                            overall = verdicts.get("overall", {})
                            result.score = overall.get("score", 0)

                            if overall.get("malicious"):
                                result.verdict = "malicious"
                            elif result.score > 0:
                                result.verdict = "suspicious"
                            else:
                                result.verdict = "benign"

                            result.categories = overall.get("categories", [])
                            result.brands_targeted = overall.get("brands", [])

                            # Parse scan date
                            task = scan.get("task", {})
                            if task.get("time"):
                                try:
                                    result.scan_date = datetime.fromisoformat(
                                        task["time"].replace("Z", "+00:00")
                                    )
                                except ValueError:
                                    pass

                            logger.debug(f"urlscan.io: {domain} = {result.verdict} (score: {result.score})")

            # Cache result
            self._set_cached("urlscan", domain, {
                "found": result.found,
                "scan_id": result.scan_id,
                "verdict": result.verdict,
                "score": result.score,
                "categories": result.categories,
                "brands_targeted": result.brands_targeted,
                "scan_date": result.scan_date.isoformat() if result.scan_date else None,
                "screenshot_url": result.screenshot_url,
            })

        except asyncio.TimeoutError:
            logger.debug(f"urlscan.io timeout for {domain}")
        except Exception as e:
            logger.debug(f"urlscan.io error for {domain}: {e}")

        return result

    async def query_virustotal(self, domain: str) -> VirusTotalResult:
        """
        Query VirusTotal for domain reputation.

        Free tier: 4 req/min, 500 req/day.
        Requires API key.
        """
        result = VirusTotalResult()

        if not self.virustotal_api_key:
            return result

        # Check cache
        cached = self._get_cached("virustotal", domain)
        if cached:
            return VirusTotalResult(**cached)

        # Rate limiting
        now = time.time()
        elapsed = now - self._last_vt_request
        if elapsed < self._vt_min_interval:
            await asyncio.sleep(self._vt_min_interval - elapsed)
        self._last_vt_request = time.time()

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{quote(domain)}"
            headers = {"x-apikey": self.virustotal_api_key}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get("data", {}).get("attributes", {})

                        result.found = True

                        # Get last analysis stats
                        stats = attrs.get("last_analysis_stats", {})
                        result.malicious_count = stats.get("malicious", 0)
                        result.suspicious_count = stats.get("suspicious", 0)
                        result.total_engines = sum(stats.values())

                        # Categories from vendors
                        categories = attrs.get("categories", {})
                        result.categories = list(set(categories.values()))

                        # Reputation score
                        result.reputation = attrs.get("reputation", 0)

                        # Last analysis date
                        last_analysis = attrs.get("last_analysis_date")
                        if last_analysis:
                            result.last_analysis_date = datetime.fromtimestamp(last_analysis)

                        logger.debug(
                            f"VirusTotal: {domain} = {result.malicious_count}/{result.total_engines} malicious"
                        )

                    elif resp.status == 404:
                        # Domain not found (never submitted)
                        result.found = False
                    elif resp.status == 429:
                        logger.warning("VirusTotal rate limit exceeded")

            # Cache result
            self._set_cached("virustotal", domain, {
                "found": result.found,
                "malicious_count": result.malicious_count,
                "suspicious_count": result.suspicious_count,
                "total_engines": result.total_engines,
                "categories": result.categories,
                "reputation": result.reputation,
                "last_analysis_date": result.last_analysis_date.isoformat() if result.last_analysis_date else None,
            })

        except asyncio.TimeoutError:
            logger.debug(f"VirusTotal timeout for {domain}")
        except Exception as e:
            logger.debug(f"VirusTotal error for {domain}: {e}")

        return result

    async def query_urlhaus(self, domain: str) -> URLhausResult:
        """
        Query abuse.ch URLhaus for known malware/phishing URLs.

        Free, no API key required, no strict rate limits.
        """
        result = URLhausResult()

        # Check cache
        cached = self._get_cached("urlhaus", domain)
        if cached:
            return URLhausResult(**cached)

        try:
            url = "https://urlhaus-api.abuse.ch/v1/host/"
            data = {"host": domain}

            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data, timeout=10) as resp:
                    if resp.status == 200:
                        response = await resp.json()

                        if response.get("query_status") == "ok":
                            result.found = True

                            # Get URL count and threat info
                            urls = response.get("urls", [])
                            if urls:
                                # Get most recent URL entry
                                latest = urls[0]
                                result.threat_type = latest.get("threat")
                                result.tags = latest.get("tags", [])
                                result.url_status = latest.get("url_status")

                                date_added = latest.get("date_added")
                                if date_added:
                                    try:
                                        result.date_added = datetime.strptime(
                                            date_added, "%Y-%m-%d %H:%M:%S"
                                        )
                                    except ValueError:
                                        pass

                            logger.debug(
                                f"URLhaus: {domain} = {result.threat_type} ({len(urls)} URLs)"
                            )

            # Cache result
            self._set_cached("urlhaus", domain, {
                "found": result.found,
                "threat_type": result.threat_type,
                "tags": result.tags,
                "url_status": result.url_status,
                "date_added": result.date_added.isoformat() if result.date_added else None,
            })

        except asyncio.TimeoutError:
            logger.debug(f"URLhaus timeout for {domain}")
        except Exception as e:
            logger.debug(f"URLhaus error for {domain}: {e}")

        return result

    async def query_all(self, domain: str) -> ExternalIntelResult:
        """
        Query all external intelligence sources in parallel.

        Returns aggregated result with score and reasons.
        """
        result = ExternalIntelResult()

        # Query all sources in parallel
        urlscan_task = self.query_urlscan(domain)
        urlhaus_task = self.query_urlhaus(domain)

        # VirusTotal has stricter rate limits, only query if we have API key
        if self.virustotal_api_key:
            vt_task = self.query_virustotal(domain)
            results = await asyncio.gather(urlscan_task, vt_task, urlhaus_task)
            result.urlscan, result.virustotal, result.urlhaus = results
        else:
            results = await asyncio.gather(urlscan_task, urlhaus_task)
            result.urlscan, result.urlhaus = results

        # Calculate aggregated score and reasons
        result.score, result.reasons = self._calculate_score(result)

        return result

    def _calculate_score(self, result: ExternalIntelResult) -> tuple:
        """Calculate aggregated score and reasons from external intel."""
        score = 0
        reasons = []

        # URLhaus (highest priority - known malware/phishing)
        if result.urlhaus and result.urlhaus.found:
            score += 40
            threat = result.urlhaus.threat_type or "unknown"
            reasons.append(f"EXTERNAL: URLhaus known threat ({threat})")
            if result.urlhaus.tags:
                reasons.append(f"EXTERNAL: URLhaus tags: {', '.join(result.urlhaus.tags[:3])}")

        # VirusTotal
        if result.virustotal and result.virustotal.found:
            vt = result.virustotal
            if vt.malicious_count >= 5:
                score += 35
                reasons.append(
                    f"EXTERNAL: VirusTotal {vt.malicious_count}/{vt.total_engines} engines flagged malicious"
                )
            elif vt.malicious_count >= 2:
                score += 20
                reasons.append(
                    f"EXTERNAL: VirusTotal {vt.malicious_count} engines flagged malicious"
                )
            elif vt.malicious_count >= 1:
                score += 10
                reasons.append("EXTERNAL: VirusTotal 1 engine flagged malicious")

            if vt.suspicious_count >= 3:
                score += 10
                reasons.append(f"EXTERNAL: VirusTotal {vt.suspicious_count} engines flagged suspicious")

            # Negative reputation is suspicious
            if vt.reputation < -10:
                score += 5
                reasons.append(f"EXTERNAL: VirusTotal negative reputation ({vt.reputation})")

        # urlscan.io
        if result.urlscan and result.urlscan.found:
            us = result.urlscan
            if us.verdict == "malicious":
                score += 30
                reasons.append(f"EXTERNAL: urlscan.io verdict: malicious (score: {us.score})")
            elif us.verdict == "suspicious" and us.score >= 50:
                score += 15
                reasons.append(f"EXTERNAL: urlscan.io verdict: suspicious (score: {us.score})")
            elif us.verdict == "suspicious":
                score += 5
                reasons.append(f"EXTERNAL: urlscan.io: low suspicion (score: {us.score})")

            if us.brands_targeted:
                brands = ", ".join(us.brands_targeted[:3])
                reasons.append(f"EXTERNAL: urlscan.io brands targeted: {brands}")

            if us.categories:
                cats = ", ".join(us.categories[:3])
                reasons.append(f"EXTERNAL: urlscan.io categories: {cats}")

        return score, reasons


async def query_external_intel(
    domain: str,
    urlscan_api_key: Optional[str] = None,
    virustotal_api_key: Optional[str] = None,
    cache_dir: Optional[Path] = None,
) -> ExternalIntelResult:
    """
    Convenience function to query external intelligence for a domain.

    Args:
        domain: Domain to query
        urlscan_api_key: Optional API key for urlscan.io (increases limits)
        virustotal_api_key: Optional API key for VirusTotal (required for VT)
        cache_dir: Optional directory for caching results

    Returns:
        ExternalIntelResult with scores and reasons
    """
    intel = ExternalIntelligence(
        urlscan_api_key=urlscan_api_key,
        virustotal_api_key=virustotal_api_key,
        cache_dir=cache_dir,
    )
    return await intel.query_all(domain)
