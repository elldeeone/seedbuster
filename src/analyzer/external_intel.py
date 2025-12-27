"""
Layer 6: External Intelligence

Queries external threat intelligence services:
- urlscan.io: Check existing scans and verdicts
- VirusTotal: Domain/URL reputation from 70+ vendors
- abuse.ch URLhaus: Known malware/phishing URLs

All services have free tiers sufficient for moderate volume.

Optionally, SeedBuster can submit a fresh urlscan.io scan to collect evidence
from a different scanner vantage point (useful when a site cloaks content based
on client IP/UA). This is disabled unless configured with an API key and an
explicit opt-in.
"""

import asyncio
import hashlib
import json
import logging
import time
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import quote, urlparse

import aiohttp

logger = logging.getLogger(__name__)

URLSCAN_UI_KEYWORDS = [
    # Known wallet landing UI (buttons/flows)
    "continue on legacy wallet",
    "go to the new kaspa ng wallet",
    "recover from seed",
    "recover wallet",
    "restore wallet",
    "import wallet",
]

URLSCAN_SEED_KEYWORDS = [
    "seed phrase",
    "recovery phrase",
    "mnemonic",
    "12-word",
    "24-word",
    "12 words",
    "24 words",
]


@dataclass
class URLScanResult:
    """Result from urlscan.io."""
    found: bool = False
    submitted: bool = False  # True if we submitted a fresh scan
    scan_id: Optional[str] = None
    verdict: Optional[str] = None  # malicious, suspicious, benign
    score: int = 0
    categories: List[str] = field(default_factory=list)
    brands_targeted: List[str] = field(default_factory=list)
    scan_date: Optional[datetime] = None
    screenshot_url: Optional[str] = None
    result_url: Optional[str] = None
    api_url: Optional[str] = None


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
                "scan_id": self.urlscan.scan_id if self.urlscan else None,
                "verdict": self.urlscan.verdict if self.urlscan else None,
                "score": self.urlscan.score if self.urlscan else 0,
                "result_url": self.urlscan.result_url if self.urlscan else None,
                "screenshot_url": self.urlscan.screenshot_url if self.urlscan else None,
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

    Queries are search-only by default (no new scans submitted) unless
    urlscan submission is explicitly enabled by providing an API key and
    calling `submit_urlscan_scan()`.
    """

    def __init__(
        self,
        urlscan_api_key: Optional[str] = None,
        virustotal_api_key: Optional[str] = None,
        cache_dir: Optional[Path] = None,
        cache_ttl_hours: int = 24,
        scoring_weights: Optional[Dict[str, Any]] = None,
    ):
        self.urlscan_api_key = urlscan_api_key
        self.virustotal_api_key = virustotal_api_key
        self.cache_dir = cache_dir
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.scoring = scoring_weights or {}

        # Rate limiting
        self._last_vt_request = 0.0
        self._vt_min_interval = 15.0  # 4 req/min = 15s between requests

        # Avoid burning urlscan quota on repeat submissions for the same target.
        self._urlscan_submit_min_interval = 60 * 60  # 1 hour
        self._urlscan_submit_cache: Dict[str, tuple[URLScanResult, float]] = {}

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
                            if result.scan_id:
                                result.result_url = f"https://urlscan.io/result/{result.scan_id}/"

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
                "submitted": False,
                "scan_id": result.scan_id,
                "verdict": result.verdict,
                "score": result.score,
                "categories": result.categories,
                "brands_targeted": result.brands_targeted,
                "scan_date": result.scan_date.isoformat() if result.scan_date else None,
                "screenshot_url": result.screenshot_url,
                "result_url": result.result_url,
            })

        except asyncio.TimeoutError:
            logger.debug(f"urlscan.io timeout for {domain}")
        except Exception as e:
            logger.debug(f"urlscan.io error for {domain}: {e}")

        return result

    async def query_urlscan_best(
        self,
        domain: str,
        *,
        max_results: int = 10,
        max_dom_checks: int = 8,
    ) -> URLScanResult:
        """Find the most useful existing urlscan.io scan for a domain.

        Some phishing kits serve decoy content to scanner IP ranges (including urlscan).
        In that case, the *latest* scan can be the decoy even if an older scan captured
        the wallet/seed UI. This method searches multiple historical scans and prefers
        scans whose saved DOM includes wallet/seed UI keywords.

        Note: This is still a passive lookup (no new scan submission).
        """
        result = URLScanResult()

        # Check cache
        cached = self._get_cached("urlscan_best", domain)
        if cached:
            return URLScanResult(**cached)

        domains_to_search = []
        domain_clean = (domain or "").strip().lower()
        if domain_clean:
            domains_to_search.append(domain_clean)
            if domain_clean.startswith("www."):
                domains_to_search.append(domain_clean[4:])
            else:
                domains_to_search.append(f"www.{domain_clean}")

        scans: list[dict] = []
        seen_ids: set[str] = set()

        try:
            async with aiohttp.ClientSession() as session:
                # 1) Search multiple domain variants
                for d in domains_to_search:
                    url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(d)}&size={max_results}"
                    headers = {}
                    if self.urlscan_api_key:
                        headers["API-Key"] = self.urlscan_api_key

                    async with session.get(url, headers=headers, timeout=10) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json()
                        for scan in data.get("results", []) or []:
                            scan_id = scan.get("_id")
                            if not scan_id or scan_id in seen_ids:
                                continue
                            seen_ids.add(scan_id)
                            scans.append(scan)

                if not scans:
                    self._set_cached("urlscan_best", domain, {
                        "found": False,
                        "submitted": False,
                        "scan_id": None,
                        "verdict": None,
                        "score": 0,
                        "categories": [],
                        "brands_targeted": [],
                        "scan_date": None,
                        "screenshot_url": None,
                        "result_url": None,
                        "api_url": None,
                    })
                    return result

                # Sort by scan time (newest first) as a reasonable default.
                def scan_time(s: dict) -> str:
                    return (s.get("task", {}) or {}).get("time", "") or ""

                scans.sort(key=scan_time, reverse=True)

                best: URLScanResult | None = None
                best_score = -1

                # 2) Evaluate candidates, preferring those with wallet/seed UI text in DOM.
                for i, scan in enumerate(scans[: max_results * 2]):  # guard against duplicates from variants
                    scan_id = scan.get("_id")
                    if not scan_id:
                        continue

                    candidate = URLScanResult(found=True)
                    candidate.scan_id = scan_id
                    candidate.screenshot_url = scan.get("screenshot")
                    candidate.result_url = f"https://urlscan.io/result/{scan_id}/"

                    verdicts = scan.get("verdicts", {}) or {}
                    overall = verdicts.get("overall", {}) or {}
                    candidate.score = int(overall.get("score", 0) or 0)
                    if overall.get("malicious"):
                        candidate.verdict = "malicious"
                    elif candidate.score > 0:
                        candidate.verdict = "suspicious"
                    else:
                        candidate.verdict = "benign"
                    candidate.categories = list(overall.get("categories", []) or [])
                    candidate.brands_targeted = list(overall.get("brands", []) or [])

                    # Base selection score (using configurable weights)
                    s = self.scoring  # shorthand
                    selection_score = 0
                    if candidate.verdict == "malicious":
                        selection_score += s.get("urlscan_malicious_bonus", 200)
                    selection_score += candidate.score

                    # Only fetch DOM for a limited number of candidates to keep this lightweight.
                    if i < max_dom_checks:
                        dom_url = f"https://urlscan.io/dom/{scan_id}/"
                        try:
                            async with session.get(dom_url, timeout=10) as dom_resp:
                                if dom_resp.status == 200:
                                    dom_html = (await dom_resp.text()) or ""
                                else:
                                    dom_html = ""
                        except Exception:
                            dom_html = ""

                        if dom_html:
                            dom_lower = dom_html.lower()
                            seed_hits = sum(1 for kw in URLSCAN_SEED_KEYWORDS if kw in dom_lower)
                            ui_hits = sum(1 for kw in URLSCAN_UI_KEYWORDS if kw in dom_lower)
                            inputs_count = len(re.findall(r"<input\\b", dom_lower))

                            # Seed/mnemonic keywords are strong evidence.
                            selection_score += seed_hits * s.get("urlscan_seed_keyword_bonus", 50)
                            selection_score += ui_hits * s.get("urlscan_ui_keyword_bonus", 20)

                            # 12/24 input grids are common for mnemonic capture.
                            exact_counts = s.get("seed_form_exact_counts", [12, 24])
                            many_inputs_threshold = s.get("urlscan_many_inputs_threshold", 8)
                            if inputs_count in exact_counts:
                                selection_score += s.get("urlscan_exact_input_bonus", 80)
                            elif inputs_count >= many_inputs_threshold:
                                selection_score += s.get("urlscan_many_inputs_bonus", 20)

                    if selection_score > best_score:
                        best_score = selection_score
                        best = candidate

                if best:
                    result = best

        except asyncio.TimeoutError:
            logger.debug(f"urlscan.io best-scan timeout for {domain}")
        except Exception as e:
            logger.debug(f"urlscan.io best-scan error for {domain}: {e}")

        # Cache result
        self._set_cached("urlscan_best", domain, {
            "found": result.found,
            "submitted": result.submitted,
            "scan_id": result.scan_id,
            "verdict": result.verdict,
            "score": result.score,
            "categories": result.categories,
            "brands_targeted": result.brands_targeted,
            "scan_date": result.scan_date.isoformat() if isinstance(result.scan_date, datetime) else None,
            "screenshot_url": result.screenshot_url,
            "result_url": result.result_url,
            "api_url": result.api_url,
        })

        return result

    async def submit_urlscan_scan(
        self,
        target_url: str,
        *,
        visibility: str = "unlisted",
        tags: Optional[list[str]] = None,
    ) -> URLScanResult:
        """Submit a fresh urlscan.io scan and return the submission metadata.

        This does not block waiting for the scan to finish; callers can use the
        returned `result_url` to view the scan when ready.

        Requires `urlscan_api_key`.
        """
        result = URLScanResult()

        if not self.urlscan_api_key:
            return result

        host = (urlparse(target_url).hostname or target_url).lower()
        now = time.time()
        cached = self._urlscan_submit_cache.get(host)
        if cached and (now - cached[1]) < self._urlscan_submit_min_interval:
            return cached[0]

        url = "https://urlscan.io/api/v1/scan/"
        headers = {
            "API-Key": self.urlscan_api_key,
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "url": target_url,
            "visibility": visibility,
        }
        if tags:
            payload["tags"] = tags

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload, timeout=20) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        scan_id = data.get("uuid") or data.get("_id") or data.get("scan_id")
                        result_url = data.get("result")
                        api_url = data.get("api")

                        result.found = True
                        result.submitted = True
                        result.scan_id = scan_id
                        result.result_url = result_url or (f"https://urlscan.io/result/{scan_id}/" if scan_id else None)
                        result.api_url = api_url or (f"https://urlscan.io/api/v1/result/{scan_id}/" if scan_id else None)
                        result.screenshot_url = (
                            f"https://urlscan.io/screenshots/{scan_id}.png" if scan_id else None
                        )
                    else:
                        logger.debug(f"urlscan.io submit failed ({resp.status}) for {target_url}")

        except asyncio.TimeoutError:
            logger.debug(f"urlscan.io submit timeout for {target_url}")
        except Exception as e:
            logger.debug(f"urlscan.io submit error for {target_url}: {e}")

        if result.submitted and host:
            self._urlscan_submit_cache[host] = (result, now)

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
        s = self.scoring  # shorthand for scoring weights

        # URLhaus (highest priority - known malware/phishing)
        if result.urlhaus and result.urlhaus.found:
            score += s.get("external_urlhaus_found", 40)
            threat = result.urlhaus.threat_type or "unknown"
            reasons.append(f"EXTERNAL: URLhaus known threat ({threat})")
            if result.urlhaus.tags:
                reasons.append(f"EXTERNAL: URLhaus tags: {', '.join(result.urlhaus.tags[:3])}")

        # VirusTotal
        if result.virustotal and result.virustotal.found:
            vt = result.virustotal
            vt_high_threshold = s.get("external_vt_malicious_high_threshold", 5)
            vt_med_threshold = s.get("external_vt_malicious_medium_threshold", 2)
            vt_susp_threshold = s.get("external_vt_suspicious_threshold", 3)
            vt_rep_threshold = s.get("external_vt_reputation_threshold", -10)

            if vt.malicious_count >= vt_high_threshold:
                score += s.get("external_vt_malicious_high", 35)
                reasons.append(
                    f"EXTERNAL: VirusTotal {vt.malicious_count}/{vt.total_engines} engines flagged malicious"
                )
            elif vt.malicious_count >= vt_med_threshold:
                score += s.get("external_vt_malicious_medium", 20)
                reasons.append(
                    f"EXTERNAL: VirusTotal {vt.malicious_count} engines flagged malicious"
                )
            elif vt.malicious_count >= 1:
                score += s.get("external_vt_malicious_low", 10)
                reasons.append("EXTERNAL: VirusTotal 1 engine flagged malicious")

            if vt.suspicious_count >= vt_susp_threshold:
                score += s.get("external_vt_suspicious", 10)
                reasons.append(f"EXTERNAL: VirusTotal {vt.suspicious_count} engines flagged suspicious")

            # Negative reputation is suspicious
            if vt.reputation < vt_rep_threshold:
                score += s.get("external_vt_negative_rep", 5)
                reasons.append(f"EXTERNAL: VirusTotal negative reputation ({vt.reputation})")

        # urlscan.io
        if result.urlscan and result.urlscan.found:
            us = result.urlscan
            urlscan_susp_threshold = s.get("external_urlscan_suspicious_threshold", 50)

            if us.verdict == "malicious":
                score += s.get("external_urlscan_malicious", 30)
                reasons.append(f"EXTERNAL: urlscan.io verdict: malicious (score: {us.score})")
            elif us.verdict == "suspicious" and us.score >= urlscan_susp_threshold:
                score += s.get("external_urlscan_suspicious_high", 15)
                reasons.append(f"EXTERNAL: urlscan.io verdict: suspicious (score: {us.score})")
            elif us.verdict == "suspicious":
                score += s.get("external_urlscan_suspicious_low", 5)
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
    scoring_weights: Optional[Dict[str, Any]] = None,
) -> ExternalIntelResult:
    """
    Convenience function to query external intelligence for a domain.

    Args:
        domain: Domain to query
        urlscan_api_key: Optional API key for urlscan.io (increases limits)
        virustotal_api_key: Optional API key for VirusTotal (required for VT)
        cache_dir: Optional directory for caching results
        scoring_weights: Optional scoring weights from config

    Returns:
        ExternalIntelResult with scores and reasons
    """
    intel = ExternalIntelligence(
        urlscan_api_key=urlscan_api_key,
        virustotal_api_key=virustotal_api_key,
        cache_dir=cache_dir,
        scoring_weights=scoring_weights,
    )
    return await intel.query_all(domain)
