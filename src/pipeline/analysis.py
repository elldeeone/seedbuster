"""Analysis engine for SeedBuster."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from datetime import datetime
from urllib.parse import urlparse

from ..analyzer.clustering import analyze_for_clustering
from ..analyzer.temporal import ScanReason
from ..bot.formatters import AlertData, ClusterInfo, LearningInfo, TemporalInfo
from ..storage.database import DomainStatus, Verdict

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """Encapsulates domain analysis logic."""

    def __init__(
        self,
        *,
        config,
        database,
        evidence_store,
        browser,
        infrastructure,
        temporal,
        external_intel,
        detector,
        cluster_manager,
        threat_intel_updater,
        report_manager,
        bot,
    ):
        self.config = config
        self.database = database
        self.evidence_store = evidence_store
        self.browser = browser
        self.infrastructure = infrastructure
        self.temporal = temporal
        self.external_intel = external_intel
        self.detector = detector
        self.cluster_manager = cluster_manager
        self.threat_intel_updater = threat_intel_updater
        self.report_manager = report_manager
        self.bot = bot

    async def _lookup_urlscan_history(self, domain: str) -> tuple[list[str], str | None, bool]:
        """Find historical urlscan.io scans with wallet/seed UI for unreachable pages."""
        reasons: list[str] = []
        result_url: str | None = None
        found = False

        try:
            best = await self.external_intel.query_urlscan_best(domain)
        except Exception as e:
            logger.warning(f"Historical urlscan.io lookup failed for {domain}: {e}")
            return reasons, result_url, found

        if best and best.found and best.result_url:
            reasons.append(f"EXTERNAL: urlscan.io historical scan with wallet/seed UI: {best.result_url}")
            result_url = best.result_url
            found = True

        return reasons, result_url, found

    async def analyze(self, task: dict, scan_reason: ScanReason = ScanReason.INITIAL, is_rescan: bool = False):
        """Analyze a single domain task (initial or rescan)."""
        domain_id = task["id"]
        domain = task["domain"]
        is_rescan = scan_reason != ScanReason.INITIAL
        domain_score = task["domain_score"]
        domain_reasons = task.get("reasons", [])

        logger.info(f"Analyzing: {domain}")

        browser_result = None
        infra_result = None
        external_result = None
        detection = None
        cluster_result = None
        urlscan_result_url: str | None = None

        try:
            # Update status
            await self.database.update_domain_status(domain_id, DomainStatus.ANALYZING)

            # Quick DNS check first (extract hostname only, ignore path/scheme)
            raw_target = (domain or "").strip()
            parsed_target = urlparse(raw_target if "://" in raw_target else f"http://{raw_target}")
            hostname = (parsed_target.hostname or raw_target.split("/")[0]).strip()

            dns_resolves = True
            resolved_ips: set[str] = set()
            non_global_ips: set[str] = set()

            try:
                # IP literal
                ip_obj = ipaddress.ip_address(hostname)
                resolved_ips.add(str(ip_obj))
            except ValueError:
                try:
                    addrinfos = await asyncio.to_thread(
                        socket.getaddrinfo,
                        hostname,
                        None,
                        socket.AF_UNSPEC,
                        socket.SOCK_STREAM,
                    )
                    resolved_ips = {sockaddr[0] for *_rest, sockaddr in addrinfos}
                except socket.gaierror:
                    dns_resolves = False
            except socket.gaierror:
                dns_resolves = False
                logger.info(f"Domain does not resolve: {hostname}")

            if dns_resolves and resolved_ips:
                for ip in resolved_ips:
                    try:
                        if not ipaddress.ip_address(ip).is_global:
                            non_global_ips.add(ip)
                    except ValueError:
                        continue

            if not dns_resolves or not resolved_ips:
                # Domain doesn't exist - report based on domain score alone
                urlscan_history_reasons, urlscan_result_url, urlscan_history_found = await self._lookup_urlscan_history(domain)
                analysis_score = domain_score
                if urlscan_history_found:
                    analysis_score = max(analysis_score, max(self.config.analysis_score_threshold, 75))
                    verdict = Verdict.HIGH
                else:
                    verdict = Verdict.MEDIUM if domain_score >= 50 else Verdict.LOW
                reasons = (
                    domain_reasons
                    + ["Domain does not resolve (not registered or offline)"]
                    + urlscan_history_reasons
                )

                # Save analysis
                await self.evidence_store.save_analysis(domain, {
                    "domain": domain,
                    "score": analysis_score,
                    "verdict": verdict.value,
                    "reasons": reasons,
                    "dns_resolves": False,
                })
                self.temporal.add_snapshot(
                    domain=domain,
                    score=analysis_score,
                    verdict=verdict.value,
                    reasons=reasons,
                    scan_reason=scan_reason,
                )
            elif non_global_ips:
                # SSRF hardening: never browse or connect to private/local targets.
                verdict = Verdict.MEDIUM if domain_score >= 50 else Verdict.LOW
                analysis_score = domain_score
                reasons = domain_reasons + [
                    (
                        "Analysis blocked (SSRF guard): "
                        f"{hostname} resolves to private/local IP(s): {', '.join(sorted(non_global_ips))}"
                    )
                ]

                await self.evidence_store.save_analysis(domain, {
                    "domain": domain,
                    "score": analysis_score,
                    "verdict": verdict.value,
                    "reasons": reasons,
                    "dns_resolves": True,
                    "resolved_ips": sorted(resolved_ips),
                    "blocked_for_ssrf": True,
                })
                self.temporal.add_snapshot(
                    domain=domain,
                    score=analysis_score,
                    verdict=verdict.value,
                    reasons=reasons,
                    scan_reason=scan_reason,
                )
            else:
                # Run browser, infrastructure, and external intel in PARALLEL
                browser_result, infra_result, external_result = await asyncio.gather(
                    self.browser.analyze(domain),
                    self.infrastructure.analyze(domain),
                    self.external_intel.query_all(domain),
                    return_exceptions=True,
                )

                if isinstance(browser_result, Exception):
                    browser_result = None
                if isinstance(infra_result, Exception):
                    logger.warning(f"Infrastructure analysis failed for {domain}: {infra_result}")
                    infra_result = None
                if isinstance(external_result, Exception):
                    logger.warning(f"External intel query failed for {domain}: {external_result}")
                    external_result = None

                if infra_result:
                    logger.info(
                        f"Infrastructure analysis for {domain}: "
                        f"score={infra_result.risk_score}, "
                        f"reasons={len(infra_result.risk_reasons)}"
                    )
                if external_result and external_result.score > 0:
                    logger.info(
                        f"External intel for {domain}: "
                        f"score={external_result.score}, "
                        f"reasons={len(external_result.reasons)}"
                    )
                if external_result and external_result.urlscan and external_result.urlscan.result_url:
                    urlscan_result_url = external_result.urlscan.result_url

                if not browser_result or not browser_result.success:
                    error = getattr(browser_result, "error", None) or "Analysis failed"
                    logger.warning(f"Failed to analyze {domain}: {error}")
                    analysis_score = min(100, domain_score + (external_result.score if external_result else 0))
                    urlscan_history_reasons, history_result_url, urlscan_history_found = await self._lookup_urlscan_history(domain)
                    if history_result_url and not urlscan_result_url:
                        urlscan_result_url = history_result_url
                    if urlscan_history_found:
                        analysis_score = max(analysis_score, max(self.config.analysis_score_threshold, 75))
                        verdict = Verdict.HIGH
                    else:
                        verdict = Verdict.LOW
                    reasons = (
                        domain_reasons
                        + [error]
                        + (external_result.reasons if external_result else [])
                        + urlscan_history_reasons
                    )

                    await self.evidence_store.save_analysis(domain, {
                        "domain": domain,
                        "score": analysis_score,
                        "verdict": verdict.value,
                        "reasons": reasons,
                        "dns_resolves": True,
                        "resolved_ips": sorted(resolved_ips),
                        "analysis_error": error,
                        "external_intel": external_result.to_dict() if external_result else None,
                    })
                    self.temporal.add_snapshot(
                        domain=domain,
                        html=getattr(browser_result, "html", None) if browser_result else None,
                        title=getattr(browser_result, "title", "") or "",
                        screenshot=getattr(browser_result, "screenshot", None) if browser_result else None,
                        score=analysis_score,
                        verdict=verdict.value,
                        reasons=reasons,
                        external_domains=getattr(browser_result, "external_requests", None) if browser_result else [],
                        blocked_requests=len(getattr(browser_result, "blocked_requests", []) or []) if browser_result else 0,
                        tls_age_days=infra_result.tls.age_days if infra_result and infra_result.tls else -1,
                        hosting_provider=(
                            infra_result.hosting.hosting_provider if infra_result and infra_result.hosting else ""
                        ),
                        scan_reason=scan_reason,
                    )
                else:
                    # Save all screenshots for comparison
                    has_early = (
                        hasattr(browser_result, 'screenshot_early') and
                        browser_result.screenshot_early
                    )
                    has_blocked = (
                        hasattr(browser_result, 'blocked_requests') and
                        browser_result.blocked_requests
                    )

                    if has_early:
                        # Save early screenshot (before JS-based evasion)
                        await self.evidence_store.save_screenshot(domain, browser_result.screenshot_early, suffix="_early")
                        if has_blocked:
                            logger.info(f"Saved early screenshot for {domain} (anti-bot blocked)")

                    if browser_result.screenshot:
                        # Save final screenshot
                        await self.evidence_store.save_screenshot(domain, browser_result.screenshot)

                    # Clear stale exploration screenshots from previous scans (directory is reused).
                    removed = self.evidence_store.clear_exploration_screenshots(domain)
                    if removed:
                        logger.info(f"Cleared {removed} old exploration screenshots for {domain}")

                    # Save exploration screenshots (especially ones with suspicious content)
                    if browser_result.exploration_steps:
                        for i, step in enumerate(browser_result.exploration_steps):
                            if step.screenshot and step.success:
                                if getattr(step, "is_seed_form", False):
                                    suffix = f"_exploration_seedform_{i+1}"
                                    logger.info(f"Saving seed form screenshot: {step.button_text} (mnemonic form detected)")
                                else:
                                    text_inputs = [
                                        inp for inp in step.input_fields
                                        if inp.get("type") in ("text", "password", "")
                                    ]
                                    if len(text_inputs) >= 12:
                                        suffix = f"_exploration_seedform_{i+1}"
                                        logger.info(f"Saving seed form screenshot: {step.button_text} ({len(text_inputs)} inputs)")
                                    elif len(text_inputs) >= 6:
                                        suffix = f"_exploration_suspicious_{i+1}"
                                    else:
                                        suffix = f"_exploration_{i+1}"
                                await self.evidence_store.save_screenshot(domain, step.screenshot, suffix=suffix)

                    if browser_result.html:
                        await self.evidence_store.save_html(domain, browser_result.html)

                    # Get temporal analysis (if we have previous snapshots)
                    temporal_analysis = self.temporal.analyze(domain)

                    # Detect phishing signals (including all intelligence layers)
                    detection = self.detector.detect(
                        browser_result,
                        domain_score,
                        infrastructure=infra_result,
                        temporal=temporal_analysis,
                    )

                    # Add external intelligence results
                    external_score = external_result.score if external_result else 0
                    external_reasons = external_result.reasons if external_result else []
                    analysis_score = min(100, detection.score + external_score)
                    reasons = detection.reasons + external_reasons

                    # Optional: submit a fresh urlscan.io scan when cloaking is suspected/confirmed.
                    urlscan_submission = None
                    blocked_requests = getattr(browser_result, "blocked_requests", []) or []
                    cloaking_suspected = len(blocked_requests) > 0
                    if (
                        self.config.urlscan_submit_enabled
                        and self.config.urlscan_api_key
                        and analysis_score >= self.config.analysis_score_threshold
                        and (cloaking_suspected or temporal_analysis.cloaking_detected)
                    ):
                        target_url = domain if "://" in domain else f"https://{domain}"
                        urlscan_submission = await self.external_intel.submit_urlscan_scan(
                            target_url,
                            visibility=self.config.urlscan_submit_visibility,
                            tags=["seedbuster", "cloaking"],
                        )
                        if urlscan_submission.submitted and urlscan_submission.result_url:
                            reasons.append(
                                f"EXTERNAL: urlscan.io active scan submitted: {urlscan_submission.result_url}"
                            )
                            urlscan_result_url = urlscan_submission.result_url

                    if analysis_score >= self.config.analysis_score_threshold and (
                        cloaking_suspected or temporal_analysis.cloaking_detected
                    ):
                        best = await self.external_intel.query_urlscan_best(domain)
                        if best.found and best.result_url and best.result_url != urlscan_result_url:
                            reasons.append(
                                f"EXTERNAL: urlscan.io historical scan with wallet/seed UI: {best.result_url}"
                            )
                            urlscan_result_url = best.result_url

                    self.temporal.add_snapshot(
                        domain=domain,
                        html=browser_result.html,
                        title=browser_result.title or "",
                        screenshot=browser_result.screenshot,
                        score=analysis_score,
                        verdict=detection.verdict,
                        reasons=reasons,
                        external_domains=browser_result.external_requests,
                        blocked_requests=len(getattr(browser_result, 'blocked_requests', []) or []),
                        tls_age_days=infra_result.tls.age_days if infra_result and infra_result.tls else -1,
                        hosting_provider=(
                            infra_result.hosting.hosting_provider if infra_result and infra_result.hosting else ""
                        ),
                        scan_reason=scan_reason,
                    )

                    # Cluster analysis - link related phishing sites
                    cluster_result = analyze_for_clustering(
                        manager=self.cluster_manager,
                        domain=domain,
                        detection_result={
                            "score": analysis_score,
                            "suspicious_endpoints": detection.suspicious_endpoints,
                            "kit_matches": detection.kit_matches,
                        },
                        infrastructure={
                            "nameservers": infra_result.domain_info.nameservers if infra_result.domain_info else [],
                            "asn": str(infra_result.hosting.asn) if infra_result and infra_result.hosting else None,
                            "ip": infra_result.hosting.ip_address if infra_result and infra_result.hosting else None,
                        } if infra_result else None,
                    )
                    if cluster_result.related_domains:
                        logger.info(f"Clustering: {domain} linked to {len(cluster_result.related_domains)} related sites")

                    verdict = Verdict(detection.verdict)

                    hosting_provider = (
                        infra_result.hosting.hosting_provider if infra_result and infra_result.hosting else None
                    )

                    backend_domains: list[str] = []
                    seen_backend_hosts: set[str] = set()
                    for endpoint in detection.suspicious_endpoints or []:
                        if not isinstance(endpoint, str):
                            continue
                        raw = endpoint.strip()
                        if not raw:
                            continue
                        try:
                            parsed = urlparse(raw if "://" in raw else f"https://{raw}")
                            host = (parsed.hostname or "").strip().lower()
                        except Exception:
                            host = ""
                        if not host or host in seen_backend_hosts:
                            continue
                        seen_backend_hosts.add(host)
                        backend_domains.append(host)

                    api_keys_found = [
                        r for r in (reasons or []) if isinstance(r, str) and ("api key" in r.lower() or "apikey" in r.lower())
                    ]

                    await self.evidence_store.save_analysis(domain, {
                        "domain": domain,
                        "final_url": getattr(browser_result, "final_url", None),
                        "hosting_provider": hosting_provider,
                        "backend_domains": backend_domains,
                        "api_keys_found": api_keys_found,
                        "score": analysis_score,
                        "verdict": verdict.value,
                        "reasons": reasons,
                        "visual_match": detection.visual_match_score,
                        "seed_form": detection.seed_form_detected,
                        "suspicious_endpoints": detection.suspicious_endpoints,
                        "infrastructure": {
                            "score": detection.infrastructure_score,
                            "reasons": detection.infrastructure_reasons,
                            "tls_age_days": infra_result.tls.age_days if infra_result and infra_result.tls else None,
                            "domain_age_days": (
                                infra_result.domain_info.age_days
                                if infra_result and infra_result.domain_info
                                else None
                            ),
                            "hosting_provider": (
                                infra_result.hosting.hosting_provider
                                if infra_result and infra_result.hosting
                                else None
                            ),
                            "uses_privacy_dns": (
                                infra_result.domain_info.uses_privacy_dns
                                if infra_result and infra_result.domain_info
                                else False
                            ),
                        },
                        "code_analysis": {
                            "score": detection.code_score,
                            "reasons": detection.code_reasons,
                            "kit_matches": detection.kit_matches,
                        },
                        "temporal": {
                            "score": detection.temporal_score,
                            "reasons": detection.temporal_reasons,
                            "cloaking_detected": detection.cloaking_detected,
                            "snapshots_count": temporal_analysis.snapshots_count,
                        },
                        "cluster": {
                            "cluster_id": cluster_result.cluster_id if cluster_result else None,
                            "cluster_name": cluster_result.cluster_name if cluster_result else None,
                            "is_new_cluster": cluster_result.is_new_cluster if cluster_result else None,
                            "related_domains": cluster_result.related_domains if cluster_result else None,
                            "confidence": cluster_result.confidence if cluster_result else None,
                        },
                        "external_intel": external_result.to_dict() if external_result else None,
                        "urlscan_submission": (
                            {
                                "scan_id": urlscan_submission.scan_id,
                                "result_url": urlscan_submission.result_url,
                                "visibility": self.config.urlscan_submit_visibility,
                            }
                            if urlscan_submission and urlscan_submission.submitted
                            else None
                        ),
                    })

            # Update database
            evidence_path = str(self.evidence_store.get_evidence_path(domain))
            await self.database.update_domain_analysis(
                domain_id=domain_id,
                analysis_score=analysis_score,
                verdict=verdict,
                verdict_reasons="\n".join(reasons),
                evidence_path=evidence_path,
            )

            # Determine if we should send an alert
            # For monthly rescans of watchlist domains, only alert if findings increased from baseline
            should_alert = analysis_score >= self.config.analysis_score_threshold
            is_watchlist_update = False

            if scan_reason == ScanReason.RESCAN_MONTHLY:
                # Get domain record to check if it's a watchlist domain
                domain_record = await self.database.get_domain_by_id(domain_id)

                if domain_record and domain_record.get("status") == "watchlist":
                    baseline_timestamp = domain_record.get("watchlist_baseline_timestamp")

                    if baseline_timestamp:
                        # Find baseline snapshot by timestamp
                        snapshots = self.temporal.get_snapshots(domain)
                        baseline_snapshot = None

                        # Find snapshot closest to baseline timestamp
                        try:
                            baseline_dt = datetime.fromisoformat(baseline_timestamp.replace(' ', 'T'))
                            for snapshot in snapshots:
                                if snapshot.timestamp <= baseline_dt:
                                    baseline_snapshot = snapshot
                                else:
                                    break  # Snapshots are ordered by time
                        except (ValueError, AttributeError):
                            logger.warning(f"Invalid baseline timestamp for {domain}: {baseline_timestamp}")

                        if baseline_snapshot:
                            # Compare against BASELINE (not previous scan)
                            score_increase = analysis_score - baseline_snapshot.score
                            baseline_verdict = baseline_snapshot.verdict.lower() if baseline_snapshot.verdict else "low"
                            current_verdict = verdict.value.lower()

                            # Verdict escalation check
                            verdict_order = {"benign": 0, "low": 1, "medium": 2, "high": 3}
                            verdict_escalated = verdict_order.get(current_verdict, 0) > verdict_order.get(baseline_verdict, 0)

                            # Seed form detection check
                            seed_form_now_detected = detection.seed_form_detected if detection else False
                            baseline_had_seed_form = any(
                                "seed" in reason.lower() and "form" in reason.lower()
                                for reason in baseline_snapshot.reasons
                            )
                            seed_form_newly_detected = seed_form_now_detected and not baseline_had_seed_form

                            # Alert triggers (compared to BASELINE)
                            should_alert = (
                                should_alert and (
                                    score_increase >= 10 or
                                    verdict_escalated or
                                    seed_form_newly_detected
                                )
                            )

                            if should_alert:
                                is_watchlist_update = True
                                logger.info(
                                    f"Watchlist alert for {domain}: baseline score {baseline_snapshot.score}→{analysis_score} (+{score_increase}), "
                                    f"verdict {baseline_verdict}→{current_verdict}, new_seed_form={seed_form_newly_detected}"
                                )
                            else:
                                logger.info(
                                    f"No significant change from baseline for {domain}: "
                                    f"score {baseline_snapshot.score}→{analysis_score} ({score_increase:+d}), skipping notification"
                                )
                        else:
                            # No baseline snapshot found, use most recent as fallback
                            logger.warning(f"No baseline snapshot found for {domain}, using most recent as baseline")
                            baseline_snapshot = snapshots[-2] if len(snapshots) >= 2 else None
                            if baseline_snapshot:
                                score_increase = analysis_score - baseline_snapshot.score
                                should_alert = should_alert and score_increase >= 10
                            is_watchlist_update = should_alert
                    else:
                        # No baseline timestamp set yet, this scan becomes the baseline
                        is_watchlist_update = should_alert
                        logger.info(f"Setting baseline for watchlist domain {domain}")
                else:
                    # Not a watchlist domain, use previous logic for backward compatibility
                    snapshots = self.temporal.get_snapshots(domain)
                    previous_snapshot = snapshots[-2] if len(snapshots) >= 2 else None

                    if previous_snapshot:
                        score_increase = analysis_score - previous_snapshot.score
                        previous_verdict = previous_snapshot.verdict.lower() if previous_snapshot.verdict else "low"
                        current_verdict = verdict.value.lower()

                        # Verdict escalation check
                        verdict_order = {"benign": 0, "low": 1, "medium": 2, "high": 3}
                        verdict_escalated = verdict_order.get(current_verdict, 0) > verdict_order.get(previous_verdict, 0)

                        # Seed form is a smoking gun - always alert
                        seed_form_now_detected = detection.seed_form_detected if detection else False

                        # Only alert if meaningful change detected
                        should_alert = (
                            should_alert and (
                                score_increase >= 10 or
                                verdict_escalated or
                                seed_form_now_detected
                            )
                        )

                        if should_alert:
                            is_watchlist_update = True
                    else:
                        # First rescan, treat it as a watchlist update if alerting
                        is_watchlist_update = should_alert
            
            # Send alert if criteria met
            if should_alert:
                if self.config.report_require_approval and analysis_score >= self.config.report_min_score:
                    try:
                        await self.report_manager.ensure_pending_reports(domain_id=domain_id)
                    except Exception as e:
                        logger.warning(f"Could not create pending report rows for {domain}: {e}")

                screenshot_path = self.evidence_store.get_screenshot_path(domain)
                screenshot_paths = self.evidence_store.get_all_screenshot_paths(domain)

                blocked_requests = getattr(browser_result, 'blocked_requests', []) or [] if browser_result else []
                cloaking_suspected = len(blocked_requests) > 0

                temporal_analysis = self.temporal.analyze(domain)

                snapshots = self.temporal.get_snapshots(domain)
                snapshot_count = len(snapshots)

                temporal_info = TemporalInfo(
                    is_initial_scan=not is_rescan,
                    scan_number=snapshot_count,
                    total_scans=5,
                    rescans_scheduled=not is_rescan,
                    cloaking_suspected=cloaking_suspected,
                    cloaking_confirmed=temporal_analysis.cloaking_detected,
                    cloaking_confidence=temporal_analysis.cloaking_confidence,
                    previous_score=None,
                )

                if is_rescan and len(snapshots) >= 2:
                    temporal_info.previous_score = snapshots[-2].score

                cluster_info = None
                if cluster_result:
                    cluster_info = ClusterInfo(
                        cluster_id=cluster_result.cluster_id,
                        cluster_name=cluster_result.cluster_name,
                        is_new_cluster=cluster_result.is_new_cluster,
                        related_domains=cluster_result.related_domains,
                        confidence=cluster_result.confidence,
                    )

                learning_info = None
                if detection and cluster_result:
                    matched_backends = self.threat_intel_updater.extract_matched_backends(
                        detection.suspicious_endpoints
                    )
                    matched_api_keys = self.threat_intel_updater.extract_matched_api_keys(reasons)

                    if self.threat_intel_updater.should_learn(
                        domain=domain,
                        analysis_score=analysis_score,
                        cluster_confidence=cluster_result.confidence,
                        cluster_name=cluster_result.cluster_name,
                        matched_backends=matched_backends,
                        matched_api_keys=matched_api_keys,
                    ):
                        learning_result = self.threat_intel_updater.learn(
                            domain=domain,
                            analysis_score=analysis_score,
                            cluster_confidence=cluster_result.confidence,
                            cluster_name=cluster_result.cluster_name,
                            matched_backends=matched_backends,
                            matched_api_keys=matched_api_keys,
                        )
                        if learning_result.updated:
                            logger.info(f"Threat intel auto-updated: {learning_result.message}")
                            self.detector.reload_threat_intel()
                            learning_info = LearningInfo(
                                learned=True,
                                version=learning_result.version,
                                added_to_frontends=learning_result.added_to_frontends,
                                added_to_api_keys=learning_result.added_to_api_keys,
                            )

                await self.bot.send_alert(AlertData(
                    domain=domain,
                    domain_id=self.evidence_store.get_domain_id(domain),
                    verdict=verdict.value,
                    score=analysis_score,
                    reasons=reasons,
                    screenshot_path=str(screenshot_path) if screenshot_path else None,
                    screenshot_paths=[str(p) for p in screenshot_paths] if screenshot_paths else None,
                    evidence_path=evidence_path,
                    urlscan_result_url=urlscan_result_url,
                    temporal=temporal_info,
                    cluster=cluster_info,
                    seed_form_found=detection.seed_form_detected if detection else False,
                    learning=learning_info,
                    is_watchlist_update=is_watchlist_update,
                ))

            if (
                not self.config.report_require_approval
                and scan_reason == ScanReason.INITIAL
                and analysis_score >= self.config.report_min_score
                and browser_result
                and getattr(browser_result, "success", False)
                and self.report_manager.get_available_platforms()
            ):
                results = await self.report_manager.report_domain(domain_id=domain_id, domain=domain)
                summary = self.report_manager.format_results_summary(results)
                await self.bot.send_message(f"Auto-report results for `{domain}`:\n\n{summary}")

            logger.info(f"Completed: {domain} (verdict={verdict.value}, score={analysis_score})")

        except Exception as e:
            logger.error(f"Error analyzing {domain}: {e}")
            await self.database.update_domain_status(domain_id, DomainStatus.PENDING)
