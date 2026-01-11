"""Report retry worker."""

from __future__ import annotations

import json
import logging

from .base import ReportResult, ReportStatus

logger = logging.getLogger(__name__)


class ReportManagerRetryMixin:
    """Retry worker for rate-limited reports."""

    async def retry_due_reports(self, *, limit: int = 20) -> list[ReportResult]:
        """Retry rate-limited reports that are due."""
        if self._preview_only_enabled():
            logger.info("REPORT_PREVIEW_ONLY enabled; skipping retry_due_reports")
            return []

        due = await self.database.get_due_retry_reports(limit=limit)
        if not due:
            return []

        attempted: list[ReportResult] = []

        for row in due:
            try:
                report_id = int(row["id"])
                domain_id = int(row["domain_id"])
                platform = str(row.get("platform") or "").strip().lower()
                domain = str(row.get("domain") or "").strip()

                reporter = self.reporters.get(platform)
                if not reporter or not reporter.is_configured():
                    result = ReportResult(
                        platform=platform or "unknown",
                        status=ReportStatus.FAILED,
                        report_id=str(report_id),
                        message="Reporter not configured",
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                if self.enabled_platforms is not None and platform not in self.enabled_platforms:
                    continue

                evidence = await self.build_evidence(domain_id=domain_id, domain=domain)
                if not evidence:
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.FAILED,
                        report_id=str(report_id),
                        message="Could not build evidence",
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                applicable, skip_reason = reporter.is_applicable(evidence)
                if not applicable:
                    msg = skip_reason or "Not applicable"
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.SKIPPED,
                        report_id=str(report_id),
                        message=msg,
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                limiter = self._get_rate_limiter(platform, reporter.rate_limit_per_minute)
                if not await limiter.acquire(timeout=5):
                    current_attempts = int(row.get("attempts") or 0)
                    next_attempts = current_attempts + 1
                    base_retry_after = max(30, int(limiter.wait_time() or 60))

                    if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                        platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                        url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                        msg = (
                            f"Rate limit persisted after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                            f"URL: {evidence.url}"
                        )
                        result = ReportResult(
                            platform=platform,
                            status=ReportStatus.MANUAL_REQUIRED,
                            report_id=str(report_id),
                            message=msg,
                            response_data={"domain_id": domain_id, "domain": domain},
                        )
                        attempted.append(result)
                        try:
                            content = self._build_manual_instructions_text(platform, evidence, result)
                            await self.evidence_store.save_report_instructions(domain, platform, content)
                        except Exception as exc:
                            logger.warning(
                                "Failed to save manual report instructions for %s (%s): %s",
                                domain,
                                platform,
                                exc,
                            )
                        await self.database.update_report(
                            report_id=report_id,
                            status=result.status.value,
                            response=result.message,
                        )
                        continue

                    retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                    msg = (
                        f"Rate limit exceeded; retry scheduled in {retry_after}s "
                        f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                    )
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.RATE_LIMITED,
                        report_id=str(report_id),
                        message=msg,
                        retry_after=retry_after,
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                        retry_after=retry_after,
                    )
                    continue

                try:
                    report_id = int(row.get("id") or 0)
                    current_attempts = int(row.get("attempts") or 0)

                    result = await reporter.submit(evidence)

                    if result.status == ReportStatus.RATE_LIMITED:
                        next_attempts = current_attempts + 1
                        base_retry_after = int(result.retry_after or 60)
                        if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                            platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                            url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                            msg = (
                                f"Rate limit persisted after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                                f"URL: {evidence.url}"
                            )
                            result = ReportResult(
                                platform=platform,
                                status=ReportStatus.MANUAL_REQUIRED,
                                message=msg,
                            )
                        else:
                            retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                            result.retry_after = retry_after
                            base_msg = (result.message or "Rate limited").strip()
                            result.message = (
                                f"{base_msg}; retry scheduled in {retry_after}s "
                                f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                            )

                    result.report_id = str(report_id)
                    attempted.append(result)

                    if result.status == ReportStatus.MANUAL_REQUIRED:
                        try:
                            content = self._build_manual_instructions_text(platform, evidence, result)
                            await self.evidence_store.save_report_instructions(domain, platform, content)
                        except Exception as exc:
                            logger.warning(
                                "Failed to save manual report instructions for %s (%s): %s",
                                domain,
                                platform,
                                exc,
                            )

                    response_data_json = None
                    if result.response_data:
                        try:
                            response_data_json = json.dumps(result.response_data)
                        except Exception:
                            pass

                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                        response_data=response_data_json,
                        retry_after=result.retry_after,
                    )

                    await self._mark_domain_reported_if_needed(domain_id, {platform: result})

                except Exception as exc:
                    logger.exception("Retry reporting failed")
                    try:
                        report_id = int(row.get("id") or 0)
                        if report_id:
                            await self.database.update_report(
                                report_id=report_id,
                                status=ReportStatus.RATE_LIMITED.value,
                                response=f"Retry worker error: {exc}",
                                retry_after=300,
                            )
                    except Exception:
                        pass
            except Exception as exc:
                logger.exception("Retry worker failed for report row")
                try:
                    report_id = int(row.get("id") or 0)
                    if report_id:
                        await self.database.update_report(
                            report_id=report_id,
                            status=ReportStatus.RATE_LIMITED.value,
                            response=f"Retry worker error: {exc}",
                            retry_after=300,
                        )
                except Exception:
                    pass

        return attempted
