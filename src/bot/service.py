"""Business logic helpers for the Telegram bot."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .formatters import AlertFormatter
from ..storage.database import DomainStatus


@dataclass
class KeyboardButton:
    text: str
    callback_data: str


@dataclass
class SubmitResponse:
    message: str
    buttons: list[list[KeyboardButton]] = field(default_factory=list)


@dataclass
class BulkSubmitResult:
    submitted: int = 0
    duplicates: int = 0
    invalid: int = 0

    def summary(self) -> str:
        parts = [
            f"Submitted: {self.submitted}",
            f"Duplicates: {self.duplicates}",
            f"Invalid: {self.invalid}",
        ]
        return "\n".join(parts)


class BotService:
    """Encapsulates non-UI logic for the Telegram bot."""

    def __init__(
        self,
        *,
        database,
        evidence_store,
        report_manager=None,
        queue_size_callback: Optional[Callable[[], int]] = None,
        submit_callback: Optional[Callable[[str], None]] = None,
        rescan_callback: Optional[Callable[[str], None]] = None,
    ):
        self.database = database
        self.evidence_store = evidence_store
        self.report_manager = report_manager
        self.queue_size_callback = queue_size_callback
        self.submit_callback = submit_callback
        self.rescan_callback = rescan_callback
        self._recent_cache_limit = 200

    async def format_status(self, *, is_running: bool) -> str:
        stats = await self.database.get_stats()
        queue_size = self.queue_size_callback() if self.queue_size_callback else 0
        return AlertFormatter.format_status(stats=stats, queue_size=queue_size, is_running=is_running)

    async def format_recent(self, *, limit: int) -> str:
        domains = await self.database.get_recent_domains(limit=limit)
        return AlertFormatter.format_recent(domains, limit)

    async def submit(self, raw_input: str) -> SubmitResponse:
        """Handle domain submission (existing vs new)."""
        url_input = (raw_input or "").lower()
        url_input = url_input.replace("https://", "").replace("http://", "")

        if "/" in url_input:
            domain = url_input.split("/")[0]
            path = "/" + "/".join(url_input.split("/")[1:])
            full_url = f"{domain}{path}"
        else:
            domain = url_input
            path = ""
            full_url = domain

        existing = await self.database.get_domain(full_url) or await self.database.get_domain(domain)
        if existing:
            existing_domain = existing.get("domain", domain)
            score = existing.get("analysis_score") or 0
            verdict = existing.get("verdict", "unknown")
            status = existing.get("status", "unknown")
            analyzed_at = existing.get("analyzed_at", "unknown")
            domain_id = self.evidence_store.get_domain_id(existing_domain)

            rows: list[list[KeyboardButton]] = []
            if path and path not in existing_domain:
                rows.append([KeyboardButton(text=f"🔍 Scan {path}", callback_data=f"scanpath_{full_url[:50]}")])
                rows.append([
                    KeyboardButton(text="🔄 Rescan Base", callback_data=f"rescan_{domain_id}"),
                    KeyboardButton(text="📁 Evidence", callback_data=f"evidence_{domain_id}"),
                ])
            else:
                rows.append([
                    KeyboardButton(text="🔄 Rescan Now", callback_data=f"rescan_{domain_id}"),
                    KeyboardButton(text="📁 Evidence", callback_data=f"evidence_{domain_id}"),
                ])
            rows.append([KeyboardButton(text="📊 Report Status", callback_data=f"status_{domain_id}")])

            path_note = f"\n\n_Path `{path}` not yet analyzed._" if path and path not in existing_domain else ""
            message = (
                f"*Domain already analyzed:* `{existing_domain}`\n\n"
                f"Score: {score}/100 ({verdict})\n"
                f"Status: {status}\n"
                f"Analyzed: {analyzed_at}{path_note}\n\n"
                "Choose an action below:"
            )
            return SubmitResponse(message=message, buttons=rows)

        if self.submit_callback:
            self.submit_callback(full_url)
        display = full_url if path else domain
        return SubmitResponse(message=f"Submitted `{display}` for analysis.")

    async def bulk_submit(self, raw_text: str) -> BulkSubmitResult:
        """Handle bulk submissions; returns counts."""
        if not raw_text:
            return BulkSubmitResult()

        candidates: list[str] = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith(("url", "age", "size", "ips", "asns")):
                continue
            first = line.split()[0]
            candidates.append(first)
        if not candidates:
            candidates = raw_text.split()

        def normalize(token: str) -> str | None:
            t = (token or "").strip().strip("`'\"(),;")
            if not t:
                return None
            t = t.replace("https://", "").replace("http://", "")
            t = t.strip().strip("`'\"(),;")
            if not t or "." not in t:
                return None
            return t.lower()

        normalized: list[str] = []
        seen = set()
        invalid = 0
        for token in candidates:
            norm = normalize(token)
            if not norm:
                invalid += 1
                continue
            if norm in seen:
                continue
            seen.add(norm)
            normalized.append(norm)

        max_batch = 200
        if len(normalized) > max_batch:
            normalized = normalized[:max_batch]

        result = BulkSubmitResult()
        for domain in normalized:
            existing = await self.database.get_domain(domain)
            if existing:
                result.duplicates += 1
                continue
            if self.submit_callback:
                self.submit_callback(domain)
            result.submitted += 1

        result.invalid = invalid
        return result

    def rescan(self, domain: str) -> str:
        if self.rescan_callback:
            try:
                self.rescan_callback(domain)
                return f"Rescan queued for `{domain}`"
            except Exception as exc:  # pragma: no cover - defensive
                return f"Failed to queue rescan: {exc}"
        return "Rescan unavailable."

    async def find_by_short_id(self, prefix: str):
        domains = await self.database.get_recent_domains(limit=self._recent_cache_limit)
        for d in domains:
            try:
                if self.evidence_store.get_domain_id(d["domain"]).startswith(prefix):
                    return d
            except Exception:
                continue
        return None

    async def mark_false_positive(self, short_id: str) -> str:
        target = await self.find_by_short_id(short_id)
        if not target:
            return f"Domain not found: {short_id}"
        await self.database.mark_false_positive(target["id"])
        return (
            f"Marked as false positive: `{target['domain']}`\n"
            "Consider adding to allowlist with `/allowlist add <domain>`"
        )

    async def acknowledge(self, short_id: str) -> str:
        target = await self.find_by_short_id(short_id)
        if not target:
            return f"Domain not found: {short_id}"
        await self.database.update_domain_status(target["id"], DomainStatus.ANALYZED)
        return f"Acknowledged: `{target['domain']}`"

    async def defer(self, short_id: str) -> str:
        target = await self.find_by_short_id(short_id)
        if not target:
            return f"Domain not found: {short_id}"
        await self.database.update_domain_status(target["id"], DomainStatus.DEFERRED)
        return (
            f"\U0001F551 Deferred: `{target['domain']}`\n\n"
            "Waiting for rescans at 6h/12h/24h/48h intervals.\n"
            "You'll receive an update when rescans complete."
        )
