"""Shared helpers/constants for the dashboard server."""

from __future__ import annotations

import difflib
import hashlib
import html
import json
from pathlib import Path
from typing import Iterable

from ..storage.database import DomainStatus
from ..utils.domain_similarity import (
    DOMAIN_SIMILARITY_LIMIT,
    DOMAIN_SIMILARITY_MIN_LEN,
    DOMAIN_SIMILARITY_THRESHOLD,
    domain_similarity_key,
)
from ..utils.domains import extract_hostname, registered_domain, strip_port

EVIDENCE_HTML_CSP = (
    "sandbox; "
    "default-src 'none'; "
    "img-src 'self' data:; "
    "style-src 'unsafe-inline'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

SCAMS_CACHE_TTL_SECONDS = 24 * 60 * 60


def _escape(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _coerce_int(value: object, *, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    if min_value is not None:
        parsed = max(min_value, parsed)
    if max_value is not None:
        parsed = min(max_value, parsed)
    return parsed


def _extract_hostname(value: str) -> str:
    return extract_hostname(value)


def _strip_port(host: str) -> str:
    return strip_port(host)


def _candidate_parent_domains(host: str) -> list[str]:
    raw = (host or "").strip().lower().strip(".")
    if not raw:
        return []
    host = _strip_port(raw)
    if not host:
        return []
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            candidates.append(value)

    root = registered_domain(host)
    _add(host)
    if not root:
        return candidates
    labels = host.split(".")
    root_labels = root.split(".")
    root_len = len(root_labels)
    if len(labels) > root_len:
        for idx in range(len(labels) - root_len):
            parent = ".".join(labels[idx + 1 :])
            _add(parent)
    return candidates


def _format_public_submission_notes(
    submitted_url: str | None,
    source_url: str | None,
    reporter_notes: str | None,
) -> str | None:
    parts: list[str] = []
    submitted_value = (submitted_url or "").strip()
    if submitted_value:
        parts.append(f"Submitted URL: {submitted_value}")
    source_value = (source_url or "").strip()
    if source_value:
        parts.append(f"Seen at: {source_value}")
    notes_value = (reporter_notes or "").strip()
    if notes_value:
        parts.append(f"Why suspicious: {notes_value}")
    return "\n".join(parts) if parts else None


def _is_active_threat_record(record: dict) -> bool:
    status = str(record.get("status") or "").strip().lower()
    if status in {
        DomainStatus.WATCHLIST.value,
        DomainStatus.ALLOWLISTED.value,
        DomainStatus.FALSE_POSITIVE.value,
    }:
        return False
    takedown = str(record.get("takedown_status") or "").strip().lower()
    if takedown in {"confirmed_down", "likely_down"}:
        return False
    return True


def _existing_submission_message(record: dict) -> str:
    if _is_active_threat_record(record):
        return "Already in Active Threats"
    status = str(record.get("status") or "").strip().lower()
    takedown = str(record.get("takedown_status") or "").strip().lower()
    detail = ""
    if takedown in {"confirmed_down", "likely_down"}:
        detail = f"takedown: {takedown}"
    elif status in {
        DomainStatus.ALLOWLISTED.value,
        DomainStatus.FALSE_POSITIVE.value,
        DomainStatus.WATCHLIST.value,
    }:
        detail = f"status: {status}"
    elif status:
        detail = f"status: {status}"
    if detail:
        return f"Already in system ({detail})"
    return "Already in system"


def _domain_similarity_key(domain: str) -> str:
    return domain_similarity_key(domain)


def _domain_similarity_pairs(members: Iterable[dict], *, limit: int = DOMAIN_SIMILARITY_LIMIT) -> list[dict]:
    labels: list[tuple[str, str]] = []
    for member in members:
        domain = str(member.get("domain") or "")
        if not domain:
            continue
        labels.append((domain, _domain_similarity_key(domain)))

    pairs: list[dict] = []
    for idx, (left_domain, left_label) in enumerate(labels):
        if not left_label or len(left_label) < DOMAIN_SIMILARITY_MIN_LEN:
            continue
        for right_domain, right_label in labels[idx + 1 :]:
            if not right_label or min(len(left_label), len(right_label)) < DOMAIN_SIMILARITY_MIN_LEN:
                continue
            ratio = difflib.SequenceMatcher(None, left_label, right_label).ratio()
            if ratio >= DOMAIN_SIMILARITY_THRESHOLD:
                pairs.append({
                    "left": left_domain,
                    "right": right_domain,
                    "similarity": round(ratio, 2),
                })

    if not pairs:
        return []
    pairs.sort(key=lambda item: (-item["similarity"], item["left"], item["right"]))
    return pairs[:limit]


def _try_relative_to(path: Path, base: Path) -> Path | None:
    try:
        return path.resolve().relative_to(base.resolve())
    except Exception:
        return None


def _domain_dir_name(domain: str) -> str:
    """Replicate EvidenceStore directory naming for cross-process use."""
    domain_hash = hashlib.sha256(domain.lower().encode()).hexdigest()[:12]
    safe_domain = "".join(c if c.isalnum() or c in ".-" else "_" for c in domain)
    return f"{safe_domain}_{domain_hash}"


def _format_bytes(num: int) -> str:
    """Human-readable bytes."""
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(num or 0)
    for unit in units:
        if n < step:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= step
    return f"{n:.1f} PB"


def _display_domain(domain: str) -> str:
    raw = (domain or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if lowered.startswith("www.") and len(raw) > 4:
        return raw[4:]
    return raw


def _status_badge(value: str) -> str:
    status = (value or "").strip().lower() or "unknown"
    badge_class = f"sb-badge sb-badge-{status}"
    return f'<span class="{badge_class}">{_escape(status)}</span>'


def _verdict_badge(value: str | None) -> str:
    verdict = (value or "").strip().lower() or "unknown"
    badge_class = f"sb-badge sb-badge-{verdict}"
    return f'<span class="{badge_class}">{_escape(verdict)}</span>'


def _report_badge(value: str | None) -> str:
    status = (value or "").strip().lower() or "unknown"
    badge_class = f"sb-badge sb-badge-{status}"
    return f'<span class="{badge_class}">{_escape(status)}</span>'


_DEFAULT_STATUS_OPTIONS = [
    "dangerous",
    "",
    "pending",
    "analyzing",
    "analyzed",
    "reported",
    "failed",
    "watchlist",
    "allowlisted",
    "false_positive",
]
_DEFAULT_VERDICT_OPTIONS = ["", "high", "medium", "low", "benign", "unknown", "false_positive"]
_DEFAULT_DANGEROUS_EXCLUDE = ["watchlist", "false_positive", "allowlisted"]

_options_path = Path(__file__).parent / "frontend" / "src" / "shared_options.json"
try:
    _shared_options = json.loads(_options_path.read_text(encoding="utf-8"))
except Exception:
    _shared_options = {}

STATUS_FILTER_OPTIONS = _shared_options.get("statusOptions", _DEFAULT_STATUS_OPTIONS)
VERDICT_FILTER_OPTIONS = _shared_options.get("verdictOptions", _DEFAULT_VERDICT_OPTIONS)
DANGEROUS_EXCLUDE_STATUSES = _shared_options.get("dangerousExcludeStatuses", _DEFAULT_DANGEROUS_EXCLUDE)

DONATION_WALLET = "kaspa:qqe57lvu4p4zhdlnlj6ne8hu0hgcfwwfzrhcgaenpt056k0hge85k7qtaw3m9"
