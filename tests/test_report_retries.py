"""Tests for persistent reporting retries and DB migrations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from src.reporter.base import BaseReporter, ReportResult, ReportStatus
from src.reporter.manager import ReportManager
from src.storage.database import Database
from src.storage.evidence import EvidenceStore


class _FakeLimiter:
    def __init__(self, *, can_acquire: bool, wait_seconds: int = 42):
        self._can_acquire = can_acquire
        self._wait_seconds = wait_seconds

    async def acquire(self, timeout: float | None = None) -> bool:  # noqa: ARG002
        return self._can_acquire

    def wait_time(self) -> float:
        return float(self._wait_seconds)


class _FakeReporter(BaseReporter):
    platform_name = "fake"
    rate_limit_per_minute = 60

    def __init__(self):
        super().__init__()
        self._configured = True
        self.calls: int = 0

    async def submit(self, evidence) -> ReportResult:  # noqa: ANN001
        self.calls += 1
        return ReportResult(
            platform="fake",
            status=ReportStatus.SUBMITTED,
            message="ok",
        )


class _AlwaysRateLimitedReporter(BaseReporter):
    platform_name = "limited"
    platform_url = "https://platform.example/report"
    rate_limit_per_minute = 60

    def __init__(self, *, retry_after: int = 60):
        super().__init__()
        self._configured = True
        self._retry_after = retry_after
        self.calls: int = 0

    async def submit(self, evidence) -> ReportResult:  # noqa: ANN001
        self.calls += 1
        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.RATE_LIMITED,
            message="429",
            retry_after=self._retry_after,
        )


@pytest.mark.asyncio
async def test_database_connect_migrates_old_reports_schema(tmp_path: Path):
    db_path = tmp_path / "seedbuster.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                platform TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                submitted_at TIMESTAMP,
                response TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (domain_id) REFERENCES domains(id)
            );
            """
        )

    db = Database(db_path)
    await db.connect()
    await db.close()

    with sqlite3.connect(db_path) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(reports)")]
        assert "attempted_at" in columns
        assert "attempts" in columns
        assert "retry_after" in columns
        assert "next_attempt_at" in columns

        indexes = [row[1] for row in conn.execute("PRAGMA index_list(reports)")]
        assert "idx_reports_status_next_attempt" in indexes


@pytest.mark.asyncio
async def test_get_due_retry_reports_respects_next_attempt_at(tmp_path: Path):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    domain_id = await db.add_domain(domain="example.com", source="manual", domain_score=10)
    assert domain_id is not None

    report_id = await db.add_report(domain_id=domain_id, platform="fake", status="pending")

    await db.update_report(
        report_id=report_id,
        status=ReportStatus.RATE_LIMITED.value,
        response="later",
        retry_after=60,
        next_attempt_at="2999-01-01 00:00:00",
    )
    assert await db.get_due_retry_reports(limit=10) == []

    await db.update_report(
        report_id=report_id,
        status=ReportStatus.RATE_LIMITED.value,
        response="now",
        retry_after=0,
        next_attempt_at="2000-01-01 00:00:00",
    )
    due = await db.get_due_retry_reports(limit=10)
    assert len(due) == 1
    assert int(due[0]["id"]) == report_id

    await db.close()


@pytest.mark.asyncio
async def test_report_manager_persists_rate_limited_and_retry_succeeds(tmp_path: Path, monkeypatch):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    domain_id = await db.add_domain(domain="example.com", source="manual", domain_score=10)
    assert domain_id is not None

    store = EvidenceStore(tmp_path / "evidence")
    reporter = _FakeReporter()
    manager = ReportManager(database=db, evidence_store=store, enabled_platforms=["fake"])
    manager.reporters = {"fake": reporter}

    calls = {"n": 0}

    def fake_get_rate_limiter(*args, **kwargs):  # noqa: ANN001, ARG001
        calls["n"] += 1
        return _FakeLimiter(can_acquire=calls["n"] > 1, wait_seconds=30)

    monkeypatch.setattr("src.reporter.manager.get_rate_limiter", fake_get_rate_limiter)

    results = await manager.report_domain(domain_id=domain_id, domain="example.com", platforms=["fake"])
    assert results["fake"].status == ReportStatus.RATE_LIMITED
    assert reporter.calls == 0

    latest = await db.get_latest_report(domain_id=domain_id, platform="fake")
    assert latest is not None
    report_id = int(latest["id"])
    assert str(latest["status"]).lower() == ReportStatus.RATE_LIMITED.value
    assert latest.get("next_attempt_at")

    # Make it due and retry.
    await db.update_report(
        report_id=report_id,
        status=ReportStatus.RATE_LIMITED.value,
        response="due",
        retry_after=0,
        next_attempt_at="2000-01-01 00:00:00",
    )

    retry_results = await manager.retry_due_reports(limit=10)
    assert len(retry_results) == 1
    assert retry_results[0].status == ReportStatus.SUBMITTED
    assert reporter.calls == 1

    updated = await db.get_latest_report(domain_id=domain_id, platform="fake")
    assert updated is not None
    assert str(updated["status"]).lower() == ReportStatus.SUBMITTED.value

    domain_row = await db.get_domain_by_id(domain_id)
    assert domain_row is not None
    assert domain_row["status"] == "reported"

    await db.close()


@pytest.mark.asyncio
async def test_report_domain_force_bypasses_retry_schedule(tmp_path: Path, monkeypatch):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    domain = "example.com"
    domain_id = await db.add_domain(domain=domain, source="manual", domain_score=10)
    assert domain_id is not None

    store = EvidenceStore(tmp_path / "evidence")
    reporter = _FakeReporter()
    manager = ReportManager(database=db, evidence_store=store, enabled_platforms=["fake"])
    manager.reporters = {"fake": reporter}

    def fake_get_rate_limiter(*args, **kwargs):  # noqa: ANN001, ARG001
        return _FakeLimiter(can_acquire=True, wait_seconds=1)

    monkeypatch.setattr("src.reporter.manager.get_rate_limiter", fake_get_rate_limiter)

    report_id = await db.add_report(domain_id=domain_id, platform="fake", status="pending")
    await db.update_report(
        report_id=report_id,
        status=ReportStatus.RATE_LIMITED.value,
        response="later",
        retry_after=60,
        next_attempt_at="2999-01-01 00:00:00",
    )

    # Without forcing, the manager should respect next_attempt_at.
    results = await manager.report_domain(domain_id=domain_id, domain=domain, platforms=["fake"])
    assert results["fake"].status == ReportStatus.RATE_LIMITED
    assert reporter.calls == 0

    # Forcing should bypass the schedule and attempt submission.
    forced = await manager.report_domain(domain_id=domain_id, domain=domain, platforms=["fake"], force=True)
    assert forced["fake"].status == ReportStatus.SUBMITTED
    assert reporter.calls == 1

    updated = await db.get_latest_report(domain_id=domain_id, platform="fake")
    assert updated is not None
    assert str(updated["status"]).lower() == ReportStatus.SUBMITTED.value
    assert updated.get("next_attempt_at") is None

    await db.close()


@pytest.mark.asyncio
async def test_report_manager_dedupes_successful_report_rows(tmp_path: Path):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    domain_id = await db.add_domain(domain="example.com", source="manual", domain_score=10)
    assert domain_id is not None

    store = EvidenceStore(tmp_path / "evidence")
    reporter = _FakeReporter()
    manager = ReportManager(database=db, evidence_store=store, enabled_platforms=["fake"])
    manager.reporters = {"fake": reporter}

    report_id = await db.add_report(domain_id=domain_id, platform="fake", status=ReportStatus.SUBMITTED.value)
    await db.update_report(report_id=report_id, status=ReportStatus.SUBMITTED.value, response="ok")

    results = await manager.report_domain(domain_id=domain_id, domain="example.com", platforms=["fake"])
    assert results["fake"].status == ReportStatus.DUPLICATE
    assert reporter.calls == 0

    rows = await db.get_reports_for_domain(domain_id)
    assert len(rows) == 1

    await db.close()


@pytest.mark.asyncio
async def test_report_manager_ensure_pending_reports_creates_rows_once(tmp_path: Path):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    domain_id = await db.add_domain(domain="example.com", source="manual", domain_score=10)
    assert domain_id is not None

    store = EvidenceStore(tmp_path / "evidence")
    reporter = _FakeReporter()
    manager = ReportManager(database=db, evidence_store=store, enabled_platforms=["fake"])
    manager.reporters = {"fake": reporter}

    await manager.ensure_pending_reports(domain_id=domain_id)
    rows = await db.get_reports_for_domain(domain_id)
    assert len(rows) == 1
    assert rows[0]["platform"] == "fake"
    assert rows[0]["status"] == ReportStatus.PENDING.value

    # Second call should not create duplicates.
    await manager.ensure_pending_reports(domain_id=domain_id)
    rows = await db.get_reports_for_domain(domain_id)
    assert len(rows) == 1

    await db.close()


@pytest.mark.asyncio
async def test_retry_due_reports_exponential_backoff_increases_retry_after(tmp_path: Path, monkeypatch):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    domain = "example.com"
    domain_id = await db.add_domain(domain=domain, source="manual", domain_score=10)
    assert domain_id is not None

    store = EvidenceStore(tmp_path / "evidence")
    reporter = _AlwaysRateLimitedReporter(retry_after=60)
    manager = ReportManager(database=db, evidence_store=store, enabled_platforms=["limited"])
    manager.reporters = {"limited": reporter}

    report_id = await db.add_report(
        domain_id=domain_id,
        platform="limited",
        status=ReportStatus.RATE_LIMITED.value,
    )

    def fake_get_rate_limiter(*args, **kwargs):  # noqa: ANN001, ARG001
        return _FakeLimiter(can_acquire=True, wait_seconds=1)

    monkeypatch.setattr("src.reporter.manager.get_rate_limiter", fake_get_rate_limiter)

    expected_retry_afters = [60, 120, 240]
    for attempt_number, expected in enumerate(expected_retry_afters, start=1):
        retry_results = await manager.retry_due_reports(limit=10)
        assert len(retry_results) == 1
        assert retry_results[0].status == ReportStatus.RATE_LIMITED
        assert retry_results[0].retry_after == expected

        row = await db.get_latest_report(domain_id=domain_id, platform="limited")
        assert row is not None
        assert int(row["id"]) == report_id
        assert int(row.get("attempts") or 0) == attempt_number
        assert int(row.get("retry_after") or 0) == expected

        # Force the report due again without bumping attempts.
        async with db._lock:
            await db._connection.execute(
                "UPDATE reports SET next_attempt_at = '2000-01-01 00:00:00' WHERE id = ?",
                (report_id,),
            )
            await db._connection.commit()

    assert reporter.calls == len(expected_retry_afters)
    await db.close()


@pytest.mark.asyncio
async def test_retry_due_reports_flips_to_manual_required_after_max_attempts(tmp_path: Path, monkeypatch):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    domain = "example.com"
    domain_id = await db.add_domain(domain=domain, source="manual", domain_score=10)
    assert domain_id is not None

    store = EvidenceStore(tmp_path / "evidence")
    reporter = _AlwaysRateLimitedReporter(retry_after=60)
    manager = ReportManager(database=db, evidence_store=store, enabled_platforms=["limited"])
    manager.reporters = {"limited": reporter}

    report_id = await db.add_report(
        domain_id=domain_id,
        platform="limited",
        status=ReportStatus.RATE_LIMITED.value,
    )

    def fake_get_rate_limiter(*args, **kwargs):  # noqa: ANN001, ARG001
        return _FakeLimiter(can_acquire=True, wait_seconds=1)

    monkeypatch.setattr("src.reporter.manager.get_rate_limiter", fake_get_rate_limiter)

    # Retry until the manager gives up and switches to manual_required.
    for _ in range(ReportManager.MAX_RATE_LIMIT_ATTEMPTS):
        retry_results = await manager.retry_due_reports(limit=10)
        assert len(retry_results) == 1
        assert retry_results[0].status == ReportStatus.RATE_LIMITED

        async with db._lock:
            await db._connection.execute(
                "UPDATE reports SET next_attempt_at = '2000-01-01 00:00:00' WHERE id = ?",
                (report_id,),
            )
            await db._connection.commit()

    final_results = await manager.retry_due_reports(limit=10)
    assert len(final_results) == 1
    assert final_results[0].status == ReportStatus.MANUAL_REQUIRED

    row = await db.get_latest_report(domain_id=domain_id, platform="limited")
    assert row is not None
    assert str(row.get("status") or "").lower() == ReportStatus.MANUAL_REQUIRED.value
    assert row.get("next_attempt_at") is None

    instruction_path = store.get_report_instructions_path(domain, "limited")
    assert instruction_path.exists()
    content = instruction_path.read_text(encoding="utf-8")
    assert "SeedBuster Manual Report Instructions" in content
    assert "Manual URL: https://platform.example/report" in content

    assert reporter.calls == ReportManager.MAX_RATE_LIMIT_ATTEMPTS + 1
    await db.close()
