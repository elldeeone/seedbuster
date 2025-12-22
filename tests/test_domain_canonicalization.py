import pytest

from src.storage.database import Database


@pytest.mark.asyncio
async def test_add_domain_dedupes_www_and_updates_score(tmp_path):
    db = Database(tmp_path / "canon.db")
    await db.connect()

    first_id = await db.add_domain("www.example.com", source="manual", domain_score=10)
    second_id = await db.add_domain("example.com", source="manual", domain_score=25)

    assert first_id == second_id

    row = await db.get_domain("example.com")
    assert row is not None
    assert row["canonical_domain"] == "example.com"
    assert row["domain_score"] == 25  # updated to higher score
    assert await db.domain_exists("www.example.com") is True
    assert await db.domain_exists("example.com") is True

    await db.close()


@pytest.mark.asyncio
async def test_merge_duplicate_domains_moves_children(tmp_path):
    db = Database(tmp_path / "merge.db")
    await db.connect()

    # Insert duplicates manually to simulate pre-canonical rows
    async with db._lock:
        await db._connection.executescript(
            """
            INSERT INTO domains (id, domain, canonical_domain, domain_score, analysis_score, verdict, status)
            VALUES (1, 'www.dupe.test', 'dupe.test', 10, 20, 'medium', 'analyzed');
            INSERT INTO domains (id, domain, canonical_domain, domain_score, analysis_score, verdict, status, evidence_path)
            VALUES (2, 'dupe.test', 'dupe.test', 30, 80, 'high', 'reported', '/tmp/evidence/dupe');
            """
        )
        await db._connection.execute(
            "INSERT INTO evidence (domain_id, type, path) VALUES (1, 'html', '/tmp/evidence/www/page.html')"
        )
        await db._connection.execute(
            "INSERT INTO reports (domain_id, platform, status) VALUES (1, 'abuse', 'pending')"
        )
        await db._connection.commit()

    merged = await db._merge_canonical_duplicates()
    assert merged == 1

    async with db._lock:
        cursor = await db._connection.execute("SELECT id, domain, canonical_domain, domain_score, analysis_score, verdict, status, evidence_path FROM domains")
        rows = [dict(r) for r in await cursor.fetchall()]
    assert len(rows) == 1
    row = rows[0]
    assert row["domain"] == "dupe.test"  # kept primary with better score
    assert row["canonical_domain"] == "dupe.test"
    assert row["domain_score"] == 30
    assert row["analysis_score"] == 80
    assert row["verdict"] == "high"
    assert row["status"] == "reported"
    assert row["evidence_path"] == "/tmp/evidence/dupe"

    async with db._lock:
        cursor = await db._connection.execute("SELECT domain_id FROM evidence")
        evidence_ids = [r[0] for r in await cursor.fetchall()]
        cursor = await db._connection.execute("SELECT domain_id FROM reports")
        report_ids = [r[0] for r in await cursor.fetchall()]
    assert evidence_ids == [row["id"]]
    assert report_ids == [row["id"]]

    await db.close()
