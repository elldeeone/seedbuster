"""Database schema creation helpers."""

from __future__ import annotations


class DatabaseSchemaMixin:
    """Database schema creation helpers."""

    async def _create_tables(self) -> None:
        """Create database tables if they don't exist."""
        async with self._lock:
            await self._connection.executescript(
                """
                    CREATE TABLE IF NOT EXISTS domains (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT UNIQUE NOT NULL,
                        canonical_domain TEXT,
                        watchlist_baseline_timestamp TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        source TEXT DEFAULT 'certstream',
                        source_url TEXT,
                        domain_score INTEGER DEFAULT 0,
                        analysis_score INTEGER,
                        verdict TEXT,
                        verdict_reasons TEXT,
                        operator_notes TEXT,
                        status TEXT DEFAULT 'pending',
                        scam_type TEXT,
                        analyzed_at TIMESTAMP,
                        reported_at TIMESTAMP,
                        takedown_status TEXT DEFAULT 'active',
                        takedown_detected_at TIMESTAMP,
                        takedown_confirmed_at TIMESTAMP,
                        takedown_override BOOLEAN DEFAULT FALSE,
                        takedown_override_at TIMESTAMP,
                        evidence_path TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS evidence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        type TEXT NOT NULL,
                        path TEXT NOT NULL,
                        hash TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );

                    CREATE TABLE IF NOT EXISTS reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        platform TEXT NOT NULL,
                        status TEXT DEFAULT 'pending',
                        attempted_at TIMESTAMP,
                        submitted_at TIMESTAMP,
                        response TEXT,
                        response_data TEXT,
                        attempts INTEGER DEFAULT 0,
                        retry_after INTEGER,
                        next_attempt_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );

                    CREATE TABLE IF NOT EXISTS dashboard_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        kind TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        target TEXT,
                        bulk_id TEXT,
                        status TEXT DEFAULT 'pending',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        claimed_at TIMESTAMP,
                        processed_at TIMESTAMP,
                        error TEXT
                    );

                    -- Public submissions held for admin review
                    CREATE TABLE IF NOT EXISTS public_submissions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        canonical_domain TEXT NOT NULL,
                        submitted_url TEXT,
                        source_url TEXT,
                        reporter_notes TEXT,
                        submission_count INTEGER DEFAULT 1,
                        first_submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'pending_review',
                        reviewed_at TIMESTAMP,
                        reviewer_notes TEXT,
                        promoted_domain_id INTEGER,
                        UNIQUE(canonical_domain),
                        FOREIGN KEY (promoted_domain_id) REFERENCES domains(id)
                    );

                    -- Engagement tracking for public report clicks (deduped by session)
                    CREATE TABLE IF NOT EXISTS report_engagement (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        platform TEXT NOT NULL,
                        session_hash TEXT NOT NULL,
                        click_count INTEGER DEFAULT 1,
                        first_engaged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_engaged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(domain_id, platform, session_hash),
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );

                    -- Public rescan requests (deduped by session)
                    CREATE TABLE IF NOT EXISTS rescan_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        session_hash TEXT NOT NULL,
                        click_count INTEGER DEFAULT 1,
                        first_requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(domain_id, session_hash),
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );

                    -- Historical takedown checks for domains
                    CREATE TABLE IF NOT EXISTS takedown_checks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain_id INTEGER NOT NULL,
                        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        http_status INTEGER,
                        http_error TEXT,
                        dns_resolves BOOLEAN,
                        dns_result TEXT,
                        is_sinkholed BOOLEAN DEFAULT FALSE,
                        domain_status TEXT,
                        content_hash TEXT,
                        still_phishing BOOLEAN,
                        takedown_status TEXT,
                        confidence REAL,
                        provider_signal TEXT,
                        backend_status INTEGER,
                        backend_error TEXT,
                        backend_target TEXT,
                        FOREIGN KEY (domain_id) REFERENCES domains(id)
                    );
                """
            )
            await self._connection.commit()

        # Migrations must run before creating indexes that reference newer columns,
        # otherwise existing DBs on older schemas would fail to start up.
        await self._migrate_domains_table()
        await self._migrate_takedown_checks_table()
        await self._migrate_reports_table()
        await self._migrate_report_engagement_table()
        await self._migrate_dashboard_actions_table()
        await self._migrate_public_submissions_table()
        await self._migrate_deferred_to_watchlist()
        await self._backfill_canonical_domains(lock_held=True)
        await self._merge_canonical_duplicates()
        await self._create_indexes()

    async def _create_indexes(self) -> None:
        """Create indexes (best-effort, safe for older DBs)."""
        statements = [
            "CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status)",
            "CREATE INDEX IF NOT EXISTS idx_domains_verdict ON domains(verdict)",
            "CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain)",
            "CREATE INDEX IF NOT EXISTS idx_domains_canonical ON domains(canonical_domain)",
            "CREATE INDEX IF NOT EXISTS idx_reports_domain_platform ON reports(domain_id, platform)",
            "CREATE INDEX IF NOT EXISTS idx_reports_status_next_attempt ON reports(status, next_attempt_at)",
            "CREATE INDEX IF NOT EXISTS idx_dashboard_actions_status ON dashboard_actions(status, id)",
            "CREATE INDEX IF NOT EXISTS idx_dashboard_actions_bulk_status ON dashboard_actions(bulk_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_dashboard_actions_kind_target_status ON dashboard_actions(kind, target, status)",
            "CREATE INDEX IF NOT EXISTS idx_public_submissions_status ON public_submissions(status, first_submitted_at)",
            "CREATE INDEX IF NOT EXISTS idx_report_engagement_domain_platform ON report_engagement(domain_id, platform)",
            "CREATE INDEX IF NOT EXISTS idx_report_engagement_last_engaged ON report_engagement(last_engaged_at)",
            "CREATE INDEX IF NOT EXISTS idx_rescan_requests_domain ON rescan_requests(domain_id)",
            "CREATE INDEX IF NOT EXISTS idx_rescan_requests_last_requested ON rescan_requests(last_requested_at)",
            "CREATE INDEX IF NOT EXISTS idx_takedown_checks_domain ON takedown_checks(domain_id, checked_at DESC)",
        ]

        for stmt in statements:
            try:
                await self._connection.execute(stmt)
            except Exception:
                continue
        await self._connection.commit()
