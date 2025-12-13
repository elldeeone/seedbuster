from src.analyzer.temporal import TemporalTracker, ScanReason


def test_temporal_cloaking_seed_form_toggle(tmp_path):
    tracker = TemporalTracker(tmp_path)
    domain = "example.com"

    tracker.add_snapshot(
        domain=domain,
        score=100,
        verdict="high",
        reasons=["Seed phrase form found via exploration: 'Recover from Seed'"],
        scan_reason=ScanReason.INITIAL,
    )
    tracker.add_snapshot(
        domain=domain,
        score=100,
        verdict="high",
        reasons=["Kaspa-related title"],
        scan_reason=ScanReason.RESCAN_6H,
    )

    analysis = tracker.analyze(domain)
    assert analysis.cloaking_detected
    assert analysis.cloaking_pattern == "seed_form_toggle"
    assert any("seed form appears/disappears" in r.lower() for r in analysis.temporal_reasons)
