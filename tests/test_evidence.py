from src.storage.evidence import EvidenceStore


def test_clear_exploration_screenshots(tmp_path):
    store = EvidenceStore(tmp_path)
    domain = "example.com"

    domain_dir = store.get_domain_dir(domain)
    (domain_dir / "screenshot_exploration_1.png").write_bytes(b"x")
    (domain_dir / "screenshot_exploration_seedform_2.png").write_bytes(b"x")
    (domain_dir / "screenshot.png").write_bytes(b"x")

    removed = store.clear_exploration_screenshots(domain)

    assert removed == 2
    assert not (domain_dir / "screenshot_exploration_1.png").exists()
    assert not (domain_dir / "screenshot_exploration_seedform_2.png").exists()
    assert (domain_dir / "screenshot.png").exists()
