from src.utils.allowlist import read_allowlist, write_allowlist
from src.utils.domain_similarity import domain_similarity_key, domain_similarity_key_from_host
from src.utils.domains import ensure_url, extract_first_url, extract_hostname
from src.utils.files import safe_filename_component
from src.storage.rankings import verdict_escalated
from src.utils.reporting import select_report_url


def test_ensure_url_adds_scheme():
    assert ensure_url("example.com") == "https://example.com"


def test_ensure_url_preserves_scheme():
    assert ensure_url("http://example.com") == "http://example.com"


def test_extract_first_url_strips_punctuation():
    text = "See https://example.com/path)."
    assert extract_first_url(text) == "https://example.com/path"


def test_extract_hostname_strips_port_and_lowercases():
    assert extract_hostname("HTTPS://Example.com:8080/test") == "example.com"


def test_allowlist_read_write_roundtrip(tmp_path):
    path = tmp_path / "allowlist.txt"
    write_allowlist(path, {"example.com", "test.com"})
    loaded = read_allowlist(path)
    assert loaded == {"example.com", "test.com"}


def test_domain_similarity_key_multitenant():
    assert domain_similarity_key("alpha.vercel.app") == "alpha"
    assert domain_similarity_key_from_host("vercel.app") == ""


def test_safe_filename_component_defaults_and_limits():
    assert safe_filename_component("", default="unknown") == "unknown"
    assert safe_filename_component("Hello World", lower=True) == "hello_world"
    assert safe_filename_component("abc" * 10, max_length=5) == "abcab"


def test_verdict_escalated():
    assert verdict_escalated("high", "medium") is True
    assert verdict_escalated("low", "medium") is False


def test_select_report_url_prefers_initial_on_domain_change():
    url = select_report_url(
        "example.com",
        final_url="https://other.com/path",
        initial_url="https://example.com/start",
        final_domain="other.com",
    )
    assert url == "https://example.com/start"


def test_select_report_url_prefers_final_when_same_domain():
    url = select_report_url(
        "example.com",
        final_url="https://example.com/final",
        initial_url="https://example.com/start",
        final_domain="example.com",
    )
    assert url == "https://example.com/final"
