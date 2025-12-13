from src.analyzer.browser import BrowserAnalyzer


def test_extract_navigation_target_from_onclick_location_href():
    assert (
        BrowserAnalyzer._extract_navigation_target_from_onclick("window.location.href='Home.html'")
        == "Home.html"
    )


def test_extract_navigation_target_from_onclick_location_assign():
    assert (
        BrowserAnalyzer._extract_navigation_target_from_onclick('window.location="https://example.com/path"')
        == "https://example.com/path"
    )


def test_extract_navigation_target_from_onclick_none():
    assert BrowserAnalyzer._extract_navigation_target_from_onclick("") is None
