"""Token extraction helpers for visual matching."""

from __future__ import annotations

import html as html_lib
import re
from html.parser import HTMLParser

STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "your",
    "you",
    "are",
    "was",
    "were",
    "will",
    "have",
    "has",
    "had",
    "not",
    "but",
    "all",
    "any",
    "can",
    "our",
    "their",
    "they",
    "them",
    "his",
    "her",
    "she",
    "him",
    "its",
    "into",
    "out",
    "over",
    "more",
    "less",
    "new",
    "old",
    "about",
    "use",
    "using",
    "click",
    "continue",
}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[override]
        if tag in {"script", "style", "noscript", "svg", "canvas"}:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:  # type: ignore[override]
        if tag in {"script", "style", "noscript", "svg", "canvas"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:  # type: ignore[override]
        if self._skip_depth:
            return
        if data and data.strip():
            self._chunks.append(data)

    def text(self) -> str:
        return " ".join(self._chunks)


def _normalize_text(text: str) -> str:
    text = html_lib.unescape(text or "")
    if "<" in text and ">" in text:
        text = text[:200000]
        parser = _TextExtractor()
        parser.feed(text)
        raw = parser.text()
    else:
        raw = text
    raw = re.sub(r"\\s+", " ", raw)
    return raw.strip()


def _extract_tokens(text: str, *, limit: int = 200) -> list[str]:
    text = (text or "").lower()
    domains = re.findall(r"[a-z0-9][a-z0-9-]{1,63}(?:\\.[a-z0-9-]{2,})+", text)
    raw = re.findall(r"[a-z0-9]{3,}", text)
    tokens = []
    seen = set()
    for token in domains + raw:
        if token in STOPWORDS or token in seen:
            continue
        if len(token) > 40:
            continue
        seen.add(token)
        tokens.append(token)
        if len(tokens) >= limit:
            break
    return tokens


def _extract_attribute_tokens(raw_html: str, *, limit: int = 120) -> list[str]:
    if not raw_html:
        return []
    raw_html = raw_html[:200000]
    urls = re.findall(r"(?i)(?:href|src)=['\"]([^'\"]+)['\"]", raw_html)
    urls += re.findall(r"(?i)url\\(['\"]?([^'\")]+)['\"]?\\)", raw_html)
    tokens: list[str] = []
    seen = set()
    for url in urls:
        url = url.split("#", 1)[0].split("?", 1)[0]
        if not url:
            continue
        domains = re.findall(r"[a-z0-9][a-z0-9-]{1,63}(?:\\.[a-z0-9-]{2,})+", url.lower())
        for domain in domains:
            if domain in STOPWORDS or domain in seen:
                continue
            seen.add(domain)
            tokens.append(domain)
            if len(tokens) >= limit:
                return tokens
        filename = url.rstrip("/").split("/")[-1].lower()
        filename = re.sub(r"[^a-z0-9]+", " ", filename).strip()
        for token in filename.split():
            if len(token) < 3 or token in STOPWORDS or token in seen:
                continue
            seen.add(token)
            tokens.append(token)
            if len(tokens) >= limit:
                return tokens
    return tokens


def extract_visual_tokens(text: str, raw_html: str) -> list[str]:
    normalized = _normalize_text(text)
    tokens = _extract_tokens(normalized)
    tokens.extend(_extract_attribute_tokens(raw_html))

    deduped: list[str] = []
    seen = set()
    for token in tokens:
        if token in seen:
            continue
        seen.add(token)
        deduped.append(token)
        if len(deduped) >= 300:
            break
    return deduped
