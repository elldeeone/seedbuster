"""Network exfiltration helpers."""

from __future__ import annotations

from urllib.parse import urlparse

from .browser import BrowserResult


class DetectorNetworkMixin:
    """Network exfiltration helpers."""

    def _detect_exfiltration(self, result: BrowserResult) -> tuple[int, list[str], list[str]]:
        """Detect data exfiltration patterns using threat intel."""
        score = 0
        reasons: list[str] = []
        suspicious: list[str] = []
        seen_suspicious: set[str] = set()
        intel = self._threat_intel
        target_host = ""
        try:
            target_url = result.domain if "://" in result.domain else f"https://{result.domain}"
            target_host = (urlparse(target_url).hostname or "").lower()
        except Exception:
            target_host = ""

        def add_suspicious(value: str) -> None:
            v = (value or "").strip()
            if not v or v in seen_suspicious:
                return
            seen_suspicious.add(v)
            suspicious.append(v)

        for submission in result.form_submissions:
            url = (submission.get("url") or "").strip()
            if not url:
                continue

            submission_host = ""
            try:
                submission_host = (urlparse(url).hostname or "").lower()
            except Exception:
                submission_host = ""

            pattern_matches = intel.check_malicious_patterns(url)
            for match in pattern_matches:
                score += 15
                reasons.append(f"Malicious URL pattern: {match.value}")
                add_suspicious(url)

            is_external = False
            if submission_host and target_host:
                is_external = submission_host != target_host
            elif submission_host and not target_host:
                is_external = submission_host not in (result.domain.split("/")[0].lower(), "")
            else:
                is_external = False

            if is_external:
                if intel.is_malicious_url(url):
                    score += 25
                    reasons.append(f"External exfiltration to known malicious host: {submission_host}")
                    add_suspicious(url)
                elif intel.is_suspicious_domain(submission_host):
                    score += 15
                    reasons.append(f"External exfiltration to suspicious domain: {submission_host}")
                    add_suspicious(url)
                else:
                    score += 30
                    reasons.append(f"External form submission: {submission_host}")
                    add_suspicious(url)

        for endpoint in result.external_requests:
            if endpoint in (target_host, ""):
                continue
            if intel.is_malicious_url(endpoint):
                score += 20
                reasons.append(f"External request to malicious host: {endpoint}")
                add_suspicious(endpoint)
            elif intel.is_suspicious_domain(endpoint):
                score += 10
                reasons.append(f"External request to suspicious domain: {endpoint}")
                add_suspicious(endpoint)

        if result.html:
            indicators = intel.check_exfiltration_indicators(result.html)
            for indicator in indicators:
                score += 10
                reasons.append(f"Exfiltration pattern: {indicator.value}")

            fingerprint_indicators = []
            if "toDataURL" in result.html or "getImageData" in result.html:
                fingerprint_indicators.append("canvas")
            if "WEBGL_debug_renderer_info" in result.html or "getParameter(37" in result.html:
                fingerprint_indicators.append("webgl")
            if "AudioContext" in result.html and "createOscillator" in result.html:
                fingerprint_indicators.append("audio")

            if len(fingerprint_indicators) >= 2:
                score += 10
                reasons.append(f"Device fingerprinting: {', '.join(fingerprint_indicators)}")

        return score, reasons, suspicious
