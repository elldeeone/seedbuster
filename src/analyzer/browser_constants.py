"""Browser analyzer constants and helpers."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

# Known anti-bot/fingerprinting services to block
ANTIBOT_DOMAINS = {
    "ipdata.co",
    "ipinfo.io",
    "ipapi.co",
    "ip-api.com",
    "ipgeolocation.io",
    "ipify.org",
    "api.ipify.org",
    "fingerprint.com",
    "fpjs.io",
    "arkoselabs.com",
    "funcaptcha.com",
    "datadome.co",
    "perimeterx.net",
    "px-cdn.net",
    "hcaptcha.com",
    "recaptcha.net",
    "gstatic.com/recaptcha",
    "challenges.cloudflare.com",
    "kasada.io",
    "queue-it.net",
    "distil.net",
    "imperva.com",
    "incapsula.com",
}

# Realistic user agents for stealth mode
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
META_REFRESH_RE = re.compile(r"<meta[^>]+http-equiv=['\"]?refresh['\"]?[^>]*>", re.IGNORECASE)


def _normalize_url_for_compare(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except Exception:
        return url
    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or ""
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def _extract_meta_refresh_url(html: str) -> Optional[str]:
    if not html:
        return None
    match = META_REFRESH_RE.search(html)
    if not match:
        return None
    tag = match.group(0)
    content_match = re.search(r"content=['\"]?([^'\">]+)", tag, re.IGNORECASE)
    if not content_match:
        return None
    content = content_match.group(1)
    if "url=" not in content.lower():
        return None
    parts = content.split(";", 1)
    if len(parts) < 2:
        return None
    url_part = parts[1].strip()
    if "url=" in url_part.lower():
        url_part = url_part.split("=", 1)[1].strip()
    return url_part or None


STEALTH_SCRIPT = """
// Override navigator.webdriver
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined
});

// Override plugins to look like a real browser
Object.defineProperty(navigator, 'plugins', {
    get: () => [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
        { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' }
    ]
});

// Override languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en']
});

// Fix permissions API
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications' ?
        Promise.resolve({ state: Notification.permission }) :
        originalQuery(parameters)
);

// Fix chrome object
window.chrome = {
    runtime: {},
    loadTimes: function() {},
    csi: function() {},
    app: {}
};

// Ensure consistent screen dimensions
Object.defineProperty(screen, 'availWidth', { get: () => window.innerWidth });
Object.defineProperty(screen, 'availHeight', { get: () => window.innerHeight });

// WebGL fingerprint spoofing
const getParameterProxyHandler = {
    apply: function(target, thisArg, args) {
        const param = args[0];
        const gl = thisArg;
        // Return realistic values for common fingerprinting parameters
        if (param === 37445) return 'Google Inc. (NVIDIA)'; // UNMASKED_VENDOR_WEBGL
        if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)'; // UNMASKED_RENDERER_WEBGL
        return target.apply(thisArg, args);
    }
};
try {
    WebGLRenderingContext.prototype.getParameter = new Proxy(
        WebGLRenderingContext.prototype.getParameter, getParameterProxyHandler
    );
    WebGL2RenderingContext.prototype.getParameter = new Proxy(
        WebGL2RenderingContext.prototype.getParameter, getParameterProxyHandler
    );
} catch(e) {}

// Canvas fingerprint noise injection
const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    if (type === 'image/png' || type === undefined) {
        const context = this.getContext('2d');
        if (context) {
            const imageData = context.getImageData(0, 0, this.width, this.height);
            // Add subtle noise to prevent fingerprinting
            for (let i = 0; i < imageData.data.length; i += 4) {
                imageData.data[i] ^= (Math.random() * 2) | 0;
            }
            context.putImageData(imageData, 0, 0);
        }
    }
    return originalToDataURL.apply(this, arguments);
};

// AudioContext fingerprint spoofing
const originalGetChannelData = AudioBuffer.prototype.getChannelData;
AudioBuffer.prototype.getChannelData = function(channel) {
    const result = originalGetChannelData.apply(this, arguments);
    // Add subtle noise
    for (let i = 0; i < result.length; i += 100) {
        result[i] += (Math.random() * 0.0001);
    }
    return result;
};

// Prevent detection via connection info
Object.defineProperty(navigator, 'connection', {
    get: () => ({
        effectiveType: '4g',
        rtt: 50,
        downlink: 10,
        saveData: false
    })
});

// Mock battery API (often used for fingerprinting)
navigator.getBattery = () => Promise.resolve({
    charging: true,
    chargingTime: 0,
    dischargingTime: Infinity,
    level: 1.0
});
"""
