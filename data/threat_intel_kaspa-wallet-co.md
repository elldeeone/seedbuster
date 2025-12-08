# Threat Intelligence Report: kaspa-wallet.co

**Analysis Date:** 2025-12-08
**Status:** CONFIRMED MALICIOUS - Seed Phrase Stealer

## Infrastructure Summary

| Component | Value |
|-----------|-------|
| Domain | kaspa-wallet.co |
| IP | 172.66.0.96 (Cloudflare proxy) |
| Hosting | DigitalOcean App Platform |
| SSL Issuer | Google Trust Services |
| SSL Issued | Oct 15, 2025 (~2 months old) |
| Server | Cloudflare + Express.js backends |

## Exfiltration Infrastructure

### Backend 1: Walrus (IP Logging)
- **URL:** `https://walrus-app-o5hvw.ondigitalocean.app`
- **Endpoint:** `/log-ip`
- **DO App ID:** `b0c0ead8-1bbd-460c-b129-4ff9d4e4e1a8`
- **Purpose:** Log visitor IP addresses for fingerprinting

### Backend 2: Whale (Form Exfiltration)
- **URL:** `https://whale-app-poxe2.ondigitalocean.app`
- **Endpoints:**
  - `/api/form/` - Main form submission
  - `/api/form/text` - Text data
- **DO App ID:** `96092792-7c82-4298-b718-cadf3b84ad46`
- **Auth:** Requires `x-api-key` header
- **API Key:** `e7a25d99-66d4-4a1b-a6e0-3f2e93f25f1b`
- **Purpose:** **SEED PHRASE EXFILTRATION**

## Exposed API Keys

| Service | API Key | Purpose |
|---------|---------|---------|
| ipdata.co | `520a83d66268292f5b97ca64c496ef3b9cfb1bb1f85f2615b103f66f` | Visitor geolocation & threat scoring |
| Whale API | `e7a25d99-66d4-4a1b-a6e0-3f2e93f25f1b` | Backend authentication |

## Anti-Detection Techniques

1. **Device Fingerprinting** - Persistent tracking across IPs and sessions
2. **ipdata.co Integration** - IP reputation checking
3. **Content Switching** - Shows different content to bots vs real users
4. **Decoy Landing Page** - Legitimate-looking Kaspa info page for scanners

## Security Header Analysis

**Missing Critical Headers:**
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security

(Real wallet applications implement these for security)

## IOCs (Indicators of Compromise)

### Domains
```
kaspa-wallet.co
walrus-app-o5hvw.ondigitalocean.app
whale-app-poxe2.ondigitalocean.app
```

### IPs
```
172.66.0.96 (Cloudflare, not the origin)
```

### API Keys (for detection)
```
520a83d66268292f5b97ca64c496ef3b9cfb1bb1f85f2615b103f66f (ipdata)
e7a25d99-66d4-4a1b-a6e0-3f2e93f25f1b (whale backend)
```

### URL Patterns
```
/log-ip
/api/form/
/api/form/text
```

## Recommendations

1. **Block domains** in firewall/DNS
2. **Report to:** Google Safe Browsing, PhishTank, DigitalOcean abuse
3. **Alert Kaspa community** about this specific scam
4. **Monitor** for similar "whale/walrus" infrastructure naming pattern

## Scammer Profile Notes

- Uses animal-themed naming (walrus, whale)
- Uses DigitalOcean App Platform for backends
- Uses Cloudflare for DDoS protection
- Sophisticated anti-bot measures
- React-based frontend
- Express.js backends with CORS enabled
