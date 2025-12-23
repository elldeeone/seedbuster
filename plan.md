# SeedBuster Public Features Plan

## Overview

This plan outlines three interconnected features for the public-facing SeedBuster dashboard:

1. **Public Domain Submission** - Allow community to submit suspicious domains (held for review)
2. **Public Reporting with Counters** - Expose manual report functionality with engagement tracking
3. **Takedown Detection** - Monitor and track when reported sites go offline

---

## 1. Public Domain Submission

### Goals
- Allow the public to submit suspicious domains they've discovered
- Submissions are held for admin review (not auto-scanned)
- Prevent abuse vectors (no direct scan triggering, no vulnerability injection)

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS public_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    canonical_domain TEXT NOT NULL,  -- Normalized for dedup
    source_url TEXT,                  -- Original URL if provided
    reporter_notes TEXT,              -- Why they think it's suspicious

    -- Submission metadata
    submission_count INTEGER DEFAULT 1,  -- How many times submitted
    first_submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Review workflow
    status TEXT DEFAULT 'pending_review',  -- pending_review, approved, rejected, duplicate
    reviewed_at TIMESTAMP,
    reviewer_notes TEXT,

    -- Link to domains table if approved
    promoted_domain_id INTEGER,

    UNIQUE(canonical_domain),
    FOREIGN KEY (promoted_domain_id) REFERENCES domains(id)
);

-- Index for admin review queue
CREATE INDEX IF NOT EXISTS idx_public_submissions_status
ON public_submissions(status, first_submitted_at);
```

### API Endpoints

#### `POST /api/public/submit`
Public endpoint for domain submission.

**Request:**
```json
{
    "domain": "suspicious-site.com",
    "source_url": "https://suspicious-site.com/wallet-connect",  // optional
    "notes": "Saw this advertised on Twitter, asks for seed phrase"  // optional
}
```

**Response:**
```json
{
    "status": "submitted",
    "message": "Thank you for your submission. It will be reviewed by our team.",
    "submission_id": "abc123",  // Optional, for reference
    "duplicate": false  // true if already submitted by others
}
```

**Validation & Safety:**
- Domain canonicalization (strip protocol, www, trailing slash)
- Block internal/private IPs (127.0.0.1, 10.x, 192.168.x, etc.)
- Block localhost, .local, .internal domains
- Rate limit: 10 submissions per IP per hour
- Honeypot field (hidden input - if filled, reject silently)
- Max notes length: 1000 characters
- No file uploads (attack vector)
- Sanitize all input (no script injection)

#### `GET /admin/api/submissions`
Admin endpoint to view submission queue.

**Response:**
```json
{
    "submissions": [
        {
            "id": 1,
            "domain": "suspicious-site.com",
            "canonical_domain": "suspicious-site.com",
            "source_url": "https://suspicious-site.com/wallet",
            "reporter_notes": "Asks for seed phrase",
            "submission_count": 5,
            "first_submitted_at": "2025-12-20T10:00:00Z",
            "last_submitted_at": "2025-12-23T14:30:00Z",
            "status": "pending_review"
        }
    ],
    "total_pending": 12
}
```

#### `POST /admin/api/submissions/{id}/approve`
Approve submission and queue for scanning.

**Request:**
```json
{
    "notes": "Confirmed suspicious via manual check"  // optional
}
```

**Behavior:**
1. Create entry in `domains` table with `source: 'public_submission'`
2. Update `public_submissions.status = 'approved'`
3. Set `public_submissions.promoted_domain_id` to new domain ID
4. Queue domain for analysis via existing `submit_callback`

#### `POST /admin/api/submissions/{id}/reject`
Reject submission.

**Request:**
```json
{
    "reason": "legitimate_site" | "insufficient_info" | "already_tracked" | "other",
    "notes": "This is a legitimate wallet service"  // optional
}
```

### Frontend Changes

#### Public Submission Form
- Add to public dashboard header or dedicated `/submit` page
- Simple form: domain input + optional notes
- Honeypot field (CSS hidden)
- Success message with "thank you" confirmation
- Show if domain was already submitted by others ("3 others reported this")

#### Admin Submission Queue
- New card in admin dashboard: "Public Submissions (12 pending)"
- List view with:
  - Domain
  - Submission count (popularity signal)
  - First/last submitted dates
  - Quick preview link (external, nofollow)
  - Approve / Reject buttons
- Bulk actions for spam cleanup

---

## 2. Public Reporting with Counters

### Goals
- Expose manual report functionality on public dashboard
- Force manual mode for ALL platforms (even those with auto capability)
- Track community engagement with counters
- Correlate engagement with takedown timing

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS report_engagement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    platform TEXT NOT NULL,

    -- Session tracking for dedup
    session_hash TEXT NOT NULL,  -- Hash of IP + User-Agent (or cookie ID)

    -- Timestamps
    first_engaged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_engaged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Prevent rapid re-clicking
    UNIQUE(domain_id, platform, session_hash),
    FOREIGN KEY (domain_id) REFERENCES domains(id)
);

-- For efficient counter queries
CREATE INDEX IF NOT EXISTS idx_report_engagement_domain_platform
ON report_engagement(domain_id, platform);

-- For cleanup of old sessions
CREATE INDEX IF NOT EXISTS idx_report_engagement_last_engaged
ON report_engagement(last_engaged_at);
```

### Session Deduplication Logic

```python
# On "I reported this" click:
# 1. Generate session_hash from IP + User-Agent (or use cookie)
# 2. Check if session exists for this domain+platform
# 3. If exists and last_engaged_at < 24 hours ago → reject (return current count)
# 4. If exists and last_engaged_at >= 24 hours ago → update timestamp, count as new
# 5. If not exists → create record, count as new engagement

ENGAGEMENT_COOLDOWN_HOURS = 24
```

### API Endpoints

#### `GET /api/domains/{id}/report-options`
Get available reporting platforms with manual instructions and counters.

**Response:**
```json
{
    "domain": "scam-site.example.com",
    "domain_id": 123,
    "platforms": [
        {
            "id": "cloudflare",
            "name": "Cloudflare",
            "manual_only": true,
            "form_url": "https://abuse.cloudflare.com/",
            "engagement_count": 47,
            "fields": [
                {"name": "url", "label": "Abusive URL", "value": "https://scam-site.example.com", "multiline": false},
                {"name": "evidence", "label": "Evidence/Description", "value": "Cryptocurrency phishing...", "multiline": true}
            ],
            "notes": ["Select 'Phishing' as the abuse type", "Include the URL exactly as shown"]
        },
        {
            "id": "google_safebrowsing",
            "name": "Google Safe Browsing",
            "manual_only": true,
            "form_url": "https://safebrowsing.google.com/safebrowsing/report_phish/",
            "engagement_count": 23,
            "fields": [...],
            "notes": [...]
        }
        // ... more platforms
    ],
    "total_engagements": 142
}
```

#### `POST /api/domains/{id}/report-engagement`
Record that a user engaged with a report (clicked "I reported this").

**Request:**
```json
{
    "platform": "cloudflare"
}
```

**Response:**
```json
{
    "status": "recorded",  // or "cooldown" if within 24h
    "new_count": 48,
    "message": "Thank you for reporting!"  // or "You've already reported recently"
}
```

### Reporter Changes

#### Add `generate_manual_submission()` to All Reporters

Currently, some reporters (Netcraft) only have auto mode. Add manual fallback:

```python
# In base.py
class BaseReporter(ABC):
    # ... existing code ...

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        """
        Generate manual submission data for this platform.

        Override in subclasses for platform-specific instructions.
        Default implementation returns basic form URL and evidence fields.
        """
        return ManualSubmissionData(
            form_url=self.platform_url,
            reason="Manual submission",
            fields=[
                ManualSubmissionField(
                    name="url",
                    label="Phishing URL",
                    value=evidence.url,
                ),
                ManualSubmissionField(
                    name="evidence",
                    label="Evidence",
                    value=evidence.to_summary(),
                    multiline=True,
                ),
            ],
            notes=[],
        )
```

#### Netcraft Manual Method

```python
# In netcraft.py
def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
    return ManualSubmissionData(
        form_url="https://report.netcraft.com/report",
        reason="Manual web form submission",
        fields=[
            ManualSubmissionField(
                name="url",
                label="Suspicious URL",
                value=evidence.url,
            ),
            ManualSubmissionField(
                name="comments",
                label="Additional Information",
                value=self._build_reason_string(evidence),
                multiline=True,
            ),
        ],
        notes=[
            "Netcraft accepts reports without an account",
            "Provide your email if you want updates on the report",
        ],
    )
```

### Frontend Changes

#### Public Report Panel

On domain detail page (public mode):

```
┌─────────────────────────────────────────────────────────┐
│ Help Take Down This Scam                                │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ Report to these platforms to help get this site removed:│
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🛡️ Cloudflare                          47 reported │ │
│ │ [View Instructions] [I Reported This ✓]            │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🔍 Google Safe Browsing                23 reported │ │
│ │ [View Instructions] [I Reported This ✓]            │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🏢 Hosting Provider (DigitalOcean)      8 reported │ │
│ │ [View Instructions] [I Reported This ✓]            │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ Total community reports: 142                            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### Instructions Modal

When "View Instructions" is clicked:

```
┌─────────────────────────────────────────────────────────┐
│ Report to Cloudflare                              [X]   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 1. Open the Cloudflare abuse form:                      │
│    🔗 https://abuse.cloudflare.com/                     │
│                                                         │
│ 2. Copy these details:                                  │
│                                                         │
│    Abusive URL:                                         │
│    ┌─────────────────────────────────────────────────┐  │
│    │ https://scam-site.example.com          [Copy]   │  │
│    └─────────────────────────────────────────────────┘  │
│                                                         │
│    Evidence/Description:                                │
│    ┌─────────────────────────────────────────────────┐  │
│    │ Cryptocurrency phishing site targeting...       │  │
│    │ Confidence: 95%                                 │  │
│    │ Detected: Fake wallet connect interface...      │  │
│    │                                         [Copy]   │  │
│    └─────────────────────────────────────────────────┘  │
│                                                         │
│ 3. Select "Phishing" as the abuse type                  │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │              [I Reported This ✓]                    │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Takedown Detection

### Goals
- Detect when reported phishing sites go offline
- Distinguish between: takedown, temporary downtime, site migration
- Correlate community engagement with takedown timing
- Track takedown success rates per platform

### Detection Signals

#### Primary Indicators (High Confidence)

| Signal | Detection Method | Confidence |
|--------|-----------------|------------|
| **NXDOMAIN** | DNS lookup returns no records | Very High |
| **HTTP 404/410** | Site returns "not found" or "gone" | High |
| **Registrar Hold** | WHOIS/RDAP shows `clientHold` or `serverHold` | Very High |
| **Sinkhole IP** | Resolves to 127.0.0.1, 0.0.0.0 | Very High |
| **Hosting Suspension** | Provider-specific error page | High |
| **Certificate Revoked** | OCSP returns "revoked" status | High |

#### Secondary Indicators (Medium Confidence)

| Signal | Detection Method | Confidence |
|--------|-----------------|------------|
| **HTTP 503** | Service unavailable | Medium |
| **Connection Timeout** | No response within threshold | Medium |
| **SSL Handshake Failure** | Certificate invalid/expired | Medium |
| **Content Changed** | Page no longer matches phishing patterns | Medium |
| **Redirect to Parked** | Redirects to registrar parking page | Medium |

#### Hosting Provider Suspension Patterns

| Provider | Suspension Indicator |
|----------|---------------------|
| **Cloudflare** | Error 1020 "Access Denied", Error 1000-series |
| **Vercel** | Default 404 page with Vercel branding |
| **Netlify** | "Page Not Found" with Netlify styling |
| **DigitalOcean** | 404/503 or branded error page |
| **AWS** | S3 403 "Access Denied", EC2 connection refused |
| **GCP** | Default 404 or Cloud Run error page |
| **Azure** | Default IIS error or Azure branding |

### Database Schema

```sql
-- Track takedown status over time
CREATE TABLE IF NOT EXISTS takedown_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- HTTP status
    http_status INTEGER,  -- 200, 404, 503, null if connection failed
    http_error TEXT,      -- Connection error message if any

    -- DNS status
    dns_resolves BOOLEAN,
    dns_result TEXT,      -- IP addresses or NXDOMAIN
    is_sinkholed BOOLEAN DEFAULT FALSE,

    -- WHOIS/RDAP status
    domain_status TEXT,   -- ok, clientHold, serverHold, etc.

    -- Content analysis
    content_hash TEXT,    -- Hash of page content for change detection
    still_phishing BOOLEAN,  -- Does content still match phishing patterns?

    -- Overall assessment
    takedown_status TEXT,  -- active, likely_down, confirmed_down, migrated
    confidence REAL,       -- 0.0 to 1.0

    FOREIGN KEY (domain_id) REFERENCES domains(id)
);

CREATE INDEX IF NOT EXISTS idx_takedown_checks_domain
ON takedown_checks(domain_id, checked_at DESC);

-- Summary status on domains table
ALTER TABLE domains ADD COLUMN takedown_status TEXT DEFAULT 'active';
ALTER TABLE domains ADD COLUMN takedown_detected_at TIMESTAMP;
ALTER TABLE domains ADD COLUMN takedown_confirmed_at TIMESTAMP;
```

### Takedown Status Flow

```
                    ┌──────────────┐
                    │    active    │
                    └──────┬───────┘
                           │
              (First failure detected)
                           │
                           ▼
                    ┌──────────────┐
                    │ likely_down  │ ◄─── (Temporary? Check again)
                    └──────┬───────┘
                           │
           (Consistent failures for 24h+)
                           │
                           ▼
                    ┌──────────────┐
                    │confirmed_down│
                    └──────────────┘
                           │
                           │ (If site comes back)
                           ▼
                    ┌──────────────┐
                    │  resurrected │ ◄─── (May have migrated)
                    └──────────────┘
```

### Takedown Checker Implementation

```python
# src/analyzer/takedown_checker.py

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import asyncio
import httpx
import dns.resolver

class TakedownStatus(str, Enum):
    ACTIVE = "active"
    LIKELY_DOWN = "likely_down"
    CONFIRMED_DOWN = "confirmed_down"
    MIGRATED = "migrated"
    RESURRECTED = "resurrected"

@dataclass
class TakedownCheckResult:
    status: TakedownStatus
    confidence: float
    http_status: Optional[int]
    dns_resolves: bool
    is_sinkholed: bool
    domain_status: Optional[str]
    details: str

SINKHOLE_IPS = {"127.0.0.1", "0.0.0.0", "::1"}

class TakedownChecker:
    """Check if a domain has been taken down."""

    async def check_domain(self, domain: str) -> TakedownCheckResult:
        """Perform comprehensive takedown check."""

        # Parallel checks
        dns_result, http_result, whois_result = await asyncio.gather(
            self._check_dns(domain),
            self._check_http(domain),
            self._check_whois(domain),
            return_exceptions=True,
        )

        # Analyze results
        return self._analyze_results(domain, dns_result, http_result, whois_result)

    async def _check_dns(self, domain: str) -> dict:
        """Check DNS resolution."""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ips = [str(rdata) for rdata in answers]
            is_sinkholed = any(ip in SINKHOLE_IPS for ip in ips)
            return {
                "resolves": True,
                "ips": ips,
                "is_sinkholed": is_sinkholed,
            }
        except dns.resolver.NXDOMAIN:
            return {"resolves": False, "error": "NXDOMAIN"}
        except Exception as e:
            return {"resolves": False, "error": str(e)}

    async def _check_http(self, domain: str) -> dict:
        """Check HTTP accessibility."""
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(f"https://{domain}")
                return {
                    "status": resp.status_code,
                    "accessible": resp.status_code < 400,
                    "content_length": len(resp.content),
                }
        except Exception as e:
            return {"status": None, "accessible": False, "error": str(e)}

    async def _check_whois(self, domain: str) -> dict:
        """Check WHOIS/RDAP for domain status."""
        # Use existing RDAP infrastructure
        # Look for clientHold, serverHold, pendingDelete, etc.
        pass

    def _analyze_results(self, domain, dns, http, whois) -> TakedownCheckResult:
        """Combine signals into overall takedown assessment."""

        confidence = 0.0
        signals = []

        # DNS signals
        if isinstance(dns, dict):
            if not dns.get("resolves"):
                confidence += 0.4
                signals.append("DNS: NXDOMAIN")
            elif dns.get("is_sinkholed"):
                confidence += 0.5
                signals.append("DNS: Sinkholed")

        # HTTP signals
        if isinstance(http, dict):
            status = http.get("status")
            if status in (404, 410):
                confidence += 0.3
                signals.append(f"HTTP: {status}")
            elif status in (403, 503):
                confidence += 0.15
                signals.append(f"HTTP: {status}")
            elif status is None:
                confidence += 0.2
                signals.append("HTTP: Connection failed")

        # WHOIS signals
        if isinstance(whois, dict):
            domain_status = whois.get("status", "")
            if "hold" in domain_status.lower():
                confidence += 0.4
                signals.append(f"WHOIS: {domain_status}")

        # Determine status
        if confidence >= 0.8:
            status = TakedownStatus.CONFIRMED_DOWN
        elif confidence >= 0.4:
            status = TakedownStatus.LIKELY_DOWN
        else:
            status = TakedownStatus.ACTIVE

        return TakedownCheckResult(
            status=status,
            confidence=min(confidence, 1.0),
            http_status=http.get("status") if isinstance(http, dict) else None,
            dns_resolves=dns.get("resolves", False) if isinstance(dns, dict) else False,
            is_sinkholed=dns.get("is_sinkholed", False) if isinstance(dns, dict) else False,
            domain_status=whois.get("status") if isinstance(whois, dict) else None,
            details="; ".join(signals),
        )
```

### Monitoring Schedule

| Domain Status | Check Frequency |
|---------------|-----------------|
| Just reported (0-24h) | Every 30 minutes |
| Recently reported (1-7 days) | Every 2 hours |
| Older reports (7-30 days) | Every 6 hours |
| Confirmed down | Daily for 30 days (watch for resurrection) |

### Correlation Analytics

Track relationship between community engagement and takedowns:

```sql
-- Example query: Engagement vs Takedown Time
SELECT
    d.domain,
    COUNT(DISTINCT re.id) as engagement_count,
    d.reported_at,
    d.takedown_detected_at,
    ROUND((JULIANDAY(d.takedown_detected_at) - JULIANDAY(d.reported_at)) * 24, 1) as hours_to_takedown
FROM domains d
LEFT JOIN report_engagement re ON re.domain_id = d.id
WHERE d.takedown_status = 'confirmed_down'
GROUP BY d.id
ORDER BY hours_to_takedown;
```

---

## 4. New Manual Reporters to Add

Based on research, these platforms should be added as manual-only reporters:

### Cloud/Hosting Providers

| Platform | Abuse URL | Method | Priority |
|----------|-----------|--------|----------|
| **AWS** | https://support.aws.amazon.com/#/contacts/report-abuse | Form | High |
| **Google Cloud** | https://support.google.com/code/contact/cloud_platform_report | Form | High |
| **Microsoft Azure** | https://msrc.microsoft.com/report | Form | High |
| **Vercel** | https://vercel.com/abuse | Form | High |
| **Netlify** | fraud@netlify.com | Email | High |
| **Render** | abuse@render.com | Email | Medium |
| **Fly.io** | abuse@fly.io | Email | Medium |
| **Railway** | abuse@railway.app | Email | Low |
| **Heroku** | https://help.heroku.com/tickets/new (Security category) | Form | Medium |

### Registrars

| Registrar | Abuse URL | Method | Priority |
|-----------|-----------|--------|----------|
| **GoDaddy** | https://supportcenter.godaddy.com/abusereport/phishing | Form | High |
| **Namecheap** | abuse@namecheaphosting.com | Email | High |
| **Porkbun** | https://porkbun.com/abuse | Form | Medium |
| **Cloudflare Registrar** | https://abuse.cloudflare.com/ | Form | High (already have) |
| **Google Domains** | https://support.google.com/domains/troubleshooter/9339157 | Form | Medium |
| **Tucows/Hover** | https://tucowsdomains.com/report-abuse/ | Form | Low |

### API/Service Providers

| Service | Abuse Contact | Method | Use Case |
|---------|---------------|--------|----------|
| **Telegram** | abuse@telegram.org or @notoscam bot | Email/Bot | Exfil bots |
| **Discord** | https://discord.com/safety/360044103651 | Form | Webhook abuse |
| **Sendgrid** | abuse@sendgrid.com | Email | Phishing emails |
| **Mailgun** | abuse@mailgun.com | Email | Phishing emails |

### DNS/Browser Protection

| Service | Report URL | Method | Notes |
|---------|-----------|--------|-------|
| **Quad9** | https://quad9.net/contact/ | Form | DNS blocking |
| **OpenDNS** | support@opendns.com | Email | DNS blocking |
| **Firefox (via Google)** | https://safebrowsing.google.com/safebrowsing/report_phish/?tpl=mozilla | Form | Browser warning |

### Reporter Implementation Template

```python
# Example: Vercel Reporter
# src/reporter/vercel.py

from .base import (
    BaseReporter,
    ManualSubmissionData,
    ManualSubmissionField,
    ReportEvidence,
    ReportResult,
    ReportStatus,
)

class VercelReporter(BaseReporter):
    """Vercel hosting abuse reporter."""

    platform_name = "vercel"
    platform_url = "https://vercel.com/abuse"
    manual_only = True

    def __init__(self):
        super().__init__()
        self._configured = True

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """Generate manual submission instructions for Vercel."""

        manual_data = ManualSubmissionData(
            form_url=self.platform_url,
            reason="Vercel abuse form",
            fields=[
                ManualSubmissionField(
                    name="url",
                    label="URL of abusive content",
                    value=evidence.url,
                ),
                ManualSubmissionField(
                    name="description",
                    label="Description of abuse",
                    value=self._build_description(evidence),
                    multiline=True,
                ),
            ],
            notes=[
                "Select 'Phishing' as the type of abuse",
                "Vercel typically responds within 24-48 hours",
            ],
        )

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message=f"Manual submission required: {self.platform_url}",
            response_data={"manual_fields": manual_data.to_dict()},
        )

    def _build_description(self, evidence: ReportEvidence) -> str:
        lines = [
            "This site is hosting a cryptocurrency phishing scam.",
            f"Confidence: {evidence.confidence_score}%",
            "",
            "Evidence:",
        ]
        for reason in evidence.detection_reasons[:5]:
            lines.append(f"- {reason}")
        lines.append("")
        lines.append("Detected by SeedBuster anti-phishing project.")
        return "\n".join(lines)
```

---

## 5. Implementation Phases

### Phase 1: Foundation (Core Infrastructure)
- [ ] Add `public_submissions` table
- [ ] Add `report_engagement` table
- [ ] Add `takedown_checks` table
- [ ] Add `generate_manual_submission()` to BaseReporter
- [ ] Add manual method to Netcraft reporter

### Phase 2: Public Submission
- [ ] Implement `POST /api/public/submit` endpoint
- [ ] Add domain validation and rate limiting
- [ ] Implement `GET /admin/api/submissions` endpoint
- [ ] Implement approve/reject endpoints
- [ ] Add submission form to public frontend
- [ ] Add submission queue to admin dashboard

### Phase 3: Public Reporting
- [ ] Implement `GET /api/domains/{id}/report-options` endpoint
- [ ] Implement `POST /api/domains/{id}/report-engagement` endpoint
- [ ] Add session-based deduplication (24h cooldown)
- [ ] Add report panel to public domain detail page
- [ ] Add instructions modal with copy buttons

### Phase 4: New Reporters
- [ ] Add Vercel reporter
- [ ] Add Netlify reporter
- [ ] Add AWS reporter
- [ ] Add GCP reporter
- [ ] Add Azure reporter
- [ ] Add GoDaddy reporter
- [ ] Add Namecheap reporter
- [ ] Add Porkbun reporter
- [ ] Add Telegram reporter
- [ ] Add Discord reporter
- [ ] Add Quad9 reporter

### Phase 5: Takedown Detection
- [ ] Implement TakedownChecker class
- [ ] Add DNS resolution checking
- [ ] Add HTTP status checking
- [ ] Add WHOIS/RDAP status checking
- [ ] Add hosting provider error detection
- [ ] Implement monitoring scheduler
- [ ] Add takedown status to domain detail page
- [ ] Add correlation analytics queries

### Phase 6: Analytics & Polish
- [ ] Dashboard showing engagement vs takedown correlation
- [ ] Platform effectiveness metrics
- [ ] Community leaderboard (optional)
- [ ] Email notifications for takedowns (optional)

---

## 6. Security Considerations

### Public Submission
- **Input validation**: Strict domain parsing, no arbitrary URLs
- **Rate limiting**: Per-IP limits to prevent flooding
- **No auto-scanning**: Submissions only queue for review
- **Honeypot fields**: Catch automated submissions
- **No file uploads**: Eliminate attack vector entirely

### Public Reporting
- **No server-side actions**: Just tracking engagement
- **Session dedup**: Prevent counter manipulation
- **Read-only data**: No modifications to core data

### Takedown Detection
- **Passive monitoring**: No active interaction with targets
- **Rate limited checks**: Don't hammer DNS/HTTP
- **No credential exposure**: All checks are anonymous

---

## 7. References

### Anti-Phishing Organizations
- [APWG (Anti-Phishing Working Group)](https://apwg.org/)
- [PhishTank](https://phishtank.org/)
- [Netcraft](https://www.netcraft.com/platform/threat-detection-and-takedown/)
- [Google Safe Browsing](https://safebrowsing.google.com/)

### Abuse Reporting Resources
- [phish.report](https://phish.report/) - Aggregated abuse contacts
- [abuse.ch URLhaus](https://urlhaus.abuse.ch/) - Malware URL database

### Hosting Provider Abuse Pages
- [AWS Abuse](https://repost.aws/knowledge-center/report-aws-abuse)
- [GCP Abuse](https://support.google.com/code/contact/cloud_platform_report)
- [Azure Abuse](https://msrc.microsoft.com/report)
- [Cloudflare Abuse](https://abuse.cloudflare.com/)
- [Vercel Abuse](https://vercel.com/abuse)
- [DigitalOcean Abuse](https://www.digitalocean.com/company/contact/abuse)

### Registrar Abuse Pages
- [GoDaddy Abuse](https://supportcenter.godaddy.com/abusereport/phishing)
- [Namecheap Abuse](https://www.namecheap.com/support/knowledgebase/article.aspx/9196/5/how-and-where-can-i-file-abuse-complaints/)
- [Porkbun Abuse](https://porkbun.com/abuse)

### DNS Security
- [Quad9](https://quad9.net/)
- [OpenDNS](https://www.opendns.com/)
