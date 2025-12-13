"""Infrastructure Intelligence for SeedBuster.

Analyzes hosting infrastructure, TLS certificates, IP reputation,
and network characteristics to detect phishing patterns.
"""

import asyncio
import logging
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class TLSCertInfo:
    """TLS certificate information."""

    domain: str
    issuer: str
    subject: str
    not_before: datetime
    not_after: datetime
    age_days: int
    validity_days: int
    is_wildcard: bool
    san_domains: list[str] = field(default_factory=list)
    fingerprint_sha256: str = ""

    @property
    def is_new(self) -> bool:
        """Certificate is less than 30 days old."""
        return self.age_days < 30

    @property
    def is_short_lived(self) -> bool:
        """Certificate validity is 90 days or less (like Let's Encrypt)."""
        return self.validity_days <= 90

    @property
    def is_free_cert(self) -> bool:
        """Certificate is from a free CA (Let's Encrypt, ZeroSSL, etc.)."""
        free_cas = [
            "let's encrypt",
            "zerossl",
            "buypass",
            "ssl.com",
            "google trust services",  # Used by some free services
        ]
        issuer_lower = self.issuer.lower()
        return any(ca in issuer_lower for ca in free_cas)


@dataclass
class HostingInfo:
    """Hosting provider and network information."""

    ip_address: str
    asn: int = 0
    asn_name: str = ""
    asn_country: str = ""
    hosting_provider: str = ""
    is_cloud_provider: bool = False
    is_bulletproof: bool = False
    datacenter: str = ""
    reverse_dns: str = ""

    # Known cloud/hosting providers often abused for phishing
    CLOUD_PROVIDERS = {
        "digitalocean": ["digitalocean", "DO-13"],
        "cloudflare": ["cloudflare", "CLOUDFLARENET"],
        "aws": ["amazon", "AMAZON-", "AWS"],
        "google": ["google", "GOOGLE"],
        "azure": ["microsoft", "MSFT"],
        "vultr": ["vultr", "VULTR"],
        "linode": ["linode", "LINODE"],
        "hetzner": ["hetzner", "HETZNER"],
        "ovh": ["ovh", "OVH"],
        "namecheap": ["namecheap"],
        "hostinger": ["hostinger"],
        "godaddy": ["godaddy"],
    }

    # Known bulletproof/abuse-friendly hosting
    BULLETPROOF_ASNS = {
        # Add known bulletproof hosting ASNs here
        # These are examples - research for accurate list
    }


@dataclass
class DomainInfo:
    """Domain registration and DNS information."""

    domain: str
    registered_date: Optional[datetime] = None
    age_days: int = -1  # -1 means unknown
    registrar: str = ""
    nameservers: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    a_records: list[str] = field(default_factory=list)

    # Privacy-focused / abuse-friendly registrars and DNS providers
    SUSPICIOUS_NS_PROVIDERS = [
        "njalla",      # Privacy-focused, popular with threat actors
        "1984hosting", # Privacy-focused Iceland
        "orangewebsite", # Privacy-focused Iceland
        "flokinet",    # Privacy-focused
    ]

    SUSPICIOUS_REGISTRARS = [
        "njalla",
        "namecheap",   # Often abused due to easy registration
        "porkbun",     # Low-cost, sometimes abused
        "dynadot",
    ]

    @property
    def is_new_domain(self) -> bool:
        """Domain is less than 30 days old."""
        return 0 <= self.age_days < 30

    @property
    def is_very_new(self) -> bool:
        """Domain is less than 7 days old."""
        return 0 <= self.age_days < 7

    @property
    def uses_privacy_dns(self) -> bool:
        """Domain uses privacy-focused DNS providers."""
        ns_combined = " ".join(self.nameservers).lower()
        return any(provider in ns_combined for provider in self.SUSPICIOUS_NS_PROVIDERS)

    @property
    def uses_suspicious_registrar(self) -> bool:
        """Domain registered with often-abused registrar."""
        registrar_lower = self.registrar.lower()
        return any(reg in registrar_lower for reg in self.SUSPICIOUS_REGISTRARS)


@dataclass
class InfrastructureResult:
    """Complete infrastructure analysis result."""

    domain: str
    tls: Optional[TLSCertInfo] = None
    hosting: Optional[HostingInfo] = None
    domain_info: Optional[DomainInfo] = None

    # Scoring
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)

    # Related infrastructure
    related_domains: list[str] = field(default_factory=list)
    shared_ip_domains: list[str] = field(default_factory=list)

    def calculate_risk_score(self) -> tuple[int, list[str]]:
        """Calculate infrastructure risk score."""
        score = 0
        reasons = []

        # TLS Certificate signals
        if self.tls:
            if self.tls.is_new:
                score += 15
                reasons.append(f"New TLS certificate ({self.tls.age_days} days old)")

            if self.tls.is_free_cert:
                score += 5
                reasons.append(f"Free TLS certificate ({self.tls.issuer})")

            if self.tls.is_short_lived:
                score += 5
                reasons.append("Short-lived certificate (≤90 days)")

        # Hosting signals
        if self.hosting:
            if self.hosting.is_cloud_provider:
                score += 5
                reasons.append(f"Cloud hosting ({self.hosting.hosting_provider})")

            if self.hosting.is_bulletproof:
                score += 25
                reasons.append(f"Bulletproof hosting ({self.hosting.asn_name})")

        # Domain signals
        if self.domain_info:
            if self.domain_info.is_very_new:
                score += 20
                reasons.append(f"Very new domain ({self.domain_info.age_days} days)")
            elif self.domain_info.is_new_domain:
                score += 10
                reasons.append(f"New domain ({self.domain_info.age_days} days)")

            # Privacy-focused infrastructure is a strong signal
            if self.domain_info.uses_privacy_dns:
                score += 25
                ns_providers = [
                    ns for ns in self.domain_info.nameservers
                    if any(p in ns.lower() for p in DomainInfo.SUSPICIOUS_NS_PROVIDERS)
                ]
                reasons.append(f"Privacy-focused DNS (Njalla/similar): {ns_providers[0] if ns_providers else 'detected'}")

        self.risk_score = score
        self.risk_reasons = reasons
        return score, reasons


class InfrastructureAnalyzer:
    """Analyzes infrastructure characteristics of domains."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
        return self._session

    async def close(self):
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def analyze(self, domain: str) -> InfrastructureResult:
        """Perform complete infrastructure analysis."""
        result = InfrastructureResult(domain=domain)

        # Run analyses in parallel
        tls_task = asyncio.create_task(self.get_tls_info(domain))
        hosting_task = asyncio.create_task(self.get_hosting_info(domain))
        domain_task = asyncio.create_task(self.get_domain_info(domain))

        # Gather results
        try:
            result.tls = await tls_task
        except Exception as e:
            logger.debug(f"TLS analysis failed for {domain}: {e}")

        try:
            result.hosting = await hosting_task
        except Exception as e:
            logger.debug(f"Hosting analysis failed for {domain}: {e}")

        try:
            result.domain_info = await domain_task
        except Exception as e:
            logger.debug(f"Domain analysis failed for {domain}: {e}")

        # Find related domains if we have IP
        if result.hosting and result.hosting.ip_address:
            try:
                result.shared_ip_domains = await self.find_domains_on_ip(
                    result.hosting.ip_address
                )
            except Exception as e:
                logger.debug(f"Related domain lookup failed: {e}")

        # Calculate risk score
        result.calculate_risk_score()

        return result

    async def get_tls_info(self, domain: str) -> Optional[TLSCertInfo]:
        """Get TLS certificate information."""
        try:
            # Create SSL context
            context = ssl.create_default_context()

            # Connect and get certificate
            loop = asyncio.get_event_loop()
            cert = await loop.run_in_executor(
                None,
                self._fetch_certificate,
                domain,
                context
            )

            if not cert:
                return None

            # Parse certificate details
            issuer = dict(x[0] for x in cert.get('issuer', []))
            subject = dict(x[0] for x in cert.get('subject', []))

            not_before = datetime.strptime(
                cert['notBefore'], '%b %d %H:%M:%S %Y %Z'
            ).replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(
                cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
            ).replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_days = (now - not_before).days
            validity_days = (not_after - not_before).days

            # Get SAN domains
            san_domains = []
            for san_type, san_value in cert.get('subjectAltName', []):
                if san_type == 'DNS':
                    san_domains.append(san_value)

            # Check for wildcard
            common_name = subject.get('commonName', '')
            is_wildcard = common_name.startswith('*.')

            return TLSCertInfo(
                domain=domain,
                issuer=issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                subject=common_name,
                not_before=not_before,
                not_after=not_after,
                age_days=age_days,
                validity_days=validity_days,
                is_wildcard=is_wildcard,
                san_domains=san_domains,
            )

        except Exception as e:
            logger.debug(f"Failed to get TLS info for {domain}: {e}")
            return None

    def _fetch_certificate(self, domain: str, context: ssl.SSLContext) -> Optional[dict]:
        """Fetch certificate synchronously (run in executor)."""
        try:
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()
        except Exception:
            return None

    async def get_hosting_info(self, domain: str) -> Optional[HostingInfo]:
        """Get hosting provider and network information."""
        try:
            # Resolve domain to IP
            loop = asyncio.get_event_loop()
            ip_address = await loop.run_in_executor(
                None,
                socket.gethostbyname,
                domain
            )

            result = HostingInfo(ip_address=ip_address)

            # Get reverse DNS
            try:
                reverse_dns = await loop.run_in_executor(
                    None,
                    socket.gethostbyaddr,
                    ip_address
                )
                result.reverse_dns = reverse_dns[0]
            except socket.herror:
                pass

            # Query IP info API for ASN details
            session = await self._get_session()
            try:
                # Use ip-api.com (free, no key required)
                async with session.get(
                    f"http://ip-api.com/json/{ip_address}?fields=status,as,org,isp,country"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('status') == 'success':
                            # Parse ASN from "AS12345 Name" format
                            as_info = data.get('as', '')
                            if as_info:
                                match = re.match(r'AS(\d+)\s*(.*)', as_info)
                                if match:
                                    result.asn = int(match.group(1))
                                    result.asn_name = match.group(2).strip()

                            result.asn_country = data.get('country', '')
                            result.datacenter = data.get('isp', '')

                            # Identify hosting provider
                            self._identify_hosting_provider(result)
            except Exception as e:
                logger.debug(f"IP API query failed: {e}")

            return result

        except Exception as e:
            logger.debug(f"Failed to get hosting info for {domain}: {e}")
            return None

    def _identify_hosting_provider(self, hosting: HostingInfo):
        """Identify the hosting provider from ASN/name."""
        combined = f"{hosting.asn_name} {hosting.datacenter} {hosting.reverse_dns}".lower()

        for provider, keywords in HostingInfo.CLOUD_PROVIDERS.items():
            if any(kw.lower() in combined for kw in keywords):
                hosting.hosting_provider = provider
                hosting.is_cloud_provider = True
                break

        # Check for bulletproof hosting
        if hosting.asn in HostingInfo.BULLETPROOF_ASNS:
            hosting.is_bulletproof = True

    async def get_domain_info(self, domain: str) -> Optional[DomainInfo]:
        """Get domain registration and DNS information."""
        try:
            result = DomainInfo(domain=domain)
            loop = asyncio.get_event_loop()

            # Get A records
            try:
                result.a_records = await loop.run_in_executor(
                    None,
                    lambda: socket.gethostbyname_ex(domain)[2]
                )
            except socket.gaierror:
                pass

            # Get MX records via DNS query
            # Note: For full implementation, use dnspython library
            # For now, we'll skip MX/NS lookups or add later

            # Domain age via RDAP (more reliable than WHOIS)
            session = await self._get_session()
            try:
                # Try RDAP for domain info
                rdap_url = f"https://rdap.org/domain/{domain}"

                async with session.get(rdap_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()

                        # Find registration date
                        for event in data.get('events', []):
                            if event.get('eventAction') == 'registration':
                                reg_date_str = event.get('eventDate', '')
                                if reg_date_str:
                                    # Parse ISO format date
                                    reg_date = datetime.fromisoformat(
                                        reg_date_str.replace('Z', '+00:00')
                                    )
                                    result.registered_date = reg_date
                                    result.age_days = (
                                        datetime.now(timezone.utc) - reg_date
                                    ).days
                                break

                        # Get registrar
                        for entity in data.get('entities', []):
                            if 'registrar' in entity.get('roles', []):
                                vcard = entity.get('vcardArray', [])
                                if len(vcard) > 1:
                                    for item in vcard[1]:
                                        if item[0] == 'fn':
                                            result.registrar = item[3]
                                            break
                                break

                        # Get nameservers
                        result.nameservers = [
                            ns.get('ldhName', '')
                            for ns in data.get('nameservers', [])
                            if ns.get('ldhName')
                        ]
            except Exception as e:
                logger.debug(f"RDAP query failed for {domain}: {e}")

            return result

        except Exception as e:
            logger.debug(f"Failed to get domain info for {domain}: {e}")
            return None

    async def find_domains_on_ip(self, ip_address: str) -> list[str]:
        """Find other domains hosted on the same IP.

        Note: This requires a reverse IP lookup service.
        Free options are limited; this is a placeholder for integration.
        """
        # Placeholder - would integrate with:
        # - SecurityTrails API
        # - ViewDNS.info
        # - HackerTarget
        # - Custom passive DNS database
        return []

    async def check_ip_reputation(self, ip_address: str) -> dict:
        """Check IP against reputation services.

        Note: Placeholder for integration with:
        - AbuseIPDB
        - VirusTotal
        - IPQualityScore
        - Custom blocklists
        """
        return {
            "abuse_score": 0,
            "is_blocklisted": False,
            "blocklists": [],
        }


# Convenience function for quick analysis
async def analyze_infrastructure(domain: str) -> InfrastructureResult:
    """Analyze domain infrastructure."""
    analyzer = InfrastructureAnalyzer()
    try:
        return await analyzer.analyze(domain)
    finally:
        await analyzer.close()
