"""Infrastructure scoring helpers."""

from __future__ import annotations

from .infrastructure import InfrastructureResult


class DetectorInfrastructureMixin:
    """Infrastructure scoring helpers."""

    def _score_infrastructure(self, infra: InfrastructureResult) -> tuple[int, list[str]]:
        """Score infrastructure signals for phishing indicators."""
        score = 0
        reasons: list[str] = []
        s = self.scoring

        if infra.tls:
            if infra.tls.is_new:
                score += s.get("infra_new_tls", 10)
                reasons.append(f"INFRA: New TLS cert ({infra.tls.age_days} days old)")

            if infra.tls.is_free_cert and infra.tls.is_short_lived:
                score += s.get("infra_free_short_tls", 5)
                reasons.append(f"INFRA: Free short-lived cert ({infra.tls.issuer})")

        if infra.domain_info:
            if infra.domain_info.is_very_new:
                score += s.get("infra_very_new_domain", 20)
                reasons.append(f"INFRA: Very new domain ({infra.domain_info.age_days} days)")
            elif infra.domain_info.is_new_domain:
                score += s.get("infra_new_domain", 10)
                reasons.append(f"INFRA: New domain ({infra.domain_info.age_days} days)")

            if infra.domain_info.uses_privacy_dns:
                score += s.get("infra_privacy_dns", 20)
                ns_list = infra.domain_info.nameservers
                ns_sample = ns_list[0] if ns_list else "detected"
                providers = [
                    p
                    for p in infra.domain_info.SUSPICIOUS_NS_PROVIDERS
                    if any(p in (ns or "").lower() for ns in ns_list)
                ]
                provider = providers[0] if providers else "detected"
                reasons.append(f"INFRA: Privacy DNS ({provider}): {ns_sample}")

        if infra.hosting:
            if infra.hosting.is_bulletproof:
                score += s.get("infra_bulletproof", 25)
                reasons.append(f"INFRA: Bulletproof hosting ({infra.hosting.asn_name})")

        return score, reasons
