"""Composed dashboard server class."""

from __future__ import annotations

from .server_admin_actions import DashboardServerAdminActionsMixin
from .server_admin_api_allowlist import DashboardServerAdminApiAllowlistMixin
from .server_admin_api_campaigns import DashboardServerAdminApiCampaignsMixin
from .server_admin_api_domain_actions import DashboardServerAdminApiDomainActionsMixin
from .server_admin_api_domains import DashboardServerAdminApiDomainsMixin
from .server_admin_api_evidence import DashboardServerAdminApiEvidenceMixin
from .server_admin_api_stats import DashboardServerAdminApiStatsMixin
from .server_admin_api_submissions import DashboardServerAdminApiSubmissionsMixin
from .server_admin_campaign_detail import DashboardServerAdminCampaignDetailMixin
from .server_admin_dashboard import DashboardServerAdminDashboardMixin
from .server_admin_domain import DashboardServerAdminDomainMixin
from .server_admin_exports import DashboardServerAdminExportsMixin
from .server_allowlist import DashboardServerAllowlistMixin
from .server_campaigns import DashboardServerCampaignsMixin
from .server_config import DashboardConfig
from .server_core import DashboardServerCoreMixin
from .server_evidence import DashboardServerEvidenceMixin
from .server_frontend import DashboardServerFrontendMixin
from .server_maintenance import DashboardServerMaintenanceMixin
from .server_public_api import DashboardServerPublicApiMixin
from .server_public_pages import DashboardServerPublicPagesMixin
from .server_request import DashboardServerRequestMixin
from .server_routes import DashboardServerRoutesMixin
from .server_scams import DashboardServerScamsMixin
from .server_security import DashboardServerSecurityMixin
from .server_stats import DashboardServerStatsMixin


class DashboardServer(
    DashboardServerCoreMixin,
    DashboardServerSecurityMixin,
    DashboardServerAllowlistMixin,
    DashboardServerRequestMixin,
    DashboardServerCampaignsMixin,
    DashboardServerStatsMixin,
    DashboardServerScamsMixin,
    DashboardServerEvidenceMixin,
    DashboardServerMaintenanceMixin,
    DashboardServerFrontendMixin,
    DashboardServerPublicPagesMixin,
    DashboardServerPublicApiMixin,
    DashboardServerAdminDashboardMixin,
    DashboardServerAdminDomainMixin,
    DashboardServerAdminActionsMixin,
    DashboardServerAdminCampaignDetailMixin,
    DashboardServerAdminExportsMixin,
    DashboardServerAdminApiAllowlistMixin,
    DashboardServerAdminApiCampaignsMixin,
    DashboardServerAdminApiDomainsMixin,
    DashboardServerAdminApiDomainActionsMixin,
    DashboardServerAdminApiSubmissionsMixin,
    DashboardServerAdminApiStatsMixin,
    DashboardServerAdminApiEvidenceMixin,
    DashboardServerRoutesMixin,
):
    """Dashboard server composed from mixins."""


__all__ = ["DashboardConfig", "DashboardServer"]
