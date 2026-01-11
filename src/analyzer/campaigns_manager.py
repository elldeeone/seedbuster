"""Threat campaign manager composition."""

from __future__ import annotations

from .campaigns_access import CampaignAccessMixin
from .campaigns_base import ThreatCampaignManagerBase
from .campaigns_matching import CampaignMatchingMixin
from .campaigns_merge import CampaignMergeMixin
from .campaigns_storage import CampaignStorageMixin


class ThreatCampaignManager(
    ThreatCampaignManagerBase,
    CampaignStorageMixin,
    CampaignMergeMixin,
    CampaignMatchingMixin,
    CampaignAccessMixin,
):
    """Concrete threat campaign manager."""

    pass
