"""Report manager for coordinating abuse reports across platforms."""

from __future__ import annotations

from .manager_core import ReportManagerCoreMixin
from .manager_identity import ReportManagerIdentityMixin
from .manager_hints import ReportManagerHintsMixin
from .manager_evidence import ReportManagerEvidenceMixin
from .manager_retry import ReportManagerRetryMixin
from .manager_manual import ReportManagerManualMixin
from .manager_status import ReportManagerStatusMixin
from .manager_preview import ReportManagerPreviewMixin
from .manager_preview_templates import ReportManagerPreviewTemplateMixin
from .manager_reporting import ReportManagerReportingMixin
from .rate_limiter import get_rate_limiter


class ReportManager(
    ReportManagerCoreMixin,
    ReportManagerIdentityMixin,
    ReportManagerHintsMixin,
    ReportManagerEvidenceMixin,
    ReportManagerRetryMixin,
    ReportManagerManualMixin,
    ReportManagerStatusMixin,
    ReportManagerPreviewTemplateMixin,
    ReportManagerPreviewMixin,
    ReportManagerReportingMixin,
):
    """
    Manages multi-platform abuse reporting.

    Coordinates reporters, handles rate limiting, tracks report status
    in database, and provides evidence packaging.
    """

    pass


__all__ = ["ReportManager", "get_rate_limiter"]
