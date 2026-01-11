"""Layout template loader for server-rendered pages."""

from __future__ import annotations

from pathlib import Path
from string import Template

from .server_helpers import DONATION_WALLET, _escape

_LAYOUT_TEMPLATE: Template | None = None
_LAYOUT_STYLE: str | None = None


def _load_layout_assets() -> tuple[Template, str]:
    global _LAYOUT_TEMPLATE, _LAYOUT_STYLE
    if _LAYOUT_TEMPLATE is None or _LAYOUT_STYLE is None:
        base_dir = Path(__file__).parent / "templates"
        template_text = (base_dir / "layout.html").read_text(encoding="utf-8")
        style_text = (base_dir / "dashboard.css").read_text(encoding="utf-8")
        _LAYOUT_TEMPLATE = Template(template_text)
        _LAYOUT_STYLE = style_text
    return _LAYOUT_TEMPLATE, _LAYOUT_STYLE  # type: ignore[return-value]


def _layout(*, title: str, body: str, admin: bool) -> str:
    """Render the base HTML layout wrapper."""
    campaigns_href = "/admin/campaigns" if admin else "/campaigns"
    nav_items = [f'<a class="nav-link" href="{campaigns_href}">Threat Campaigns</a>']
    if admin:
        nav_items.append('<a class="nav-link" href="/">Public View</a>')
    nav = "".join(nav_items)

    mode_indicator = "ADMIN" if admin else "PUBLIC"
    mode_class = "mode-admin" if admin else "mode-public"
    toggle_href = "/admin" if admin else "/"
    footer_mode = '<span class="sb-footer-mode">Admin view</span>' if admin else ""

    template, style = _load_layout_assets()
    return template.safe_substitute(
        title=_escape(title),
        body=body,
        nav=nav,
        mode_indicator=mode_indicator,
        mode_class=mode_class,
        donation_wallet=DONATION_WALLET,
        toggle_href=toggle_href,
        footer_mode=footer_mode,
        style=style,
    )
