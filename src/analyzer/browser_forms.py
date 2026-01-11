"""Browser analyzer form extraction helpers."""

from __future__ import annotations

import logging

from playwright.async_api import Page

logger = logging.getLogger(__name__)


class BrowserFormsMixin:
    """Form extraction helpers."""

    async def _extract_forms(self, page: Page) -> list[dict]:
        """Extract form information from the page."""
        try:
            forms = await page.evaluate(
                """
                () => {
                    const forms = document.querySelectorAll('form');
                    return Array.from(forms).map(form => ({
                        action: form.action,
                        method: form.method,
                        id: form.id,
                        class: form.className,
                        inputCount: form.querySelectorAll('input').length,
                        hasPasswordField: form.querySelector('input[type="password"]') !== null,
                    }));
                }
            """
            )
            return forms
        except Exception as exc:
            logger.error("Error extracting forms: %s", exc)
            return []

    async def _extract_inputs(self, page: Page) -> list[dict]:
        """Extract input field information from the page."""
        try:
            inputs = await page.evaluate(
                """
                () => {
                    const inputs = document.querySelectorAll('input, textarea');
                    return Array.from(inputs).map(input => ({
                        tag: input.tagName.toLowerCase(),
                        type: input.type,
                        name: input.name,
                        id: input.id,
                        placeholder: input.placeholder,
                        class: input.className,
                        maxLength: input.maxLength,
                        required: input.required,
                    }));
                }
            """
            )
            return inputs
        except Exception as exc:
            logger.error("Error extracting inputs: %s", exc)
            return []

    def _is_mnemonic_form(self, inputs: list[dict], page_text: str = "") -> bool:
        """Check if the page contains a mnemonic/seed phrase input form."""
        page_text_lower = page_text.lower()

        mnemonic_keywords = [
            "12 words",
            "24 words",
            "12-word",
            "24-word",
            "mnemonic",
            "seed phrase",
            "recovery phrase",
            "secret phrase",
            "backup phrase",
            "enter mnemonic",
            "import mnemonic",
            "comprised of 12",
            "comprised of 24",
        ]
        has_mnemonic_text = any(kw in page_text_lower for kw in mnemonic_keywords)

        for inp in inputs:
            if inp.get("tag") == "textarea":
                attrs = (
                    inp.get("placeholder", "")
                    + inp.get("name", "")
                    + inp.get("id", "")
                    + inp.get("class", "")
                ).lower()
                if any(kw in attrs for kw in ["mnemonic", "seed", "phrase", "word", "secret"]):
                    return True
                if has_mnemonic_text:
                    return True

        text_inputs = [
            inp
            for inp in inputs
            if inp.get("type") in ("text", "password", "") and inp.get("tag") != "textarea"
        ]
        if len(text_inputs) >= 12:
            return True

        seed_inputs = [
            inp
            for inp in inputs
            if any(
                kw
                in (
                    inp.get("placeholder", "") + inp.get("name", "") + inp.get("id", "")
                ).lower()
                for kw in ["word", "seed", "phrase", "mnemonic"]
            )
        ]
        if seed_inputs and has_mnemonic_text:
            return True

        return False
