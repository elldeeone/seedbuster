"""Seed phrase detection helpers."""

from __future__ import annotations

import re

from .browser import BrowserResult


class DetectorSeedMixin:
    """Seed form helpers."""

    def _detect_seed_form(self, result: BrowserResult) -> tuple[int, list[str]]:
        """Detect seed phrase input forms."""
        score = 0
        reasons: list[str] = []

        s = self.scoring
        exact_counts = s.get("seed_form_exact_counts", [12, 24])
        possible_range = s.get("seed_form_possible_range", [10, 26])
        seed_like_definitive = s.get("seed_like_inputs_definitive", 10)
        seed_like_possible = s.get("seed_like_inputs_possible", 3)

        if result.exploration_steps:
            for step in result.exploration_steps:
                if getattr(step, "is_seed_form", False):
                    score += s.get("seed_form_definitive", 50)
                    reasons.append(
                        f"Seed phrase form found via exploration: '{step.button_text}'"
                    )
                    return score, reasons
                text_input_count = sum(
                    1
                    for inp in step.input_fields
                    if (inp.get("type", "") or "").lower() in ("text", "password", "")
                )
                if text_input_count in exact_counts:
                    score += s.get("seed_form_definitive", 50)
                    reasons.append(
                        "Seed phrase form found via exploration: "
                        f"'{step.button_text}' ({text_input_count} inputs)"
                    )
                    return score, reasons

        seed_like_inputs = 0
        for inp in result.input_fields:
            inp_type = inp.get("type", "").lower()
            placeholder = inp.get("placeholder", "").lower()
            name = inp.get("name", "").lower()
            inp_id = inp.get("id", "").lower()

            if inp_type in ("text", "password", ""):
                if any(
                    pattern in placeholder + name + inp_id
                    for pattern in ["word", "seed", "mnemonic", "phrase", "recovery"]
                ):
                    seed_like_inputs += 1
                elif re.search(
                    r"(word|w|seed|phrase)\s*#?\d+",
                    placeholder + name + inp_id,
                    re.I,
                ):
                    seed_like_inputs += 1

        text_input_count = sum(
            1 for inp in result.input_fields if inp.get("type", "") in ("text", "password", "")
        )

        if text_input_count in exact_counts or seed_like_inputs >= seed_like_definitive:
            score += s.get("seed_form_12_24_inputs", 35)
            reasons.append(f"Seed phrase form detected ({text_input_count} inputs)")
        elif text_input_count in range(possible_range[0], possible_range[1]) and seed_like_inputs >= seed_like_possible:
            score += s.get("seed_form_possible", 25)
            reasons.append(
                f"Possible seed form ({text_input_count} inputs, {seed_like_inputs} seed-like)"
            )
        elif seed_like_inputs >= seed_like_possible:
            score += s.get("seed_form_inputs", 15)
            reasons.append(f"Seed-related inputs detected ({seed_like_inputs} found)")

        return score, reasons

    def _count_seed_inputs(self, result: BrowserResult) -> int:
        """Count inputs that appear to be for seed words."""
        count = 0
        for inp in result.input_fields:
            if inp.get("type", "") in ("text", "password", ""):
                placeholder = inp.get("placeholder", "").lower()
                name = inp.get("name", "").lower()
                if any(kw in placeholder + name for kw in ["word", "seed", "mnemonic"]):
                    count += 1
        return count
