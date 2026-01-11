"""Exploration analysis helpers."""

from __future__ import annotations

import re

from .browser import BrowserResult


class DetectorExplorationMixin:
    """Exploration analysis helpers."""

    def _analyze_exploration(self, browser_result: BrowserResult) -> tuple[int, list[str]]:
        """Analyze click-through exploration results for hidden phishing forms."""
        score = 0
        reasons: list[str] = []

        s = self.scoring
        exact_counts = s.get("seed_form_exact_counts", [12, 24])
        possible_range = s.get("seed_form_possible_range", [10, 26])
        seed_like_definitive = s.get("seed_like_inputs_definitive", 10)
        seed_like_possible = s.get("seed_like_inputs_possible", 3)

        for step in browser_result.exploration_steps:
            if not step.success:
                continue

            seed_like_inputs = 0
            for inp in step.input_fields:
                inp_type = inp.get("type", "").lower()
                placeholder = inp.get("placeholder", "").lower()
                name = inp.get("name", "").lower()
                inp_id = inp.get("id", "").lower()

                combined = placeholder + name + inp_id
                if inp_type in ("text", "password", ""):
                    if any(kw in combined for kw in ["word", "seed", "phrase", "mnemonic", "recovery"]):
                        seed_like_inputs += 1
                    elif re.search(r"(word|w|seed)\s*#?\d+", combined, re.I):
                        seed_like_inputs += 1

            text_input_count = sum(
                1 for inp in step.input_fields if inp.get("type", "") in ("text", "password", "")
            )

            if text_input_count in exact_counts or seed_like_inputs >= seed_like_definitive:
                score += s.get("seed_form_definitive", 50)
                reasons.append(
                    f"EXPLORE: Seed form detected via exploration: '{step.button_text}' ({text_input_count} inputs)"
                )
                break
            if text_input_count in range(possible_range[0], possible_range[1]) and seed_like_inputs >= seed_like_possible:
                score += s.get("seed_form_possible", 25)
                reasons.append(
                    f"EXPLORE: Possible seed form detected via exploration: '{step.button_text}'"
                )
                break

        return score, reasons
