"""Visual fingerprinting and matching helpers."""

from __future__ import annotations

import io
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from PIL import Image, ImageChops, ImageFilter
import imagehash

from .visual_tokens import extract_visual_tokens

REGION_WEIGHTS = {
    "full": 0.4,
    "hero": 0.25,
    "center": 0.2,
    "auto": 0.1,
    "logo": 0.05,
}


@dataclass(frozen=True)
class VisualSignature:
    hashes: dict[str, dict[str, str]]
    color_hists: dict[str, list[float]]
    text_tokens: list[str]


@dataclass(frozen=True)
class VisualFingerprint:
    name: str
    group: str
    variant: Optional[str]
    hashes: dict[str, dict[str, str]]
    color_hists: dict[str, list[float]]
    text_tokens: list[str]
    hints: list[str]


@dataclass(frozen=True)
class VisualMatchResult:
    score: float
    label: Optional[str]
    variant: Optional[str]
    image_score: float
    text_score: float
    hint_bonus: float


def _hash_similarity(a: imagehash.ImageHash, b: imagehash.ImageHash) -> float:
    diff = a - b
    bits = a.hash.size
    return max(0.0, (bits - diff) / bits * 100.0)


def _color_hist(image: Image.Image, bins: int = 8) -> list[float]:
    img = image.convert("RGB").resize((64, 64))
    pixels = img.getdata()
    counts = [0] * (bins * 3)
    for r, g, b in pixels:
        counts[r * bins // 256] += 1
        counts[bins + (g * bins // 256)] += 1
        counts[2 * bins + (b * bins // 256)] += 1
    total = sum(counts) or 1
    return [c / total for c in counts]


def _color_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    l1 = sum(abs(x - y) for x, y in zip(a, b))
    return max(0.0, (1.0 - l1 / 2.0) * 100.0)


def _auto_crop(image: Image.Image) -> Image.Image:
    img = image.convert("RGB")
    bg = Image.new("RGB", img.size, img.getpixel((0, 0)))
    diff = ImageChops.difference(img, bg)
    bbox = diff.getbbox()
    return img.crop(bbox) if bbox else img


def _hero_crop(image: Image.Image) -> Image.Image:
    img = image
    height = img.height
    return img.crop((0, 0, img.width, max(1, int(height * 0.35))))


def _center_crop(image: Image.Image) -> Image.Image:
    img = image
    height = img.height
    crop_h = max(1, int(height * 0.5))
    top = max(0, (height - crop_h) // 2)
    return img.crop((0, top, img.width, top + crop_h))


def _logo_crop(image: Image.Image) -> Image.Image:
    img = image
    return img.crop((0, 0, max(1, int(img.width * 0.3)), max(1, int(img.height * 0.2))))


def _prepare_image(image: Image.Image, max_dim: int = 1600) -> Image.Image:
    img = image.convert("RGB")
    if max(img.width, img.height) <= max_dim:
        return img
    scale = max_dim / max(img.width, img.height)
    size = (max(1, int(img.width * scale)), max(1, int(img.height * scale)))
    return img.resize(size, Image.LANCZOS)


def _regions(image: Image.Image) -> dict[str, Image.Image]:
    img = _prepare_image(image)
    return {
        "full": img,
        "hero": _hero_crop(img),
        "center": _center_crop(img),
        "auto": _auto_crop(img),
        "logo": _logo_crop(img),
    }


def build_signature(image: Image.Image, text: Optional[str], raw_html: Optional[str]) -> VisualSignature:
    tokens = extract_visual_tokens(text or "", raw_html or "")
    hashes: dict[str, dict[str, str]] = {}
    color_hists: dict[str, list[float]] = {}

    for region, img in _regions(image).items():
        edges = img.convert("L").filter(ImageFilter.FIND_EDGES)
        hashes[region] = {
            "phash": str(imagehash.phash(img)),
            "dhash": str(imagehash.dhash(img)),
            "ahash": str(imagehash.average_hash(img)),
            "phash_edges": str(imagehash.phash(edges)),
        }
        color_hists[region] = _color_hist(img)

    return VisualSignature(hashes=hashes, color_hists=color_hists, text_tokens=tokens)


def fingerprint_payload(
    *,
    name: str,
    group: str,
    variant: Optional[str],
    image: Image.Image,
    text: Optional[str],
    raw_html: Optional[str],
    url: Optional[str] = None,
    viewport: Optional[tuple[int, int]] = None,
    hints: Optional[list[str]] = None,
) -> dict:
    signature = build_signature(image, text, raw_html)
    return {
        "version": 2,
        "name": name,
        "group": group,
        "variant": variant,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "url": url,
        "viewport": list(viewport) if viewport else None,
        "hashes": signature.hashes,
        "color_hists": signature.color_hists,
        "text_tokens": signature.text_tokens,
        "hints": hints or [],
    }


class VisualMatcher:
    def __init__(self, fingerprints_dir: Path):
        self.fingerprints_dir = Path(fingerprints_dir)
        self._fingerprints: list[VisualFingerprint] = []
        self._last_mtime: float = 0.0
        self._load_fingerprints()

    def reload(self) -> None:
        self._load_fingerprints()

    def _latest_mtime(self) -> float:
        latest = 0.0
        if not self.fingerprints_dir.exists():
            return latest
        for path in self.fingerprints_dir.glob("*"):
            try:
                latest = max(latest, path.stat().st_mtime)
            except OSError:
                continue
        return latest

    def _load_fingerprints(self) -> None:
        self._fingerprints = []
        self.fingerprints_dir.mkdir(parents=True, exist_ok=True)
        json_stems = {p.stem for p in self.fingerprints_dir.glob("*.json")}

        for fp_file in self.fingerprints_dir.glob("*"):
            if fp_file.suffix == ".hash" and fp_file.stem in json_stems:
                continue
            if fp_file.suffix == ".json":
                entry = self._load_json(fp_file)
            elif fp_file.suffix == ".hash":
                entry = self._load_legacy(fp_file)
            else:
                continue
            if entry:
                self._fingerprints.append(entry)

        self._last_mtime = self._latest_mtime()

    def _load_json(self, path: Path) -> Optional[VisualFingerprint]:
        try:
            data = json.loads(path.read_text())
        except Exception:
            return None
        name = str(data.get("name") or path.stem)
        group = str(data.get("group") or name)
        variant = data.get("variant")
        hashes = data.get("hashes") or {}
        color_hists = data.get("color_hists") or {}
        text_tokens = data.get("text_tokens") or []
        hints = [str(h) for h in (data.get("hints") or []) if h]
        return VisualFingerprint(
            name=name,
            group=group,
            variant=variant,
            hashes=hashes,
            color_hists=color_hists,
            text_tokens=text_tokens,
            hints=hints,
        )

    def _load_legacy(self, path: Path) -> Optional[VisualFingerprint]:
        try:
            hash_str = path.read_text().strip()
            imagehash.hex_to_hash(hash_str)
        except Exception:
            return None
        name = path.stem
        group = name.split("__", 1)[0]
        return VisualFingerprint(
            name=name,
            group=group,
            variant=None,
            hashes={"full": {"phash": hash_str}},
            color_hists={},
            text_tokens=[],
            hints=[],
        )

    def _ensure_fresh(self) -> None:
        latest = self._latest_mtime()
        if latest > self._last_mtime:
            self._load_fingerprints()

    def _region_score(self, signature: VisualSignature, fp: VisualFingerprint, region: str) -> float:
        sig_hashes = signature.hashes.get(region) or {}
        fp_hashes = fp.hashes.get(region) or {}
        scores = []
        for key in ("phash", "dhash", "ahash"):
            if key in sig_hashes and key in fp_hashes:
                scores.append(
                    _hash_similarity(
                        imagehash.hex_to_hash(sig_hashes[key]),
                        imagehash.hex_to_hash(fp_hashes[key]),
                    )
                )
        if not scores:
            return 0.0
        hash_score = sum(scores) / len(scores)
        color_score = _color_similarity(
            signature.color_hists.get(region, []),
            fp.color_hists.get(region, []),
        )
        return hash_score * 0.85 + color_score * 0.15

    def _image_score(self, signature: VisualSignature, fp: VisualFingerprint) -> float:
        weighted = 0.0
        weight_total = 0.0
        for region, weight in REGION_WEIGHTS.items():
            if region not in signature.hashes or region not in fp.hashes:
                continue
            region_score = self._region_score(signature, fp, region)
            weighted += region_score * weight
            weight_total += weight
        if weight_total == 0:
            return 0.0
        return weighted / weight_total

    def _text_score(self, signature: VisualSignature, fp: VisualFingerprint) -> float:
        if not signature.text_tokens or not fp.text_tokens:
            return 0.0
        sig = set(signature.text_tokens)
        base = set(fp.text_tokens)
        union = sig | base
        if not union:
            return 0.0
        overlap = len(sig & base)
        jaccard = overlap / len(union)
        containment = overlap / max(1, min(len(sig), len(base)))
        return max(jaccard, containment) * 100.0

    def _hint_bonus(self, signature: VisualSignature, fp: VisualFingerprint) -> float:
        if not fp.hints or not signature.text_tokens:
            return 0.0
        text = " ".join(signature.text_tokens)
        for hint in fp.hints:
            if hint.lower() in text:
                return 10.0
        return 0.0

    def match(
        self,
        screenshot: bytes,
        text: Optional[str] = None,
        raw_html: Optional[str] = None,
    ) -> VisualMatchResult:
        self._ensure_fresh()
        if not self._fingerprints:
            return VisualMatchResult(0.0, None, None, 0.0, 0.0, 0.0)

        image = Image.open(io.BytesIO(screenshot))
        signature = build_signature(image, text or "", raw_html or "")
        grouped: dict[str, VisualMatchResult] = {}

        for fp in self._fingerprints:
            image_score = self._image_score(signature, fp)
            text_score = self._text_score(signature, fp)
            hint_bonus = self._hint_bonus(signature, fp)
            base_score = image_score * 0.7 + text_score * 0.25 + hint_bonus
            final_score = min(100.0, max(image_score, base_score))

            existing = grouped.get(fp.group)
            candidate = VisualMatchResult(
                score=final_score,
                label=fp.group,
                variant=fp.variant or fp.name,
                image_score=image_score,
                text_score=text_score,
                hint_bonus=hint_bonus,
            )
            if not existing or candidate.score > existing.score:
                grouped[fp.group] = candidate

        if not grouped:
            return VisualMatchResult(0.0, None, None, 0.0, 0.0, 0.0)

        best = max(grouped.values(), key=lambda r: r.score)
        return best

    def save_fingerprint_json(
        self,
        *,
        name: str,
        group: str,
        variant: Optional[str],
        screenshot: bytes,
        html: Optional[str],
        text: Optional[str] = None,
        url: Optional[str] = None,
        viewport: Optional[tuple[int, int]] = None,
        hints: Optional[list[str]] = None,
    ) -> Path:
        image = Image.open(io.BytesIO(screenshot))
        payload = fingerprint_payload(
            name=name,
            group=group,
            variant=variant,
            image=image,
            text=text or "",
            raw_html=html,
            url=url,
            viewport=viewport,
            hints=hints,
        )
        path = self.fingerprints_dir / f"{name}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        return path
