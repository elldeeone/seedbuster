#!/usr/bin/env python3
"""Create fingerprint from an existing screenshot file.

Usage:
    python scripts/hash_screenshot.py <path_to_screenshot.png> [fingerprint_name]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer.detector import PhishingDetector


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/hash_screenshot.py <screenshot.png> [name]")
        print("Example: python scripts/hash_screenshot.py ~/Desktop/recovery.png kaspanet-wallet-recovery")
        sys.exit(1)

    screenshot_path = Path(sys.argv[1]).expanduser()
    name = sys.argv[2] if len(sys.argv) > 2 else "kaspanet-wallet-recovery"

    if not screenshot_path.exists():
        print(f"Error: File not found: {screenshot_path}")
        sys.exit(1)

    fingerprints_dir = Path("data/fingerprints")
    fingerprints_dir.mkdir(parents=True, exist_ok=True)

    detector = PhishingDetector(fingerprints_dir=fingerprints_dir)

    print(f"Reading screenshot: {screenshot_path}")
    screenshot_bytes = screenshot_path.read_bytes()

    # Save fingerprint
    detector.save_fingerprint(name, screenshot_bytes)
    print(f"Fingerprint saved: {name}")

    # Copy screenshot to fingerprints folder for reference
    ref_path = fingerprints_dir / f"{name}.png"
    ref_path.write_bytes(screenshot_bytes)
    print(f"Reference copy saved: {ref_path}")

    # Also set as primary fingerprint
    if name != "kaspanet-wallet":
        detector.save_fingerprint("kaspanet-wallet", screenshot_bytes)
        print("Updated primary fingerprint (kaspanet-wallet)")

    print("\nDone! Fingerprints:")
    for fp in fingerprints_dir.glob("*.hash"):
        print(f"  - {fp.name}")


if __name__ == "__main__":
    main()
