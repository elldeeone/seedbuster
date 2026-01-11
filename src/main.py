"""Main entry point for SeedBuster phishing detection pipeline."""

from __future__ import annotations

from .pipeline.runner import SeedBusterPipeline, main

__all__ = ["SeedBusterPipeline", "main"]

if __name__ == "__main__":
    main()
