"""Unified caching abstraction for SeedBuster.

Provides consistent caching behavior across:
- External intelligence (urlscan.io, VirusTotal, URLhaus)
- Infrastructure analysis (ASN lookups)
- RDAP registrar lookups

Supports:
- In-memory caching with TTL
- Optional disk persistence with JSON serialization
- Composite key generation
- Thread-safe operations
"""

import hashlib
import json
import logging
import threading
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Optional, TypeVar, Union

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CacheEntry:
    """Represents a cached value with timestamp."""

    __slots__ = ("value", "timestamp", "ttl_seconds")

    def __init__(self, value: Any, timestamp: float, ttl_seconds: Optional[int] = None):
        self.value = value
        self.timestamp = timestamp
        self.ttl_seconds = ttl_seconds

    def is_expired(self, default_ttl: int) -> bool:
        """Check if this entry has expired."""
        ttl = self.ttl_seconds if self.ttl_seconds is not None else default_ttl
        return time.time() - self.timestamp >= ttl


class CacheManager:
    """
    Unified cache manager supporting memory and disk caching.

    Usage:
        cache = CacheManager(
            cache_dir=Path("data/cache"),
            ttl_seconds=3600,
            namespace="urlscan",
        )

        # Simple get/set
        cache.set("example.com", result)
        cached = cache.get("example.com")

        # Get with fallback
        result = await cache.get_or_fetch("key", fetch_async_fn)
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: int = 3600,
        namespace: str = "",
        use_memory: bool = True,
        use_disk: bool = True,
    ):
        """
        Initialize cache manager.

        Args:
            cache_dir: Directory for disk cache (None disables disk caching)
            ttl_seconds: Default TTL for cache entries
            namespace: Prefix for cache keys (e.g., "urlscan", "virustotal")
            use_memory: Enable in-memory caching
            use_disk: Enable disk caching (requires cache_dir)
        """
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_seconds
        self.namespace = namespace
        self.use_memory = use_memory
        self.use_disk = use_disk and cache_dir is not None

        self._memory: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()

        if self.use_disk and cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)

    def _make_key(self, key: str) -> str:
        """Generate full cache key with namespace."""
        if self.namespace:
            return f"{self.namespace}:{key}"
        return key

    def _disk_path(self, key: str) -> Optional[Path]:
        """Get disk cache file path for a key."""
        if not self.cache_dir:
            return None
        # Use MD5 hash for safe filesystem naming
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"

    def _serialize(self, value: Any) -> Any:
        """Serialize value for disk storage."""
        if is_dataclass(value) and not isinstance(value, type):
            return {"__dataclass__": type(value).__name__, "data": asdict(value)}
        if isinstance(value, datetime):
            return {"__datetime__": value.isoformat()}
        if isinstance(value, dict):
            return {k: self._serialize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._serialize(v) for v in value]
        return value

    def _read_disk(self, key: str) -> Optional[CacheEntry]:
        """Read entry from disk cache."""
        path = self._disk_path(key)
        if not path or not path.exists():
            return None

        try:
            with open(path, "r") as f:
                data = json.load(f)
            return CacheEntry(
                value=data.get("value"),
                timestamp=data.get("timestamp", 0),
                ttl_seconds=data.get("ttl_seconds"),
            )
        except Exception as e:
            logger.debug(f"Failed to read disk cache for {key}: {e}")
            return None

    def _write_disk(self, key: str, entry: CacheEntry) -> None:
        """Write entry to disk cache."""
        path = self._disk_path(key)
        if not path:
            return

        try:
            with open(path, "w") as f:
                json.dump(
                    {
                        "key": key,
                        "value": self._serialize(entry.value),
                        "timestamp": entry.timestamp,
                        "ttl_seconds": entry.ttl_seconds,
                        "cached_at": datetime.now().isoformat(),
                    },
                    f,
                )
        except Exception as e:
            logger.debug(f"Failed to write disk cache for {key}: {e}")

    def _delete_disk(self, key: str) -> None:
        """Delete entry from disk cache."""
        path = self._disk_path(key)
        if path and path.exists():
            try:
                path.unlink()
            except Exception as e:
                logger.debug(f"Failed to delete disk cache for {key}: {e}")

    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value if exists and not expired.

        Args:
            key: Cache key (will be prefixed with namespace)

        Returns:
            Cached value or None if not found/expired
        """
        full_key = self._make_key(key)

        with self._lock:
            # Check memory cache first
            if self.use_memory and full_key in self._memory:
                entry = self._memory[full_key]
                if not entry.is_expired(self.ttl_seconds):
                    return entry.value
                # Expired - remove from memory
                del self._memory[full_key]

            # Check disk cache
            if self.use_disk:
                entry = self._read_disk(full_key)
                if entry and not entry.is_expired(self.ttl_seconds):
                    # Promote to memory cache
                    if self.use_memory:
                        self._memory[full_key] = entry
                    return entry.value
                # Expired - clean up disk
                if entry:
                    self._delete_disk(full_key)

        return None

    def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """
        Set cached value.

        Args:
            key: Cache key (will be prefixed with namespace)
            value: Value to cache
            ttl_seconds: Override default TTL for this entry
        """
        full_key = self._make_key(key)
        entry = CacheEntry(
            value=value,
            timestamp=time.time(),
            ttl_seconds=ttl_seconds,
        )

        with self._lock:
            if self.use_memory:
                self._memory[full_key] = entry
            if self.use_disk:
                self._write_disk(full_key, entry)

    def delete(self, key: str) -> None:
        """Delete cached value."""
        full_key = self._make_key(key)

        with self._lock:
            if self.use_memory and full_key in self._memory:
                del self._memory[full_key]
            if self.use_disk:
                self._delete_disk(full_key)

    def clear(self) -> None:
        """Clear all cached values in this namespace."""
        with self._lock:
            # Clear memory cache for this namespace
            if self.use_memory:
                if self.namespace:
                    prefix = f"{self.namespace}:"
                    keys_to_delete = [k for k in self._memory if k.startswith(prefix)]
                    for k in keys_to_delete:
                        del self._memory[k]
                else:
                    self._memory.clear()

            # Clear disk cache (all files in cache_dir for this namespace)
            if self.use_disk and self.cache_dir:
                # Note: We can't easily filter by namespace on disk since keys are hashed
                # For safety, only clear all if no namespace is set
                if not self.namespace:
                    for f in self.cache_dir.glob("*.json"):
                        try:
                            f.unlink()
                        except Exception:
                            pass

    def get_or_set(
        self,
        key: str,
        fetch_fn: Callable[[], T],
        ttl_seconds: Optional[int] = None,
    ) -> T:
        """
        Get cached value or fetch and cache it.

        Args:
            key: Cache key
            fetch_fn: Synchronous function to fetch value if not cached
            ttl_seconds: Override default TTL

        Returns:
            Cached or freshly fetched value
        """
        cached = self.get(key)
        if cached is not None:
            return cached

        value = fetch_fn()
        self.set(key, value, ttl_seconds)
        return value

    async def get_or_fetch(
        self,
        key: str,
        fetch_fn: Callable[[], Any],
        ttl_seconds: Optional[int] = None,
    ) -> Any:
        """
        Get cached value or fetch and cache it (async version).

        Args:
            key: Cache key
            fetch_fn: Async function to fetch value if not cached
            ttl_seconds: Override default TTL

        Returns:
            Cached or freshly fetched value
        """
        cached = self.get(key)
        if cached is not None:
            return cached

        value = await fetch_fn()
        self.set(key, value, ttl_seconds)
        return value

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            memory_count = len(self._memory)
            disk_count = 0
            if self.use_disk and self.cache_dir:
                disk_count = len(list(self.cache_dir.glob("*.json")))

            return {
                "namespace": self.namespace,
                "ttl_seconds": self.ttl_seconds,
                "memory_entries": memory_count,
                "disk_entries": disk_count,
                "use_memory": self.use_memory,
                "use_disk": self.use_disk,
            }


# Convenience factory functions for common cache types


def create_intel_cache(
    cache_dir: Optional[Path] = None,
    ttl_hours: int = 24,
) -> CacheManager:
    """Create cache for external intelligence queries."""
    return CacheManager(
        cache_dir=cache_dir,
        ttl_seconds=ttl_hours * 3600,
        namespace="intel",
        use_memory=True,
        use_disk=True,
    )


def create_asn_cache(ttl_seconds: int = 3600) -> CacheManager:
    """Create cache for ASN lookups (memory-only)."""
    return CacheManager(
        cache_dir=None,
        ttl_seconds=ttl_seconds,
        namespace="asn",
        use_memory=True,
        use_disk=False,
    )


def create_rdap_cache(ttl_seconds: int = 3600) -> CacheManager:
    """Create cache for RDAP lookups (memory-only)."""
    return CacheManager(
        cache_dir=None,
        ttl_seconds=ttl_seconds,
        namespace="rdap",
        use_memory=True,
        use_disk=False,
    )
