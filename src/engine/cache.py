"""
TTL-based decision cache for U-HAP Phase 3.

The cache stores authorization decisions keyed by a hash of all inputs
that affect the decision. It has a configurable TTL and is invalidated
completely on policy reload.

Cache key κ = hash(uid, namespace, resource, action, role_bitvec, group_sig, attr_sig)

  - role_bitvec:  integer bit-vector of user's roles (computed by the evaluator)
  - group_sig:    frozenset of group names (or tuple for hashability)
  - attr_sig:     frozenset of (attr_key, attr_value) pairs

Public API:
  DecisionCache         -- TTL-based cache class
  make_cache_key(...)   -- build the canonical cache key κ
"""

import hashlib
import time
from typing import Any, Dict, Iterable, Optional, Tuple


def make_cache_key(
    uid: str,
    namespace: str,
    resource: str,
    action: str,
    role_bitvec: int,
    groups: Iterable[str] = (),
    attributes: Dict[str, Any] = None,
) -> int:
    """Build the canonical cache key κ for a request.

    Args:
        uid:         Authenticated user identity.
        namespace:   Kubernetes namespace.
        resource:    Resource name.
        action:      Action verb.
        role_bitvec: Integer bit-vector of user roles (from RoleBitVector.encode).
        groups:      User group memberships.
        attributes:  User + context attributes dict.

    Returns:
        int hash (Python hash of a canonical tuple)
    """
    if attributes is None:
        attributes = {}

    # Build a stable, hashable representation of the attributes
    attr_sig = frozenset(
        (k, str(v)) for k, v in attributes.items()
    )
    group_sig = frozenset(groups)

    return hash((uid, namespace, resource, action, role_bitvec, group_sig, attr_sig))


class DecisionCache:
    """TTL-based decision cache with policy-change invalidation.

    Stores (decision, reason) pairs indexed by cache key κ.
    Entries expire after `ttl_seconds`. All entries are invalidated
    when `invalidate()` is called (e.g., on policy reload).

    Usage:
        cache = DecisionCache(ttl_seconds=30)

        key = make_cache_key(uid, ns, res, action, b_user, groups, attrs)
        cached = cache.get(key)
        if cached is not None:
            allowed, reason = cached
        else:
            allowed, reason = evaluate(...)
            cache.put(key, allowed, reason)
    """

    def __init__(self, ttl_seconds: float = 30.0):
        """Initialize the cache.

        Args:
            ttl_seconds: Time-to-live for each cache entry in seconds.
                         Defaults to 30 seconds. Set to 0 to disable TTL
                         (entries live until invalidated).
        """
        self._ttl = ttl_seconds
        # _store: key -> (allowed, reason, expires_at)
        self._store: Dict[int, Tuple[bool, str, float]] = {}
        # Stats for benchmarking / audit
        self._hits: int = 0
        self._misses: int = 0

    def get(self, key: int) -> Optional[Tuple[bool, str]]:
        """Retrieve a cached decision.

        Args:
            key: Cache key κ from make_cache_key().

        Returns:
            (allowed, reason) if the entry exists and has not expired,
            None otherwise.
        """
        entry = self._store.get(key)
        if entry is None:
            self._misses += 1
            return None

        allowed, reason, expires_at = entry
        if self._ttl > 0 and time.monotonic() > expires_at:
            # Expired — remove and report miss
            del self._store[key]
            self._misses += 1
            return None

        self._hits += 1
        return allowed, reason

    def put(self, key: int, allowed: bool, reason: str) -> None:
        """Store a decision in the cache.

        Args:
            key:     Cache key κ.
            allowed: Decision (True = ALLOW, False = DENY).
            reason:  Reason string for the decision.
        """
        if self._ttl > 0:
            expires_at = time.monotonic() + self._ttl
        else:
            expires_at = float("inf")
        self._store[key] = (allowed, reason, expires_at)

    def invalidate(self) -> None:
        """Remove all cached entries.

        Call this when policies are reloaded to ensure stale decisions are
        not served.
        """
        self._store.clear()

    @property
    def size(self) -> int:
        """Current number of entries in the cache."""
        return len(self._store)

    @property
    def hits(self) -> int:
        """Total cache hits since creation or last reset."""
        return self._hits

    @property
    def misses(self) -> int:
        """Total cache misses since creation or last reset."""
        return self._misses

    @property
    def hit_rate(self) -> float:
        """Hit rate as a fraction [0, 1]. Returns 0 if no requests yet."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def reset_stats(self) -> None:
        """Reset hit/miss counters."""
        self._hits = 0
        self._misses = 0
