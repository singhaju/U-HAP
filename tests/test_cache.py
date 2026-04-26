"""
Tests for the TTL-based decision cache (Step D).
"""

import time
import pytest

from engine.cache import DecisionCache, make_cache_key


# ---------------------------------------------------------------------------
# Cache key construction
# ---------------------------------------------------------------------------

class TestMakeCacheKey:
    def test_same_inputs_same_key(self):
        k1 = make_cache_key("alice", "prod", "pods", "get", 0b101, ["devs"], {"net": "on-premise"})
        k2 = make_cache_key("alice", "prod", "pods", "get", 0b101, ["devs"], {"net": "on-premise"})
        assert k1 == k2

    def test_different_uid_different_key(self):
        k1 = make_cache_key("alice", "prod", "pods", "get", 0b101)
        k2 = make_cache_key("bob",   "prod", "pods", "get", 0b101)
        assert k1 != k2

    def test_different_namespace_different_key(self):
        k1 = make_cache_key("alice", "prod", "pods", "get", 0)
        k2 = make_cache_key("alice", "dev",  "pods", "get", 0)
        assert k1 != k2

    def test_different_action_different_key(self):
        k1 = make_cache_key("alice", "prod", "pods", "get",    0)
        k2 = make_cache_key("alice", "prod", "pods", "delete", 0)
        assert k1 != k2

    def test_different_bitvec_different_key(self):
        k1 = make_cache_key("alice", "prod", "pods", "get", 0b001)
        k2 = make_cache_key("alice", "prod", "pods", "get", 0b010)
        assert k1 != k2

    def test_different_groups_different_key(self):
        k1 = make_cache_key("alice", "prod", "pods", "get", 0, ["devs"])
        k2 = make_cache_key("alice", "prod", "pods", "get", 0, ["admins"])
        assert k1 != k2

    def test_different_attrs_different_key(self):
        k1 = make_cache_key("alice", "prod", "pods", "get", 0, [], {"net": "on-premise"})
        k2 = make_cache_key("alice", "prod", "pods", "get", 0, [], {"net": "remote"})
        assert k1 != k2

    def test_none_attributes_ok(self):
        k = make_cache_key("alice", "prod", "pods", "get", 0, [], None)
        assert isinstance(k, int)

    def test_group_order_irrelevant(self):
        """Groups are stored as frozenset; order doesn't matter."""
        k1 = make_cache_key("alice", "prod", "pods", "get", 0, ["a", "b"])
        k2 = make_cache_key("alice", "prod", "pods", "get", 0, ["b", "a"])
        assert k1 == k2


# ---------------------------------------------------------------------------
# DecisionCache basic operations
# ---------------------------------------------------------------------------

class TestDecisionCacheBasic:
    def test_get_miss_returns_none(self):
        cache = DecisionCache()
        assert cache.get(12345) is None

    def test_put_then_get(self):
        cache = DecisionCache()
        key = make_cache_key("alice", "prod", "pods", "get", 0)
        cache.put(key, True, "acl: alice")
        result = cache.get(key)
        assert result is not None
        allowed, reason = result
        assert allowed is True
        assert reason == "acl: alice"

    def test_put_deny_decision(self):
        cache = DecisionCache()
        key = make_cache_key("bob", "prod", "secrets", "delete", 0)
        cache.put(key, False, "deny rule: wildcard")
        allowed, reason = cache.get(key)
        assert allowed is False
        assert "deny" in reason

    def test_invalidate_clears_all(self):
        cache = DecisionCache()
        k1 = make_cache_key("alice", "prod", "pods", "get", 0)
        k2 = make_cache_key("bob",   "prod", "pods", "get", 0)
        cache.put(k1, True, "acl: alice")
        cache.put(k2, False, "no path")
        cache.invalidate()
        assert cache.get(k1) is None
        assert cache.get(k2) is None
        assert cache.size == 0

    def test_size_tracking(self):
        cache = DecisionCache()
        assert cache.size == 0
        cache.put(1, True, "acl")
        cache.put(2, False, "deny")
        assert cache.size == 2
        cache.invalidate()
        assert cache.size == 0

    def test_overwrite_entry(self):
        cache = DecisionCache()
        key = 42
        cache.put(key, True, "acl: alice")
        cache.put(key, False, "deny rule")
        allowed, _ = cache.get(key)
        assert allowed is False


# ---------------------------------------------------------------------------
# TTL behavior
# ---------------------------------------------------------------------------

class TestDecisionCacheTTL:
    def test_entry_expires_after_ttl(self):
        cache = DecisionCache(ttl_seconds=0.05)  # 50ms TTL
        key = make_cache_key("alice", "prod", "pods", "get", 0)
        cache.put(key, True, "acl")
        # Should be present immediately
        assert cache.get(key) is not None
        # Wait for TTL to expire
        time.sleep(0.1)
        assert cache.get(key) is None

    def test_zero_ttl_entries_never_expire(self):
        """TTL=0 means no expiry."""
        cache = DecisionCache(ttl_seconds=0)
        key = make_cache_key("alice", "prod", "pods", "get", 0)
        cache.put(key, True, "acl")
        time.sleep(0.05)
        assert cache.get(key) is not None

    def test_fresh_entry_within_ttl(self):
        cache = DecisionCache(ttl_seconds=10)
        key = make_cache_key("alice", "prod", "pods", "get", 0)
        cache.put(key, True, "acl")
        assert cache.get(key) is not None


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

class TestDecisionCacheStats:
    def test_hit_miss_counts(self):
        cache = DecisionCache()
        key = make_cache_key("alice", "prod", "pods", "get", 0)

        # Miss
        cache.get(key)
        assert cache.misses == 1
        assert cache.hits == 0

        # Put then hit
        cache.put(key, True, "acl")
        cache.get(key)
        assert cache.hits == 1

    def test_hit_rate_calculation(self):
        cache = DecisionCache()
        key = make_cache_key("alice", "prod", "pods", "get", 0)
        cache.get(99999)           # miss
        cache.put(key, True, "acl")
        cache.get(key)             # hit
        assert cache.hit_rate == pytest.approx(0.5)

    def test_reset_stats(self):
        cache = DecisionCache()
        key = make_cache_key("alice", "prod", "pods", "get", 0)
        cache.put(key, True, "acl")
        cache.get(key)
        cache.get(99999)
        cache.reset_stats()
        assert cache.hits == 0
        assert cache.misses == 0
        assert cache.hit_rate == 0.0
