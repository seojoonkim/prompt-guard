"""
Prompt Guard - Message Hash Cache (v3.1.0)

LRU cache for analyzed messages:
- Stores SHA-256 hash of normalized message
- 1000 entry limit (configurable)
- 90% token reduction for repeated requests

Thread-safe for concurrent access.
"""

import hashlib
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass
class CacheEntry:
    """Cached analysis result."""
    severity: str
    action: str
    reasons: list
    patterns_count: int
    timestamp: datetime
    hit_count: int = 1


class MessageCache:
    """
    LRU cache for message analysis results.
    
    Usage:
        cache = MessageCache(max_size=1000)
        
        # Check cache first
        cached = cache.get(message)
        if cached:
            return cached  # 90% token savings
        
        # Analyze and store
        result = analyze(message)
        cache.put(message, result)
    """
    
    def __init__(self, max_size: int = 1000):
        """Initialize cache with maximum size."""
        self.max_size = max_size
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
        }
    
    def _hash_message(self, message: str) -> str:
        """Generate SHA-256 hash of normalized message."""
        # Normalize: lowercase, strip whitespace
        normalized = message.lower().strip()
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    
    def get(self, message: str) -> Optional[CacheEntry]:
        """
        Get cached result for message.
        
        Returns CacheEntry if found, None otherwise.
        Updates LRU order on hit.
        """
        key = self._hash_message(message)
        
        with self._lock:
            if key in self._cache:
                # Move to end (most recently used)
                self._cache.move_to_end(key)
                entry = self._cache[key]
                entry.hit_count += 1
                self._stats["hits"] += 1
                return entry
            
            self._stats["misses"] += 1
            return None
    
    def put(self, message: str, severity: str, action: str, 
            reasons: list, patterns_count: int) -> str:
        """
        Store analysis result in cache.
        
        Returns the cache key (hash).
        """
        key = self._hash_message(message)
        
        with self._lock:
            # Evict oldest if at capacity
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
                self._stats["evictions"] += 1
            
            self._cache[key] = CacheEntry(
                severity=severity,
                action=action,
                reasons=reasons,
                patterns_count=patterns_count,
                timestamp=datetime.now(),
            )
        
        return key
    
    def invalidate(self, message: str) -> bool:
        """Remove a specific message from cache."""
        key = self._hash_message(message)
        
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> int:
        """Clear all cached entries. Returns count of cleared items."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total = self._stats["hits"] + self._stats["misses"]
            hit_rate = (self._stats["hits"] / total * 100) if total > 0 else 0
            
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "evictions": self._stats["evictions"],
                "hit_rate": f"{hit_rate:.1f}%",
            }
    
    def get_recent(self, n: int = 10) -> list:
        """Get n most recently accessed entries."""
        with self._lock:
            items = list(self._cache.items())[-n:]
            return [
                {
                    "hash": k[:16] + "...",
                    "severity": v.severity,
                    "action": v.action,
                    "hits": v.hit_count,
                    "timestamp": v.timestamp.isoformat(),
                }
                for k, v in reversed(items)
            ]
    
    def contains(self, message: str) -> bool:
        """Check if message is in cache without updating LRU."""
        key = self._hash_message(message)
        with self._lock:
            return key in self._cache


# Singleton instance
_default_cache: Optional[MessageCache] = None


def get_cache(max_size: int = 1000) -> MessageCache:
    """Get or create the default message cache."""
    global _default_cache
    if _default_cache is None:
        _default_cache = MessageCache(max_size=max_size)
    return _default_cache


def reset_cache() -> None:
    """Reset the default cache (for testing)."""
    global _default_cache
    _default_cache = None
