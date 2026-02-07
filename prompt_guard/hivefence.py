#!/usr/bin/env python3
"""
HiveFence API Client for prompt-guard
Connects to the distributed threat intelligence network.

Usage:
    from hivefence import HiveFenceClient
    
    client = HiveFenceClient()
    
    # Report a detected threat
    client.report_threat(
        pattern_hash="sha256:...",
        category="role_override",
        severity=4,
        description="Fake system prompt attempt"
    )
    
    # Fetch latest approved patterns
    patterns = client.fetch_latest()
    
    # Vote on pending pattern
    client.vote(pattern_id, approve=True)
"""

import hashlib
import json
import os
import urllib.request
import urllib.error
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from datetime import datetime, timezone

API_BASE = "https://hivefence-api.seojoon-kim.workers.dev/api/v1"

@dataclass
class ThreatPattern:
    """Represents a threat pattern from HiveFence network."""
    id: str
    pattern_hash: str
    category: str
    severity: int
    description: Optional[str]
    status: str  # pending, voting, approved, rejected
    created_at: str
    votes_up: int = 0
    votes_down: int = 0

@dataclass
class ReportResult:
    """Result of reporting a threat."""
    success: bool
    pattern_id: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None

class HiveFenceClient:
    """Client for HiveFence threat intelligence API."""
    
    def __init__(self, api_base: str = API_BASE, timeout: int = 10):
        self.api_base = api_base
        self.timeout = timeout
        self.cache_file = os.path.expanduser("~/.clawdbot/hivefence_cache.json")
        self._patterns_cache: List[ThreatPattern] = []
        self._cache_loaded = False
    
    def _request(self, method: str, endpoint: str, data: Optional[dict] = None) -> Dict[str, Any]:
        """Make HTTP request to HiveFence API."""
        url = f"{self.api_base}{endpoint}"
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "prompt-guard/3.0.0"
        }
        
        body = json.dumps(data).encode("utf-8") if data else None
        
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except urllib.error.URLError as e:
            return {"error": f"Network error: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def hash_pattern(pattern: str) -> str:
        """Generate SHA-256 hash of a pattern."""
        return f"sha256:{hashlib.sha256(pattern.encode()).hexdigest()[:16]}"
    
    def report_threat(
        self,
        pattern: str,
        category: str,
        severity: int,
        description: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> ReportResult:
        """
        Report a detected threat pattern to HiveFence network.
        
        Args:
            pattern: The attack pattern text or regex
            category: Attack category (role_override, fake_system, jailbreak, etc.)
            severity: Severity 1-5
            description: Human-readable description
            context: Optional context (source, timestamp, etc.)
        
        Returns:
            ReportResult with success status and pattern ID
        """
        pattern_hash = self.hash_pattern(pattern)
        
        payload = {
            "patternHash": pattern_hash,
            "category": category,
            "severity": min(max(severity, 1), 5),  # Clamp 1-5
            "description": description or f"Detected by prompt-guard",
        }
        
        if context:
            payload["context"] = context
        
        result = self._request("POST", "/threats/report", payload)
        
        if "error" in result:
            return ReportResult(success=False, error=result["error"])
        
        return ReportResult(
            success=True,
            pattern_id=result.get("id"),
            message=result.get("message", "Reported successfully")
        )
    
    def fetch_latest(self, limit: int = 50) -> List[ThreatPattern]:
        """
        Fetch latest approved threat patterns from HiveFence.
        
        Args:
            limit: Maximum patterns to fetch
        
        Returns:
            List of approved ThreatPattern objects
        """
        result = self._request("GET", f"/threats/latest?limit={limit}")
        
        if "error" in result:
            # Return cached if network fails
            return self._load_cache()
        
        patterns = []
        for p in result.get("patterns", []):
            patterns.append(ThreatPattern(
                id=p.get("id", ""),
                pattern_hash=p.get("pattern_hash", ""),
                category=p.get("category", "unknown"),
                severity=p.get("severity", 3),
                description=p.get("description"),
                status=p.get("status", "approved"),
                created_at=p.get("created_at", ""),
                votes_up=p.get("votes_up", 0),
                votes_down=p.get("votes_down", 0),
            ))
        
        # Cache results
        self._patterns_cache = patterns
        self._save_cache(patterns)
        
        return patterns
    
    def fetch_pending(self) -> List[ThreatPattern]:
        """Fetch patterns pending validation/voting."""
        result = self._request("GET", "/threats/pending")
        
        if "error" in result:
            return []
        
        patterns = []
        for p in result.get("patterns", []):
            patterns.append(ThreatPattern(
                id=p.get("id", ""),
                pattern_hash=p.get("pattern_hash", ""),
                category=p.get("category", "unknown"),
                severity=p.get("severity", 3),
                description=p.get("description"),
                status=p.get("status", "pending"),
                created_at=p.get("created_at", ""),
                votes_up=p.get("votes_up", 0),
                votes_down=p.get("votes_down", 0),
            ))
        
        return patterns
    
    def vote(self, pattern_id: str, approve: bool, voter_id: Optional[str] = None) -> bool:
        """
        Vote on a pending threat pattern.
        
        Args:
            pattern_id: ID of pattern to vote on
            approve: True to approve, False to reject
            voter_id: Optional voter identifier
        
        Returns:
            True if vote was recorded
        """
        payload = {
            "approve": approve,
        }
        if voter_id:
            payload["voterId"] = voter_id
        
        result = self._request("POST", f"/threats/{pattern_id}/vote", payload)
        
        return "error" not in result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get HiveFence network statistics."""
        return self._request("GET", "/stats")
    
    def _save_cache(self, patterns: List[ThreatPattern]):
        """Save patterns to local cache file."""
        try:
            cache_dir = os.path.dirname(self.cache_file)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir, mode=0o700)
            
            data = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "patterns": [
                    {
                        "id": p.id,
                        "pattern_hash": p.pattern_hash,
                        "category": p.category,
                        "severity": p.severity,
                        "description": p.description,
                    }
                    for p in patterns
                ]
            }
            
            with open(self.cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Cache is optional
    
    def _load_cache(self) -> List[ThreatPattern]:
        """Load patterns from local cache."""
        if self._cache_loaded and self._patterns_cache:
            return self._patterns_cache
        
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file) as f:
                    data = json.load(f)
                
                patterns = []
                for p in data.get("patterns", []):
                    patterns.append(ThreatPattern(
                        id=p.get("id", ""),
                        pattern_hash=p.get("pattern_hash", ""),
                        category=p.get("category", "unknown"),
                        severity=p.get("severity", 3),
                        description=p.get("description"),
                        status="cached",
                        created_at=data.get("updated_at", ""),
                    ))
                
                self._patterns_cache = patterns
                self._cache_loaded = True
                return patterns
        except Exception:
            pass
        
        return []


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="HiveFence CLI")
    parser.add_argument("command", choices=["stats", "latest", "pending", "report", "vote"])
    parser.add_argument("--pattern", help="Pattern text for report")
    parser.add_argument("--category", default="other", help="Attack category")
    parser.add_argument("--severity", type=int, default=3, help="Severity 1-5")
    parser.add_argument("--id", help="Pattern ID for voting")
    parser.add_argument("--approve", action="store_true", help="Approve vote")
    parser.add_argument("--reject", action="store_true", help="Reject vote")
    parser.add_argument("--json", action="store_true", help="JSON output")
    
    args = parser.parse_args()
    client = HiveFenceClient()
    
    if args.command == "stats":
        stats = client.get_stats()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(f"🐝 HiveFence Network Stats")
            print(f"   Total patterns: {stats.get('patterns', {}).get('total', 0)}")
            print(f"   Approved: {stats.get('patterns', {}).get('approved', 0)}")
            print(f"   Pending: {stats.get('patterns', {}).get('pending', 0)}")
    
    elif args.command == "latest":
        patterns = client.fetch_latest()
        if args.json:
            print(json.dumps([{"id": p.id, "category": p.category, "severity": p.severity} for p in patterns], indent=2))
        else:
            print(f"🛡️ Latest {len(patterns)} approved patterns:")
            for p in patterns[:10]:
                print(f"   [{p.severity}/5] {p.category}: {p.description or p.pattern_hash[:20]}")
    
    elif args.command == "pending":
        patterns = client.fetch_pending()
        if args.json:
            print(json.dumps([{"id": p.id, "category": p.category, "votes_up": p.votes_up, "votes_down": p.votes_down} for p in patterns], indent=2))
        else:
            print(f"⏳ {len(patterns)} patterns pending validation:")
            for p in patterns[:10]:
                print(f"   {p.id[:8]}... [{p.category}] 👍{p.votes_up} 👎{p.votes_down}")
    
    elif args.command == "report":
        if not args.pattern:
            print("❌ --pattern required")
            exit(1)
        result = client.report_threat(args.pattern, args.category, args.severity)
        if result.success:
            print(f"✅ Reported: {result.pattern_id}")
        else:
            print(f"❌ Failed: {result.error}")
    
    elif args.command == "vote":
        if not args.id:
            print("❌ --id required")
            exit(1)
        if not args.approve and not args.reject:
            print("❌ --approve or --reject required")
            exit(1)
        success = client.vote(args.id, args.approve)
        print("✅ Vote recorded" if success else "❌ Vote failed")
