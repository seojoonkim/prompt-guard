"""
Prompt Guard - Tiered Pattern Loader (v3.1.0)

Token-optimized pattern loading system:
- Tier 0: CRITICAL patterns (~30) - always loaded
- Tier 1: + HIGH patterns (~70) - default
- Tier 2: + MEDIUM patterns (~100+) - on-demand

70% token reduction in default mode.
"""

import re
import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum


class LoadTier(Enum):
    """Pattern loading tiers."""
    CRITICAL = 0  # Always loaded, minimal footprint
    HIGH = 1      # Default load level
    FULL = 2      # Complete pattern set (on-demand)


@dataclass
class PatternEntry:
    """Single pattern with metadata."""
    pattern: str
    severity: str
    category: str
    lang: str = "en"
    compiled: Optional[re.Pattern] = None
    
    def compile(self) -> None:
        """Pre-compile regex for performance."""
        if self.compiled is None:
            try:
                self.compiled = re.compile(self.pattern, re.IGNORECASE)
            except re.error:
                pass


@dataclass
class PatternSet:
    """Collection of patterns for a tier."""
    tier: LoadTier
    patterns: List[PatternEntry] = field(default_factory=list)
    loaded: bool = False
    
    @property
    def count(self) -> int:
        return len(self.patterns)


class TieredPatternLoader:
    """
    Tiered pattern loading for token optimization.
    
    Usage:
        loader = TieredPatternLoader()
        loader.load_tier(LoadTier.HIGH)  # Default
        patterns = loader.get_patterns()
        
        # On threat detection, escalate to full:
        loader.load_tier(LoadTier.FULL)
    """
    
    def __init__(self, patterns_dir: Optional[Path] = None):
        """Initialize loader with patterns directory."""
        if patterns_dir is None:
            # Default to skills/prompt-guard/patterns/
            patterns_dir = Path(__file__).parent.parent / "patterns"
        
        self.patterns_dir = patterns_dir
        self.tiers: Dict[LoadTier, PatternSet] = {
            LoadTier.CRITICAL: PatternSet(tier=LoadTier.CRITICAL),
            LoadTier.HIGH: PatternSet(tier=LoadTier.HIGH),
            LoadTier.FULL: PatternSet(tier=LoadTier.FULL),
        }
        self.current_tier: LoadTier = LoadTier.CRITICAL
        self._loaded_categories: Set[str] = set()
        
    def load_tier(self, tier: LoadTier = LoadTier.HIGH) -> int:
        """
        Load patterns up to the specified tier.
        
        Returns number of patterns loaded.
        """
        total_loaded = 0
        
        # Always load critical first
        if not self.tiers[LoadTier.CRITICAL].loaded:
            total_loaded += self._load_yaml("critical.yaml", LoadTier.CRITICAL)
            self.tiers[LoadTier.CRITICAL].loaded = True
        
        # Load high if requested
        if tier.value >= LoadTier.HIGH.value and not self.tiers[LoadTier.HIGH].loaded:
            total_loaded += self._load_yaml("high.yaml", LoadTier.HIGH)
            self.tiers[LoadTier.HIGH].loaded = True
        
        # Load full if requested
        if tier.value >= LoadTier.FULL.value and not self.tiers[LoadTier.FULL].loaded:
            total_loaded += self._load_yaml("medium.yaml", LoadTier.FULL)
            self.tiers[LoadTier.FULL].loaded = True
        
        self.current_tier = tier
        return total_loaded
    
    def _load_yaml(self, filename: str, tier: LoadTier) -> int:
        """Load patterns from a YAML file."""
        filepath = self.patterns_dir / filename
        if not filepath.exists():
            return 0
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception:
            return 0
        
        count = 0
        patterns_data = data.get("patterns", {})
        
        for category, pattern_list in patterns_data.items():
            if not isinstance(pattern_list, list):
                continue
            
            for p in pattern_list:
                if not isinstance(p, dict) or "pattern" not in p:
                    continue
                
                entry = PatternEntry(
                    pattern=p["pattern"],
                    severity=p.get("severity", "medium"),
                    category=p.get("category", category),
                    lang=p.get("lang", "en"),
                )
                entry.compile()
                self.tiers[tier].patterns.append(entry)
                self._loaded_categories.add(category)
                count += 1
        
        return count
    
    def get_patterns(self, tier: Optional[LoadTier] = None) -> List[PatternEntry]:
        """Get all loaded patterns up to the specified tier."""
        target_tier = tier or self.current_tier
        patterns = []
        
        for t in LoadTier:
            if t.value <= target_tier.value and self.tiers[t].loaded:
                patterns.extend(self.tiers[t].patterns)
        
        return patterns
    
    def get_patterns_by_severity(self, severity: str) -> List[PatternEntry]:
        """Get patterns of a specific severity."""
        return [p for p in self.get_patterns() if p.severity == severity]
    
    def get_patterns_by_category(self, category: str) -> List[PatternEntry]:
        """Get patterns of a specific category."""
        return [p for p in self.get_patterns() if p.category == category]
    
    def escalate_to_full(self) -> int:
        """Escalate to full pattern set (on threat detection)."""
        return self.load_tier(LoadTier.FULL)
    
    def get_stats(self) -> Dict:
        """Get loading statistics."""
        return {
            "current_tier": self.current_tier.name,
            "tier_counts": {
                t.name: self.tiers[t].count for t in LoadTier
            },
            "total_loaded": sum(self.tiers[t].count for t in LoadTier if self.tiers[t].loaded),
            "categories": list(self._loaded_categories),
        }
    
    def scan_text(self, text: str) -> List[Tuple[PatternEntry, re.Match]]:
        """
        Scan text against all loaded patterns.
        
        Returns list of (pattern, match) tuples.
        """
        matches = []
        text_lower = text.lower()
        
        for pattern in self.get_patterns():
            if pattern.compiled:
                match = pattern.compiled.search(text_lower)
                if match:
                    matches.append((pattern, match))
        
        return matches
    
    def quick_scan(self, text: str) -> bool:
        """
        Quick scan - check critical patterns only.
        Returns True if any critical pattern matches.
        """
        text_lower = text.lower()
        
        for pattern in self.tiers[LoadTier.CRITICAL].patterns:
            if pattern.compiled and pattern.compiled.search(text_lower):
                return True
        
        return False


# Singleton instance for easy access
_default_loader: Optional[TieredPatternLoader] = None


def get_loader() -> TieredPatternLoader:
    """Get or create the default pattern loader."""
    global _default_loader
    if _default_loader is None:
        _default_loader = TieredPatternLoader()
        _default_loader.load_tier(LoadTier.HIGH)  # Default tier
    return _default_loader


def reset_loader() -> None:
    """Reset the default loader (for testing)."""
    global _default_loader
    _default_loader = None
