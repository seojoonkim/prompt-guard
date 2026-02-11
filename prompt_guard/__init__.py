"""
Prompt Guard - AI prompt injection detection library (v3.2.0)

v3.2.0: Skill Weaponization Defense + API Client
- 27 new patterns: reverse shell, SSH injection, exfiltration, cognitive rootkit, semantic worm
- Bidirectional API client for pattern updates + anonymized threat reporting

v3.1.0: Token Optimization
- Tiered pattern loading (70% reduction)
- Message hash cache (90% reduction for repeats)

Public API:
    from prompt_guard import PromptGuard, Severity, Action, DetectionResult, SanitizeResult
    from prompt_guard.cache import MessageCache, get_cache
    from prompt_guard.pattern_loader import TieredPatternLoader, LoadTier
    from prompt_guard.api_client import PGAPIClient
"""

__version__ = "3.2.0"

from prompt_guard.models import Severity, Action, DetectionResult, SanitizeResult
from prompt_guard.engine import PromptGuard
from prompt_guard.cache import MessageCache, get_cache
from prompt_guard.pattern_loader import TieredPatternLoader, LoadTier, get_loader
from prompt_guard.api_client import PGAPIClient

__all__ = [
    "PromptGuard",
    "Severity",
    "Action",
    "DetectionResult",
    "SanitizeResult",
    "MessageCache",
    "get_cache",
    "TieredPatternLoader",
    "LoadTier",
    "get_loader",
    "PGAPIClient",
    "__version__",
]
