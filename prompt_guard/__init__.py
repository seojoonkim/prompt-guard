"""
Prompt Guard - AI prompt injection detection library (v3.1.0)

v3.1.0: Token Optimization
- Tiered pattern loading (70% reduction)
- Message hash cache (90% reduction for repeats)

Public API:
    from prompt_guard import PromptGuard, Severity, Action, DetectionResult, SanitizeResult
    from prompt_guard.cache import MessageCache, get_cache
    from prompt_guard.pattern_loader import TieredPatternLoader, LoadTier
"""

__version__ = "3.1.0"

from prompt_guard.models import Severity, Action, DetectionResult, SanitizeResult
from prompt_guard.engine import PromptGuard
from prompt_guard.cache import MessageCache, get_cache
from prompt_guard.pattern_loader import TieredPatternLoader, LoadTier, get_loader

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
    "__version__",
]
