"""
Prompt Guard - AI prompt injection detection library (v3.2.0)

577+ attack patterns | 11 SHIELD categories | 10 languages

Standalone Mode (default — no API, no internet required):
    from prompt_guard import PromptGuard
    guard = PromptGuard()
    result = guard.analyze("user message")

API-Enhanced Mode (optional — latest patterns + threat intelligence):
    from prompt_guard.api_client import PGAPIClient
    client = PGAPIClient(reporting_enabled=True)
    # Pull newest patterns, report anonymized threats

v3.2.0: Skill Weaponization Defense
- 27 new patterns: reverse shell, SSH injection, exfiltration, cognitive rootkit, semantic worm
- Optional API client for live pattern updates + anonymized threat reporting

v3.1.0: Token Optimization
- Tiered pattern loading (70% reduction)
- Message hash cache (90% reduction for repeats)
"""

__version__ = "3.2.0"

from prompt_guard.models import Severity, Action, DetectionResult, SanitizeResult
from prompt_guard.engine import PromptGuard
from prompt_guard.cache import MessageCache, get_cache
from prompt_guard.pattern_loader import TieredPatternLoader, LoadTier, get_loader

# NOTE: PGAPIClient is NOT imported here by design.
# The API client is optional. Import it explicitly when needed:
#   from prompt_guard.api_client import PGAPIClient

__all__ = [
    # Core (always available, no network required)
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
    # Optional (import from prompt_guard.api_client directly):
    # "PGAPIClient",
]
