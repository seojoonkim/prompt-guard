"""
Prompt Guard - AI prompt injection detection library.

Public API:
    from prompt_guard import PromptGuard, Severity, Action, DetectionResult, SanitizeResult
"""

__version__ = "3.1.0"

from prompt_guard.models import Severity, Action, DetectionResult, SanitizeResult
from prompt_guard.engine import PromptGuard

__all__ = [
    "PromptGuard",
    "Severity",
    "Action",
    "DetectionResult",
    "SanitizeResult",
    "__version__",
]
