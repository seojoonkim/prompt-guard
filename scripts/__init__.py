"""
Prompt Guard - Prompt injection defense for any LLM agent.

Usage:
    from prompt_guard import PromptGuard, Severity, Action

    guard = PromptGuard()
    result = guard.analyze("user message here")
"""

__version__ = "2.8.2"

from scripts.detect import (
    PromptGuard,
    Severity,
    Action,
    DetectionResult,
    SanitizeResult,
)

__all__ = [
    "PromptGuard",
    "Severity",
    "Action",
    "DetectionResult",
    "SanitizeResult",
    "__version__",
]
