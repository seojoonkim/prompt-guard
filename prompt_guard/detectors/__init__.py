"""
Prompt Guard - Semantic Detection Layer (v3.7.0)

Optional LLM-based and local-model-based detection that augments
the core regex/heuristic engine. Disabled by default.

    # Enable with BYOK (user's own API key):
    guard = PromptGuard(config={
        "semantic_detection": {
            "enabled": True,
            "detector": "llm-judge",
            "provider": "openai",
            "model": "gpt-4o-mini",
        }
    })

    # Or with a local model (no API key needed):
    guard = PromptGuard(config={
        "semantic_detection": {
            "enabled": True,
            "detector": "local",
            "model": "qualifire/prompt-injection-sentinel",
        }
    })
"""

from prompt_guard.detectors.base import (
    BaseDetector,
    DetectorResult,
    MergedResult,
)
from prompt_guard.detectors.registry import (
    register_detector,
    get_detector,
    list_detectors,
)

__all__ = [
    "BaseDetector",
    "DetectorResult",
    "MergedResult",
    "register_detector",
    "get_detector",
    "list_detectors",
]
