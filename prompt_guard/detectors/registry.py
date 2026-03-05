"""
Prompt Guard - Detector registry.

Plugin-style registration: detectors register themselves at import time.
The engine looks up detectors by name via get_detector().
"""

import logging
from typing import Dict, List, Optional, Type

from prompt_guard.detectors.base import BaseDetector

logger = logging.getLogger("prompt_guard.detectors")

_DETECTORS: Dict[str, Type[BaseDetector]] = {}


def register_detector(name: str, cls: Type[BaseDetector]) -> None:
    """Register a detector class by name."""
    _DETECTORS[name] = cls
    logger.debug("Registered detector: %s", name)


def get_detector(name: str, config: dict) -> Optional[BaseDetector]:
    """Instantiate a registered detector by name. Returns None if not found."""
    cls = _DETECTORS.get(name)
    if cls is None:
        logger.warning("Unknown detector: %s (available: %s)", name, list(_DETECTORS.keys()))
        return None
    return cls(config)


def list_detectors() -> List[str]:
    """Return names of all registered detectors."""
    return list(_DETECTORS.keys())
