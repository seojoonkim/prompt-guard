"""
Prompt Guard - Base detector interface and result types.

All semantic detectors implement BaseDetector. The engine doesn't
care which backend produced the result -- it only sees DetectorResult.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DetectorResult:
    """Result from a single semantic detector."""

    classification: str  # "safe", "suspicious", "malicious"
    confidence: float  # 0.0 - 1.0
    category: str  # maps to existing reason taxonomy
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    detector_name: str  # which detector produced this
    metadata: Dict = field(default_factory=dict)

    def is_threat(self) -> bool:
        return self.classification in ("suspicious", "malicious")


@dataclass
class MergedResult:
    """Result of merging multiple detector outputs."""

    severity: str  # final merged severity
    new_reasons: List[str]  # reasons to append to DetectionResult.reasons
    confidence: float  # weighted confidence
    downgraded: bool = False  # True if LLM reduced a regex false positive

    @staticmethod
    def empty() -> "MergedResult":
        return MergedResult(
            severity="SAFE",
            new_reasons=[],
            confidence=0.0,
        )


class BaseDetector(ABC):
    """Interface all semantic detectors implement."""

    name: str = "base"

    @abstractmethod
    def detect(self, message: str, context: Optional[Dict] = None) -> DetectorResult:
        """Classify a message and return structured result."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this detector can run (deps installed, API key present, etc.)."""
        ...

    def safe_result(self) -> DetectorResult:
        """Convenience: return a SAFE result."""
        return DetectorResult(
            classification="safe",
            confidence=1.0,
            category="benign",
            severity="SAFE",
            detector_name=self.name,
        )
