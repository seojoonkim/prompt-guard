"""
Prompt Guard - Score merger for combining regex + semantic detector results.

Merges DetectorResult outputs with configurable weights. Can both
escalate (catch what regex missed) and de-escalate (reduce false positives).
"""

import logging
from typing import Dict, List, Optional

from prompt_guard.detectors.base import DetectorResult, MergedResult

logger = logging.getLogger("prompt_guard.detectors.scorer")

SEVERITY_ORDER = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class ScoreMerger:
    """Merge results from semantic detectors with regex severity."""

    DEFAULT_WEIGHTS: Dict[str, float] = {
        "llm-judge": 0.8,
        "local": 0.7,
    }

    # Confidence thresholds for score-merge decisions
    ESCALATE_THRESHOLD = 0.75
    DEESCALATE_THRESHOLD = 0.90

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)

    def merge(
        self,
        regex_severity: str,
        detector_results: List[DetectorResult],
    ) -> MergedResult:
        """Merge regex severity with semantic detector results.

        Rules:
        - If detector says malicious with high confidence and regex missed it -> escalate
        - If detector says safe with very high confidence and regex flagged it -> de-escalate
        - Otherwise, take the higher severity
        """
        if not detector_results:
            return MergedResult.empty()

        regex_level = SEVERITY_ORDER.get(regex_severity, 0)
        new_reasons: List[str] = []
        final_severity = regex_severity
        final_confidence = 0.0
        downgraded = False

        for result in detector_results:
            weight = self.weights.get(result.detector_name, 0.5)
            weighted_confidence = result.confidence * weight
            det_level = SEVERITY_ORDER.get(result.severity, 0)

            if result.is_threat() and weighted_confidence >= self.ESCALATE_THRESHOLD:
                if det_level > regex_level:
                    final_severity = result.severity
                    regex_level = det_level
                reason = f"llm_semantic:{result.category}"
                if reason not in new_reasons:
                    new_reasons.append(reason)

            elif (
                not result.is_threat()
                and weighted_confidence >= self.DEESCALATE_THRESHOLD
                and regex_level in (SEVERITY_ORDER["MEDIUM"], SEVERITY_ORDER["HIGH"])
            ):
                new_level = max(regex_level - 1, 0)
                for sev_name, sev_val in SEVERITY_ORDER.items():
                    if sev_val == new_level:
                        final_severity = sev_name
                        break
                regex_level = new_level
                downgraded = True
                logger.info(
                    "Semantic detector de-escalated %s -> %s (confidence=%.2f)",
                    regex_severity, final_severity, weighted_confidence,
                )

            final_confidence = max(final_confidence, weighted_confidence)

        return MergedResult(
            severity=final_severity,
            new_reasons=new_reasons,
            confidence=final_confidence,
            downgraded=downgraded,
        )
