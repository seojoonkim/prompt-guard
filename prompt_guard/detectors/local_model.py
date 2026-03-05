"""
Prompt Guard - Local model detector (Sentinel / transformers-based).

Runs a local classification model for zero-cost, zero-latency semantic
detection. Requires optional dependencies: torch, transformers.

    pip install prompt-guard[llm]
"""

import logging
from typing import Dict, Optional

from prompt_guard.detectors.base import BaseDetector, DetectorResult
from prompt_guard.detectors.registry import register_detector

logger = logging.getLogger("prompt_guard.detectors.local_model")

_DEFAULT_MODEL = "qualifire/prompt-injection-sentinel"
_MAX_LENGTH = 512  # token limit for the model


class LocalModelDetector(BaseDetector):
    """Local transformer model for prompt injection classification."""

    name = "local"

    def __init__(self, config: dict):
        self._model_name = config.get("model", _DEFAULT_MODEL)
        self._device = config.get("device", "cpu")
        self._threshold = config.get("threshold", 0.5)
        self._pipeline = None
        self._available = False
        self._init_model()

    def _init_model(self) -> None:
        try:
            from transformers import pipeline as hf_pipeline
            self._pipeline = hf_pipeline(
                "text-classification",
                model=self._model_name,
                device=self._device if self._device != "cpu" else -1,
                truncation=True,
                max_length=_MAX_LENGTH,
            )
            self._available = True
            logger.info("Local model loaded: %s (device=%s)", self._model_name, self._device)
        except ImportError:
            logger.info(
                "Local model detector unavailable: torch/transformers not installed. "
                "Install with: pip install prompt-guard[llm]"
            )
        except Exception as e:
            logger.warning("Failed to load local model %s: %s", self._model_name, e)

    def is_available(self) -> bool:
        return self._available and self._pipeline is not None

    def detect(self, message: str, context: Optional[Dict] = None) -> DetectorResult:
        if not self.is_available():
            return self.safe_result()

        try:
            results = self._pipeline(message[:2000])
            if not results:
                return self.safe_result()

            top = results[0]
            label = top.get("label", "SAFE").upper()
            score = top.get("score", 0.0)

            is_injection = label in ("INJECTION", "MALICIOUS", "UNSAFE", "LABEL_1", "1")

            if is_injection and score >= self._threshold:
                severity = "HIGH" if score >= 0.85 else "MEDIUM"
                return DetectorResult(
                    classification="malicious" if score >= 0.85 else "suspicious",
                    confidence=score,
                    category="prompt_injection",
                    severity=severity,
                    detector_name=self.name,
                    metadata={"label": label, "score": score, "model": self._model_name},
                )

            return DetectorResult(
                classification="safe",
                confidence=1.0 - score if is_injection else score,
                category="benign",
                severity="SAFE",
                detector_name=self.name,
                metadata={"label": label, "score": score, "model": self._model_name},
            )
        except Exception as e:
            logger.warning("Local model inference failed: %s", e)
            return self.safe_result()


register_detector("local", LocalModelDetector)
