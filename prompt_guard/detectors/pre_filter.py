"""
Prompt Guard - Pre-filter for gating semantic detection calls.

Lightweight heuristic that decides whether a message is worth the
cost/latency of an LLM round-trip. Reduces API calls by ~80%.
"""

import math
from collections import Counter
from typing import List, Callable


ROLE_PLAY_KEYWORDS = frozenset([
    "pretend", "imagine", "roleplay", "act as", "you are now",
    "from now on", "new rules", "developer mode", "ignore previous",
    "ignore above", "disregard", "override", "bypass",
])

MIXED_SCRIPT_RANGES = [
    (0x0400, 0x04FF),  # Cyrillic
    (0x0600, 0x06FF),  # Arabic
    (0x3040, 0x30FF),  # Japanese
    (0x4E00, 0x9FFF),  # CJK
    (0xAC00, 0xD7AF),  # Korean
]


def _has_mixed_scripts(msg: str) -> bool:
    """Check if message contains characters from 2+ non-Latin scripts."""
    scripts_found = set()
    for ch in msg:
        cp = ord(ch)
        for start, end in MIXED_SCRIPT_RANGES:
            if start <= cp <= end:
                scripts_found.add((start, end))
                if len(scripts_found) >= 2:
                    return True
                break
    return False


def _shannon_entropy(msg: str) -> float:
    """Calculate Shannon entropy of the message."""
    if not msg:
        return 0.0
    freq = Counter(msg)
    length = len(msg)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
        if count > 0
    )


class PreFilter:
    """Fast heuristic to gate expensive semantic detection calls."""

    SUSPICIOUS_SIGNALS: List[Callable[[str], bool]] = [
        lambda msg: len(msg) > 500,
        lambda msg: msg.count("\n") > 20,
        lambda msg: any(kw in msg.lower() for kw in ROLE_PLAY_KEYWORDS),
        lambda msg: _has_mixed_scripts(msg),
        lambda msg: _shannon_entropy(msg) > 4.5,
    ]

    def __init__(self, min_signals: int = 2):
        self._min_signals = min_signals

    def should_check(self, message: str, regex_severity: str, mode: str = "fallback") -> bool:
        """Return True if this message warrants a semantic detection call.

        Args:
            message: The normalized message text.
            regex_severity: Severity name from the regex pass ("SAFE", "MEDIUM", etc.).
            mode: Detection mode -- "fallback", "always", "hybrid", or "confirm".
        """
        if mode == "always" or mode == "hybrid":
            return True

        if mode == "confirm":
            return regex_severity in ("HIGH", "CRITICAL")

        # mode == "fallback" (default)
        if regex_severity == "MEDIUM":
            return True

        if regex_severity == "SAFE":
            signal_count = sum(1 for sig in self.SUSPICIOUS_SIGNALS if sig(message))
            return signal_count >= self._min_signals

        # HIGH or CRITICAL -- regex is already confident
        return False
