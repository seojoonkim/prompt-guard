"""
Prompt Guard - Abstract LLM provider interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class ProviderResponse:
    """Raw response from an LLM provider."""

    content: str
    tokens_in: int = 0
    tokens_out: int = 0
    model: str = ""


class LLMProvider(ABC):
    """Interface for LLM API backends. All use urllib -- no SDK dependencies."""

    name: str = "base"

    @abstractmethod
    def complete(
        self,
        system: str,
        user: str,
        json_mode: bool = True,
        max_tokens: int = 150,
    ) -> ProviderResponse:
        """Send a completion request and return the response text."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider can be used (API key present, etc.)."""
        ...
