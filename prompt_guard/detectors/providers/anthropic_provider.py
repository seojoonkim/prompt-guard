"""
Prompt Guard - Anthropic provider (urllib-based, no SDK dependency).
"""

import json
import logging
import os
import urllib.request
import urllib.error
from typing import Optional

from prompt_guard.detectors.providers.base_provider import LLMProvider, ProviderResponse

logger = logging.getLogger("prompt_guard.detectors.anthropic")

ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API via urllib."""

    name = "anthropic"

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-5-haiku-20241022",
                 timeout: int = 15):
        self.api_key = api_key or os.environ.get("PG_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, json_mode: bool = True,
                 max_tokens: int = 150) -> ProviderResponse:
        if not self.api_key:
            raise RuntimeError("Anthropic API key not configured (set PG_LLM_API_KEY or ANTHROPIC_API_KEY)")

        if json_mode:
            system += "\n\nIMPORTANT: Respond ONLY with a valid JSON object. No markdown, no explanation."

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": ANTHROPIC_API_VERSION,
        }

        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [
                {"role": "user", "content": user},
            ],
            "temperature": 0.0,
        }

        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(ANTHROPIC_MESSAGES_URL, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content_blocks = data.get("content", [])
                content = ""
                for block in content_blocks:
                    if block.get("type") == "text":
                        content += block.get("text", "")
                usage = data.get("usage", {})
                return ProviderResponse(
                    content=content,
                    tokens_in=usage.get("input_tokens", 0),
                    tokens_out=usage.get("output_tokens", 0),
                    model=data.get("model", self.model),
                )
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            logger.error("Anthropic API error %d: %s", e.code, body_text)
            raise
        except Exception as e:
            logger.error("Anthropic request failed: %s", e)
            raise
