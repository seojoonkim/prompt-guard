"""
Prompt Guard - OpenAI provider (urllib-based, no SDK dependency).

Uses the same HTTP pattern as api_client.py for consistency.
"""

import json
import logging
import os
import urllib.request
import urllib.error
from typing import Optional

from prompt_guard.detectors.providers.base_provider import LLMProvider, ProviderResponse

logger = logging.getLogger("prompt_guard.detectors.openai")

OPENAI_CHAT_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIProvider(LLMProvider):
    """OpenAI-compatible Chat Completions API via urllib.

    Works with OpenAI, local servers (Ollama, vLLM, llama.cpp, LM Studio, LocalAI),
    and any OpenAI-compatible endpoint via the base_url parameter.
    """

    name = "openai"

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o-mini",
                 timeout: int = 15, base_url: Optional[str] = None):
        self.api_key = (
            api_key
            or os.environ.get("PG_LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )
        self.model = model
        self.timeout = timeout
        base = (
            base_url
            or os.environ.get("PG_LLM_BASE_URL")
            or OPENAI_CHAT_URL.rsplit("/", 2)[0]  # "https://api.openai.com"
        ).rstrip("/")
        self._chat_url = f"{base}/v1/chat/completions"

    def is_available(self) -> bool:
        # Local servers often don't require an API key
        if self._chat_url != OPENAI_CHAT_URL:
            return True
        return bool(self.api_key)

    def complete(self, system: str, user: str, json_mode: bool = True,
                 max_tokens: int = 150) -> ProviderResponse:
        if not self.api_key and self._chat_url == OPENAI_CHAT_URL:
            raise RuntimeError("OpenAI API key not configured (set PG_LLM_API_KEY or OPENAI_API_KEY)")

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.0,
        }
        # Only use json_object mode for OpenAI proper; local servers often don't support it
        if json_mode and self._chat_url == OPENAI_CHAT_URL:
            body["response_format"] = {"type": "json_object"}

        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self._chat_url, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                msg = data["choices"][0]["message"]
                content = msg.get("content") or ""
                # Reasoning models (o1, gpt-oss-safeguard) may put output in a
                # separate "reasoning" field when content is empty or truncated.
                if not content.strip() and msg.get("reasoning"):
                    content = msg["reasoning"]
                usage = data.get("usage", {})
                return ProviderResponse(
                    content=content,
                    tokens_in=usage.get("prompt_tokens", 0),
                    tokens_out=usage.get("completion_tokens", 0),
                    model=data.get("model", self.model),
                )
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            logger.error("OpenAI API error %d: %s", e.code, body_text)
            raise
        except Exception as e:
            logger.error("OpenAI request failed: %s", e)
            raise
