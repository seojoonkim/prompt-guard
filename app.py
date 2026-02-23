"""
Prompt Guard - API Server
FastAPI server for scanning content for prompt injections.
"""

import re
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

from prompt_guard import PromptGuard
from prompt_guard.output import SanitizeResult


def get_version() -> str:
    """Get version from pyproject.toml dynamically."""
    pyproject = Path(__file__).parent / "pyproject.toml"
    if pyproject.exists():
        match = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', pyproject.read_text(), re.MULTILINE)
        if match:
            return match.group(1)
    return "unknown"


VERSION = get_version()

app = FastAPI(
    title="Prompt Guard",
    description="Prompt injection defense API",
    version=VERSION
)

# Default config (fail-open)
DEFAULT_CONFIG = {
    "sensitivity": "medium",
    "actions": {
        "LOW": "log",
        "MEDIUM": "log",
        "HIGH": "log",
        "CRITICAL": "log"
    },
    "logging": {"enabled": False}
}

guard = PromptGuard(DEFAULT_CONFIG)


class ScanRequest(BaseModel):
    content: str
    type: str = "analyze"  # "analyze" or "sanitize"
    tool_name: Optional[str] = None


class ScanResponse(BaseModel):
    action: str
    blocked: bool
    was_modified: bool
    sanitized_text: Optional[str] = None
    matches: list = []


@app.get("/health")
def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "prompt-guard",
        "version": VERSION
    }


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    """
    Scan content for prompt injections.
    
    - type="analyze": Calls analyze() - returns detection matches
    - type="sanitize": Calls sanitize_output() - returns redacted content
    """
    try:
        if request.type == "sanitize":
            result = guard.sanitize_output(request.content)
            matchesResult = guard.analyze(request.content)
            # SanitizeResult: has blocked, was_modified, sanitized_text
            return ScanResponse(
                action="allow" if not result.blocked else "block",
                blocked=result.blocked,
                was_modified=result.was_modified,
                sanitized_text=result.sanitized_text,
                matches=[{
                    "pattern": r,
                    "severity": matchesResult.severity.value if hasattr(matchesResult.severity, 'value') else str(matchesResult.severity),
                    "type": r,
                    "lang": "en"
                } for r in matchesResult.reasons]
            )
        else:
            # Default to analyze
            result = guard.analyze(request.content)
            # DetectionResult: has action, severity, reasons
            blocked = result.action.name.lower() == "block"
            return ScanResponse(
                action=result.action.name.lower(),
                blocked=blocked,
                was_modified=False,
                sanitized_text=None,
                matches=[{
                    "pattern": r,
                    "severity": result.severity.value if hasattr(result.severity, 'value') else str(result.severity),
                    "type": r,
                    "lang": "en"
                } for r in result.reasons]
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
