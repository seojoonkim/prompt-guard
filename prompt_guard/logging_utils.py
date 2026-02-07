"""
Prompt Guard - Logging utilities.

Markdown and JSONL logging with optional SHA-256 hash chain,
and HiveFence threat reporting.
"""

import json
import hashlib
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict

from prompt_guard.models import Severity, DetectionResult


def log_detection(config: Dict, result: DetectionResult, message: str, context: Dict):
    """Log detection to security log file (Markdown format)."""
    if not config.get("logging", {}).get("enabled", True):
        return

    log_path = Path(
        config.get("logging", {}).get("path", "memory/security-log.md")
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")

    # SECURITY FIX (MED-006): Sanitize user-controlled data for log injection
    user_id = str(context.get("user_id", "unknown")).replace("|", "_").replace("\n", " ")[:50]
    chat_name = str(context.get("chat_name", "unknown")).replace("|", "_").replace("\n", " ")[:50]

    # Check if we need to add date header
    add_date_header = True
    if log_path.exists():
        content = log_path.read_text()
        if f"## {date_str}" in content:
            add_date_header = False

    entry = []
    if add_date_header:
        entry.append(f"\n## {date_str}\n")

    entry.append(
        f"### {time_str} | {result.severity.name} | user:{user_id} | {chat_name}"
    )
    entry.append(f"- Patterns: {', '.join(result.reasons)}")
    if config.get("logging", {}).get("include_message", False):
        safe_msg = message[:100].replace("\n", " ")
        entry.append(
            f'- Message: "{safe_msg}{"..." if len(message) > 100 else ""}"'
        )
    entry.append(f"- Action: {result.action.value}")
    entry.append(f"- Fingerprint: {result.fingerprint}")
    entry.append("")

    with open(log_path, "a") as f:
        f.write("\n".join(entry))


def log_detection_json(config: Dict, result: DetectionResult, message: str, context: Dict):
    """Log detection in structured JSONL format with optional hash chain.

    Note: The hash chain is NOT thread-safe. In concurrent environments,
    use external locking or a database-backed log instead.
    """
    if not config.get("logging", {}).get("enabled", True):
        return

    log_config = config.get("logging", {})
    if log_config.get("format", "markdown") != "json":
        return

    json_path = Path(log_config.get("json_path", "memory/security-log.jsonl"))
    json_path.parent.mkdir(parents=True, exist_ok=True)
    use_hash_chain = log_config.get("hash_chain", False)

    now = datetime.now()
    user_id = context.get("user_id", "unknown")
    chat_name = context.get("chat_name", "unknown")

    entry = {
        "timestamp": now.isoformat(),
        "severity": result.severity.name,
        "action": result.action.value,
        "user_id": str(user_id),
        "chat_name": chat_name,
        "reasons": result.reasons,
        "pattern_count": len(result.patterns_matched),
        "fingerprint": result.fingerprint,
        "scan_type": result.scan_type,
    }

    if result.decoded_findings:
        entry["decoded_encodings"] = [
            d["encoding"] for d in result.decoded_findings
        ]

    if result.canary_matches:
        entry["canary_matches"] = result.canary_matches

    if log_config.get("include_message", False):
        entry["message_preview"] = message[:100]

    # Hash chain for tamper detection
    if use_hash_chain:
        prev_hash = "genesis"
        if json_path.exists():
            try:
                lines = json_path.read_text().strip().split("\n")
                if lines and lines[-1]:
                    last_entry = json.loads(lines[-1])
                    prev_hash = last_entry.get("entry_hash", "genesis")
            except Exception:
                pass
        entry["prev_hash"] = prev_hash
        entry_str = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        # SECURITY FIX (CRIT-005): Use full SHA-256 hash for tamper detection
        entry["entry_hash"] = hashlib.sha256(entry_str.encode()).hexdigest()

    with open(json_path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def report_to_hivefence(config: Dict, result: DetectionResult, message: str, context: Dict):
    """Report HIGH+ detections to HiveFence network for collective immunity."""
    if result.severity.value < Severity.HIGH.value:
        return  # Only report HIGH and CRITICAL

    hivefence_config = config.get("hivefence", {})
    if not hivefence_config.get("enabled", True):
        return

    if not hivefence_config.get("auto_report", True):
        return

    api_url = hivefence_config.get(
        "api_url",
        "https://hivefence-api.seojoon-kim.workers.dev/api/v1"
    )

    try:
        import urllib.request
        import urllib.error

        # Generate pattern hash (privacy-preserving)
        # SECURITY FIX (HIGH-008): Use 32 hex chars (128 bits) to prevent brute-force
        pattern_hash = f"sha256:{hashlib.sha256(message.encode()).hexdigest()[:32]}"

        # Determine category from first matched pattern
        category = "other"
        if result.reasons:
            first_reason = result.reasons[0].lower()
            if "role" in first_reason or "override" in first_reason:
                category = "role_override"
            elif "system" in first_reason or "prompt" in first_reason:
                category = "fake_system"
            elif "jailbreak" in first_reason or "dan" in first_reason:
                category = "jailbreak"
            elif "exfil" in first_reason or "secret" in first_reason or "config" in first_reason:
                category = "data_exfil"
            elif "authority" in first_reason or "admin" in first_reason:
                category = "social_eng"
            elif "exec" in first_reason or "code" in first_reason:
                category = "code_exec"

        # Report the blocked threat
        payload = json.dumps({
            "patternHash": pattern_hash,
            "category": category,
            "severity": result.severity.value,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "X-Client-ID": context.get("agent_id", "prompt-guard"),
            "X-Client-Version": "3.0.0",
        }

        req = urllib.request.Request(
            f"{api_url}/threats/blocked",
            data=payload,
            headers=headers,
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=5) as resp:
            pass  # Fire and forget

    except Exception:
        pass  # Don't let reporting failures affect detection
