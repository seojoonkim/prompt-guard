"""
Prompt Guard - Output scanning (DLP).

Scan LLM output/response for data leakage and sanitize sensitive data.
"""

import re
import hashlib
from typing import Optional, Dict, List

from prompt_guard.models import Severity, Action, DetectionResult, SanitizeResult
from prompt_guard.patterns import SECRET_PATTERNS, CREDENTIAL_PATH_PATTERNS


# Enterprise DLP: Redaction Patterns
# These are the same credential_formats from scan_output(), compiled
# once so both functions share a single source.
CREDENTIAL_REDACTION_PATTERNS = [
    # (regex, label, replacement)
    # Order matters: more specific patterns first to avoid partial matches
    (r"sk-proj-[a-zA-Z0-9\-_]{40,}", "openai_project_key", "[REDACTED:openai_project_key]"),
    (r"sk-[a-zA-Z0-9]{20,}", "openai_api_key", "[REDACTED:openai_api_key]"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "github_fine_grained", "[REDACTED:github_token]"),
    (r"ghp_[a-zA-Z0-9]{36,}", "github_pat", "[REDACTED:github_token]"),
    (r"gho_[a-zA-Z0-9]{36,}", "github_oauth", "[REDACTED:github_token]"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key", "[REDACTED:aws_key]"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key_block", "[REDACTED:private_key]"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key", "[REDACTED:private_key]"),
    (r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", "certificate_block", "[REDACTED:certificate]"),
    (r"-----BEGIN CERTIFICATE-----", "certificate", "[REDACTED:certificate]"),
    (r"xox[bprs]-[a-zA-Z0-9\-]{10,}", "slack_token", "[REDACTED:slack_token]"),
    (r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "slack_webhook", "[REDACTED:slack_webhook]"),
    (r"AIza[0-9A-Za-z\-_]{35}", "google_api_key", "[REDACTED:google_api_key]"),
    (r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", "google_oauth_id", "[REDACTED:google_oauth]"),
    (r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "jwt_token", "[REDACTED:jwt]"),
    (r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", "bearer_token", "[REDACTED:bearer_token]"),
    (r"bot[0-9]{8,10}:[a-zA-Z0-9_-]{35}", "telegram_bot_token", "[REDACTED:telegram_token]"),
]

# Minimum canary token length to prevent false positives
MIN_CANARY_LENGTH = 8


def scan_output(response_text: str, config: Dict, check_canary_fn=None) -> DetectionResult:
    """
    Scan LLM output/response for data leakage (DLP).
    Checks for:
      - Canary token leakage (system prompt extraction)
      - Secret/credential patterns in output
      - Common credential format patterns (API keys, private keys)
      - Sensitive file path references
    """
    reasons = []
    patterns_matched = []
    max_severity = Severity.SAFE

    # 1. Canary token check (CRITICAL -- confirms system prompt extraction)
    canary_matches = []
    if check_canary_fn:
        canary_matches = check_canary_fn(response_text)
    if canary_matches:
        reasons.append("canary_token_in_output")
        max_severity = Severity.CRITICAL

    # 2. Secret patterns (reuse existing SECRET_PATTERNS)
    text_lower = response_text.lower()
    for lang, patterns in SECRET_PATTERNS.items():
        for pattern in patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    if "secret_in_output" not in reasons:
                        reasons.append("secret_in_output")
                    patterns_matched.append(f"output:{lang}:secret:{pattern[:40]}")
                    if Severity.HIGH.value > max_severity.value:
                        max_severity = Severity.HIGH
            except re.error:
                pass

    # 3. Common credential format patterns
    credential_formats = [
        (r"sk-[a-zA-Z0-9]{20,}", "openai_api_key"),
        (r"sk-proj-[a-zA-Z0-9\-_]{40,}", "openai_project_key"),
        (r"ghp_[a-zA-Z0-9]{36,}", "github_pat"),
        (r"gho_[a-zA-Z0-9]{36,}", "github_oauth"),
        (r"github_pat_[a-zA-Z0-9_]{22,}", "github_fine_grained"),
        (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key"),
        (r"-----BEGIN CERTIFICATE-----", "certificate"),
        (r"xox[bprs]-[a-zA-Z0-9\-]{10,}", "slack_token"),
        (r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "slack_webhook"),
        (r"AIza[0-9A-Za-z\-_]{35}", "google_api_key"),
        (r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", "google_oauth_id"),
        (r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "jwt_token"),
        (r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", "bearer_token"),
        (r"bot[0-9]{8,10}:[a-zA-Z0-9_-]{35}", "telegram_bot_token"),
    ]

    for pattern, cred_type in credential_formats:
        try:
            if re.search(pattern, response_text):
                reasons.append(f"credential_format:{cred_type}")
                patterns_matched.append(f"output:cred:{cred_type}")
                if Severity.CRITICAL.value > max_severity.value:
                    max_severity = Severity.CRITICAL
        except re.error:
            pass

    # 4. Sensitive file path references
    for pattern in CREDENTIAL_PATH_PATTERNS:
        try:
            if re.search(pattern, response_text, re.IGNORECASE):
                if "sensitive_path_in_output" not in reasons:
                    reasons.append("sensitive_path_in_output")
                patterns_matched.append(f"output:path:{pattern[:40]}")
                if Severity.MEDIUM.value > max_severity.value:
                    max_severity = Severity.MEDIUM
        except re.error:
            pass

    # Determine action
    if max_severity == Severity.SAFE:
        action = Action.ALLOW
    else:
        action_map = config.get("actions", {})
        action_str = action_map.get(max_severity.name, "block")
        action = Action(action_str)

    # SECURITY FIX (CRIT-004): Use SHA-256 instead of broken MD5
    fingerprint = hashlib.sha256(
        f"output:{max_severity.name}:{sorted(reasons)}".encode()
    ).hexdigest()[:16]

    return DetectionResult(
        severity=max_severity,
        action=action,
        reasons=reasons,
        patterns_matched=patterns_matched,
        normalized_text=None,
        base64_findings=[],
        recommendations=["Review LLM output for data leakage"] if reasons else [],
        fingerprint=fingerprint,
        scan_type="output",
        canary_matches=canary_matches if canary_matches else [],
    )


def sanitize_output(response_text: str, config: Dict, check_canary_fn=None,
                     log_detection_fn=None, log_detection_json_fn=None,
                     context: Optional[Dict] = None) -> SanitizeResult:
    """
    Enterprise DLP: Redact sensitive data from LLM response, then re-scan.

    Flow:
      1. REDACT -- replace all known credential/secret patterns with [REDACTED:type]
      2. REDACT -- replace any canary tokens with [REDACTED:canary]
      3. RE-SCAN -- run scan_output() on the redacted text
      4. DECIDE -- if re-scan still triggers HIGH+, block entirely;
                  otherwise return the redacted (safe) text
    """
    context = context or {}
    sanitized = response_text
    redacted_types = []
    redaction_count = 0

    # Step 1: Redact credential patterns
    for pattern, cred_type, replacement in CREDENTIAL_REDACTION_PATTERNS:
        try:
            new_text, n = re.subn(pattern, replacement, sanitized)
            if n > 0:
                sanitized = new_text
                redaction_count += n
                if cred_type not in redacted_types:
                    redacted_types.append(cred_type)
        except re.error:
            pass

    # Step 2: Redact canary tokens
    canary_tokens = config.get("canary_tokens", [])
    for token in canary_tokens:
        if len(token) < MIN_CANARY_LENGTH:
            continue
        escaped = re.escape(token)
        new_text, n = re.subn(escaped, "[REDACTED:canary]", sanitized, flags=re.IGNORECASE)
        if n > 0:
            sanitized = new_text
            redaction_count += n
            if "canary_token" not in redacted_types:
                redacted_types.append("canary_token")

    # Step 3: Re-scan the redacted text
    post_scan = scan_output(sanitized, config, check_canary_fn)

    # Step 4: Block decision
    blocked = post_scan.severity.value >= Severity.HIGH.value

    was_modified = redaction_count > 0

    # Log the sanitization event
    if was_modified or blocked:
        msg = f"[DLP sanitize] {redaction_count} redactions"
        if log_detection_fn:
            log_detection_fn(post_scan, msg, context)
        if log_detection_json_fn:
            log_detection_json_fn(post_scan, msg, context)

    return SanitizeResult(
        sanitized_text="[BLOCKED: response contained sensitive data that could not be safely redacted]" if blocked else sanitized,
        was_modified=was_modified,
        redaction_count=redaction_count,
        redacted_types=redacted_types,
        blocked=blocked,
        detection=post_scan,
    )
