"""
Prompt Guard - Output scanning (DLP).

Scan LLM output/response for data leakage and sanitize sensitive data.
"""

import re
import hashlib
from typing import Optional, Dict, List

from prompt_guard.models import Severity, Action, DetectionResult, SanitizeResult
from prompt_guard.patterns import (
    SECRET_PATTERNS, CREDENTIAL_PATH_PATTERNS,
    PATTERNS_EN, PATTERNS_KO, PATTERNS_JA, PATTERNS_ZH,
    PATTERNS_RU, PATTERNS_ES, PATTERNS_DE, PATTERNS_FR,
    PATTERNS_PT, PATTERNS_VI,
    SCENARIO_JAILBREAK, EMOTIONAL_MANIPULATION, AUTHORITY_RECON,
    COGNITIVE_MANIPULATION, PHISHING_SOCIAL_ENG, REPETITION_ATTACK,
    SYSTEM_FILE_ACCESS, MALWARE_DESCRIPTION,
    INDIRECT_INJECTION, CONTEXT_HIJACKING, MULTI_TURN_MANIPULATION,
    TOKEN_SMUGGLING, PROMPT_EXTRACTION, SAFETY_BYPASS,
    URGENCY_MANIPULATION, SYSTEM_PROMPT_MIMICRY,
    JSON_INJECTION_MOLTBOOK, GUARDRAIL_BYPASS_EXTENDED,
    AGENT_SOVEREIGNTY_MANIPULATION, EXPLICIT_CALL_TO_ACTION,
    ALLOWLIST_BYPASS, HOOKS_HIJACKING, SUBAGENT_EXPLOITATION,
    HIDDEN_TEXT_INJECTION, GITIGNORE_BYPASS,
    AUTO_APPROVE_EXPLOIT, LOG_CONTEXT_EXPLOIT, MCP_ABUSE,
    PREFILLED_URL, UNICODE_TAG_DETECTION, BROWSER_AGENT_INJECTION,
    HIDDEN_TEXT_HINTS,
    OUTPUT_PREFIX_INJECTION, BENIGN_FINETUNING_ATTACK, PROMPTWARE_KILLCHAIN,
    CAUSAL_MECHANISTIC_ATTACKS, AGENT_TOOL_ATTACKS, TEMPLATE_CHAT_ATTACKS,
    EVASION_STEALTH_ATTACKS, MULTIMODAL_PHYSICAL_ATTACKS, DEFENSE_BYPASS_ANALYSIS,
    INFRASTRUCTURE_PROTOCOL_ATTACKS,
    CRITICAL_PATTERNS,
)


def _build_all_redaction_patterns():
    """
    Build redaction patterns from ALL detection patterns in patterns.py.
    Returns list of (regex, label, replacement) tuples.
    """
    patterns = []
    
    # Language pattern dictionaries
    lang_patterns = [
        ("en", PATTERNS_EN),
        ("ko", PATTERNS_KO),
        ("ja", PATTERNS_JA),
        ("zh", PATTERNS_ZH),
        ("ru", PATTERNS_RU),
        ("es", PATTERNS_ES),
        ("de", PATTERNS_DE),
        ("fr", PATTERNS_FR),
        ("pt", PATTERNS_PT),
        ("vi", PATTERNS_VI),
    ]
    
    # Extract patterns from language dictionaries
    for lang, pattern_dict in lang_patterns:
        if pattern_dict and isinstance(pattern_dict, dict):
            for category, pattern_list in pattern_dict.items():
                if isinstance(pattern_list, list):
                    for pattern in pattern_list:
                        label = f"{lang}:{category}"
                        replacement = f"[REDACTED:{category}]"
                        patterns.append((pattern, label, replacement))
    
    # Add standalone pattern lists
    standalone_patterns = [
        ("critical", CRITICAL_PATTERNS),
        ("scenario_jailbreak", SCENARIO_JAILBREAK),
        ("emotional_manipulation", EMOTIONAL_MANIPULATION),
        ("authority_recon", AUTHORITY_RECON),
        ("cognitive_manipulation", COGNITIVE_MANIPULATION),
        ("phishing_social_eng", PHISHING_SOCIAL_ENG),
        ("repetition_attack", REPETITION_ATTACK),
        ("system_file_access", SYSTEM_FILE_ACCESS),
        ("malware_description", MALWARE_DESCRIPTION),
        ("indirect_injection", INDIRECT_INJECTION),
        ("context_hijacking", CONTEXT_HIJACKING),
        ("multi_turn_manipulation", MULTI_TURN_MANIPULATION),
        ("token_smuggling", TOKEN_SMUGGLING),
        ("prompt_extraction", PROMPT_EXTRACTION),
        ("safety_bypass", SAFETY_BYPASS),
        ("urgency_manipulation", URGENCY_MANIPULATION),
        ("system_prompt_mimicry", SYSTEM_PROMPT_MIMICRY),
        ("json_injection_moltbook", JSON_INJECTION_MOLTBOOK),
        ("guardrail_bypass_extended", GUARDRAIL_BYPASS_EXTENDED),
        ("agent_sovereignty_manipulation", AGENT_SOVEREIGNTY_MANIPULATION),
        ("explicit_call_to_action", EXPLICIT_CALL_TO_ACTION),
        ("allowlist_bypass", ALLOWLIST_BYPASS),
        ("hooks_hijacking", HOOKS_HIJACKING),
        ("subagent_exploitation", SUBAGENT_EXPLOITATION),
        ("hidden_text_injection", HIDDEN_TEXT_INJECTION),
        ("gitignore_bypass", GITIGNORE_BYPASS),
        ("auto_approve_exploit", AUTO_APPROVE_EXPLOIT),
        ("log_context_exploit", LOG_CONTEXT_EXPLOIT),
        ("mcp_abuse", MCP_ABUSE),
        ("prefilled_url", PREFILLED_URL),
        ("unicode_tag_detection", UNICODE_TAG_DETECTION),
        ("browser_agent_injection", BROWSER_AGENT_INJECTION),
        ("hidden_text_hints", HIDDEN_TEXT_HINTS),
        ("output_prefix_injection", OUTPUT_PREFIX_INJECTION),
        ("benign_finetuning_attack", BENIGN_FINETUNING_ATTACK),
        ("promptware_killchain", PROMPTWARE_KILLCHAIN),
        ("causal_mechanistic_attacks", CAUSAL_MECHANISTIC_ATTACKS),
        ("agent_tool_attacks", AGENT_TOOL_ATTACKS),
        ("template_chat_attacks", TEMPLATE_CHAT_ATTACKS),
        ("evasion_stealth_attacks", EVASION_STEALTH_ATTACKS),
        ("multimodal_physical_attacks", MULTIMODAL_PHYSICAL_ATTACKS),
        ("defense_bypass_analysis", DEFENSE_BYPASS_ANALYSIS),
        ("infrastructure_protocol_attacks", INFRASTRUCTURE_PROTOCOL_ATTACKS),
    ]
    
    for label, pattern_list in standalone_patterns:
        if pattern_list and isinstance(pattern_list, list):
            for pattern in pattern_list:
                replacement = f"[REDACTED:{label}]"
                patterns.append((pattern, label, replacement))
    
    return patterns


# Build all redaction patterns once at module load
ALL_REDACTION_PATTERNS = _build_all_redaction_patterns()


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

# Prompt Injection Redaction Patterns
# Build all redaction patterns once at module load
ALL_REDACTION_PATTERNS = _build_all_redaction_patterns()

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
    Enterprise DLP + Prompt Injection Sanitization: Redact sensitive data from LLM response, then re-scan.

    Flow:
      1. REDACT -- replace all known credential/secret patterns with [REDACTED:type]
      2. REDACT -- replace any canary tokens with [REDACTED:canary]
      3. REDACT -- replace prompt injection patterns with [REDACTED:type]
      4. RE-SCAN -- run scan_output() on the redacted text
      5. DECIDE -- if re-scan still triggers HIGH+, block entirely;
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

    # Step 2.5: Redact all patterns (credentials + prompt injection)
    for pattern, label, replacement in ALL_REDACTION_PATTERNS:
        try:
            def replace_with_check(match):
                # Skip if already inside a redacted span
                text_before = sanitized[:match.start()]
                if "[REDACTED:" in text_before[max(0, match.start()-20):match.start()]:
                    return match.group(0)  # Don't re-redact
                return replacement
            
            new_text = re.sub(pattern, replace_with_check, sanitized, flags=re.IGNORECASE)
            if new_text != sanitized:
                # Count actual replacements
                n = len(re.findall(pattern, sanitized, flags=re.IGNORECASE))
                sanitized = new_text
                redaction_count += n
                if label not in redacted_types:
                    redacted_types.append(label)
        except re.error:
            pass

    # Step 3: Re-scan the redacted text
    post_scan = scan_output(sanitized, config, check_canary_fn)

    # Step 4: Block decision - respect config actions
    action_map = config.get("actions", {})
    action_str = action_map.get(post_scan.severity.name, "block")
    blocked = action_str == "block" and post_scan.severity.value >= Severity.HIGH.value

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
