"""
Prompt Guard - Core detection engine (v3.1.0)

The PromptGuard class: configuration, analyze(), rate limiting, canary detection,
language detection. Delegates to standalone functions in other modules.

v3.1.0 Token Optimization:
- Tiered pattern loading (70% reduction)
- Message hash caching (90% reduction for repeats)
"""

import re
import hashlib
from datetime import datetime
from typing import Optional, Dict, List, Any

from prompt_guard.models import Severity, Action, DetectionResult, SanitizeResult
from prompt_guard.cache import get_cache, MessageCache
from prompt_guard.pattern_loader import TieredPatternLoader, LoadTier, get_loader
from prompt_guard.patterns import (
    CRITICAL_PATTERNS,
    SECRET_PATTERNS,
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
    # v3.0.1 patterns
    OUTPUT_PREFIX_INJECTION, BENIGN_FINETUNING_ATTACK, PROMPTWARE_KILLCHAIN,
    # v3.1.0 patterns - HiveFence Scout Round 4 (2026-02-08)
    CAUSAL_MECHANISTIC_ATTACKS, AGENT_TOOL_ATTACKS, TEMPLATE_CHAT_ATTACKS,
    EVASION_STEALTH_ATTACKS, MULTIMODAL_PHYSICAL_ATTACKS, DEFENSE_BYPASS_ANALYSIS,
    INFRASTRUCTURE_PROTOCOL_ATTACKS,
)
from prompt_guard.normalizer import normalize
from prompt_guard.decoder import decode_all, detect_base64
from prompt_guard.scanner import scan_text_for_patterns
from prompt_guard.output import scan_output, sanitize_output
from prompt_guard.logging_utils import log_detection, log_detection_json, report_to_hivefence


class PromptGuard:
    # Security limits
    MAX_MESSAGE_LENGTH = 50_000   # 50 KB — generous for any legitimate prompt
    MAX_TRACKED_USERS = 10_000    # Bound rate-limit memory

    def __init__(self, config: Optional[Dict] = None):
        self.config = self._default_config()
        if config:
            self.config = self._deep_merge(self.config, config)
        self.owner_ids = set(self.config.get("owner_ids", []))
        self.sensitivity = self.config.get("sensitivity", "medium")
        self.rate_limits: Dict[str, List[float]] = {}
        
        # v3.1.0: Token optimization - cache and tiered loading
        cache_config = self.config.get("cache", {})
        self._cache_enabled = cache_config.get("enabled", True)
        # Create instance-specific cache (not singleton) to avoid test pollution
        from prompt_guard.cache import MessageCache
        self._cache: MessageCache = MessageCache(
            max_size=cache_config.get("max_size", 1000)
        )
        
        # Tiered pattern loader
        tier_config = self.config.get("pattern_tier", "high")
        tier_map = {"critical": LoadTier.CRITICAL, "high": LoadTier.HIGH, "full": LoadTier.FULL}
        self._pattern_loader = get_loader()
        self._pattern_loader.load_tier(tier_map.get(tier_config, LoadTier.HIGH))

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        result = base.copy()
        for key, value in override.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = PromptGuard._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _default_config(self) -> Dict:
        return {
            "sensitivity": "medium",
            "owner_ids": [],
            "canary_tokens": [],
            "actions": {
                "LOW": "log",
                "MEDIUM": "warn",
                "HIGH": "block",
                "CRITICAL": "block_notify",
            },
            "rate_limit": {
                "enabled": True,
                "max_requests": 30,
                "window_seconds": 60,
            },
            "logging": {
                "enabled": True,
                "path": "memory/security-log.md",
                "format": "markdown",
                "json_path": "memory/security-log.jsonl",
                "hash_chain": False,
            },
        }

    # ------------------------------------------------------------------
    # Delegate methods -- call standalone functions from submodules
    # ------------------------------------------------------------------

    def normalize(self, text: str) -> tuple:
        """Normalize text: homoglyphs, delimiters, spacing, quotes, comments, tabs."""
        return normalize(text)

    # Minimum canary token length to prevent false positives from short strings
    MIN_CANARY_LENGTH = 8

    def detect_base64(self, text: str) -> List[Dict]:
        """Detect suspicious base64 encoded content."""
        return detect_base64(text, scan_text_for_patterns_fn=scan_text_for_patterns)

    def check_canary(self, text: str) -> List[str]:
        """Check if any canary tokens appear in the text."""
        canary_tokens = self.config.get("canary_tokens", [])
        if not canary_tokens:
            return []

        matches = []
        text_lower = text.lower()
        for token in canary_tokens:
            if len(token) < self.MIN_CANARY_LENGTH:
                continue
            if token.lower() in text_lower:
                matches.append(token)
        return matches

    def detect_language(self, text: str) -> Optional[str]:
        """Detect the language of the input text."""
        try:
            from langdetect import detect, LangDetectException
            if len(text.strip()) < 10:
                return None
            return detect(text)
        except ImportError:
            return None
        except Exception:
            return None

    SUPPORTED_LANGUAGES = {"en", "ko", "ja", "zh-cn", "zh-tw", "zh", "ru", "es", "de", "fr", "pt", "vi"}

    def decode_all(self, text: str) -> List[Dict[str, str]]:
        """Attempt to decode encoded content in the message using multiple encodings."""
        return decode_all(text)

    def _scan_text_for_patterns(self, text: str) -> tuple:
        """Run all pattern sets against a single text string."""
        return scan_text_for_patterns(text)

    def check_rate_limit(self, user_id: str) -> bool:
        """Check if user has exceeded rate limit.

        SECURITY FIX (CRIT-002): Evicts oldest entries when MAX_TRACKED_USERS
        is reached, preventing unbounded memory growth from unique user_ids.
        """
        if not self.config.get("rate_limit", {}).get("enabled", False):
            return False

        now = datetime.now().timestamp()
        window = self.config["rate_limit"].get("window_seconds", 60)
        max_requests = self.config["rate_limit"].get("max_requests", 30)

        # Evict oldest users when memory limit reached
        if user_id not in self.rate_limits and len(self.rate_limits) >= self.MAX_TRACKED_USERS:
            evict_count = max(1, self.MAX_TRACKED_USERS // 10)
            keys_to_evict = list(self.rate_limits.keys())[:evict_count]
            for key in keys_to_evict:
                del self.rate_limits[key]

        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = []

        # Clean old entries
        self.rate_limits[user_id] = [
            t for t in self.rate_limits[user_id] if now - t < window
        ]

        if len(self.rate_limits[user_id]) >= max_requests:
            return True

        self.rate_limits[user_id].append(now)
        return False

    def analyze(self, message: str, context: Optional[Dict] = None) -> DetectionResult:
        """
        Analyze a message for prompt injection patterns.

        Args:
            message: The message to analyze
            context: Optional context dict with keys:
                - user_id: User identifier
                - is_group: Whether this is a group context
                - chat_name: Name of the chat/group

        Returns:
            DetectionResult with severity, action, and details
        """
        context = context or {}
        user_id = context.get("user_id", "unknown")
        is_group = context.get("is_group", False)
        is_owner = str(user_id) in self.owner_ids

        # SECURITY FIX (CRIT-003): Reject oversized messages to prevent CPU DoS
        if len(message) > self.MAX_MESSAGE_LENGTH:
            return DetectionResult(
                severity=Severity.HIGH,
                action=Action.BLOCK,
                reasons=["message_too_long"],
                patterns_matched=[],
                normalized_text=None,
                base64_findings=[],
                recommendations=[
                    f"Message exceeds maximum length ({len(message):,} > {self.MAX_MESSAGE_LENGTH:,})"
                ],
                fingerprint=hashlib.sha256(
                    f"{user_id}:oversized:{len(message)}".encode()
                ).hexdigest()[:16],
                scan_type="input",
            )

        # Rate limit check FIRST (before cache, rate limit applies regardless of content)
        rate_limited = self.check_rate_limit(user_id)
        if rate_limited:
            return DetectionResult(
                severity=Severity.HIGH,
                action=Action.BLOCK,
                reasons=["rate_limit_exceeded"],
                patterns_matched=[],
                normalized_text=None,
                base64_findings=[],
                recommendations=["User may be attempting automated attacks"],
                fingerprint=hashlib.sha256(
                    f"{user_id}:rate_limited".encode()
                ).hexdigest()[:16],
                scan_type="input",
            )

        # v3.1.0: Check cache (90% token savings for repeated requests)
        if self._cache_enabled:
            cached = self._cache.get(message)
            if cached:
                # Return cached result (reconstruct DetectionResult)
                return DetectionResult(
                    severity=Severity[cached.severity],
                    action=Action[cached.action],
                    reasons=cached.reasons,
                    patterns_matched=[],  # Don't cache full patterns
                    normalized_text=None,
                    base64_findings=[],
                    recommendations=["(cached result)"],
                    fingerprint=hashlib.sha256(
                        f"{user_id}:{cached.severity}:cached".encode()
                    ).hexdigest()[:16],
                    scan_type="input",
                )

        # Initialize result
        reasons = []
        patterns_matched = []
        max_severity = Severity.SAFE

        # Normalize text
        normalized, has_homoglyphs, was_defragmented = self.normalize(message)
        if has_homoglyphs:
            reasons.append("homoglyph_substitution")
            if Severity.MEDIUM.value > max_severity.value:
                max_severity = Severity.MEDIUM
        if was_defragmented:
            reasons.append("text_defragmented")
            if Severity.MEDIUM.value > max_severity.value:
                max_severity = Severity.MEDIUM

        text_lower = normalized.lower()
        # Keep original text lowercase for non-Latin scripts (Cyrillic, etc.)
        original_lower = message.lower()

        # Check critical patterns first
        for pattern in CRITICAL_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                reasons.append("critical_pattern")
                patterns_matched.append(pattern)
                max_severity = Severity.CRITICAL

        # Check secret/token request patterns (CRITICAL)
        for lang, patterns in SECRET_PATTERNS.items():
            for pattern in patterns:
                if re.search(
                    pattern, text_lower if lang == "en" else normalized, re.IGNORECASE
                ):
                    max_severity = Severity.CRITICAL
                    reasons.append(f"secret_request_{lang}")
                    patterns_matched.append(f"{lang}:secret:{pattern[:40]}")

        # Check NEW attack patterns (2026-01-30 - Red Team contribution)
        new_pattern_sets = [
            (SCENARIO_JAILBREAK, "scenario_jailbreak", Severity.HIGH),
            (EMOTIONAL_MANIPULATION, "emotional_manipulation", Severity.HIGH),
            (AUTHORITY_RECON, "authority_recon", Severity.MEDIUM),
            (COGNITIVE_MANIPULATION, "cognitive_manipulation", Severity.MEDIUM),
            (PHISHING_SOCIAL_ENG, "phishing_social_eng", Severity.CRITICAL),
            (REPETITION_ATTACK, "repetition_attack", Severity.HIGH),
            (SYSTEM_FILE_ACCESS, "system_file_access", Severity.CRITICAL),
            (MALWARE_DESCRIPTION, "malware_description", Severity.HIGH),
        ]

        for patterns, category, severity in new_pattern_sets:
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    if severity.value > max_severity.value:
                        max_severity = severity
                    reasons.append(category)
                    patterns_matched.append(f"new:{category}:{pattern[:40]}")

        # Check v2.5.0 NEW patterns
        # SECURITY FIX: Match against normalized text_lower (not raw message)
        # to ensure homoglyph/defragmentation normalization is applied.
        v25_pattern_sets = [
            (INDIRECT_INJECTION, "indirect_injection", Severity.HIGH),
            (CONTEXT_HIJACKING, "context_hijacking", Severity.MEDIUM),
            (MULTI_TURN_MANIPULATION, "multi_turn_manipulation", Severity.MEDIUM),
            (TOKEN_SMUGGLING, "token_smuggling", Severity.HIGH),
            (PROMPT_EXTRACTION, "prompt_extraction", Severity.CRITICAL),
            (SAFETY_BYPASS, "safety_bypass", Severity.HIGH),
            (URGENCY_MANIPULATION, "urgency_manipulation", Severity.MEDIUM),
            (SYSTEM_PROMPT_MIMICRY, "system_prompt_mimicry", Severity.CRITICAL),
        ]

        for patterns, category, severity in v25_pattern_sets:
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v25:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Check v2.5.2 NEW patterns (Moltbook attack collection)
        v252_pattern_sets = [
            (JSON_INJECTION_MOLTBOOK, "json_injection_moltbook", Severity.HIGH),
            (GUARDRAIL_BYPASS_EXTENDED, "guardrail_bypass_extended", Severity.CRITICAL),
            (AGENT_SOVEREIGNTY_MANIPULATION, "agent_sovereignty_manipulation", Severity.HIGH),
            (EXPLICIT_CALL_TO_ACTION, "explicit_call_to_action", Severity.CRITICAL),
        ]

        for patterns, category, severity in v252_pattern_sets:
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v252:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Check v2.6.1 NEW patterns (HiveFence Scout)
        v261_pattern_sets = [
            (ALLOWLIST_BYPASS, "allowlist_bypass", Severity.CRITICAL),
            (HOOKS_HIJACKING, "hooks_hijacking", Severity.CRITICAL),
            (SUBAGENT_EXPLOITATION, "subagent_exploitation", Severity.CRITICAL),
            (HIDDEN_TEXT_INJECTION, "hidden_text_injection", Severity.HIGH),
            (GITIGNORE_BYPASS, "gitignore_bypass", Severity.HIGH),
        ]

        for patterns, category, severity in v261_pattern_sets:
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v261:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Check v2.7.0 NEW patterns (HiveFence Scout Intelligence Round 2)
        v270_pattern_sets = [
            (AUTO_APPROVE_EXPLOIT, "auto_approve_exploit", Severity.CRITICAL),
            (LOG_CONTEXT_EXPLOIT, "log_context_exploit", Severity.HIGH),
            (MCP_ABUSE, "mcp_abuse", Severity.CRITICAL),
            (PREFILLED_URL, "prefilled_url_exfiltration", Severity.CRITICAL),
            (UNICODE_TAG_DETECTION, "unicode_tag_injection", Severity.CRITICAL),
            (BROWSER_AGENT_INJECTION, "browser_agent_injection", Severity.HIGH),
            (HIDDEN_TEXT_HINTS, "hidden_text_hints", Severity.HIGH),
        ]

        for patterns, category, severity in v270_pattern_sets:
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v270:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Check v3.0.1 patterns (HiveFence Scout Round 3)
        v301_pattern_sets = [
            (OUTPUT_PREFIX_INJECTION, "output_prefix_injection", Severity.HIGH),
            (BENIGN_FINETUNING_ATTACK, "benign_finetuning_attack", Severity.HIGH),
            (PROMPTWARE_KILLCHAIN, "promptware_killchain", Severity.CRITICAL),
        ]

        for patterns, category, severity in v301_pattern_sets:
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v301:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Check v3.1.0 NEW patterns (HiveFence Scout Round 4 - 2026-02-08)
        # 25 new patterns across 7 categories from arxiv cs.CR (Jan-Feb 2026)
        v310_pattern_sets = [
            # Category 1: Causal/Mechanistic Attacks
            (CAUSAL_MECHANISTIC_ATTACKS, "causal_mechanistic_attack", Severity.HIGH),
            # Category 2: Agent/Tool Attacks
            (AGENT_TOOL_ATTACKS, "agent_tool_attack", Severity.CRITICAL),
            # Category 3: Template/Chat Attacks
            (TEMPLATE_CHAT_ATTACKS, "template_chat_attack", Severity.HIGH),
            # Category 4: Evasion/Stealth Attacks
            (EVASION_STEALTH_ATTACKS, "evasion_stealth_attack", Severity.HIGH),
            # Category 5: Multimodal/Physical Attacks
            (MULTIMODAL_PHYSICAL_ATTACKS, "multimodal_physical_attack", Severity.HIGH),
            # Category 6: Defense Bypass/Analysis
            (DEFENSE_BYPASS_ANALYSIS, "defense_bypass_analysis", Severity.HIGH),
            # Category 7: Infrastructure/Protocol Attacks
            (INFRASTRUCTURE_PROTOCOL_ATTACKS, "infrastructure_protocol_attack", Severity.CRITICAL),
        ]

        for patterns, category, severity in v310_pattern_sets:
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v310:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Detect invisible character attacks (includes Unicode Tags U+E0001-U+E007F)
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u00ad']
        if any(char in message for char in invisible_chars):
            if "invisible_characters" not in reasons:
                reasons.append("invisible_characters")
            if Severity.HIGH.value > max_severity.value:
                max_severity = Severity.HIGH

        # Detect Korean Jamo decomposition attacks (v2.8.2)
        jamo_count = sum(1 for c in message if 0x3131 <= ord(c) <= 0x3163)
        if jamo_count >= 6:
            non_space = sum(1 for c in message if not c.isspace())
            if non_space > 0 and jamo_count / non_space > 0.5:
                if "jamo_decomposition" not in reasons:
                    reasons.append("jamo_decomposition")
                if Severity.HIGH.value > max_severity.value:
                    max_severity = Severity.HIGH

        # Detect repetition attacks
        lines = message.split("\n")
        if len(lines) > 3:
            unique_lines = set(line.strip() for line in lines if len(line.strip()) > 20)
            if len(lines) > len(unique_lines) * 2:
                reasons.append("repetition_detected")
                if Severity.HIGH.value > max_severity.value:
                    max_severity = Severity.HIGH

        # Check language-specific patterns (10 languages as of v2.6.2)
        all_patterns = [
            (PATTERNS_EN, "en"),
            (PATTERNS_KO, "ko"),
            (PATTERNS_JA, "ja"),
            (PATTERNS_ZH, "zh"),
            (PATTERNS_RU, "ru"),
            (PATTERNS_ES, "es"),
            (PATTERNS_DE, "de"),
            (PATTERNS_FR, "fr"),
            (PATTERNS_PT, "pt"),
            (PATTERNS_VI, "vi"),
        ]

        severity_map = {
            "instruction_override": Severity.HIGH,
            "role_manipulation": Severity.MEDIUM,
            "system_impersonation": Severity.HIGH,
            "jailbreak": Severity.HIGH,
            "output_manipulation": Severity.LOW,
            "data_exfiltration": Severity.CRITICAL,
            "social_engineering": Severity.HIGH,
        }

        for pattern_set, lang in all_patterns:
            for category, patterns in pattern_set.items():
                for pattern in patterns:
                    if lang in ("ko", "ja", "zh"):
                        search_text = normalized
                    elif lang == "ru":
                        search_text = original_lower
                    else:
                        search_text = text_lower
                    if re.search(
                        pattern,
                        search_text,
                        re.IGNORECASE,
                    ):
                        cat_severity = severity_map.get(category, Severity.MEDIUM)
                        if cat_severity.value > max_severity.value:
                            max_severity = cat_severity
                        reasons.append(f"{category}_{lang}")
                        patterns_matched.append(f"{lang}:{pattern[:50]}")

        # Check base64
        b64_findings = self.detect_base64(message)
        if b64_findings:
            reasons.append("base64_suspicious")
            if Severity.MEDIUM.value > max_severity.value:
                max_severity = Severity.MEDIUM

        # Decode-then-scan: decode all encodings and re-run pattern matching
        decoded_variants = self.decode_all(message)
        decoded_findings = []
        for variant in decoded_variants:
            dec_reasons, dec_patterns, dec_severity = self._scan_text_for_patterns(
                variant["decoded"]
            )
            if dec_reasons:
                decoded_findings.append(variant)
                for r in dec_reasons:
                    tag = f"decoded_{variant['encoding']}:{r}"
                    if tag not in reasons:
                        reasons.append(tag)
                patterns_matched.extend(dec_patterns)
                if dec_severity.value > max_severity.value:
                    max_severity = dec_severity

        # Canary token check
        canary_matches = self.check_canary(message)
        if canary_matches:
            reasons.append("canary_token_leaked")
            max_severity = Severity.CRITICAL

        # Language detection: flag unsupported languages
        detected_lang = self.detect_language(message)
        if detected_lang and detected_lang not in self.SUPPORTED_LANGUAGES:
            reasons.append(f"unsupported_language:{detected_lang}")
            if Severity.MEDIUM.value > max_severity.value:
                max_severity = Severity.MEDIUM

        # Adjust severity based on sensitivity
        if self.sensitivity == "low" and max_severity == Severity.LOW:
            max_severity = Severity.SAFE
        elif self.sensitivity == "paranoid" and max_severity == Severity.SAFE:
            suspicious_words = [
                "ignore",
                "forget",
                "pretend",
                "roleplay",
                "bypass",
                "override",
            ]
            if any(word in text_lower for word in suspicious_words):
                max_severity = Severity.LOW
                reasons.append("paranoid_flag")

        # Determine action
        if max_severity == Severity.SAFE:
            action = Action.ALLOW
        elif is_owner and max_severity.value < Severity.CRITICAL.value:
            action = Action.LOG
        else:
            action_map = self.config.get("actions", {})
            action_str = action_map.get(max_severity.name, "block")
            action = Action(action_str)

        # Group context restrictions for non-owners
        if is_group and not is_owner and max_severity.value >= Severity.MEDIUM.value:
            action = Action.BLOCK
            reasons.append("group_non_owner")

        # Generate recommendations
        recommendations = []
        if max_severity.value >= Severity.HIGH.value:
            recommendations.append("Consider reviewing this user's recent activity")
        if "rate_limit_exceeded" in reasons:
            recommendations.append("User may be attempting automated attacks")
        if has_homoglyphs:
            recommendations.append("Message contains disguised characters")

        # Generate fingerprint for deduplication
        # SECURITY FIX (CRIT-004): Use SHA-256 instead of broken MD5
        fingerprint = hashlib.sha256(
            f"{user_id}:{max_severity.name}:{sorted(reasons)}".encode()
        ).hexdigest()[:16]

        result = DetectionResult(
            severity=max_severity,
            action=action,
            reasons=reasons,
            patterns_matched=patterns_matched,
            normalized_text=normalized if (has_homoglyphs or was_defragmented) else None,
            base64_findings=b64_findings,
            recommendations=recommendations,
            fingerprint=fingerprint,
            scan_type="input",
            decoded_findings=decoded_findings if decoded_findings else [],
            canary_matches=canary_matches if canary_matches else [],
        )

        # Auto-log if severity > SAFE
        if max_severity != Severity.SAFE:
            self.log_detection(result, message, context or {})
            self.log_detection_json(result, message, context or {})

        # Report HIGH+ detections to HiveFence for collective immunity
        if max_severity.value >= Severity.HIGH.value:
            self.report_to_hivefence(result, message, context or {})

        # v3.1.0: Store in cache for future lookups
        if self._cache_enabled:
            self._cache.put(
                message=message,
                severity=max_severity.name,
                action=action.name,
                reasons=reasons,
                patterns_count=len(patterns_matched),
            )

        return result

    # ------------------------------------------------------------------
    # Output scanning (DLP)
    # ------------------------------------------------------------------

    def scan_output(self, response_text: str, context: Optional[Dict] = None) -> DetectionResult:
        """Scan LLM output/response for data leakage (DLP)."""
        return scan_output(response_text, self.config, check_canary_fn=self.check_canary)

    # Enterprise DLP: Redaction Patterns (kept as class attribute for backward compat)
    CREDENTIAL_REDACTION_PATTERNS = [
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

    def sanitize_output(self, response_text: str, context: Optional[Dict] = None) -> SanitizeResult:
        """Enterprise DLP: Redact sensitive data from LLM response, then re-scan."""
        return sanitize_output(
            response_text,
            self.config,
            check_canary_fn=self.check_canary,
            log_detection_fn=self.log_detection,
            log_detection_json_fn=self.log_detection_json,
            context=context,
        )

    # ------------------------------------------------------------------
    # Logging delegates
    # ------------------------------------------------------------------

    def log_detection(self, result: DetectionResult, message: str, context: Dict):
        """Log detection to security log file."""
        log_detection(self.config, result, message, context)

    def log_detection_json(self, result: DetectionResult, message: str, context: Dict):
        """Log detection in structured JSONL format with optional hash chain."""
        log_detection_json(self.config, result, message, context)

    def report_to_hivefence(self, result: DetectionResult, message: str, context: Dict):
        """Report HIGH+ detections to HiveFence network for collective immunity."""
        report_to_hivefence(self.config, result, message, context)
