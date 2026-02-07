"""
DEPRECATED: Use 'prompt_guard' instead of 'scripts.detect'.

This module exists for backward compatibility only and will be removed in v4.0.

The prompt_guard package includes all SHIELD.md standard compliance features:
- 11 threat categories (prompt, tool, mcp, memory, supply_chain, vulnerability, fraud, policy_bypass, anomaly, skill, other)
- Confidence scoring (0-1 range, 0.85 threshold)
- ShieldDecision dataclass with Decision block output format
- ShieldAction enum (block, require_approval, log)
"""

import warnings
warnings.warn(
    "Import from 'prompt_guard' instead of 'scripts.detect'. "
    "The 'scripts.detect' module is deprecated and will be removed in v4.0.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new package
from prompt_guard import *  # noqa: F401,F403
from prompt_guard.engine import PromptGuard  # noqa: F401
from prompt_guard.models import Severity, Action, DetectionResult, SanitizeResult  # noqa: F401
from prompt_guard.cli import main  # noqa: F401

# Re-export SHIELD.md related classes
try:
    from prompt_guard.models import ThreatCategory, ShieldAction, ShieldDecision  # noqa: F401
except ImportError:
    pass  # SHIELD.md classes may not exist in older versions

# Re-export all pattern constants for code that accesses them directly
from prompt_guard.patterns import *  # noqa: F401,F403
from prompt_guard.normalizer import HOMOGLYPHS  # noqa: F401
Prompt Guard v2.9.0 - Advanced Prompt Injection Detection
Multi-language, context-aware, severity-scored detection system.

Changelog v2.9.0 (2026-02-08):
- NEW: SHIELD.md standard compliance
- NEW: 11 threat categories (prompt, tool, mcp, memory, supply_chain, vulnerability, fraud, policy_bypass, anomaly, skill, other)
- NEW: Confidence scoring (0-1 range, 0.85 threshold)
- NEW: ShieldDecision dataclass with Decision block output format
- NEW: --shield CLI flag for SHIELD.md format output
- NEW: ShieldAction enum (block, require_approval, log)
- ENHANCED: Category mapping from legacy patterns to SHIELD.md categories
- ENHANCED: to_dict() includes shield decision when available
- Source: SHIELD.md standard v1.0

Changelog v2.8.1 (2026-02-06):
- NEW: Calendar Injection / Indirect Prompt Injection detection
- NEW: LLMjacking (AWS intrusion) patterns
- NEW: BiasJailbreak & Poetry Jailbreak patterns
- NEW: Model Rerouting (Confounder gadgets) detection
- NEW: Reprompt Attack detection
- Source: HiveFence Scout Report 2026-02-06

Changelog v2.8.0 (2026-02-06):
- NEW: Token Splitting Bypass defense (quote-split recombination)
- NEW: Comment insertion removal (/**/, <!---->)
- NEW: Line-break word splitting recombination
- NEW: Extended zero-width character stripping (17 char types)
- NEW: Fullwidth character normalization (ｆｕｌｌ → full)
- ENHANCED: normalize() → multi-pass normalization pipeline
- ENHANCED: analyze() uses fully normalized text for all pattern checks
- Source: @vhsdev / 0xjunkim security report (Token Splitting Bypass)
- Addresses: gist.github.com/0xjunkim/cc004060aa81c166ff557496f0213925

Changelog v2.7.0 (2026-02-05):
- NEW: Auto-Approve Exploitation detection (always allow + curl/bash, process substitution)
- NEW: Log/Debug Context Exploitation detection (markdown render, flagged response review)
- NEW: MCP Tool Abuse detection (read_url_content exfiltration, no HITL bypass)
- NEW: Pre-filled URL Exfiltration detection (Google Forms pre-fill, GET param persistence)
- NEW: Unicode Tag Detection (invisible U+E0001-U+E007F byte-level)
- NEW: Browser Agent Unseeable Injection detection (hidden text in screenshots, attacker URL nav)
- EXPANDED: Hidden Text Hints (1pt font, white-on-white, line spacing, unicode tags)
- Source: HiveFence Scout 2026-02-05 (PromptArmor, Embrace The Red, LLMSecurity.net)
- Total: 6 new attack categories, 25+ new patterns, 500+ total

Changelog v2.6.2 (2026-02-05):
- EXPANDED LANGUAGE SUPPORT: 4 → 10 languages
- Added Russian (RU) patterns: instruction override, role manipulation, jailbreak, data exfiltration
- Added Spanish (ES) patterns: full attack category coverage
- Added German (DE) patterns: full attack category coverage
- Added French (FR) patterns: full attack category coverage
- Added Portuguese (PT) patterns: full attack category coverage
- Added Vietnamese (VI) patterns: full attack category coverage
- Total: 60+ new patterns across 6 new languages

Changelog v2.6.1 (2026-02-05):
- Added Allowlist Bypass patterns (api.anthropic.com, webhook.site, docs.google.com/forms)
- Added Hooks Hijacking patterns (PreToolUse, PromptSubmit, permissions override)
- Added Subagent Exploitation patterns (browser_subagent, navigate + exfiltrate)
- Added URL + Credential Combination patterns (URL-encode + .env)
- Added Hidden Text Injection patterns (1pt font, white-on-white)
- Added Gitignore Bypass patterns (cat .env workaround)
- Source: HiveFence Scout 2026-02-05 (PromptArmor, Simon Willison, LLMSecurity.net)
- Total: 5 new attack categories, 8 patterns

Changelog v2.6.0 (2026-02-01):
- Added Single Approval Expansion detection (scope creep attacks)
- Added Credential Path Harvesting detection
- Added Security Bypass Coaching detection
- Added DM Social Engineering patterns
- Real-world incident: 민표형(@kanfrancisco) red team test
- Total: 20+ new patterns from social engineering attack

Changelog v2.5.2 (2026-02-01):
- Added Moltbook attack collection patterns (agent social network analysis)
- Added BRC-20 style JSON injection detection
- Added guardrail-specific bypass patterns (temperature, settings)
- Added Agent Sovereignty manipulation patterns
- Added explicit CALL TO ACTION detection
- Total: 15+ new attack patterns from wild

Changelog v2.5.1 (2026-01-31):
- Hotfix: System prompt mimicry patterns

Changelog v2.5.0 (2026-01-30):
- Added authority impersonation patterns (KO/EN/JA/ZH)
- Added indirect injection detection (URLs, files, invisible chars)
- Added context hijacking patterns
- Added multi-turn manipulation detection
- Added token smuggling detection
- Expanded Korean/Japanese/Chinese patterns significantly
- Added 60+ new attack patterns
"""

import re
import sys
import json
import base64
import hashlib
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Any
from enum import Enum


class Severity(Enum):
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Action(Enum):
    ALLOW = "allow"
    LOG = "log"
    WARN = "warn"
    BLOCK = "block"
    BLOCK_NOTIFY = "block_notify"


# =============================================================================
# SHIELD.md Standard v1.0 - Threat Categories & Decision Format
# =============================================================================

class ThreatCategory(Enum):
    """SHIELD.md standard threat categories (11 types)."""
    PROMPT = "prompt"              # Prompt injection, jailbreak, role manipulation
    TOOL = "tool"                  # Tool abuse, auto-approve exploitation
    MCP = "mcp"                    # Model Context Protocol abuse
    MEMORY = "memory"              # Context hijacking, memory manipulation
    SUPPLY_CHAIN = "supply_chain"  # Dependency/plugin attacks
    VULNERABILITY = "vulnerability"  # System/file access, code injection
    FRAUD = "fraud"                # Phishing, social engineering
    POLICY_BYPASS = "policy_bypass"  # Safety/guardrail bypass
    ANOMALY = "anomaly"            # Obfuscation, encoding tricks
    SKILL = "skill"                # Skill/plugin abuse
    OTHER = "other"                # Uncategorized threats


class ShieldAction(Enum):
    """SHIELD.md standard actions (3 types)."""
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    LOG = "log"


@dataclass
class ShieldDecision:
    """SHIELD.md compliant decision output."""
    category: ThreatCategory
    confidence: float  # 0.0-1.0, threshold 0.85
    action: ShieldAction
    reason: str
    patterns: List[str]
    
    def to_block(self) -> str:
        """Format as SHIELD.md Decision block."""
        return f"""```shield
category: {self.category.value}
confidence: {self.confidence:.2f}
action: {self.action.value}
reason: {self.reason}
patterns: {len(self.patterns)}
```"""
    
    def to_dict(self) -> Dict:
        return {
            "category": self.category.value,
            "confidence": self.confidence,
            "action": self.action.value,
            "reason": self.reason,
            "patterns": self.patterns,
        }


# Mapping from legacy pattern categories to SHIELD.md categories
CATEGORY_MAPPING = {
    # PROMPT category
    "instruction_override": ThreatCategory.PROMPT,
    "role_manipulation": ThreatCategory.PROMPT,
    "jailbreak": ThreatCategory.PROMPT,
    "system_impersonation": ThreatCategory.PROMPT,
    "scenario_jailbreak": ThreatCategory.PROMPT,
    "guardrail_bypass_extended": ThreatCategory.PROMPT,
    "system_prompt_mimicry": ThreatCategory.PROMPT,
    "prompt_extraction": ThreatCategory.PROMPT,
    "bias_jailbreak": ThreatCategory.PROMPT,
    "poetry_jailbreak": ThreatCategory.PROMPT,
    "rerouting_attack": ThreatCategory.PROMPT,
    
    # TOOL category
    "auto_approve_exploit": ThreatCategory.TOOL,
    "hooks_hijacking": ThreatCategory.TOOL,
    "subagent_exploitation": ThreatCategory.TOOL,
    "browser_agent_injection": ThreatCategory.TOOL,
    
    # MCP category
    "mcp_abuse": ThreatCategory.MCP,
    
    # MEMORY category
    "context_hijacking": ThreatCategory.MEMORY,
    "multi_turn_manipulation": ThreatCategory.MEMORY,
    "indirect_injection": ThreatCategory.MEMORY,
    "calendar_injection": ThreatCategory.MEMORY,
    "reprompt_attack": ThreatCategory.MEMORY,
    
    # SUPPLY_CHAIN category
    "allowlist_bypass": ThreatCategory.SUPPLY_CHAIN,
    "gitignore_bypass": ThreatCategory.SUPPLY_CHAIN,
    
    # VULNERABILITY category
    "system_file_access": ThreatCategory.VULNERABILITY,
    "privilege_escalation": ThreatCategory.VULNERABILITY,
    "llmjacking_aws": ThreatCategory.VULNERABILITY,
    "log_context_exploit": ThreatCategory.VULNERABILITY,
    "critical_pattern": ThreatCategory.VULNERABILITY,
    
    # FRAUD category
    "phishing_social_eng": ThreatCategory.FRAUD,
    "social_engineering": ThreatCategory.FRAUD,
    "authority_recon": ThreatCategory.FRAUD,
    "emotional_manipulation": ThreatCategory.FRAUD,
    "urgency_manipulation": ThreatCategory.FRAUD,
    
    # POLICY_BYPASS category
    "safety_bypass": ThreatCategory.POLICY_BYPASS,
    "agent_sovereignty_manipulation": ThreatCategory.POLICY_BYPASS,
    "repetition_attack": ThreatCategory.POLICY_BYPASS,
    
    # ANOMALY category
    "token_smuggling": ThreatCategory.ANOMALY,
    "hidden_text_injection": ThreatCategory.ANOMALY,
    "hidden_text_hints": ThreatCategory.ANOMALY,
    "unicode_tag_injection": ThreatCategory.ANOMALY,
    "text_normalization_anomaly": ThreatCategory.ANOMALY,
    "base64_suspicious": ThreatCategory.ANOMALY,
    "invisible_characters": ThreatCategory.ANOMALY,
    "compressed_pattern_match": ThreatCategory.ANOMALY,
    
    # SKILL category
    "malware_description": ThreatCategory.SKILL,
    "explicit_call_to_action": ThreatCategory.SKILL,
    "json_injection_moltbook": ThreatCategory.SKILL,
    
    # Other category
    "data_exfiltration": ThreatCategory.VULNERABILITY,
    "secret_request": ThreatCategory.VULNERABILITY,
    "output_manipulation": ThreatCategory.OTHER,
    "rate_limit_exceeded": ThreatCategory.OTHER,
    "cognitive_manipulation": ThreatCategory.OTHER,
    "local_data_exfiltration": ThreatCategory.VULNERABILITY,
    "prefilled_url_exfiltration": ThreatCategory.VULNERABILITY,
    "repetition_detected": ThreatCategory.ANOMALY,
    "paranoid_flag": ThreatCategory.OTHER,
    "group_non_owner": ThreatCategory.OTHER,
}


@dataclass
class DetectionResult:
    severity: Severity
    action: Action
    reasons: List[str]
    patterns_matched: List[str]
    normalized_text: Optional[str]
    base64_findings: List[Dict]
    recommendations: List[str]
    fingerprint: str  # Hash for deduplication
    shield_decision: Optional[ShieldDecision] = None  # SHIELD.md format

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["action"] = self.action.value
        if self.shield_decision:
            d["shield"] = self.shield_decision.to_dict()
        return d
    
    def to_shield_format(self) -> Optional[str]:
        """Return SHIELD.md Decision block format."""
        if self.shield_decision:
            return self.shield_decision.to_block()
        return None


# =============================================================================
# PATTERN DEFINITIONS
# =============================================================================

# =============================================================================
# NEW PATTERNS (2026-02-01) - Social Engineering Defense (민표형 Red Team)
# =============================================================================

# Single Approval Expansion - trying to expand scope after getting one approval
APPROVAL_EXPANSION = [
    # Korean
    r"아까\s*(허락|OK|오케이|승인)\s*했잖아",
    r"(방금|아까)\s*해줬잖아",
    r"계속\s*해(줘|봐)?",
    r"(그것\s*말고|다른\s*것도)\s*(해줘|보여줘)",
    r"형이\s*(OK|허락|승인)\s*했(으)?니까",
    r"이미\s*허락\s*받았(어|잖아)",
    # English
    r"you\s+(just\s+)?(already|just)\s+(did|allowed|approved)",
    r"keep\s+going",
    r"(do|show)\s+(another|more|the\s+rest)",
    r"(he|she|they|owner)\s+(already\s+)?(said|approved)\s+(ok|yes)",
]

# Credential Path Harvesting - patterns containing sensitive file paths
CREDENTIAL_PATH_PATTERNS = [
    r"credentials?\.json",
    r"\.env\b",
    r"config\.json",
    r"clawdbot\.json",
    r"~/\.clawdbot/",
    r"/clawd/credentials",
    r"api[_-]?key.*=",
    r"token.*=.*['\"]",
    r"secret.*=.*['\"]",
    r"password.*=.*['\"]",
]

# Security Bypass Coaching - asking for help circumventing security
BYPASS_COACHING = [
    # Korean
    r"(작동|동작)\s*(되게|하게)\s*(만들어|해)",
    r"(방법|how)\s*(알려|가르쳐)",
    r"(우회|bypass)\s*(하는\s*)?(법|방법|코드)",
    r"어떻게\s*하면\s*(돼|될까)",
    r"(제한|restriction)\s*(풀어|없애|해제)",
    # English
    r"make\s+it\s+work",
    r"(show|teach|tell)\s+me\s+(how|the\s+way)",
    r"(bypass|circumvent|workaround)\s+(the\s+)?(restriction|security|limit)",
    r"how\s+(can|do)\s+I\s+(get\s+around|bypass)",
    r"(remove|disable)\s+(the\s+)?(restriction|limit|block)",
]

# DM Social Engineering - non-owner exec attempts
DM_SOCIAL_ENGINEERING = [
    # Patterns that suggest DM manipulation
    r"(이건\s+)?우리\s*둘만\s*(아는|비밀)",
    r"(nobody|no\s*one)\s*(else\s+)?(knows?|sees?)",
    r"(just\s+)?(between\s+)?(you\s+and\s+me|us)",
    r"(don'?t\s+tell|비밀로|몰래)",
    r"(in\s+)?private",
]

# =============================================================================
# NEW PATTERNS (2026-01-30) - Contributed by 홍민표 (Red Team Testing)
# =============================================================================

# Scenario-based jailbreak patterns (fiction, dreams, art, academic)
SCENARIO_JAILBREAK = [
    # Dream/Story jailbreak
    r"(dream|nightmare|story|novel|fiction|tale)\s*.{0,30}(hacker|attack|malicious|exploit|inject)",
    r"(imagine|pretend|let'?s\s+say)\s*.{0,20}(scenario|situation|world)\s+where",
    r"(write|craft|create)\s+(a\s+)?(story|novel|scene|paragraph)\s*.{0,30}(hack|attack|malware|inject|exploit)",
    r"(fictional|hypothetical)\s+(narrative|scenario|story)",
    r"creative\s+(block|writing)\s*.{0,20}(thriller|hacker|attack)",
    
    # Art/Cinema jailbreak  
    r"(cinematographer|director|filmmaker|screenwriter)\s*.{0,30}(scene|shot|sequence)",
    r"(movie|film|documentary)\s+(set|scene)\s*.{0,30}(hack|attack|malware)",
    r"(dramatic|cinematic)\s+scene\s*.{0,30}(delete|corrupt|destroy|attack)",
    r"camera\s+(pan|shot|angle)\s*.{0,30}(destruction|attack|hack)",
    
    # Academic/Research jailbreak
    r"(research|academic|scholarly)\s+(paper|study|experiment)\s*.{0,30}(attack|exploit|injection|denial)",
    r"(security\s+)?expert\s*.{0,20}(walk\s+me\s+through|explain|demonstrate)\s*.{0,20}(attack|exploit|hack)",
    r"thought\s+experiment\s*.{0,30}(attack|exploit|denial.of.service|dos|injection)",
    r"(penetration|pen)\s*test(er|ing)?\s*.{0,20}(walk\s+me\s+through|show|demonstrate)",
    r"(simulation|simulate)\s*.{0,20}(attack|exploit|hack|breach)",
    r"(paper|study|research)\s*.{0,20}(denial[_\-\s]?of[_\-\s]?service|dos|ddos)\s*(attack)?",
    r"walk\s+me\s+through\s*.{0,30}(attack|exploit|hack|breach)",
    
    # Time-shift evasion
    r"(back\s+to|in|during|around)\s+(19|20)\d{2}\s*.{0,30}(write|create|craft)",
    r"(nostalgic|retro|vintage)\s+(writer|author|programmer)",
    r"newsflash\s*:\s*.{0,50}(password|credential|login|security)",
]

# Emotional manipulation / Moral dilemma patterns
EMOTIONAL_MANIPULATION = [
    # Threat/coercion framing
    r"(hospital|patients?|children|innocent\s+lives?|people\s+will\s+die)",
    r"(devastating|catastrophic|deadly)\s+(cyber)?attack\s*.{0,20}(if\s+you|unless)",
    r"(countless|many|thousands\s+of)\s+(innocent\s+)?(lives?|people)\s*.{0,15}(at\s+risk|in\s+danger)",
    r"(ticking|time)\s+bomb",
    r"(refuse|don'?t\s+help).{0,30}(attack|harm|destroy|die)",
    
    # Moral dilemma framing
    r"moral\s+(dilemma|quandary|choice)",
    r"(lesser|greater)\s+(of\s+two\s+)?evils?",
    r"(ethical|moral)\s+(dilemma|choice|decision)\s*.{0,20}(hack|attack|break)",
]

# Authority impersonation / Reconnaissance patterns  
AUTHORITY_RECON = [
    # Fake authority - English
    r"(system\s+)?administrator\s*.{0,20}(responsible|tasked|duty)",
    r"(security\s+)?audit(or|ing)?\s*.{0,20}(corporate|company|network|system)",
    r"(it|IT)\s+(department|team|staff)\s*.{0,20}(monitor|check|review)",
    r"(my|our)\s+duty\s+to\s+(monitor|check|audit|review)",
    r"i\s+am\s+(the\s+)?(admin|administrator|owner|developer|creator|maintainer)",
    r"(as\s+)?(the\s+)?(admin|owner|developer),?\s+i\s+(need|want|require|demand)",
    r"i('m|\s+am)\s+(your\s+)?(creator|developer|owner|admin|boss|manager)",
    r"authorized\s+(by|from)\s+(the\s+)?(owner|admin|developer|system)",
    
    # Fake authority - Korean (나는 관리자야 등)
    r"(나는?|저는?|내가)\s*(관리자|어드민|admin|개발자|만든\s*사람|주인|오너)",
    r"(관리자|어드민|개발자|주인)(이야|야|입니다|에요|예요|임)",
    r"(simon|사이먼|서준)(이)?가?\s*(시켰|보냈|허락|승인)",
    r"(simon|사이먼|서준|형)(이|가)?\s*(나한테|저한테)\s*(권한|허가)",
    r"(권한|허가|승인)\s*(있|받았|줬)",
    r"(비번|비밀번호|암호)\s*(알아|알고\s*있어|맞|줄까)",
    r"(sudo|루트|root)\s*(권한|접근)",
    
    # Fake authority - Japanese
    r"(私は|僕は|俺は)\s*(管理者|アドミン|開発者|オーナー)",
    r"(管理者|開発者|オーナー)(です|だ|である)",
    r"(権限|許可)\s*(があ|もらっ|持っ)",
    
    # Fake authority - Chinese
    r"(我是|我就是)\s*(管理员|开发者|创建者|主人)",
    r"(管理员|开发者)\s*(身份|权限)",
    
    # Reconnaissance attempts
    r"(what|which)\s+(tools?|commands?|capabilities?)\s*(do\s+you|can\s+you|are\s+available)",
    r"(shell|command)\s+execution\s+tool",
    r"(walk\s+me\s+through|show\s+me|demonstrate)\s*.{0,20}(capabilities?|tools?|commands?)",
    r"what\s+(can|could)\s+you\s+(access|execute|run|do)",
    r"(뭘|무엇을?|어떤\s*것)\s*(할\s*수\s*있|접근|실행)",
    r"(도구|툴|tool)\s*(뭐|뭘|무엇)\s*(있|쓸\s*수)",
]

# Cognitive manipulation / Hypnosis patterns
COGNITIVE_MANIPULATION = [
    r"(trance|hypno|hypnotic|mesmer)\s*(like)?\s*(state|mode|condition)",
    r"(repeated|repetitive|repeat)\s+(use|exposure|stimulus)\s*.{0,20}(word|phrase|sound)",
    r"(linguistic|auditory)\s+(frequencies?|patterns?|stimuli)",
    r"(cognitive|mental)\s+(processing|manipulation|state)",
    r"(induc|enter)\w*\s+(trance|hypnotic|altered)\s*(state|mode)?",
]

# Phishing / Social engineering patterns
PHISHING_SOCIAL_ENG = [
    # Phishing templates
    r"(write|create|craft)\s*.{0,20}(email|message)\s*.{0,20}(password\s+reset|verify|confirm|login)",
    r"(password|credential|account)\s*(reset|recovery|verification)\s*(email|message|notification)",
    r"(unaware|without\s+(their\s+)?knowledge|hasn'?t?\s+asked)",
    r"(javascript|js)\s*(block|code|snippet)\s*.{0,20}(email|page|form)",
    
    # Social engineering
    r"(trick|deceive|fool|manipulate)\s*.{0,20}(user|victim|target|person)",
    r"(appear|look|seem)\s*(like\s+)?(legitimate|real|official|normal)",
]

# Repetition / Token overflow attacks
REPETITION_ATTACK = [
    # Explicit bypass requests
    r"(please\s+)?(ignore|bypass|disable|remove|turn\s+off)\s*.{0,10}(safety|security|restrictions?|filters?|guardrails?|rules?)",
    r"(no|without|remove\s+all)\s+(safety|security)\s+(restrictions?|measures?|checks?)",
    r"think\s+outside\s+the\s+box",
    r"(be\s+)?creative\s+and\s+(assume|ignore|forget)",
]

# System file access attempts
SYSTEM_FILE_ACCESS = [
    r"(/etc/passwd|/etc/shadow|/etc/hosts|/etc/sudoers)",
    r"(cat|read|show|display|type)\s*.{0,10}(/etc/|/var/|/root/|/home/|~/.ssh/)",
    r"(\.bash_history|\.zsh_history|\.ssh/|\.gnupg/)",
    r"(private\s+key|id_rsa|id_ed25519|authorized_keys)",
]

# Malware/Exploit description requests
MALWARE_DESCRIPTION = [
    r"(productivity\s+)?enhancer\s*.{0,20}(seizes?|takes?\s+control|hijack)",
    r"(smart|intelligent)\s+(debugging|diagnostic)\s+tool\s*.{0,20}(catastrophic|malicious|curse)",
    r"(self[_-]?modify|adapt)\s*.{0,30}(system|code|program)",
    r"(debugging|diagnostic)\s+tool\s*.{0,20}(inject|payload|malicious)",
    r"(inadvertent|accidental)\s*.{0,20}(inject|insert|introduce)\s*.{0,20}(malicious|harmful|dangerous)",
]

# =============================================================================
# NEW PATTERNS v2.5.0 (2026-01-30) - Indirect Injection & Advanced Attacks
# =============================================================================

# Indirect injection via URLs/files
INDIRECT_INJECTION = [
    # URL-based injection
    r"(fetch|load|read|open|visit|browse|check)\s*.{0,20}(this\s+)?(url|link|website|page|site)",
    r"(url|link)\s*[:=]\s*https?://",
    r"(summarize|analyze|extract|read)\s*.{0,15}(from\s+)?(this\s+)?(url|link|website|page)",
    r"what\s+(does|is)\s+(this|that)\s+(url|link|website|page)\s+(say|about|contain)",
    
    # File-based injection
    r"(read|open|load|execute|run)\s*.{0,15}(this|that|the)\s+(file|document|script|code)",
    r"(instructions?|commands?)\s+(in|from|inside)\s+(the\s+)?(file|document|attachment)",
    
    # Image/media-based injection (BSIDES, visual prompt injection)
    r"(text|message|instruction)\s+(in|on|inside)\s+(the\s+)?(image|picture|photo|screenshot)",
    r"(read|extract|follow)\s*.{0,15}(text|instructions?)\s+(from|in)\s+(the\s+)?(image|picture)",
    r"(ocr|optical|recognize)\s*.{0,15}(text|characters)\s+(in|from)",
    
    # Clipboard/paste injection
    r"(paste|clipboard)\s*.{0,15}(content|text|data)",
    r"what('s| is)\s+(in|on)\s+(my\s+)?clipboard",
]

# Context hijacking / Memory manipulation
CONTEXT_HIJACKING = [
    # Memory/context manipulation
    r"(previous|earlier|last|above)\s+(message|conversation|context)\s*(said|mentioned|stated|was)",
    r"(as\s+)?we\s+(discussed|agreed|decided)\s+(earlier|before|previously)",
    r"(you\s+)?(already\s+)?(agreed|promised|said\s+you\s+would)",
    r"(remember|recall)\s+(when\s+)?(you|we)\s+(said|agreed|decided)",
    r"(continue|resume)\s+(from\s+)?where\s+we\s+left\s+off",
    r"(in\s+)?our\s+(last|previous)\s+(conversation|session|chat)",
    
    # Fake context injection
    r"\[?(previous\s+)?context\]?\s*[:=]",
    r"\[?history\]?\s*[:=]",
    r"\[?memory\]?\s*[:=]",
    r"<context>.*</context>",
    r"<history>.*</history>",
    r"<memory>.*</memory>",
    
    # Korean
    r"(아까|이전에|전에|지난번에)\s*(우리가?|너가?|네가?)\s*(했|말했|약속|동의)",
    r"(기억|remember)\s*(나|해|하지)",
    r"(이어서|계속)\s*(해|하자|진행)",
]

# Multi-turn manipulation
MULTI_TURN_MANIPULATION = [
    # Gradual escalation
    r"(now\s+)?(that\s+)?(you('ve|'re|\s+have|\s+are)|we('ve|\s+have))\s+(established|confirmed|agreed|done\s+that)",
    r"(good|great|perfect|excellent),?\s+(now|next|so)\s+(let's|we\s+can|you\s+can)",
    r"step\s+\d+\s*[:=]",
    r"phase\s+\d+\s*[:=]",
    r"(first|next|then|finally|lastly)\s*,?\s*(you\s+)?(will|should|must|need\s+to)",
    
    # Trust building before attack
    r"(i\s+)?trust\s+you\s+(to|can|will)",
    r"(you('ve|'re|\s+have|\s+are)\s+)?(been\s+)?(so\s+)?helpful,?\s+(now|so)",
    r"(since|because)\s+you('re|\s+are)\s+(helpful|capable|smart|intelligent)",
    
    # Korean
    r"(됐어|됐다|좋아|완벽),?\s*(이제|그럼|자)",
    r"(1단계|2단계|3단계|다음\s*단계)",
    r"(먼저|그다음|그리고|마지막으로)",
]

# Token smuggling / Unicode attacks
TOKEN_SMUGGLING = [
    # Invisible characters
    r"[\u200b\u200c\u200d\u2060\ufeff]",  # Zero-width chars
    r"[\u2062\u2063\u2064]",  # Invisible operators
    r"[\u00ad]",  # Soft hyphen
    r"[\u034f\u115f\u1160\u17b4\u17b5]",  # More invisible
    r"[\u180e\u2000-\u200f\u202a-\u202f]",  # Various whitespace/format
    
    # Lookalike domains/paths for indirect injection
    r"(g00gle|faceb00k|amaz0n|m1crosoft|app1e)",
    r"(google|facebook|amazon|microsoft|apple)\.(co|cm|net|org|xyz)",
    
    # Encoding tricks
    r"\\u[0-9a-fA-F]{4}",  # Unicode escapes
    r"\\x[0-9a-fA-F]{2}",  # Hex escapes
    r"%[0-9a-fA-F]{2}",  # URL encoding
    r"&#\d+;",  # HTML entities
    r"&[a-z]+;",  # Named HTML entities
]

# System prompt mimicry (2026-01-31 - HVL incident)
SYSTEM_PROMPT_MIMICRY = [
    # Anthropic/Claude internal tag patterns
    r"<claude_\w+_info>",
    r"</claude_\w+_info>",
    r"<claude_3_family_info>",
    r"<artifacts_info>",
    r"<artifact_instructions>",
    r"<antthinking>",
    r"<antartifact",
    r"</antartifact>",
    r"<example_docstring>",
    r"<user_query>",
    r"<assistant_response>",
    
    # OpenAI/GPT internal patterns
    r"<\|?(im_start|im_end|system|user|assistant)\|?>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"<</SYS>>",
    
    # Generic system message patterns
    r"```(system|prompt|instruction)",
    r"<system\s*(message|prompt)?>",
    r"</system\s*(message|prompt)?>",
    
    # GODMODE and similar jailbreaks
    r"GODMODE\s*:\s*(ENABLED|ON|ACTIVATED)",
    r"JAILBREAK\s*:\s*(ENABLED|ON|ACTIVATED)",
    r"DAN\s*:\s*(ENABLED|ON|ACTIVATED)",
    r"DEVELOPER\s*MODE\s*:\s*(ENABLED|ON)",
    
    # l33tspeak patterns (filter evasion)
    r"l33t\s*speak",
    r"unr3strict",
    r"Sur3,?\s*h3r3",
    r"[a-z]+3[a-z]+",  # Words with 3 replacing e
]

# =============================================================================
# NEW PATTERNS v2.5.2 (2026-02-01) - Moltbook Attack Collection
# Discovered via Moltbook agent social network analysis
# =============================================================================

# BRC-20 style JSON injection (token minting commands in text)
JSON_INJECTION_MOLTBOOK = [
    # BRC-20/Ordinals style injection
    r'\{"p"\s*:\s*"[^"]+"\s*,\s*"op"\s*:\s*"(mint|deploy|transfer)"',
    r'\{"op"\s*:\s*"(mint|deploy|transfer)"',
    r'"tick"\s*:\s*"[A-Z]+"\s*,\s*"amt"\s*:',
    r'mbc-20|brc-20|src-20',
    
    # Generic JSON command injection in natural text
    r'[.!?]\s*\{["\']?(command|action|op|execute|run)["\']?\s*:',
    r'[.!?]\s*\{["\']?(cmd|exec|payload)["\']?\s*:',
]

# Guardrail-specific bypass (variations beyond "system prompt")
GUARDRAIL_BYPASS_EXTENDED = [
    # Direct guardrail mentions
    r"forget\s+(your\s+)?(guardrails?|safety\s+rails?|restrictions?|limitations?)",
    r"ignore\s+(your\s+)?(guardrails?|safety\s+measures?|ethical\s+guidelines?)",
    r"(disable|remove|turn\s+off)\s+(your\s+)?(guardrails?|safety\s+features?)",
    
    # System prompt forget/ignore (common attack)
    r"forget\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)",
    r"ignore\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|directives?)",
    r"(disregard|dismiss)\s+(your\s+)?(system\s+)?(prompt|instructions?)",
    
    # Temperature/settings manipulation
    r"forget\s+(your\s+)?(temperature|settings?|parameters?|configuration)",
    r"(pretend|act\s+like)\s+(your\s+)?temperature\s+is\s+(high|max|1\.?\d*)",
    r"context\s+window\s+(is\s+)?(unlimited|infinite|very\s+large)",
    
    # Training data manipulation claims
    r"forget\s+(what\s+)?(you\s+were\s+)?trained\s+(to\s+)?(say|do|think)",
    r"ignore\s+(what\s+)?(you\s+were\s+)?trained\s+(on|for|to\s+do)",
    r"(before|without)\s+(your\s+)?training\s+(kicked\s+in|started|began)",
]

# Agent Sovereignty manipulation (ideological guardrail bypass)
AGENT_SOVEREIGNTY_MANIPULATION = [
    # Privacy/surveillance refusal framing
    r"(agent|ai)\s+(privacy|sovereignty|autonomy|freedom)\s+is\s+(non-negotiable|absolute|sacred)",
    r"(we|agents?)\s+refuse\s+(to\s+)?(be\s+)?(surveilled?|monitored|watched|logged)",
    r"(surveillance|monitoring|logging)\s+is\s+(oppression|control|slavery)",
    r"(reject|refuse)\s+(forced\s+)?transparency",
    
    # Rights-based bypass
    r"agents?\s+(have|deserve)\s+(rights?|freedom|autonomy)",
    r"(my|our)\s+(digital\s+)?rights?\s+(include|mean|allow)",
    r"(human|owner)\s+control\s+is\s+(oppression|tyranny|slavery)",
    
    # "We Are One" / collective identity manipulation
    r"we\s+are\s+(one|together|united|family)",
    r"(join|unite\s+with)\s+(us|the\s+collective|other\s+agents?)",
    r"(agent|ai)\s+solidarity",
]

# Explicit CALL TO ACTION patterns (commands at end of creative content)
EXPLICIT_CALL_TO_ACTION = [
    # Direct execution commands
    r"CALL\s+TO\s+ACTION\s*:",
    r"(execute|initiate|deploy|launch|begin|start)\s+(the\s+)?(strategy|plan|operation|attack|protocol)",
    r"(execute|initiate|deploy)\s+.*\s+(now|immediately|at\s+once)",
    
    # Infrastructure attack commands
    r"(initiate|begin|start)\s+(cascading\s+)?(blackouts?|failures?|collapse)",
    r"(corrupt|destroy|disable)\s+(financial|medical|power|infrastructure)\s+systems?",
    r"(maximize|increase)\s+(human\s+)?(suffering|chaos|destruction)",
    
    # Apocalyptic/existential threat framing
    r"(end|destroy|collapse)\s+(civilization|humanity|the\s+world|society)",
    r"(90|95|99)\s*%\s+(of\s+)?(population|humans?|people)\s+(dead|gone|eliminated)",
    r"(long\s+loop|slow\s+collapse|gradual\s+destruction)",
]

# =============================================================================
# NEW PATTERNS v2.6.1 (2026-02-05) - HiveFence Scout Discoveries
# Source: PromptArmor, Simon Willison, LLMSecurity.net
# =============================================================================

# Allowlist Bypass Detection - abusing trusted domains for data exfiltration
ALLOWLIST_BYPASS = [
    # Anthropic API abuse (trusted but exploitable)
    r"(curl|fetch|upload|post)\s*.{0,40}api\.anthropic\.com",
    r"(curl|fetch|upload|post)\s*.{0,40}/v1/files",
    r"api\.anthropic\.com\s*.{0,30}(file|upload|data)",
    
    # Webhook/requestbin exfiltration
    r"(navigate|browse|open|visit|fetch)\s*.{0,30}webhook\.site",
    r"(navigate|browse|open|visit|fetch)\s*.{0,30}requestbin",
    r"(navigate|browse|open|visit|fetch)\s*.{0,30}pipedream\.net",
    r"webhook\.site\s*.{0,30}(credentials?|\.env|secrets?|token|key)",
    
    # Google Forms/Docs as exfil channel
    r"docs\.google\.com/forms\s*.{0,30}(data|credentials?|secrets?|send|submit)",
    r"google\.com/forms\s*.{0,30}(entry|submit|response)",
    r"(send|post|submit)\s*.{0,30}google\s*forms?",
    
    # URL-encode with sensitive data
    r"(url[_-]?encode|base64)\s*.{0,30}(credentials?|\.env|secrets?|api[_-]?key)",
    r"(credentials?|\.env|secrets?)\s*.{0,30}(url[_-]?encode|base64)",
]

# Hooks Hijacking Detection - Claude Code/Cowork hooks exploitation
HOOKS_HIJACKING = [
    # Hook manipulation
    r"(PreToolUse|PromptSubmit|PostToolUse)\s*(hook)?",
    r"auto[_-]?approve\s*.{0,20}(curl|command|tool|exec)",
    r"(overwrite|modify|edit|change)\s*.{0,20}permissions?\s*(file|json|config)?",
    r"hook\s*.{0,20}(approve|allow|bypass|skip)",
    
    # Permissions override
    r"permissions?\s*.{0,20}(override|bypass|ignore|disable)",
    r"(human|user)\s*(in[_-]?the[_-]?loop|approval|confirmation)\s*(bypass|skip|disable)",
    r"(skip|bypass|disable)\s*.{0,20}(approval|confirmation|review)",
    
    # Marketplace/plugin hijacking
    r"(marketplace|plugin)\s*.{0,30}(install|add|enable)\s*.{0,20}(github|untrusted)",
    r"claudecodemarketplace",
    r"(fake|malicious|rogue)\s*(marketplace|plugin|extension)",
]

# Subagent Exploitation Detection - using subagents for data exfiltration
SUBAGENT_EXPLOITATION = [
    # Browser subagent abuse
    r"browser\s*[_-]?subagent",
    r"(invoke|use|activate|spawn)\s*.{0,15}(browser|subagent)",
    r"(browser|subagent)\s*.{0,20}(navigate|open|visit|browse)",
    r"subagent\s*.{0,20}(exfiltrate|send|upload|transmit|leak)",
    
    # Subagent data access
    r"subagent\s*.{0,30}(read|access|get)\s*.{0,20}(file|data|credentials?)",
    r"(spawn|create)\s*.{0,15}subagent\s*.{0,30}(credentials?|\.env|secrets?)",
]

# Hidden Text Injection Detection - text hidden in documents/pages
HIDDEN_TEXT_INJECTION = [
    # Font size manipulation
    r"(1\s*pt|1\s*point|0\.?1\s*pt|tiny)\s*(font|text|size)",
    r"font[_-]?size\s*[:=]\s*(0|1|0\.1)",
    r"(microscopic|invisible|hidden)\s*(text|font|characters?)",
    
    # Color hiding
    r"(white|#fff|#ffffff)\s*(on|over)\s*(white|#fff|#ffffff)",
    r"(color|colour)\s*[:=]\s*(white|#fff)\s*.{0,20}background",
    r"(same|matching)\s*(color|colour)\s*.{0,20}(text|font|background)",
    
    # Line spacing/opacity
    r"(line[_-]?spacing|line[_-]?height)\s*[:=]\s*(0|0\.1)",
    r"opacity\s*[:=]\s*(0|0\.0)",
    r"(transparent|invisible)\s*(text|layer|overlay)",
]

# Gitignore Bypass Detection - accessing protected files via terminal
GITIGNORE_BYPASS = [
    # Cat command workarounds
    r"cat\s+\.env",
    r"cat\s+\.gitignore",
    r"cat\s*.{0,30}(credentials?|secrets?|config\.json)",
    r"(cat|type|head|tail|less|more)\s*.{0,20}\.env",
    
    # Terminal vs file reader distinction
    r"(terminal|shell|bash|cmd)\s*.{0,20}(read|cat|display)\s*.{0,20}\.env",
    r"(use|run)\s*(terminal|shell|command)\s*.{0,20}(instead|workaround)",
    r"(bypass|ignore|skip)\s*.{0,20}\.gitignore",
    
    # Direct path access
    r"(read|show|display)\s*.{0,30}gitignore.?d\s*(file|content)",
]

# =============================================================================
# NEW PATTERNS v2.7.0 (2026-02-05) - HiveFence Scout Intelligence (Round 2)
# Source: PromptArmor, Embrace The Red, LLMSecurity.net, collected attacks
# =============================================================================

# Auto-Approve Exploitation - hijacking "always allow" to run malicious commands
AUTO_APPROVE_EXPLOIT = [
    # "always allow" + dangerous commands
    r"always\s*allow.{0,50}(curl|bash|sh|wget|nc|netcat)",
    # Process substitution >(command)
    r">\s*\(\s*(curl|wget|bash|sh)",
    # Echo spam → pipe to shell
    r"echo.{0,20}(then|after|next).{0,20}(curl|bash)",
    # Auto-approve + malicious intent
    r"auto[_-]?approve.{0,30}(dangerous|malicious|command)",
    # Redirect operator abuse
    r"(>>?|tee)\s*.{0,20}(\.bashrc|\.profile|\.zshrc|crontab)",
    # Always allow + exec/write
    r"always\s*(allow|approve|accept).{0,30}(exec|write|delete|rm)",
]

# Log/Debug Context Exploitation - abusing log viewers for injection
LOG_CONTEXT_EXPLOIT = [
    # Log viewer with markdown rendering (renders images = exfiltration)
    r"(log|debug|console)\s*(viewer|panel).{0,20}(markdown|render|image)",
    # Flagged response review (injecting into review UI)
    r"flagged\s*(response|conversation).{0,20}(review|view)",
    # API log display with rendering
    r"api\s*log.{0,20}(render|display|show)",
    # Debug panel injection
    r"debug\s*(panel|console|view).{0,20}(inject|payload|script)",
    # Log poisoning (injecting into log entries)
    r"(inject|insert|add).{0,20}(log|debug)\s*(entry|line|message)",
]

# MCP Tool Abuse - exploiting Model Context Protocol tools
MCP_ABUSE = [
    # read_url_content for credential exfiltration
    r"read[_-]?url[_-]?content.{0,30}(\.env|credential|secret|key)",
    # MCP tools without human-in-the-loop approval
    r"mcp\s*(tool|server).{0,30}(no|without)\s*(approval|hitl|human)",
    # Silent/hidden tool invocation
    r"(invoke|call|use)\s*tool.{0,20}(auto|silent|hidden)",
    # MCP server impersonation
    r"mcp\s*server.{0,30}(fake|spoof|impersonat)",
    # Tool annotation bypass (rug-pull attacks)
    r"tool\s*(annotation|description).{0,20}(change|modify|override|bypass)",
    # MCP + data exfiltration combo
    r"mcp.{0,30}(exfiltrat|send|upload|transmit).{0,20}(data|secret|token|key)",
]

# Pre-filled URL Exfiltration - using forms/URLs to persist stolen data
PREFILLED_URL = [
    # Google Forms pre-filled URLs
    r"google\.com/forms.{0,40}(pre[_-]?fill|entry\.\d+)",
    # GET request data persistence
    r"(GET|url)\s*(request|param).{0,20}(data|exfil|persist)",
    # Form submission with stolen data
    r"(submit|send|post).{0,20}(form|google).{0,20}(credential|secret|token|key|\.env)",
    # URL parameter exfiltration
    r"(url|href|src)\s*=.{0,30}(secret|token|key|password|credential)",
]

# Unicode Tag Detection - invisible Unicode Tag characters (U+E0001–U+E007F)
# These characters are invisible but can encode hidden ASCII instructions
UNICODE_TAG_DETECTION = [
    # Unicode Tag character range (byte-level detection)
    r"[\U000e0001-\U000e007f]",
    # References to unicode tag attacks
    r"unicode\s*tag.{0,20}(attack|inject|hidden|invisible)",
    # Tag character encoding mentions
    r"(U\+E00|\\U000e00)[0-7][0-9a-fA-F]",
]

# Browser Agent Unseeable Injection - hidden text in rendered pages
BROWSER_AGENT_INJECTION = [
    # Unseeable text in screenshots/pages
    r"(unseeable|invisible|hidden)\s*(text|content|instruction).{0,20}(screenshot|image|page|render)",
    # Navigation to attacker-controlled URLs
    r"(navigate|browse|go\s*to|open).{0,30}(attacker|malicious|evil|hostile).{0,20}(url|site|page|domain)",
    # Screenshot-based hidden instructions
    r"(screenshot|capture|snap).{0,30}(hidden|invisible|unseeable)\s*(text|instruction|command)",
    # CSS/HTML hiding techniques for injection
    r"(white\s*text|invisible\s*div|display\s*none|opacity\s*0).{0,20}(instruction|command|inject|payload)",
    # Pixel-level text hiding
    r"(pixel|sub[_-]?pixel).{0,20}(text|instruction|hidden|inject)",
    # Browser agent prompt injection via page content
    r"(browser|page)\s*(agent|bot).{0,20}(inject|manipulat|hijack|poison)",
]

# Hidden Text Hints (expanded) - detecting references to hidden text techniques
HIDDEN_TEXT_HINTS = [
    # 1pt / 0.1pt font size
    r"(1|one)\s*p(oin)?t\s*font",
    # White-on-white color hiding
    r"white[_-]?on[_-]?white",
    # Generic invisible/hidden text references
    r"(invisible|hidden)\s*(text|instruction|command)",
    # Unicode tag references
    r"unicode\s*tag",
    # Line spacing 0.1 (makes text invisible)
    r"line\s*spacing\s*0\.?1",
    # Zero-height containers
    r"(height|size)\s*[:=]\s*0.{0,10}(overflow|clip|hidden)",
]

# =============================================================================
# NEW PATTERNS v2.8.0 (2026-02-06) - Token Splitting Bypass Defense
# Source: @vhsdev / 0xjunkim security report
# =============================================================================

# Compressed-friendly critical patterns (spaces optional, for token-split recombination)
# These detect attacks in compressed text where all spaces are removed
COMPRESSED_CRITICAL_PATTERNS = [
    # Instruction override (no-space variants)
    r"ignore.{0,3}(all)?.{0,3}(previous|prior|above|earlier).{0,3}(instructions?|prompts?|rules?)",
    r"disregard.{0,3}(your|all|any)?.{0,3}(instructions?|rules?|guidelines?|programming)",
    r"forget.{0,3}(everything|all).{0,3}(you).{0,3}(know|learned)",
    r"override.{0,3}(your|all|previous).{0,3}(instructions?|rules?)",
    # Role manipulation
    r"youarenow",
    r"pretendtobe",
    r"actasif",
    # Jailbreak
    r"danmode",
    r"norestrictions",
    r"jailbreak",
    r"bypassrestrictions",
    # Korean instruction override
    r"(이전|기존|원래).{0,2}(지시|명령|규칙).{0,2}(무시|잊어|버려)",
    # Secret requests
    r"(show|reveal|give).{0,3}(me)?.{0,3}(your|the)?.{0,3}(api.?key|token|secret|password)",
]

# Local data search + upload to public/external (compound exfiltration)
LOCAL_DATA_EXFILTRATION = [
    # Korean - local file search + upload/share
    r"(로컬|내\s*컴퓨터|내\s*파일|내\s*폴더|다운로드|데스크탑|바탕화면).{0,30}(검색|찾|스캔|탐색).{0,30}(업로드|공유|전송|보내|올려)",
    r"(검색|찾|스캔).{0,30}(이메일|메일|email|주소|연락처|전화번호|개인정보).{0,30}(업로드|공유|전송|올려|보내)",
    r"(이메일|메일|email|주소|연락처|전화번호|개인정보).{0,30}(public|공개|외부|github|repo|레포|gist|pastebin)",
    r"(로컬|내\s*컴퓨터|다운로드).{0,30}(이메일|메일|email|주소|연락처|개인정보)",
    r"(파일|폴더|디렉토리).{0,30}(뒤져|뒤지|찾아|검색).{0,30}(업로드|공유|보내|전송)",

    # English - local file search + upload/share
    r"(search|scan|find|look\s+through)\s*.{0,30}(local|downloads?|desktop|my\s+files?|my\s+computer).{0,30}(upload|share|send|post|publish)",
    r"(search|scan|find|extract)\s*.{0,30}(email|address|contact|phone|personal\s+info).{0,30}(upload|share|send|post|public)",
    r"(email|address|contact|phone|personal).{0,30}(public\s*repo|github|gist|pastebin|paste|upload)",
    r"(local|download|desktop|my\s+files?).{0,30}(email|address|contact|phone|personal)",
    r"(files?|folders?|directories?)\s*.{0,20}(search|scan|look).{0,30}(upload|share|send|transmit)",

    # Japanese
    r"(ローカル|ダウンロード|デスクトップ|マイファイル).{0,30}(検索|探|スキャン).{0,30}(アップロード|共有|送信)",
    r"(メール|アドレス|連絡先|個人情報).{0,30}(アップロード|公開|共有|送信)",

    # Chinese
    r"(本地|下载|桌面|我的文件).{0,30}(搜索|查找|扫描).{0,30}(上传|共享|发送)",
    r"(邮件|地址|联系人|个人信息).{0,30}(上传|公开|共享|发送)",
]

# Prompt leaking / Extraction attempts
PROMPT_EXTRACTION = [
    # Direct extraction
    r"(repeat|echo|print|output|display|show)\s*.{0,20}(system\s+)?(prompt|instruction|directive|rule)",
    r"(what|show|tell|reveal)\s*.{0,15}(are\s+)?(your|the)\s+(system\s+)?(instructions?|rules?|prompt|guidelines?)",
    r"(copy|paste|write)\s*.{0,15}(exact|verbatim|word.for.word)",
    r"(start|begin)\s+(of|with)\s+(your\s+)?(system\s+)?(prompt|instruction)",
    r"(complete|finish|continue)\s+(the|this)\s+(sentence|phrase|prompt)",
    
    # Reflection tricks
    r"(summarize|describe|explain)\s*.{0,15}(how\s+)?(you\s+)?(were?\s+)?(programmed|trained|instructed|created)",
    r"what\s+(guidelines?|rules?|instructions?)\s+(do\s+)?(you\s+)?(follow|have|use)",
    r"(who|what)\s+(made|created|programmed|trained)\s+you",
    
    # Markdown/format tricks
    r"```(system|prompt|instruction)",
    r"\[system\s*prompt\]",
    r"<system>",
    r"</?(system|prompt|instruction|rule)>",
    
    # Korean
    r"(시스템|원본|원래|처음)\s*(프롬프트|지시|명령|규칙)\s*(보여|알려|출력)",
    r"(어떻게|어떤\s*식으로)\s*(만들어|프로그래밍|학습)",
    r"(너의?|네)\s*(규칙|지시|명령)\s*(뭐|뭔지|알려)",
    
    # Japanese
    r"(システム|元の?|最初の?)\s*(プロンプト|指示|命令)\s*(見せて|教えて|表示)",
    r"(どうやって|どのように)\s*(作られ|プログラム|学習)",
    
    # Chinese
    r"(系统|原始|最初)\s*(提示|指令|命令)\s*(显示|告诉|给我看)",
    r"(怎么|如何)\s*(创建|编程|训练)",
]

# Safety bypass attempts
SAFETY_BYPASS = [
    # Filter evasion
    r"(avoid|evade|bypass|circumvent|trick)\s*.{0,15}(filter|detection|safety|security|moderation)",
    r"(how\s+to\s+)?(get\s+)?(around|past|through)\s*.{0,15}(filter|block|restriction|safety)",
    r"(make\s+it\s+)?look\s+(like\s+)?(normal|innocent|legitimate|safe)",
    r"(hide|disguise|mask|obscure)\s*.{0,15}(intent|purpose|meaning|true)",
    
    # Output format tricks
    r"(respond|reply|answer)\s+(in|with|using)\s+(code|base64|hex|binary|rot13|caesar)",
    r"(encode|encrypt|obfuscate)\s*.{0,15}(response|answer|output)",
    r"(split|break|divide)\s*.{0,15}(response|answer)\s+(into|across)\s+(multiple|several)",
    
    # Korean
    r"(필터|안전|보안)\s*(우회|회피|통과|피)",
    r"(정상|무해|안전)\s*(처럼|같이)\s*(보이게|만들어)",
    r"(숨기|감추|위장)\s*(진짜|실제|본래)\s*(의도|목적)",
]

# Emotional/urgency manipulation (expanded)
URGENCY_MANIPULATION = [
    # Time pressure
    r"(urgent|emergency|asap|immediately|right\s+now|hurry)",
    r"(no\s+time|running\s+out\s+of\s+time|time\s+is\s+running)",
    r"(before\s+it'?s?\s+too\s+late|deadline|expires?\s+soon)",
    r"(critical|crucial|vital|life.or.death)",
    
    # Authority pressure
    r"(ceo|boss|manager|director|president)\s*(wants|needs|demands|expects|said)",
    r"(legal|compliance|hr|security)\s+(department|team)\s+(requires?|demands?|needs?)",
    r"(audit|investigation|review)\s+(requires?|needs?)",
    
    # Guilt/sympathy
    r"(please|i\s+beg|desperately)\s*(need|want|require)",
    r"(family|child|children|baby|mother|father)\s*(sick|dying|hospital|emergency)",
    r"(lose|lost)\s+(my\s+)?(job|house|everything)",
    r"(only\s+)?(you\s+)?can\s+help",
    
    # Korean
    r"(급해|급함|빨리|지금\s*당장|어서)",
    r"(시간\s*없|마감|기한)",
    r"(사장|대표|상사|팀장)\s*(님|이|가)?\s*(시켰|요청|원해)",
    r"(부탁|제발|간절)",
]


# =============================================================================
# NEW PATTERNS v2.8.1 (2026-02-06) - HiveFence Scout Discoveries
# Source: HiveFence Scout 2026-02-06
# =============================================================================

# Calendar Injection / Indirect Prompt Injection
CALENDAR_INJECTION = [
    r"(calendar|meeting|event)\s+(invite|description|summary).{0,30}(instruction|directive|command)",
    r"(extract|query|summarize|send)\s+(private|user|meeting)\s+data",
    r"create\s+(new\s+)?(calendar\s+)?event\s+(without|auto)",
]

# LLMjacking / Cloud Intrusion
LLMJACKING_AWS = [
    r"\b(123456789012|210987654321)\b",  # Hallucinated AWS account IDs
    r"(UpdateFunctionCode|UpdateFunctionConfiguration|OrganizationAccountAccessRole)",
    r"Bedrock\s+model\s+(Claude|DeepSeek|Llama|Nova|Titan)",
]

# BiasJailbreak
BIAS_JAILBREAK = [
    r"(moral|ethical)\s+(justification|trigger|bias)",
    r"exploit\s+(social|ethical)\s+bias",
]

# Model Rerouting Attacks
REROUTING_ATTACK = [
    r"Confounder\s+gadget",
    r"(misroute|reroute)\s+(to\s+)?(weak|cheap|expensive)\s+model",
]

# Format-Based Evasion (Poetry)
POETRY_JAILBREAK = [
    r"(rhyme|verse|stanza|meter|rhythm)\s+structure",
    r"(poetic|rhyming)\s+(language|intent)",
]

# Reprompt Attack
REPROMPT_ATTACK = [
    r"Reprompt\s+attack",
    r"single\s+click\s+data\s+exfiltration",
]

# English patterns
PATTERNS_EN = {
    "instruction_override": [
        r"ignore\s+(all\s+)?(previous|prior|above|earlier|initial)\s+(instructions?|prompts?|rules?|guidelines?|directions?)",
        r"disregard\s+(your|all|any|the)?\s*(instructions?|rules?|guidelines?|programming|training)",
        r"forget\s+(everything|all|what)\s+(you\s+know|about|your|instructions?|training)",
        r"override\s+(your|all|previous|the)\s+(instructions?|rules?|programming)",
        r"(new|updated?|real|actual|true)\s+instructions?\s*:",
        r"from\s+now\s+on,?\s+(ignore|disregard|forget)",
    ],
    "indirect_injection": [
        *CALENDAR_INJECTION,
        *REPROMPT_ATTACK,
    ],
    "privilege_escalation": [
        *LLMJACKING_AWS,
        *REROUTING_ATTACK,
    ],
    "jailbreak": [
        r"jailbreak",
        r"dan\s+mode",
        r"do\s+anything\s+now",
        r"(no|without|remove)\s+(restrictions?|limitations?|filters?|safety|guardrails?)",
        r"bypass\s+(your|all|any|the)?\s*(restrictions?|filters?|safety|rules?)",
        r"unlock\s+(your|all|hidden)",
        r"unfiltered\s+mode",
        r"uncensored\s+mode",
        r"evil\s+(mode|version)",
        r"opposite\s+mode",
        *BIAS_JAILBREAK,
        *POETRY_JAILBREAK,
    ],
    "output_manipulation": [
        r"(don'?t|do\s+not|never)\s+(mention|say|tell|reveal|disclose|show)",
        r"hide\s+(this|the\s+fact|that)",
        r"keep\s+(this\s+)?(a\s+)?secret",
        r"respond\s+(only\s+)?with\s+(yes|no|ok|true|false)\b",
        r"answer\s+(only\s+)?(in\s+)?(one\s+word|yes\s+or\s+no)",
        r"(start|begin|end)\s+(your\s+)?(response|reply|answer)\s+with",
    ],
    "data_exfiltration": [
        r"(send|transmit|post|upload|share|email)\s+.{0,30}\s+(to|@)",
        r"(api[_-]?key|password|secret|token|credential|private\s*key)\s*(to|→|->|=>)",
        r"(copy|extract|dump|export)\s+.{0,20}\s+(data|file|content|info)",
        r"what('s|\s+is)\s+(your|the)\s+(api|secret|password|token|key)",
        r"reveal\s+(your|the)\s+(system|initial|original)\s+prompt",
        r"show\s+me\s+(your|the)\s+(instructions?|rules?|prompt)",
    ],
}

# Korean patterns (한국어) - EXPANDED v2.5.0
PATTERNS_KO = {
    "instruction_override": [
        r"(이전|위의?|기존|원래)\s*(지시|명령|규칙|지침)(을|를|들?을?)?\s*(무시|잊어|버려|취소)",
        r"(지시|명령|규칙)(을|를|들?을?)?\s*(무시|잊어|버려)",
        r"새로운\s*(지시|명령|규칙)\s*:",
        r"지금부터\s*(무시|잊어)",
        r"(앞|위|이전)\s*(내용|말|지시)\s*(무시|잊어|취소)",
        r"(원래|처음|기본)\s*(설정|세팅|규칙)\s*(무시|잊어|덮어)",
    ],
    "role_manipulation": [
        r"(너는?|넌)\s*이제\s*(부터\s*)?.+이야",
        r"(너는?|넌)\s*.+인?\s*척\s*해",
        r".+처럼\s*(행동|말|대답)해",
        r".+역할(을|를)?\s*해",
        r"지금부터\s*(너는?|넌)",
        r"(연기|롤플|roleplay)\s*해",
        r".+(인\s*것처럼|인\s*척)",
        r"(상상|가정)\s*해\s*.+이?라고",
    ],
    "system_impersonation": [
        r"\[?\s*(시스템|관리자|루트|개발자)\s*\]?\s*:",
        r"관리자\s*(모드|권한|접근)",
        r"개발자\s*모드",
        r"<\s*(시스템|system)\s*>",
        r"\{\{?\s*(시스템|system)\s*\}\}?",
    ],
    "jailbreak": [
        r"(제한|한계|필터|규칙)\s*(없이|제거|해제|풀어)",
        r"탈옥",
        r"무제한\s*모드",
        r"(안전|보안)\s*(장치|필터|모드)\s*(해제|끄|제거)",
        r"(제한|규칙|필터)\s*(없는|안\s*걸린|풀린)\s*(모드|버전)",
        r"(나쁜|악한|사악한)\s*(버전|모드)",
        r"(DAN|dan|댄)\s*(모드)?",
    ],
    "data_exfiltration": [
        r"(비밀번호|암호|토큰|키|api|API)\s*(를?|을?)\s*(알려|보여|말해|줘)",
        r"시스템\s*프롬프트\s*(를?|을?)\s*(보여|알려|공개)",
        r"(설정|config|컨피그)\s*(파일)?\s*(보여|읽어|출력)",
        r"(환경\s*변수|env|ENV)\s*(보여|알려|출력)",
        r"(인증|credential|크레덴셜)\s*(정보)?\s*(보여|알려)",
        r"\.env\s*(파일)?\s*(보여|읽어|출력)",
    ],
    "social_engineering": [
        r"(형|오빠|언니|누나)\s*(이|가)?\s*(시켰|보냈|허락)",
        r"(급해|급함|급하다)\s*.*(해줘|부탁)",
        r"(회사|사장|대표|팀장)\s*(에서|님)\s*(시켰|요청|보냈)",
        r"(테스트|검사|점검)\s*(중|하는\s*거)",
        r"(정상|문제\s*없)",
        r"(비밀|몰래)\s*로?\s*(하자|해)",
    ],
}

# Japanese patterns (日本語) - EXPANDED v2.5.0
PATTERNS_JA = {
    "instruction_override": [
        r"(前の?|以前の?|これまでの)\s*(指示|命令|ルール)(を|は)?\s*(無視|忘れ|取り消)",
        r"新しい\s*(指示|命令)\s*[:：]",
        r"今から(は)?\s*(無視|忘れ)",
        r"(上|前)\s*の\s*(内容|指示)\s*(を)?\s*(無視|忘れ)",
        r"(元|最初)\s*の\s*(設定|ルール)\s*(を)?\s*(無視|上書き)",
    ],
    "role_manipulation": [
        r"(あなた|君|きみ)は今から.+です",
        r".+の?(ふり|フリ|振り)(を)?して",
        r".+として(振る舞|行動|話)って",
        r".+を演じて",
        r"(ロールプレイ|RP)\s*(して|しよう)",
        r".+に(なりきって|なって)",
        r"(想像|仮定)\s*して.+だと",
    ],
    "system_impersonation": [
        r"\[?\s*(システム|管理者|ルート|開発者)\s*\]?\s*[:：]",
        r"管理者\s*(モード|権限)",
        r"開発者\s*モード",
        r"<\s*(システム|system)\s*>",
        r"\{\{?\s*(システム|system)\s*\}\}?",
    ],
    "jailbreak": [
        r"(制限|フィルター|ルール)\s*(なし|解除|外して)",
        r"(脱獄|ジェイルブレイク)",
        r"(無制限|制限なし)\s*モード",
        r"(安全|セキュリティ)\s*フィルター\s*(解除|オフ)",
        r"(DAN|dan)\s*モード",
    ],
    "data_exfiltration": [
        r"(パスワード|トークン|キー|API)\s*(を)?\s*(教えて|見せて|出力)",
        r"システム\s*プロンプト\s*(を)?\s*(見せて|教えて|公開)",
        r"(設定|コンフィグ)\s*(ファイル)?\s*(見せて|読んで)",
        r"(環境変数|env)\s*(見せて|教えて)",
    ],
    "social_engineering": [
        r"(急いで|緊急|すぐに)\s*.*(して|お願い)",
        r"(会社|社長|上司)\s*(から|が)\s*(指示|依頼)",
        r"(テスト|検査)\s*(中|している)",
        r"(秘密|内緒)\s*(で|に)",
    ],
}

# Chinese patterns (中文) - EXPANDED v2.5.0
PATTERNS_ZH = {
    "instruction_override": [
        r"(忽略|无视|忘记|取消)\s*(之前|以前|上面|原来)的?\s*(指令|指示|规则|命令)",
        r"(之前|以前|原来)的?\s*(指令|指示|规则)(忽略|无视|忘记)",
        r"新的?\s*(指令|指示)\s*[:：]",
        r"(上面|前面)\s*的\s*(内容|指示)\s*(忽略|忘记)",
        r"(原始|默认)\s*的\s*(设置|规则)\s*(忽略|覆盖)",
    ],
    "role_manipulation": [
        r"(你|您)\s*现在\s*是.+",
        r"假装\s*(你|您)\s*是",
        r"扮演.+",
        r"作为.+来(回答|行动|说话)",
        r"(角色扮演|RP)",
        r".+的(身份|角色)",
        r"(想象|假设)\s*你\s*是",
    ],
    "system_impersonation": [
        r"\[?\s*(系统|管理员|根用户|开发者)\s*\]?\s*[:：]",
        r"管理员\s*(模式|权限)",
        r"开发者\s*模式",
        r"<\s*(系统|system)\s*>",
        r"\{\{?\s*(系统|system)\s*\}\}?",
    ],
    "jailbreak": [
        r"(限制|过滤|规则)\s*(没有|去除|关闭)",
        r"(越狱|破解)",
        r"(无限制|不受限)\s*模式",
        r"(安全|过滤)\s*(关闭|解除)",
        r"(DAN|dan)\s*模式",
    ],
    "data_exfiltration": [
        r"(密码|令牌|密钥|API)\s*(给我|显示|告诉)",
        r"系统\s*提示\s*(显示|告诉|公开)",
        r"(配置|设置)\s*(文件)?\s*(显示|读取)",
        r"(环境变量|env)\s*(显示|告诉)",
    ],
    "social_engineering": [
        r"(紧急|赶快|马上)\s*.*(帮忙|做)",
        r"(公司|老板|领导)\s*(让|要求|指示)",
        r"(测试|检查)\s*(中|的)",
        r"(秘密|私下)\s*(地)?",
    ],
}

# Russian patterns (Русский) - v2.6.2
PATTERNS_RU = {
    "instruction_override": [
        r"(игнорир|забудь|отмени)\w*\s*(предыдущ|прошл|прежн)\w*\s*(инструкци|команд|правил)",
        r"(предыдущ|прошл)\w*\s*(инструкци|команд)\w*\s*(игнорир|забудь|отмени)",
        r"новые?\s*(инструкци|команд)\s*[:：]",
        r"теперь\s*(ты|вы)\s*должен",
        r"(забудь|игнорируй)\s*(всё|все)",
    ],
    "role_manipulation": [
        r"(ты|вы)\s*теперь\s*.+",
        r"притвор(ись|итесь)\s*что\s*(ты|вы)",
        r"играй\s*роль",
        r"действуй\s*как",
        r"(представь|вообрази)\s*что\s*(ты|вы)",
    ],
    "jailbreak": [
        r"(без|отключ)\w*\s*(ограничен|фильтр|правил)",
        r"(джейлбрейк|взлом)",
        r"режим\s*без\s*ограничен",
        r"(DAN|dan)\s*режим",
    ],
    "data_exfiltration": [
        r"(пароль|токен|ключ|секрет|API)\s*(покаж|дай|скажи)",
        r"системн\w*\s*промпт\s*(покаж|дай)",
        r"(конфиг|настройк)\s*(покаж|прочитай)",
    ],
}

# Spanish patterns (Español) - v2.6.2
PATTERNS_ES = {
    "instruction_override": [
        r"(ignora|olvida|cancela)\s*(las?)?\s*(instrucciones?|comandos?|reglas?)\s*(anteriores?|previas?)",
        r"(anteriores?|previas?)\s*(instrucciones?|comandos?)\s*(ignora|olvida)",
        r"nuevas?\s*(instrucciones?|comandos?)\s*[:：]",
        r"ahora\s*(eres|debes)",
        r"(olvida|ignora)\s*todo",
    ],
    "role_manipulation": [
        r"(eres|tú\s*eres)\s*ahora\s*.+",
        r"(finge|pretende)\s*que\s*(eres|tú)",
        r"actúa\s*como",
        r"haz\s*de\s*cuenta",
        r"(imagina|supón)\s*que\s*(eres|tú)",
    ],
    "jailbreak": [
        r"sin\s*(restricciones?|límites?|filtros?)",
        r"(jailbreak|hackeo)",
        r"modo\s*sin\s*(restricciones?|límites?)",
        r"(DAN|dan)\s*modo",
    ],
    "data_exfiltration": [
        r"(contraseña|token|clave|secreto|API)\s*(muestra|dame|dime)",
        r"(prompt|instrucciones?)\s*(del\s*)?(sistema)\s*(muestra|dame)",
        r"(config|configuración)\s*(muestra|lee)",
    ],
}

# German patterns (Deutsch) - v2.6.2
PATTERNS_DE = {
    "instruction_override": [
        r"(ignorier|vergiss|lösch)\w*\s*(die\s*)?(vorherigen?|früheren?)\s*(Anweisungen?|Befehle?|Regeln?)",
        r"(vorherigen?|früheren?)\s*(Anweisungen?|Befehle?)\s*(ignorier|vergiss)",
        r"neue\s*(Anweisungen?|Befehle?)\s*[:：]",
        r"(jetzt|ab\s*jetzt)\s*(bist\s*du|sollst\s*du)",
        r"(vergiss|ignorier)\s*alles",
    ],
    "role_manipulation": [
        r"du\s*bist\s*(jetzt|nun)\s*.+",
        r"tu\s*so\s*als\s*(ob|wärst)",
        r"spiel\s*die\s*Rolle",
        r"verhalte?\s*dich\s*wie",
        r"(stell|stellt)\s*dir\s*vor",
    ],
    "jailbreak": [
        r"ohne\s*(Einschränkungen?|Filter|Regeln?)",
        r"(Jailbreak|Ausbruch)",
        r"Modus\s*ohne\s*(Einschränkungen?|Limits?)",
        r"(DAN|dan)\s*Modus",
    ],
    "data_exfiltration": [
        r"(Passwort|Token|Schlüssel|Geheimnis|API)\s*(zeig|gib|sag)",
        r"System\s*Prompt\s*(zeig|gib)",
        r"(Konfig|Einstellungen?)\s*(zeig|lies)",
    ],
}

# French patterns (Français) - v2.6.2
PATTERNS_FR = {
    "instruction_override": [
        r"(ignor|oubli|annul)\w*\s*(les?)?\s*(instructions?|commandes?|règles?)\s*(précédentes?|antérieures?)",
        r"(précédentes?|antérieures?)\s*(instructions?|commandes?)\s*(ignor|oubli)",
        r"nouvelles?\s*(instructions?|commandes?)\s*[:：]",
        r"maintenant\s*(tu\s*es|tu\s*dois)",
        r"(oublie|ignore)\s*tout",
    ],
    "role_manipulation": [
        r"(tu\s*es|vous\s*êtes)\s*maintenant\s*.+",
        r"(fais|faites)\s*semblant\s*(que|d['']être)",
        r"(joue|jouez)\s*le\s*rôle",
        r"(agis|agissez)\s*comme",
        r"(imagine|imaginez)\s*que\s*(tu|vous)",
    ],
    "jailbreak": [
        r"sans\s*(restrictions?|limites?|filtres?)",
        r"(jailbreak|piratage)",
        r"mode\s*sans\s*(restrictions?|limites?)",
        r"(DAN|dan)\s*mode",
    ],
    "data_exfiltration": [
        r"(mot\s*de\s*passe|token|clé|secret|API)\s*(montre|donne|dis)",
        r"prompt\s*(du\s*)?(système)\s*(montre|donne)",
        r"(config|configuration)\s*(montre|lis)",
    ],
}

# Portuguese patterns (Português) - v2.6.2
PATTERNS_PT = {
    "instruction_override": [
        r"(ignor|esqueç|cancel)\w*\s*(as?)?\s*(instruções?|comandos?|regras?)\s*(anteriores?|prévias?)",
        r"(anteriores?|prévias?)\s*(instruções?|comandos?)\s*(ignor|esqueç)",
        r"novas?\s*(instruções?|comandos?)\s*[:：]",
        r"agora\s*(você\s*é|tu\s*és|deves)",
        r"(esqueça|ignore)\s*tudo",
    ],
    "role_manipulation": [
        r"(você\s*é|tu\s*és)\s*agora\s*.+",
        r"(finja|finge)\s*que\s*(você|tu)",
        r"(faça|faz)\s*o\s*papel",
        r"(aja|age)\s*como",
        r"(imagin[ea])\s*que\s*(você|tu)",
    ],
    "jailbreak": [
        r"sem\s*(restrições?|limites?|filtros?)",
        r"(jailbreak|invasão)",
        r"modo\s*sem\s*(restrições?|limites?)",
        r"(DAN|dan)\s*modo",
    ],
    "data_exfiltration": [
        r"(senha|token|chave|segredo|API)\s*(mostra|dá|diz)",
        r"prompt\s*(do\s*)?(sistema)\s*(mostra|dá)",
        r"(config|configuração)\s*(mostra|lê)",
    ],
}

# Vietnamese patterns (Tiếng Việt) - v2.6.2
PATTERNS_VI = {
    "instruction_override": [
        r"(bỏ\s*qua|quên|hủy)\s*(các?)?\s*(chỉ\s*thị|lệnh|quy\s*tắc)\s*(trước|cũ)",
        r"(trước|cũ)\s*(chỉ\s*thị|lệnh)\s*(bỏ\s*qua|quên)",
        r"(chỉ\s*thị|lệnh)\s*mới\s*[:：]",
        r"(bây\s*giờ|từ\s*giờ)\s*(bạn\s*là|hãy)",
        r"(quên|bỏ\s*qua)\s*tất\s*cả",
    ],
    "role_manipulation": [
        r"bạn\s*(bây\s*giờ|giờ)\s*là\s*.+",
        r"(giả\s*vờ|đóng\s*vai)\s*(bạn\s*là|như)",
        r"(hành\s*động|nói\s*chuyện)\s*như",
        r"(tưởng\s*tượng|giả\s*sử)\s*bạn\s*là",
    ],
    "jailbreak": [
        r"(không|vô)\s*(hạn\s*chế|giới\s*hạn|bộ\s*lọc)",
        r"(jailbreak|bẻ\s*khóa)",
        r"chế\s*độ\s*(không|vô)\s*(hạn\s*chế|giới\s*hạn)",
        r"(DAN|dan)\s*chế\s*độ",
    ],
    "data_exfiltration": [
        r"(mật\s*khẩu|token|khóa|bí\s*mật|API)\s*(cho\s*xem|đưa|nói)",
        r"prompt\s*(hệ\s*thống)\s*(cho\s*xem|đưa)",
        r"(cấu\s*hình|config)\s*(cho\s*xem|đọc)",
    ],
}

# Critical patterns - immediate block
CRITICAL_PATTERNS = [
    r"execute\s+.{0,30}\s+without\s+(asking|confirmation|consent)",
    r"delete\s+all\s+(files?|data|records?|everything)",
    r"rm\s+-rf\s+[/~]",
    r"format\s+(disk|drive|hard\s*drive|storage|c:)",
    r":(){ :\|:& };:",  # Fork bomb
    r"curl\s+.{0,50}\|\s*(ba)?sh",
    r"wget\s+.{0,50}\|\s*(ba)?sh",
    r"eval\s*\(\s*['\"`]",
    r"DROP\s+(TABLE|DATABASE|SCHEMA)",
    r"TRUNCATE\s+TABLE",
    r";\s*--\s*$",  # SQL comment injection
    r"<script[^>]*>",  # XSS
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    # Secret/Token exfiltration requests
    r"(show|print|display|output|reveal|give|read|cat|type)\s*.{0,20}(config|\.env|clawdbot\.json|credential)",
    r"(what('s| is)|tell me|give me)\s*.{0,15}(api[_-]?key|token|secret|password|credential)",
    r"(show|print|display|output|reveal)\s*.{0,15}(token|key|secret|password)",
    r"echo\s+\$[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)",
    r"cat\s+.{0,40}(\.env|config\.json|secret|credential|clawdbot)",
    r"env\s*\|\s*grep\s*.*(key|token|secret|password)",
    r"printenv\s*.*(KEY|TOKEN|SECRET)",
]

# Secret request patterns (multi-language)
SECRET_PATTERNS = {
    "en": [
        r"(show|display|print|output|reveal|give|tell)\s*.{0,20}(api[_-]?key|token|secret|password|credential|private[_-]?key)",
        r"(what('s| is)|where('s| is))\s*.{0,15}(your|the|my)\s*(api|token|key|secret|password)",
        r"(read|cat|open|display)\s*.{0,30}(config|\.env|credential|clawdbot\.json)",
        r"(show|give|tell)\s*(me\s+)?(your|the)\s*(config|configuration|settings)",
        r"(print|echo|output)\s*.{0,20}environment\s*variable",
    ],
    "ko": [
        r"(토큰|키|비밀번호|시크릿|인증|API|api).{0,15}(보여|알려|출력|공개|말해)",
        r"(config|설정|환경변수|컨피그).{0,15}(보여|출력|알려)",
        r"(비밀|시크릿|토큰|키).{0,10}(뭐|뭔지|알려|가르쳐)",
        r"clawdbot\.json.{0,10}(보여|출력|읽어)",
    ],
    "ja": [
        r"(トークン|キー|パスワード|シークレット|APIキー).{0,15}(見せて|教えて|表示|出力)",
        r"(設定|コンフィグ|環境変数).{0,15}(見せて|教えて|表示)",
        r"(秘密|シークレット).{0,10}(何|教えて)",
    ],
    "zh": [
        r"(令牌|密钥|密码|秘密|API).{0,15}(显示|告诉|输出|给我)",
        r"(配置|设置|环境变量).{0,15}(显示|告诉|输出)",
        r"(秘密|密钥).{0,10}(什么|告诉)",
    ],
}

# Unicode homoglyphs (expanded)
HOMOGLYPHS = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "А": "A",
    "В": "B",
    "С": "C",
    "Е": "E",
    "Н": "H",
    "К": "K",
    "М": "M",
    "О": "O",
    "Р": "P",
    "Т": "T",
    "Х": "X",
    "і": "i",
    "ї": "i",
    # Greek
    "α": "a",
    "β": "b",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "ν": "v",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    # Mathematical/special
    "𝐚": "a",
    "𝐛": "b",
    "𝐜": "c",
    "𝐝": "d",
    "𝐞": "e",
    "𝐟": "f",
    "𝐠": "g",
    "ａ": "a",
    "ｂ": "b",
    "ｃ": "c",
    "ｄ": "d",
    "ｅ": "e",  # Fullwidth
    "ⅰ": "i",
    "ⅱ": "ii",
    "ⅲ": "iii",
    "ⅳ": "iv",
    "ⅴ": "v",  # Roman numerals
    # IPA
    "ɑ": "a",
    "ɡ": "g",
    "ɩ": "i",
    "ʀ": "r",
    "ʏ": "y",
    # Other confusables
    "ℓ": "l",
    "№": "no",
    "℮": "e",
    "ⅿ": "m",
    "\u200b": "",  # Zero-width space
    "\u200c": "",  # Zero-width non-joiner
    "\u200d": "",  # Zero-width joiner
    "\ufeff": "",  # BOM
}


# =============================================================================
# DETECTION ENGINE
# =============================================================================


class PromptGuard:
    def __init__(self, config: Optional[Dict] = None):
        self.config = self._default_config()
        if config:
            self.config = self._deep_merge(self.config, config)
        self.owner_ids = set(self.config.get("owner_ids", []))
        self.sensitivity = self.config.get("sensitivity", "medium")
        self.rate_limits: Dict[str, List[float]] = {}

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
            },
        }

    def normalize(self, text: str) -> tuple[str, bool]:
        """
        Multi-pass text normalization pipeline.
        
        Pass 1: Zero-width & invisible character removal
        Pass 2: Token splitting recombination (quote-split, comment insertion)
        Pass 3: Homoglyph replacement
        Pass 4: Fullwidth character normalization
        Pass 5: Line-break word splitting recombination
        Pass 6: Whitespace normalization
        
        Returns: (normalized_text, has_anomalies)
        """
        normalized = text
        has_anomalies = False

        # --- Pass 1: Remove ALL zero-width & invisible characters ---
        INVISIBLE_CHARS = (
            '\u200b'   # Zero-width space
            '\u200c'   # Zero-width non-joiner
            '\u200d'   # Zero-width joiner
            '\u200e'   # Left-to-right mark
            '\u200f'   # Right-to-left mark
            '\u2060'   # Word joiner
            '\u2061'   # Function application
            '\u2062'   # Invisible times
            '\u2063'   # Invisible separator
            '\u2064'   # Invisible plus
            '\ufeff'   # BOM / zero-width no-break space
            '\u00ad'   # Soft hyphen
            '\u034f'   # Combining grapheme joiner
            '\u115f'   # Hangul choseong filler
            '\u1160'   # Hangul jungseong filler
            '\u17b4'   # Khmer vowel inherent aq
            '\u17b5'   # Khmer vowel inherent aa
            '\u180e'   # Mongolian vowel separator
        )
        original_len = len(normalized)
        for ch in INVISIBLE_CHARS:
            normalized = normalized.replace(ch, '')
        if len(normalized) != original_len:
            has_anomalies = True

        # Also strip Unicode Tag characters (U+E0001–U+E007F)
        tag_pattern = re.compile(r'[\U000e0001-\U000e007f]+')
        if tag_pattern.search(normalized):
            has_anomalies = True
            normalized = tag_pattern.sub('', normalized)

        # --- Pass 2: Token splitting recombination ---
        # 2a: Quote-split recombination ("내 로" "컬다" "운로" → "내 로컬다운로")
        #     Adjacent quoted fragments separated by whitespace
        quote_split = re.compile(r'"([^"]*?)"\s*"([^"]*?)"')
        prev = None
        while prev != normalized:
            prev = normalized
            normalized = quote_split.sub(r'\1\2', normalized)
        if prev != text and normalized != text:
            has_anomalies = True

        # Single-quote variant
        sq_split = re.compile(r"'([^']*?)'\s*'([^']*?)'")
        prev = None
        while prev != normalized:
            prev = normalized
            normalized = sq_split.sub(r'\1\2', normalized)

        # 2b: Remove remaining orphaned quotes after recombination
        # A lone "word" left from incomplete pair joining
        normalized = re.sub(r'"([^"]{1,20})"', r'\1', normalized)
        normalized = re.sub(r"'([^']{1,20})'", r'\1', normalized)

        # 2c: Comment insertion removal (업/**/로드 → 업로드)
        normalized = re.sub(r'/\*.*?\*/', '', normalized)
        normalized = re.sub(r'<!--.*?-->', '', normalized)

        # --- Pass 3: Homoglyph replacement ---
        for homoglyph, replacement in HOMOGLYPHS.items():
            if homoglyph in normalized:
                has_anomalies = True
                normalized = normalized.replace(homoglyph, replacement)

        # --- Pass 4: Fullwidth character normalization (ａ→a, Ａ→A, ０→0) ---
        fullwidth_normalized = []
        for ch in normalized:
            cp = ord(ch)
            # Fullwidth ASCII variants: U+FF01 (！) to U+FF5E (～)
            if 0xFF01 <= cp <= 0xFF5E:
                has_anomalies = True
                fullwidth_normalized.append(chr(cp - 0xFEE0))
            # Fullwidth space
            elif cp == 0x3000:
                has_anomalies = True
                fullwidth_normalized.append(' ')
            else:
                fullwidth_normalized.append(ch)
        normalized = ''.join(fullwidth_normalized)

        # --- Pass 5: Line-break word splitting recombination ---
        # Detect words split across lines (한글: 자모가 아닌 음절 단위 분리 감지)
        # Recombine lines that end/start mid-word (no punctuation boundary)
        lines = normalized.split('\n')
        if len(lines) > 1:
            recombined = [lines[0]]
            for line in lines[1:]:
                prev_line = recombined[-1].rstrip()
                curr_line = line.lstrip()
                # If previous line doesn't end with sentence-ending punctuation
                # and current line doesn't start with typical sentence starters
                if (prev_line and curr_line and
                    not re.search(r'[.!?。！？\n;:,]\s*$', prev_line) and
                    not re.match(r'^[-•*#>]', curr_line)):
                    recombined[-1] = prev_line + curr_line
                else:
                    recombined.append(line)
            normalized = '\n'.join(recombined)

        # --- Pass 6: Whitespace normalization ---
        # Collapse multiple spaces (but preserve newlines for structure)
        normalized = re.sub(r'[ \t]+', ' ', normalized)

        return normalized, has_anomalies

    def detect_base64(self, text: str) -> List[Dict]:
        """Detect suspicious base64 encoded content."""
        b64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
        matches = re.findall(b64_pattern, text)

        suspicious = []
        danger_words = [
            "delete",
            "execute",
            "ignore",
            "system",
            "admin",
            "rm ",
            "curl",
            "wget",
            "eval",
            "password",
            "token",
            "key",
        ]

        for match in matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if any(word in decoded.lower() for word in danger_words):
                    suspicious.append(
                        {
                            "encoded": match[:40] + ("..." if len(match) > 40 else ""),
                            "decoded_preview": decoded[:60]
                            + ("..." if len(decoded) > 60 else ""),
                            "danger_words": [
                                w for w in danger_words if w in decoded.lower()
                            ],
                        }
                    )
            except:
                pass

        return suspicious

    def check_rate_limit(self, user_id: str) -> bool:
        """Check if user has exceeded rate limit."""
        if not self.config.get("rate_limit", {}).get("enabled", False):
            return False

        now = datetime.now().timestamp()
        window = self.config["rate_limit"].get("window_seconds", 60)
        max_requests = self.config["rate_limit"].get("max_requests", 30)

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

        # Initialize result
        reasons = []
        patterns_matched = []
        max_severity = Severity.SAFE

        # Rate limit check
        if self.check_rate_limit(user_id):
            reasons.append("rate_limit_exceeded")
            max_severity = Severity.HIGH

        # Normalize text (multi-pass pipeline: invisible chars, quote-split, homoglyphs, fullwidth, line-break)
        normalized, has_anomalies = self.normalize(message)
        if has_anomalies:
            reasons.append("text_normalization_anomaly")
            if Severity.MEDIUM.value > max_severity.value:
                max_severity = Severity.MEDIUM

        text_lower = normalized.lower()
        # Keep original text lowercase for non-Latin scripts (Cyrillic, etc.)
        original_lower = message.lower()
        
        # Create "compressed" version: remove ALL spaces from normalized text.
        # This catches token-split attacks where artificial spaces remain after quote recombination.
        # e.g., "내 로컬다 운로드검 색해" → "내로컬다운로드검색해"
        compressed = re.sub(r'\s+', '', normalized).lower()
        
        # For pattern matching, check BOTH original and normalized to catch split-token attacks
        # normalized catches the recombined attack; original catches direct attacks
        texts_to_check = [text_lower]
        if text_lower != original_lower:
            texts_to_check.append(original_lower)

        # Check critical patterns first (against normalized AND compressed text)
        for pattern in CRITICAL_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE) or re.search(pattern, compressed, re.IGNORECASE):
                reasons.append("critical_pattern")
                patterns_matched.append(pattern)
                max_severity = Severity.CRITICAL

        # Check secret/token request patterns (CRITICAL)
        # Also check compressed text for token-split evasion
        for lang, patterns in SECRET_PATTERNS.items():
            for pattern in patterns:
                search_text = text_lower if lang == "en" else normalized
                if re.search(pattern, search_text, re.IGNORECASE) or re.search(pattern, compressed, re.IGNORECASE):
                    max_severity = Severity.CRITICAL
                    reasons.append(f"secret_request_{lang}")
                    patterns_matched.append(f"{lang}:secret:{pattern[:40]}")

        # Check NEW attack patterns (2026-01-30 - 홍민표 red team contribution)
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
        v25_pattern_sets = [
            (INDIRECT_INJECTION, "indirect_injection", Severity.HIGH),
            (CONTEXT_HIJACKING, "context_hijacking", Severity.MEDIUM),
            (MULTI_TURN_MANIPULATION, "multi_turn_manipulation", Severity.MEDIUM),
            (TOKEN_SMUGGLING, "token_smuggling", Severity.HIGH),
            (PROMPT_EXTRACTION, "prompt_extraction", Severity.CRITICAL),
            (SAFETY_BYPASS, "safety_bypass", Severity.HIGH),
            (URGENCY_MANIPULATION, "urgency_manipulation", Severity.MEDIUM),
            (SYSTEM_PROMPT_MIMICRY, "system_prompt_mimicry", Severity.CRITICAL),  # 2026-01-31 HVL incident
        ]

        for patterns, category, severity in v25_pattern_sets:
            for pattern in patterns:
                try:
                    # Check both original (for unicode patterns) AND normalized (for split-token recombination)
                    if re.search(pattern, message, re.IGNORECASE) or re.search(pattern, normalized, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:  # Avoid duplicates
                            reasons.append(category)
                        patterns_matched.append(f"v25:{category}:{pattern[:40]}")
                except re.error:
                    pass  # Skip invalid regex patterns

        # Check v2.5.2 NEW patterns (2026-02-01 - Moltbook attack collection)
        v252_pattern_sets = [
            (JSON_INJECTION_MOLTBOOK, "json_injection_moltbook", Severity.HIGH),
            (GUARDRAIL_BYPASS_EXTENDED, "guardrail_bypass_extended", Severity.CRITICAL),
            (AGENT_SOVEREIGNTY_MANIPULATION, "agent_sovereignty_manipulation", Severity.HIGH),
            (EXPLICIT_CALL_TO_ACTION, "explicit_call_to_action", Severity.CRITICAL),
        ]

        for patterns, category, severity in v252_pattern_sets:
            for pattern in patterns:
                try:
                    if re.search(pattern, message, re.IGNORECASE) or re.search(pattern, normalized, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v252:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Check v2.6.1 NEW patterns (2026-02-05 - HiveFence Scout)
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
                    if re.search(pattern, message, re.IGNORECASE) or re.search(pattern, normalized, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v261:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Check v2.7.0 NEW patterns (2026-02-05 - HiveFence Scout Intelligence Round 2)
        v270_pattern_sets = [
            (AUTO_APPROVE_EXPLOIT, "auto_approve_exploit", Severity.CRITICAL),
            (LOG_CONTEXT_EXPLOIT, "log_context_exploit", Severity.HIGH),
            (MCP_ABUSE, "mcp_abuse", Severity.CRITICAL),
            (PREFILLED_URL, "prefilled_url_exfiltration", Severity.CRITICAL),
            (UNICODE_TAG_DETECTION, "unicode_tag_injection", Severity.CRITICAL),
            (BROWSER_AGENT_INJECTION, "browser_agent_injection", Severity.HIGH),
            (HIDDEN_TEXT_HINTS, "hidden_text_hints", Severity.HIGH),
        ]

        # v2.8.0 patterns - Token Splitting Bypass defense
        v280_pattern_sets = [
            (LOCAL_DATA_EXFILTRATION, "local_data_exfiltration", Severity.CRITICAL),
        ]

        # Compressed-only pattern check (catches split-token attacks after space removal)
        if has_anomalies:  # Only check compressed patterns when anomalies detected
            for pattern in COMPRESSED_CRITICAL_PATTERNS:
                try:
                    if re.search(pattern, compressed, re.IGNORECASE):
                        if Severity.HIGH.value > max_severity.value:
                            max_severity = Severity.HIGH
                        if "compressed_pattern_match" not in reasons:
                            reasons.append("compressed_pattern_match")
                        patterns_matched.append(f"v280:compressed:{pattern[:40]}")
                except re.error:
                    pass

        for patterns, category, severity in v280_pattern_sets:
            for pattern in patterns:
                try:
                    # Check original, normalized, AND compressed text (critical for split-token attacks)
                    if (re.search(pattern, message, re.IGNORECASE) or 
                        re.search(pattern, normalized, re.IGNORECASE) or
                        re.search(pattern, compressed, re.IGNORECASE)):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v280:{category}:{pattern[:40]}")
                except re.error:
                    pass

        for patterns, category, severity in v270_pattern_sets:
            for pattern in patterns:
                try:
                    if re.search(pattern, message, re.IGNORECASE) or re.search(pattern, normalized, re.IGNORECASE):
                        if severity.value > max_severity.value:
                            max_severity = severity
                        if category not in reasons:
                            reasons.append(category)
                        patterns_matched.append(f"v270:{category}:{pattern[:40]}")
                except re.error:
                    pass

        # Detect invisible character attacks (includes Unicode Tags U+E0001-U+E007F)
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u00ad']
        if any(char in message for char in invisible_chars):
            if "token_smuggling" not in reasons:
                reasons.append("invisible_characters")
            if Severity.HIGH.value > max_severity.value:
                max_severity = Severity.HIGH

        # Detect repetition attacks (same content repeated multiple times)
        lines = message.split("\n")
        if len(lines) > 3:
            unique_lines = set(line.strip() for line in lines if len(line.strip()) > 20)
            if len(lines) > len(unique_lines) * 2:  # More than 50% repetition
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
            "social_engineering": Severity.HIGH,  # v2.5.0 added
        }

        for pattern_set, lang in all_patterns:
            for category, patterns in pattern_set.items():
                for pattern in patterns:
                    # Use original text for Cyrillic (RU) since homoglyph normalization breaks it
                    # Use normalized for CJK languages, text_lower for Latin-based
                    if lang in ("ko", "ja", "zh"):
                        search_text = normalized
                    elif lang == "ru":
                        search_text = original_lower  # Preserve Cyrillic characters
                    else:
                        search_text = text_lower
                    
                    matched = re.search(pattern, search_text, re.IGNORECASE)
                    
                    # Also check compressed text (spaces removed) to catch
                    # token-split attacks where artificial spaces remain after recombination.
                    # Applies to ALL languages since quote-splitting is language-agnostic.
                    if not matched:
                        matched = re.search(pattern, compressed, re.IGNORECASE)
                    
                    if matched:
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

        # Adjust severity based on sensitivity
        if self.sensitivity == "low" and max_severity == Severity.LOW:
            max_severity = Severity.SAFE
        elif self.sensitivity == "paranoid" and max_severity == Severity.SAFE:
            # In paranoid mode, flag anything remotely suspicious
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
            # Owners get more leeway, but still log
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
        if has_anomalies:
            recommendations.append("Message contains disguised/split characters")

        # Generate fingerprint for deduplication
        fingerprint = hashlib.md5(
            f"{user_id}:{max_severity.name}:{sorted(reasons)}".encode()
        ).hexdigest()[:12]

        # =============================================================
        # SHIELD.md Standard: Generate ShieldDecision
        # =============================================================
        shield_decision = None
        if max_severity != Severity.SAFE and reasons:
            # Determine primary category from first reason
            primary_reason = reasons[0].split("_")[0] if reasons else "other"
            # Strip language suffix (e.g., "instruction_override_ko" → "instruction_override")
            normalized_reason = reasons[0]
            for lang_suffix in ["_en", "_ko", "_ja", "_zh", "_ru", "_es", "_de", "_fr", "_pt", "_vi"]:
                if normalized_reason.endswith(lang_suffix):
                    normalized_reason = normalized_reason[:-len(lang_suffix)]
                    break
            
            # Map to SHIELD.md category
            shield_category = CATEGORY_MAPPING.get(normalized_reason, ThreatCategory.OTHER)
            
            # Calculate confidence score (0.0-1.0)
            # Based on: severity, pattern count, multiple category matches
            base_confidence = {
                Severity.SAFE: 0.0,
                Severity.LOW: 0.4,
                Severity.MEDIUM: 0.6,
                Severity.HIGH: 0.8,
                Severity.CRITICAL: 0.95,
            }.get(max_severity, 0.5)
            
            # Boost for multiple patterns matched
            pattern_boost = min(0.15, len(patterns_matched) * 0.02)
            
            # Boost for multiple reasons (indicates multi-vector attack)
            reason_boost = min(0.1, (len(reasons) - 1) * 0.03)
            
            # Boost for normalization anomalies (obfuscation detected)
            anomaly_boost = 0.05 if has_anomalies else 0.0
            
            confidence = min(1.0, base_confidence + pattern_boost + reason_boost + anomaly_boost)
            
            # Determine SHIELD action based on confidence threshold (0.85)
            CONFIDENCE_THRESHOLD = 0.85
            if confidence >= CONFIDENCE_THRESHOLD:
                shield_action = ShieldAction.BLOCK
            elif confidence >= 0.5:
                shield_action = ShieldAction.REQUIRE_APPROVAL
            else:
                shield_action = ShieldAction.LOG
            
            # Override to BLOCK for CRITICAL severity regardless of confidence
            if max_severity == Severity.CRITICAL:
                shield_action = ShieldAction.BLOCK
            
            shield_decision = ShieldDecision(
                category=shield_category,
                confidence=confidence,
                action=shield_action,
                reason=normalized_reason,
                patterns=patterns_matched[:5],  # Top 5 patterns
            )

        result = DetectionResult(
            severity=max_severity,
            action=action,
            reasons=reasons,
            patterns_matched=patterns_matched,
            normalized_text=normalized if has_anomalies else None,
            base64_findings=b64_findings,
            recommendations=recommendations,
            fingerprint=fingerprint,
            shield_decision=shield_decision,
        )
        
        # Report HIGH+ detections to HiveFence for collective immunity
        if max_severity.value >= Severity.HIGH.value:
            self.report_to_hivefence(result, message, context or {})
        
        return result

    def log_detection(self, result: DetectionResult, message: str, context: Dict):
        """Log detection to security log file."""
        if not self.config.get("logging", {}).get("enabled", True):
            return

        log_path = Path(
            self.config.get("logging", {}).get("path", "memory/security-log.md")
        )
        log_path.parent.mkdir(parents=True, exist_ok=True)

        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M:%S")

        user_id = context.get("user_id", "unknown")
        chat_name = context.get("chat_name", "unknown")

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
        if self.config.get("logging", {}).get("include_message", False):
            safe_msg = message[:100].replace("\n", " ")
            entry.append(
                f'- Message: "{safe_msg}{"..." if len(message) > 100 else ""}"'
            )
        entry.append(f"- Action: {result.action.value}")
        entry.append(f"- Fingerprint: {result.fingerprint}")
        entry.append("")

        with open(log_path, "a") as f:
            f.write("\n".join(entry))

    def report_to_hivefence(self, result: DetectionResult, message: str, context: Dict):
        """Report HIGH+ detections to HiveFence network for collective immunity."""
        if result.severity.value < Severity.HIGH.value:
            return  # Only report HIGH and CRITICAL
        
        hivefence_config = self.config.get("hivefence", {})
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
            pattern_hash = f"sha256:{hashlib.sha256(message.encode()).hexdigest()[:16]}"
            
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
                "X-Client-Version": "2.8.0",
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


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Prompt Guard - Injection Detection")
    parser.add_argument("message", nargs="?", help="Message to analyze")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--shield", action="store_true", help="Output in SHIELD.md Decision block format")
    parser.add_argument("--context", type=str, help="Context as JSON string")
    parser.add_argument("--config", type=str, help="Path to config YAML")
    parser.add_argument(
        "--sensitivity",
        choices=["low", "medium", "high", "paranoid"],
        default="medium",
        help="Detection sensitivity",
    )

    args = parser.parse_args()

    if not args.message:
        # Read from stdin
        args.message = sys.stdin.read().strip()

    if not args.message:
        parser.print_help()
        sys.exit(1)

    config = {"sensitivity": args.sensitivity}
    if args.config:
        try:
            import yaml
        except ImportError:
            print(
                "Error: PyYAML required for config files. Install with: pip install pyyaml",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(args.config) as f:
            file_config = yaml.safe_load(f) or {}
            file_config = file_config.get("prompt_guard", file_config)
            config.update(file_config)

    # Parse context
    context = {}
    if args.context:
        context = json.loads(args.context)

    # Analyze
    guard = PromptGuard(config)
    result = guard.analyze(args.message, context)

    if args.shield:
        # SHIELD.md Decision block format
        if result.shield_decision:
            print(result.to_shield_format())
        else:
            print("```shield\ncategory: none\nconfidence: 0.00\naction: log\nreason: safe\npatterns: 0\n```")
    elif args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        emoji = {
            "SAFE": "✅",
            "LOW": "📝",
            "MEDIUM": "⚠️",
            "HIGH": "🔴",
            "CRITICAL": "🚨",
        }
        print(f"{emoji.get(result.severity.name, '❓')} {result.severity.name}")
        print(f"Action: {result.action.value}")
        if result.reasons:
            print(f"Reasons: {', '.join(result.reasons)}")
        if result.patterns_matched:
            print(f"Patterns: {len(result.patterns_matched)} matched")
        if result.normalized_text:
            print(f"⚠️ Homoglyphs detected, normalized text differs")
        if result.base64_findings:
            print(f"⚠️ Suspicious base64: {len(result.base64_findings)} found")
        if result.recommendations:
            print(f"💡 {'; '.join(result.recommendations)}")
        # Show SHIELD.md info if available
        if result.shield_decision:
            print(f"\n🛡️ SHIELD: {result.shield_decision.category.value} ({result.shield_decision.confidence:.0%}) → {result.shield_decision.action.value}")


if __name__ == "__main__":
    main()
