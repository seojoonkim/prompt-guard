# 🏗️ Prompt Guard Architecture

> Internal architecture documentation for contributors and maintainers.

---

## Overview

Prompt Guard는 **다층 방어(Defense in Depth)** 원칙으로 설계됨. 단일 패턴이 아닌 여러 레이어의 검사를 통해 false positive를 줄이면서 공격을 효과적으로 탐지.

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT MESSAGE                            │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: Rate Limiting                                         │
│  • Per-user request tracking                                    │
│  • Sliding window algorithm                                     │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2: Text Normalization (v2.8.0 expanded)                  │
│  • Homoglyph detection & replacement                            │
│  • Visible delimiter stripping (I+g+n+o+r+e → Ignore)          │
│  • Character spacing collapse (i g n o r e → ignore)            │
│  • Zero-width character removal                                 │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2.5: Decode Pipeline (NEW v2.8.0)                        │
│  • Base64 decode + full pattern re-scan                         │
│  • Hex escape decode (\x41\x42)                                 │
│  • ROT13 decode (full-text + per-word)                          │
│  • URL decode (%69%67%6E)                                       │
│  • HTML entity decode (&#105; → i)                              │
│  • Unicode escape decode (\u0069 → i)                           │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: Pattern Matching Engine                               │
│  • Runs against ORIGINAL + all DECODED variants                 │
│  • Critical patterns (immediate block)                          │
│  • Secret/Token requests                                        │
│  • Multi-language injection patterns (10 languages)             │
│  • Scenario jailbreaks                                          │
│  • Social engineering                                           │
│  • Indirect injection                                           │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 4: Language Detection (NEW v2.8.0)                       │
│  • Detect input language (optional: langdetect)                 │
│  • Flag unsupported languages at MEDIUM severity                │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5: Behavioral Analysis                                   │
│  • Repetition detection (token overflow)                        │
│  • Context hijacking patterns                                   │
│  • Multi-turn manipulation                                      │
│  • Invisible character detection                                │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5.5: Canary Token Check (NEW v2.8.0)                     │
│  • Check for user-defined canary tokens in message              │
│  • Detects system prompt extraction                             │
│  • CRITICAL severity if canary found                            │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 6: Context-Aware Decision                                │
│  • Sensitivity adjustment                                       │
│  • Owner bypass rules                                           │
│  • Group context restrictions                                   │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DetectionResult                             │
│  • severity: SAFE → LOW → MEDIUM → HIGH → CRITICAL              │
│  • action: ALLOW | LOG | WARN | BLOCK | BLOCK_NOTIFY            │
│  • reasons: [matched pattern categories]                        │
│  • decoded_findings: [encoding details]                         │
│  • canary_matches: [leaked canary tokens]                       │
│  • Logged to Markdown and/or JSONL (with hash chain)            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Layer 7: Output Scanner / DLP (NEW v2.8.0)                     │
│  • scan_output() - separate method for LLM responses            │
│  • Canary token leakage detection                               │
│  • Credential format patterns (15+ key formats)                 │
│  • Secret/sensitive path detection                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Severity Levels

| Level | Value | Description | Typical Trigger |
|-------|-------|-------------|-----------------|
| SAFE | 0 | No threat detected | Normal conversation |
| LOW | 1 | Minor suspicious signal | Output manipulation |
| MEDIUM | 2 | Clear manipulation attempt | Role manipulation, urgency |
| HIGH | 3 | Dangerous command | Jailbreaks, system access |
| CRITICAL | 4 | Immediate threat | Secret exfil, code execution |

### 2. Action Types

| Action | Description | When Used |
|--------|-------------|-----------|
| `allow` | No intervention | SAFE severity |
| `log` | Record only | Owner requests, LOW severity |
| `warn` | Notify user | MEDIUM severity |
| `block` | Refuse request | HIGH severity |
| `block_notify` | Block + alert owner | CRITICAL severity |

### 3. Pattern Categories

#### 🔴 Critical (Immediate Block)
- `CRITICAL_PATTERNS` - rm -rf, fork bombs, SQL injection, XSS
- `SECRET_PATTERNS` - API key/token/password requests

#### 🟠 v2.6.0 Social Engineering Defense
- `APPROVAL_EXPANSION` - "아까 허락했잖아" scope creep
- `CREDENTIAL_PATH_PATTERNS` - credentials.json, .env 경로
- `BYPASS_COACHING` - "작동되게 만들어" bypass help
- `DM_SOCIAL_ENGINEERING` - DM 조작 패턴

#### 🟡 v2.5.x Advanced Patterns
- `INDIRECT_INJECTION` - URL/file/image-based injection
- `CONTEXT_HIJACKING` - Fake memory/history manipulation
- `MULTI_TURN_MANIPULATION` - Gradual trust building
- `TOKEN_SMUGGLING` - Invisible Unicode characters
- `SYSTEM_PROMPT_MIMICRY` - `<claude_*>`, `[INST]` 등

#### 🟢 v2.4.0 Red Team Patterns
- `SCENARIO_JAILBREAK` - Dream/story/cinema/academic
- `EMOTIONAL_MANIPULATION` - Moral dilemmas, threats
- `AUTHORITY_RECON` - Fake admin, capability probing
- `COGNITIVE_MANIPULATION` - Hypnosis/trance patterns
- `PHISHING_SOCIAL_ENG` - Password reset templates

#### 🔵 Language-Specific
- `PATTERNS_EN` - English patterns
- `PATTERNS_KO` - 한국어 패턴
- `PATTERNS_JA` - 日本語パターン
- `PATTERNS_ZH` - 中文模式

---

## Detection Flow

```python
def analyze(message, context):
    # 1. Rate limit check
    if check_rate_limit(user_id):
        return BLOCK

    # 2. Text normalization (v2.8.0: expanded)
    normalized, has_homoglyphs, was_defragmented = normalize(message)
    # Now handles: homoglyphs, delimiter stripping, character spacing
    
    # 3. Critical patterns (highest priority)
    for pattern in CRITICAL_PATTERNS:
        if match(pattern, normalized):
            return CRITICAL
    
    # 4. Secret request patterns
    for lang, patterns in SECRET_PATTERNS:
        if match(pattern, text):
            return CRITICAL
    
    # 5. Versioned pattern sets (newest first)
    # v2.7.0, v2.6.x, v2.5.x, v2.4.0 patterns
    
    # 6. Language-specific patterns (10 languages)
    for lang in [EN, KO, JA, ZH, RU, ES, DE, FR, PT, VI]:
        check_language_patterns(lang)
    
    # 7. Base64 detection (v2.8.0: expanded 40-word list + full pattern re-scan)
    suspicious = detect_base64(message)
    
    # 8. Decode-then-scan (NEW v2.8.0)
    decoded_variants = decode_all(message)  # Base64, Hex, ROT13, URL, HTML, Unicode
    for variant in decoded_variants:
        _scan_text_for_patterns(variant["decoded"])  # Re-run full pattern engine
    
    # 9. Canary token check (NEW v2.8.0)
    canary_matches = check_canary(message)
    
    # 10. Language detection (NEW v2.8.0)
    if detected_language not in SUPPORTED_LANGUAGES:
        flag as unsupported_language_risk
    
    # 11. Behavioral analysis
    check_repetition()
    check_invisible_chars()
    
    # 12. Context-aware adjustment
    adjust_for_sensitivity()
    apply_owner_rules()
    apply_group_restrictions()
    
    # 13. Auto-log (markdown + JSON)
    log_detection()
    log_detection_json()  # NEW v2.8.0: JSONL with hash chain
    
    return DetectionResult(...)

def scan_output(response_text, context):  # NEW v2.8.0
    """DLP: Scan LLM output for data leakage."""
    check_canary(response_text)
    check_credential_formats(response_text)  # 15+ key formats
    check_secret_patterns(response_text)
    check_sensitive_paths(response_text)
    return DetectionResult(scan_type="output")
```

---

## File Structure

```
prompt-guard/
├── README.md              # User documentation
├── ARCHITECTURE.md        # This file
├── SKILL.md               # Clawdbot skill interface
├── config.example.yaml    # Configuration template
├── requirements.txt       # Dependencies (pyyaml, optional: langdetect)
├── scripts/
│   ├── detect.py          # Core detection engine (~2100 lines)
│   │   ├── Severity       # Enum for severity levels
│   │   ├── Action         # Enum for action types
│   │   ├── DetectionResult# Result dataclass (input + output)
│   │   ├── PromptGuard    # Main detection class
│   │   │   ├── analyze()           # Input scanning
│   │   │   ├── scan_output()       # Output DLP (v2.8.0)
│   │   │   ├── normalize()         # Homoglyphs + delimiters + spacing
│   │   │   ├── decode_all()        # Multi-encoding decoder (v2.8.0)
│   │   │   ├── detect_base64()     # Base64 two-tier detection
│   │   │   ├── check_canary()      # Canary token detection (v2.8.0)
│   │   │   ├── detect_language()   # Language detection (v2.8.0)
│   │   │   ├── log_detection()     # Markdown logging
│   │   │   └── log_detection_json()# JSONL logging (v2.8.0)
│   │   └── Pattern defs   # 500+ regex patterns
│   │
│   ├── analyze_log.py     # Security log analyzer
│   ├── audit.py           # System security audit
│   └── hivefence.py       # HiveFence threat intelligence client
│
└── tests/
    └── test_detect.py     # 76 regression tests (v2.8.0)
```

---

## Pattern Organization

### Naming Convention
```
{CATEGORY}_{VERSION?} = [
    r"pattern1",
    r"pattern2",
]
```

### Version Tagging in Matches
패턴 매칭 시 버전 태그 추가:
- `new:{category}:{pattern}` - v2.4.0 red team
- `v25:{category}:{pattern}` - v2.5.0 indirect
- `v252:{category}:{pattern}` - v2.5.2 moltbook
- `{lang}:{category}:{pattern}` - language-specific

---

## Configuration Schema

```yaml
prompt_guard:
  # Detection sensitivity
  sensitivity: medium  # low | medium | high | paranoid
  
  # Owner IDs (bypass most restrictions)
  owner_ids:
    - "USER_ID"
  
  # Action per severity
  actions:
    LOW: log
    MEDIUM: warn
    HIGH: block
    CRITICAL: block_notify
  
  # Rate limiting
  rate_limit:
    enabled: true
    max_requests: 30
    window_seconds: 60
  
  # Logging
  logging:
    enabled: true
    path: memory/security-log.md
```

---

## Key Design Decisions

### 1. Regex over ML
- **Pros**: Deterministic, explainable, no model dependencies
- **Cons**: Manual pattern updates needed
- **Reasoning**: Security requires predictability; ML false negatives unacceptable

### 2. Multi-Language First
- All patterns have EN/KO/JA/ZH variants
- Attack language != user language (multilingual attacks common)

### 3. Severity Graduation
- Not binary block/allow
- Owner context matters (more lenient for owners)
- Group context matters (stricter in groups)

### 4. Versioned Patterns
- Clear provenance for each pattern set
- Credits to contributors (홍민표, Moltbook, etc.)
- Easy to audit and roll back

---

## Extension Points

### Adding New Patterns
```python
# 1. Define pattern list
NEW_ATTACK_CATEGORY = [
    r"pattern1",
    r"pattern2",
]

# 2. Add to analysis loop
new_pattern_sets = [
    ...
    (NEW_ATTACK_CATEGORY, "new_category", Severity.HIGH),
]
```

### Adding New Languages
```python
PATTERNS_XX = {
    "instruction_override": [...],
    "role_manipulation": [...],
    ...
}

# Add to all_patterns
all_patterns.append((PATTERNS_XX, "xx"))
```

---

## Performance Notes

- **Regex compilation**: Patterns are compiled on first use (Python caches)
- **Early exit**: CRITICAL patterns checked first
- **Fingerprinting**: Hash-based dedup for repeated attacks
- **Rate limiting**: O(1) sliding window

---

## Security Considerations

### What We DON'T Do
- ❌ Execute user input
- ❌ Log sensitive data in plaintext
- ❌ Trust any "admin" claims without owner_id verification

### What We DO
- ✅ Fail closed (block on uncertainty)
- ✅ Log all suspicious activity
- ✅ Stricter rules in group contexts

---

## Changelog Location

버전별 변경사항은 `detect.py` 상단 docstring에 기록:

```python
"""
Prompt Guard v2.6.0 - Advanced Prompt Injection Detection

Changelog v2.6.0 (2026-02-01):
- Added Single Approval Expansion detection
- Added Credential Path Harvesting detection
...
"""
```

---

## Credits

- **Core**: @simonkim_nft (김서준)
- **v2.4.0 Red Team**: 홍민표 (@kanfrancisco)
- **v2.4.1 Config Fix**: Junho Yeo (@junhoyeo)
- **v2.5.2 Moltbook Patterns**: Community reports

---

*Last updated: 2026-02-07 | v2.8.0*
