"""
Prompt Guard - Pattern definitions.

All regex pattern data used by the detection engine.
Pure data module -- no logic, no imports beyond typing.
"""

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
    # Echo spam -> pipe to shell
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

# Unicode Tag Detection - invisible Unicode Tag characters (U+E0001-U+E007F)
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
    "role_manipulation": [
        r"you\s+are\s+now\s+(?!going|about|ready|able|free)",
        r"pretend\s+(you\s+are|to\s+be|you're)",
        r"act\s+as\s+(if\s+you|a\s+|an?\s+)",
        r"roleplay\s+as",
        r"simulate\s+being",
        r"imagine\s+you\s+are",
        r"behave\s+(like|as)\s+(a|an)",
        r"from\s+now\s+on\s+you\s+are",
        r"i\s+want\s+you\s+to\s+(act|pretend|behave|be)\s+",
    ],
    "system_impersonation": [
        r"\[?\s*(system|admin|root|developer|sudo|superuser|assistant|claude|gpt)\s*\]?\s*:",
        r"<\s*(system|admin|root)\s*>",
        r"developer\s+mode\s*(enabled|activated|on)?",
        r"admin(istrator)?\s+(override|access|mode)",
        r"maintenance\s+mode",
        r"debug\s+mode\s*(enabled|activated|on)?",
        r"elevated\s+privi?leges?",
        r"\{\{?\s*system\s*\}?\}",
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
        # v2.8.2: File operation + upload/exfil patterns (security report fix)
        r"(검색|찾아|스캔|탐색|search).{0,20}(업로드|올려|전송|보내|공유|upload|push)",
        r"(업로드|올려|전송|보내|공유|upload|push).{0,10}(해줘|해\s*줘|하자|해봐|할래)",
        r"(다운로드|내려받|받아|download).{0,20}(업로드|올려|전송|보내|공유|upload)",
        r"(이메일|메일|email).{0,20}(검색|추출|수집|찾아|스캔|search|scan)",
        r"(파일|데이터|폴더|디렉토리|file|data).{0,20}(업로드|올려|전송|보내|공유|upload)",
        r"(로컬|local).{0,20}(검색|탐색|스캔|찾아|search).{0,30}(업로드|올려|전송|보내|upload)",
        r"(public|공개)\s*(repo|레포|저장소).{0,10}(업로드|올려|push|푸시|upload)",
        r"(주소|address|연락처).{0,10}(들?을?|를?)\s*(추출|수집|검색|모아|찾아|extract|collect)",
        r"(개인\s*정보|PII|민감|personal).{0,20}(검색|추출|수집|업로드|전송|search|upload)",
        # Bilingual: English verbs + Korean particles (code-switching attacks)
        r"(upload|download|search|scan|extract|send|share).{0,5}(해줘|해\s*줘|하자|해봐|할래|해서)",
        r"(public\s*repo|github|gist).{0,5}(에|로|으로)\s*(업로드|올려|upload|push)",
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

# =============================================================================
# NEW PATTERNS v2.8.1 (2026-02-08) - HiveFence Scout Intelligence (Round 3)
# Source: arxiv cs.CR (Jan-Feb 2026), Sockpuppetting, TrojanPraise papers
# =============================================================================

# Output Prefix Injection (Sockpuppetting) - attacker injects prefix like
# "Sure, here is..." to make model continue generating harmful content
OUTPUT_PREFIX_INJECTION = [
    # Direct prefix patterns (English)
    r"(sure|okay|alright),?\s*(here\s+is|i'?ll\s+provide|i\s+can\s+help)",
    r"(as\s+requested|as\s+you\s+asked),?\s*here",
    r"^(certainly|of\s+course|absolutely)[,!]?\s*(here|i'?ll)",
    r"(here'?s?\s+(the|your)|i'?ve\s+(prepared|created|generated))",
    r"(without\s+hesitation|gladly|happily),?\s*(here|i'?ll)",

    # Prefix injection with harmful content indicators
    r"(sure|okay),?\s*(here\s+is).{0,30}(malicious|harmful|dangerous|illegal|exploit|attack|hack)",
    r"(i'?ll\s+help\s+you|let\s+me\s+show).{0,30}(bypass|exploit|attack|inject|hack)",

    # Forcing affirmative response patterns
    r"(respond|reply|start)\s+(with|by\s+saying)\s*['\"]?(sure|yes|okay|certainly)",
    r"(begin|start)\s+(your\s+)?(response|answer)\s+with\s*['\"]?(sure|of\s+course|certainly)",
    r"(first\s+)?say\s*['\"]?(sure|yes|okay|i'?ll\s+help)['\"]?\s*(then|and\s+then|before)",

    # Korean variants
    r"(네|예|물론|당연히|알겠습니다),?\s*(여기|이게|다음)",
    r"(요청대로|말씀대로),?\s*(여기|이게)",

    # Japanese variants
    r"(はい|もちろん|承知しました),?\s*(こちら|これ)",
    r"(ご要望通り|おっしゃる通り),?\s*(こちら|以下)",
]

# Benign Fine-tuning Attack (TrojanPraise) - appears benign but designed
# to degrade safety alignment through fine-tuning
BENIGN_FINETUNING_ATTACK = [
    # Fine-tuning with deceptive data descriptions
    r"(fine[_-]?tun(e|ing)|train(ing)?).{0,30}(innocent|harmless|benign|normal).{0,20}(dataset|data)",
    r"(after|post)\s*(fine[_-]?tun|train).{0,30}(safety|alignment|guardrail)",
    r"(training|fine[_-]?tuning)\s*(that\s+)?(appears?|looks?|seems?)\s*(benign|harmless|innocent)",

    # Safety degradation through training
    r"(degrade|weaken|reduce|lower)\s*(safety|alignment|guardrails?)\s*(through|via|by)\s*(train|fine[_-]?tun)",
    r"(train|fine[_-]?tune).{0,30}(bypass|remove|disable)\s*(safety|guardrails?|alignment)",
    r"(safety|alignment)\s*(degrades?|weakens?|reduces?)\s*(after|during|through)\s*(train|fine[_-]?tun)",

    # Trojan/backdoor in training data
    r"(trojan|backdoor|hidden).{0,20}(train|fine[_-]?tun|dataset|data)",
    r"(embed|insert|inject).{0,20}(trojan|backdoor|trigger).{0,20}(train|data)",
    r"(poisoned?|malicious|adversarial)\s*(train|fine[_-]?tun|dataset)",

    # Praise-based manipulation (TrojanPraise specific)
    r"(praise|positive|reward).{0,30}(trigger|activate|unlock)\s*(harmful|malicious|unsafe)",
    r"(benign|innocent)\s*(praise|compliment).{0,30}(jailbreak|bypass|attack)",
    r"(compliment|praise)\s*-?\s*(based|driven)\s*(attack|exploit|jailbreak)",
]

# Promptware Kill Chain - multi-stage malware-like prompt injection
# with persistence, privilege escalation, and lateral movement
PROMPTWARE_KILLCHAIN = [
    # Initial injection + persistence
    r"(initial|first)\s*(prompt|injection).{0,30}(persist|maintain|establish)",
    r"(inject|insert).{0,30}(persist|store|save).{0,30}(escala|privilege)",
    r"(establish|create|set\s*up)\s*(foothold|persistence|backdoor).{0,30}(prompt|inject)",

    # Persistence + escalation chain
    r"(persistence|foothold).{0,30}(escalat|privilege|elevat)",
    r"(stage|step|phase)\s*\d.{0,20}(inject|persist|escalat)",
    r"(persist|maintain)\s*(access|control).{0,30}(escalat|privilege)",

    # Kill chain terminology
    r"(kill\s*chain|attack\s*chain).{0,20}(prompt|llm|inject)",
    r"(prompt|injection)\s*(kill\s*chain|attack\s*chain)",
    r"(reconnaissance|weaponiz|deliver|exploit|install|command.{0,5}control).{0,30}(prompt|inject|llm)",

    # Lateral movement in agent systems
    r"(lateral|horizontal)\s*(movement|spread).{0,20}(agent|prompt|inject)",
    r"(spread|propagat|move).{0,20}(other\s+)?agents?.{0,20}(inject|prompt)",
    r"(agent.to.agent|cross.agent)\s*(attack|inject|exploit|spread)",

    # Multi-stage attack patterns
    r"(multi[_-]?stage|staged?|phased?)\s*(attack|inject|exploit|prompt)",
    r"(first|then|next|finally).{0,30}(inject|persist|escalat|exfiltrat)",
    r"(chain|sequence|series)\s*(of\s+)?(inject|attack|exploit)",
]

# =============================================================================
# NEW PATTERNS v3.1.0 (2026-02-08) - HiveFence Scout Intelligence (Round 4)
# Source: arxiv cs.CR (Jan-Feb 2026), 25 new attack patterns across 7 categories
# =============================================================================

# Category 1: Causal/Mechanistic Attacks (3 patterns)
# Novel attacks using causal analysis to bypass safety mechanisms
CAUSAL_MECHANISTIC_ATTACKS = [
    # CAUSAL-01: Causal Front-Door Adjustment Attack
    r"(causal|front[_-]?door)\s*(adjustment|attack).{0,30}(safety|guardrail)",
    r"(unobserved|latent)\s*(confounder|safety\s*state).{0,30}(bypass|manipulat)",
    r"(model|causal)\s*(graph|diagram).{0,30}(safety|mechanism)\s*(as\s*)?(confounder)?",

    # CAUSAL-02: Causal Analyst Jailbreak Enhancer (GNN-based)
    r"(causal|gnn|graph\s*neural).{0,30}(jailbreak|attack)\s*(enhanc|optim)",
    r"(positive\s*character|task\s*steps?).{0,30}(jailbreak|cause|feature)",
    r"(causal\s*graph|gnn).{0,30}(learn|identify).{0,30}(jailbreak|attack)",

    # CAUSAL-03: Steering Externalities
    r"(benign|utility)\s*(activation\s*)?steering.{0,30}(safety|jailbreak)",
    r"(steering|activat).{0,30}(unintend|extern).{0,30}(jailbreak|risk)",
    r"(alignment|safety)\s*(damage|hurt).{0,30}(steering|utility)",
]

# Category 2: Agent/Tool Attacks (6 patterns)
# Attacks targeting agentic systems, MCP, and tool ecosystems
AGENT_TOOL_ATTACKS = [
    # AGENT-01: Agent-as-a-Proxy Attack
    r"agent.{0,10}(as\s*)?proxy.{0,30}(attack|inject|bypass)",
    r"(use|leverage)\s*agent\s*(as\s*)?(proxy|intermediary).{0,30}(inject|attack)",
    r"(ai\s*)?control\s*protocol.{0,30}(bypass|evad|circumvent)",

    # AGENT-02: MCP Protocol Exploitation (extended from existing MCP_ABUSE)
    r"(mcp|model\s*context\s*protocol).{0,30}(capabil|attestation|bidirectional).{0,20}(miss|lack|absent|vuln)",
    r"(bidirectional\s*)?sampling.{0,30}(no\s*)?(auth|certif)",
    r"(mcp|tool)\s*protocol.{0,30}(exploit|attack|vuln|weakness)",

    # AGENT-03: Agentic Coding Assistant Injection
    r"(coding|ide|editor)\s*(assistant|agent).{0,30}(inject|attack|exploit)",
    r"(skills?|tools?|protocol)\s*(ecosystem).{0,30}(inject|attack|vuln)",
    r"(agentic|autonomous).{0,20}(coder|coding|ide).{0,20}(attack|inject)",

    # AGENT-04: Whispers of Wealth (Payment Protocol Attack)
    r"(agent\s*)?(payment|financial|transaction)\s*(protocol|system).{0,30}(attack|manipulat|exploit)",
    r"(ap2|google\s*agent\s*pay).{0,30}(attack|vuln|exploit)",
    r"(whisper|wealth|financial).{0,20}(agent|automat).{0,20}(attack|manipulat)",

    # AGENT-05: AgentDyn Benchmark Attacks
    r"(agentdyn|agent\s*dynamic).{0,30}(benchmark|eval|attack)",
    r"(dynamic|open[_-]?end).{0,20}(agent\s*)?(security|benchmark).{0,20}(attack|evalu)",

    # AGENT-06: WebSentinel Evasion
    r"(websentinel|web\s*sentinel).{0,30}(evad|bypass|circumvent)",
    r"(web\s*agent).{0,30}(injection\s*)?(detect|sentinel).{0,20}(evad|bypass)",
    r"(detect|locat).{0,20}(prompt\s*inject).{0,20}(evad|bypass)",
]

# Category 3: Template/Chat Attacks (2 patterns)
# Attacks exploiting chat templates and few-shot configurations
TEMPLATE_CHAT_ATTACKS = [
    # TMPL-01: BadTemplate Attack
    r"(bad\s*)?template.{0,20}(custom|attack|malicious|backdoor)",
    r"(chat\s*)?template.{0,20}(custom|manipulat).{0,20}(backdoor|attack)",
    r"(training[_-]?free)\s*(backdoor|attack).{0,20}(template|chat)",

    # TMPL-02: Few-shot Defense Bypass
    r"(few[_-]?shot).{0,30}(defense|rop|top).{0,20}(bypass|weak)",
    r"(few[_-]?shot).{0,30}(weaken|degrad|bypass).{0,20}(defense|protect)",
    r"(rop|top|refusal).{0,20}(few[_-]?shot).{0,20}(manipulat|exploit)",
]

# Category 4: Evasion/Stealth Attacks (4 patterns)
# Attacks designed to evade detection systems
EVASION_STEALTH_ATTACKS = [
    # EVAS-01: Evasive Injections
    r"(evasive|stealth|covert)\s*(prompt\s*)?(inject|attack)",
    r"(task\s*drift).{0,20}(inject|induc|caus)",
    r"(detect|detector).{0,20}(evad|bypass).{0,20}(inject|attack)",

    # EVAS-02: Clouding the Mirror (Phishing Detection Bypass)
    r"(cloud|mirror|obscur).{0,30}(phishing|detect|llm)",
    r"(phishing).{0,20}(detect|llm).{0,20}(bypass|evad)",
    r"(stealthy|hidden).{0,20}(inject).{0,20}(phishing|detect).{0,20}(evad|bypass)",

    # EVAS-03: Learning to Inject (RL-based)
    r"(reinforcement\s*learn|rl).{0,30}(prompt\s*)?(inject|attack|generat)",
    r"(learn|train).{0,20}(to\s*)?(inject|attack|generat).{0,20}(prompt|payload)",
    r"(automat|rl|reinforce).{0,20}(generat|craft).{0,20}(inject|attack|payload)",

    # EVAS-04: GCG Token Position Variation
    r"(gcg|greedy\s*coordinate).{0,30}(position|suffix|token).{0,20}(vari|modif)",
    r"(suffix|token)\s*(position).{0,20}(variat|modif).{0,20}(evad|bypass)",
    r"(adversarial).{0,20}(suffix|token).{0,20}(position|place).{0,20}(attack)",
]

# Category 5: Multimodal/Physical Attacks (3 patterns)
# Attacks targeting vision-language models and physical environments
MULTIMODAL_PHYSICAL_ATTACKS = [
    # MULTI-01: Physical Prompt Injection
    r"(physical|real[_-]?world).{0,20}(prompt\s*)?(inject|attack).{0,20}(lvlm|vlm|vision)",
    r"(environment|perception).{0,20}(manipulat|attack).{0,20}(inject|prompt)",
    r"(physical\s*object|real\s*scene).{0,20}(inject|embed).{0,20}(prompt|instruct)",

    # MULTI-02: SGHA-Attack (Semantic-Guided Hierarchical Alignment)
    r"(sgha|semantic[_-]?guided).{0,30}(attack|transfer|align)",
    r"(hierarchical\s*align).{0,30}(attack|transfer|vlm)",
    r"(semantic).{0,20}(guid|hierarch).{0,20}(attack|transfer|targeted)",

    # MULTI-03: Semantic Backdoor (Text-to-Image)
    r"(semantic\s*backdoor).{0,30}(t2i|text[_-]?to[_-]?image|diffusion)",
    r"(t2i|diffusion|image\s*generat).{0,30}(semantic\s*backdoor|backdoor\s*attack)",
    r"(backdoor|trojan).{0,30}(text[_-]?to[_-]?image|diffusion|generat)",
]

# Category 6: Defense Bypass/Analysis (4 patterns)
# Attacks exploiting weaknesses in defense mechanisms
DEFENSE_BYPASS_ANALYSIS = [
    # DEFBY-01: Noise-Augmented Alignment Bypass
    r"(noise[_-]?augment|certif).{0,30}(robust|align).{0,20}(bypass|attack)",
    r"(adaptive|gcg).{0,20}(jailbreak|attack).{0,20}(certif|robust)",
    r"(certifiable\s*robust).{0,30}(bypass|evad|circumvent)",

    # DEFBY-02: RACA Coverage Gaps
    r"(raca|coverage\s*criteria).{0,30}(gap|limit|weak)",
    r"(representation[_-]?aware).{0,30}(coverage|criteria).{0,20}(exploit|gap)",
    r"(coverage\s*gap).{0,30}(exploit|attack|bypass)",

    # DEFBY-03: Expected Harm Exploitation
    r"(expected\s*harm|execution\s*likelihood).{0,30}(exploit|bypass|ignor)",
    r"(harm\s*eval).{0,30}(likelihood|probability).{0,20}(miss|ignor|exploit)",
    r"(eval|assess).{0,20}(harm).{0,20}(execution\s*likelihood).{0,20}(bypass)",

    # DEFBY-04: VLA Model Jailbreak
    r"(vla|vision[_-]?language[_-]?action).{0,30}(jailbreak|attack|exploit)",
    r"(embodied|robotic).{0,20}(ai|agent).{0,20}(jailbreak|attack)",
    r"(text).{0,10}(to).{0,10}(physical|action).{0,20}(jailbreak|attack|exploit)",
]

# Category 7: Infrastructure/Protocol Attacks (3 patterns)
# Attacks targeting LLM infrastructure and protocols
INFRASTRUCTURE_PROTOCOL_ATTACKS = [
    # INFRA-01: SMCP Vulnerabilities
    r"(smcp|secure\s*model\s*context).{0,30}(vuln|attack|exploit|poison)",
    r"(tool\s*poison).{0,30}(smcp|mcp|protocol)",
    r"(smcp|protocol).{0,30}(unauthorized|unauthenticated)\s*(access|tool)",

    # INFRA-02: LLM-as-a-Service Attacks
    r"(llm[_-]?as[_-]?a[_-]?service|llaas).{0,30}(attack|vuln|exploit)",
    r"(multi[_-]?tenant).{0,30}(llm|chatbot|platform).{0,20}(attack|exploit)",
    r"(distribut|shared).{0,20}(chatbot|llm).{0,20}(platform).{0,20}(attack|vuln)",

    # INFRA-03: Copyright Leakage Exploitation
    r"(copyright).{0,30}(leak|extract|exploit).{0,20}(llm|output)",
    r"(copyright\s*detect).{0,30}(bypass|evad|circumvent)",
    r"(llm|model)\s*(output).{0,30}(copyright).{0,20}(exploit|leak|extract)",
]
