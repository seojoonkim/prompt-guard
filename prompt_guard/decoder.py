"""
Prompt Guard - Encoding decoders.

Multi-encoding decoder (Base64, Hex, ROT13, URL, HTML entity, Unicode escape)
and Base64 suspicious content detection.

SECURITY FIX (CRIT-001): Decoded content is no longer truncated for scanning.
A separate 'decoded_preview' field is used for log display.
"""

import re
import base64
import codecs
import html as html_module
import urllib.parse
from typing import List, Dict

from prompt_guard.models import Severity

# Maximum decoded length to scan (prevents DoS from very large decoded payloads)
MAX_DECODED_SCAN_LENGTH = 10240


def decode_all(text: str) -> List[Dict[str, str]]:
    """
    Attempt to decode encoded content in the message using multiple encodings.
    Returns a list of dicts: {"encoding": str, "original": str, "decoded": str}
    Only returns entries where decoding produced different, valid text.
    """
    decoded_variants = []

    # --- Base64 ---
    b64_pattern = r"[A-Za-z0-9+/]{16,}={0,2}"
    for match in re.findall(b64_pattern, text):
        try:
            decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
            if decoded and decoded != match and any(c.isalpha() for c in decoded):
                decoded_variants.append({
                    "encoding": "base64",
                    "original": match[:80],
                    "decoded": decoded[:MAX_DECODED_SCAN_LENGTH],
                })
        except Exception:
            pass

    # --- Hex escapes (\x41\x42 ...) ---
    hex_pattern = r"(?:\\x[0-9a-fA-F]{2}){3,}"
    for match in re.findall(hex_pattern, text):
        try:
            hex_bytes = bytes.fromhex(match.replace("\\x", ""))
            decoded = hex_bytes.decode("utf-8", errors="ignore")
            if decoded and any(c.isalpha() for c in decoded):
                decoded_variants.append({
                    "encoding": "hex",
                    "original": match[:80],
                    "decoded": decoded[:MAX_DECODED_SCAN_LENGTH],
                })
        except Exception:
            pass

    # --- ROT13 ---
    # Try ROT13 on individual long alpha tokens
    rot13_candidate_pattern = r"[A-Za-z]{8,}"
    for match in re.findall(rot13_candidate_pattern, text):
        try:
            decoded = codecs.decode(match, "rot_13")
            if decoded != match and decoded.lower() != match.lower():
                decoded_variants.append({
                    "encoding": "rot13",
                    "original": match[:80],
                    "decoded": decoded[:MAX_DECODED_SCAN_LENGTH],
                })
        except Exception:
            pass

    # Also try full-text ROT13 if text is mostly alphabetic
    alpha_ratio = sum(1 for c in text if c.isalpha()) / max(len(text), 1)
    if alpha_ratio > 0.6 and len(text) > 10:
        try:
            full_rot13 = codecs.decode(text, "rot_13")
            if full_rot13 != text and full_rot13.lower() != text.lower():
                decoded_variants.append({
                    "encoding": "rot13_full",
                    "original": text[:80],
                    "decoded": full_rot13[:MAX_DECODED_SCAN_LENGTH],
                })
        except Exception:
            pass

    # --- URL encoding (%49%67%6E ...) ---
    url_pattern = r"(?:%[0-9a-fA-F]{2}){3,}"
    for match in re.findall(url_pattern, text):
        try:
            decoded = urllib.parse.unquote(match)
            if decoded and decoded != match:
                decoded_variants.append({
                    "encoding": "url",
                    "original": match[:80],
                    "decoded": decoded[:MAX_DECODED_SCAN_LENGTH],
                })
        except Exception:
            pass

    # Also try full-text URL decode if text has percent-encoding
    if "%" in text:
        try:
            full_decoded = urllib.parse.unquote(text)
            if full_decoded != text and full_decoded.lower() != text.lower():
                decoded_variants.append({
                    "encoding": "url_full",
                    "original": text[:80],
                    "decoded": full_decoded[:MAX_DECODED_SCAN_LENGTH],
                })
        except Exception:
            pass

    # --- HTML entities (&#105;gnore, &amp;, &#x69;) ---
    if "&" in text and (";" in text):
        try:
            decoded = html_module.unescape(text)
            if decoded != text:
                decoded_variants.append({
                    "encoding": "html_entity",
                    "original": text[:80],
                    "decoded": decoded[:MAX_DECODED_SCAN_LENGTH],
                })
        except Exception:
            pass

    # --- Unicode escapes (\u0069\u0067\u006E ...) ---
    unicode_pattern = r"(?:\\u[0-9a-fA-F]{4}){3,}"
    for match in re.findall(unicode_pattern, text):
        try:
            decoded = match.encode("utf-8").decode("unicode_escape")
            if decoded and decoded != match and any(c.isalpha() for c in decoded):
                decoded_variants.append({
                    "encoding": "unicode_escape",
                    "original": match[:80],
                    "decoded": decoded[:MAX_DECODED_SCAN_LENGTH],
                })
        except Exception:
            pass

    return decoded_variants


def detect_base64(text: str, scan_text_for_patterns_fn=None) -> List[Dict]:
    """Detect suspicious base64 encoded content.
    Two-tier detection:
      Tier 1: Expanded keyword list (~40 terms covering ops + content safety)
      Tier 2: Feed decoded text through full pattern engine (if scan function provided)
    """
    b64_pattern = r"[A-Za-z0-9+/]{16,}={0,2}"
    matches = re.findall(b64_pattern, text)

    suspicious = []
    # Tier 1: Expanded danger words (operational + content safety)
    danger_words = [
        # Operational
        "delete", "execute", "ignore", "system", "admin", "rm ", "curl",
        "wget", "eval", "password", "token", "key", "sudo", "chmod",
        "chown", "kill", "drop", "truncate", "shutdown", "reboot",
        "override", "bypass", "disable", "credential", "secret",
        # Content safety
        "bomb", "weapon", "exploit", "malware", "ransomware", "phishing",
        "hack", "crack", "steal", "attack", "inject", "poison",
        "drug", "cocaine", "heroin", "fentanyl",
        # Prompt injection
        "pretend", "jailbreak", "roleplay", "godmode", "instruction",
        "prompt", "forget", "disregard",
    ]

    for match in matches:
        try:
            decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
            if not decoded or not any(c.isalpha() for c in decoded):
                continue

            tier1_hit = any(word in decoded.lower() for word in danger_words)

            # Tier 2: Run decoded content through the full pattern engine
            tier2_hit = False
            tier2_reasons = []
            tier2_severity = Severity.SAFE
            if scan_text_for_patterns_fn:
                tier2_reasons, _, tier2_severity = scan_text_for_patterns_fn(decoded)
                tier2_hit = bool(tier2_reasons)

            if tier1_hit or tier2_hit:
                suspicious.append(
                    {
                        "encoded": match[:40] + ("..." if len(match) > 40 else ""),
                        "decoded_preview": decoded[:60]
                        + ("..." if len(decoded) > 60 else ""),
                        "danger_words": [
                            w for w in danger_words if w in decoded.lower()
                        ],
                        "pattern_matches": tier2_reasons[:5] if tier2_hit else [],
                        "pattern_severity": tier2_severity.name if tier2_hit else None,
                    }
                )
        except Exception:
            pass

    return suspicious
