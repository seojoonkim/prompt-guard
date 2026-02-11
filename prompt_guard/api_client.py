"""
Prompt Guard - API Client (v3.2.0)

THIS MODULE IS OPTIONAL.
Prompt Guard works fully offline with 577+ bundled patterns.
Use this module only if you want live pattern updates or threat reporting.

    # Core usage (no API needed):
    from prompt_guard import PromptGuard
    guard = PromptGuard()
    result = guard.analyze("message")   # works 100% offline

    # Optional API-enhanced usage:
    from prompt_guard.api_client import PGAPIClient
    client = PGAPIClient()
    if client.has_updates():
        patterns = client.fetch_patterns("critical")

Pattern Updates (PULL-ONLY):
    - Fetches latest pattern YAML files from PG_API server
    - Verifies integrity via SHA-256 checksums
    - Zero user data sent to server

Threat Reporting (OPT-IN):
    - Sends anonymized threat data (hash, severity, category only)
    - NEVER sends raw message content
    - Anonymous by default (no user identification)
"""

import hashlib
import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger("prompt_guard.api")

# Default API endpoint (can be overridden via env var or config)
DEFAULT_API_URL = "https://pg-api.vercel.app"

# Timeout for API requests (seconds)
REQUEST_TIMEOUT = 10


class PGAPIClient:
    """
    Bidirectional API client for Prompt Guard pattern delivery
    and anonymized threat intelligence reporting.

    Security Design:
        - Pattern fetch: PULL-ONLY, no user data sent
        - Threat reports: NEVER include raw message text
        - All data is anonymized (hashes only)
        - No authentication tokens stored on client
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        client_version: str = "3.2.0",
        reporting_enabled: bool = False,
    ):
        self.api_url = (
            api_url
            or os.environ.get("PG_API_URL")
            or DEFAULT_API_URL
        ).rstrip("/")
        self.client_version = client_version
        self.reporting_enabled = reporting_enabled
        self._manifest_cache: Optional[Dict] = None

    # -------------------------------------------------------------------------
    # Pattern Fetch (PULL-ONLY — zero user data sent)
    # -------------------------------------------------------------------------

    def get_manifest(self) -> Optional[Dict]:
        """
        Fetch the pattern manifest (versions + checksums for all tiers).
        Used to check if local patterns need updating.

        Returns:
            Manifest dict with tier checksums, or None on failure.
        """
        try:
            url = f"{self.api_url}/api/patterns?tier=manifest"
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "X-PG-Client-Version": self.client_version,
                },
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "ok":
                    self._manifest_cache = data["data"]
                    return self._manifest_cache
        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to fetch manifest: %s", e)
        return None

    def fetch_patterns(self, tier: str = "critical") -> Optional[Dict]:
        """
        Fetch pattern YAML content for a specific tier.

        Args:
            tier: "critical", "high", or "medium"

        Returns:
            Dict with {tier, version, checksum, content}, or None on failure.
        """
        if tier not in ("critical", "high", "medium"):
            logger.error("Invalid tier: %s", tier)
            return None

        try:
            url = f"{self.api_url}/api/patterns?tier={tier}"
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "X-PG-Client-Version": self.client_version,
                },
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "ok":
                    pattern_data = data["data"]

                    # Verify checksum integrity
                    content = pattern_data.get("content", "")
                    expected_checksum = pattern_data.get("checksum", "")
                    actual_checksum = hashlib.sha256(
                        content.encode("utf-8")
                    ).hexdigest()[:16]

                    if actual_checksum != expected_checksum:
                        logger.error(
                            "Checksum mismatch for tier %s: "
                            "expected=%s, actual=%s",
                            tier, expected_checksum, actual_checksum,
                        )
                        return None

                    return pattern_data
        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to fetch patterns for tier %s: %s", tier, e)
        return None

    def has_updates(self, local_checksums: Optional[Dict[str, str]] = None) -> bool:
        """
        Check if remote patterns are newer than local patterns.

        Args:
            local_checksums: Dict of {tier: checksum} for local patterns.
                             If None, always returns True.

        Returns:
            True if updates are available.
        """
        if local_checksums is None:
            return True

        manifest = self.get_manifest()
        if not manifest:
            return False

        for tier, info in manifest.get("tiers", {}).items():
            remote_checksum = info.get("checksum", "")
            local_checksum = local_checksums.get(tier, "")
            if remote_checksum != local_checksum:
                return True

        return False

    # -------------------------------------------------------------------------
    # Threat Reporting (OPT-IN — anonymized data only)
    # -------------------------------------------------------------------------

    def report_threat(self, detection_result: Any) -> bool:
        """
        Report an anonymized threat detection to the collective intelligence API.

        SECURITY: This method NEVER sends raw message content.
        Only sends: message hash, severity, category, pattern count, timestamp.

        Args:
            detection_result: A DetectionResult object from PromptGuard.analyze()

        Returns:
            True if report was accepted, False otherwise.
        """
        if not self.reporting_enabled:
            return False

        try:
            # Build anonymized report (NO raw message content)
            report = {
                "messageHash": getattr(
                    detection_result, "fingerprint", "unknown"
                ),
                "severity": getattr(
                    detection_result, "severity", "unknown"
                ),
                "category": (
                    detection_result.reasons[0]
                    if hasattr(detection_result, "reasons")
                    and detection_result.reasons
                    else "other"
                ),
                "patternsMatched": len(
                    getattr(detection_result, "patterns_matched", [])
                ),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "clientVersion": self.client_version,
            }

            # Handle severity enum
            if hasattr(report["severity"], "name"):
                report["severity"] = report["severity"].name.lower()

            payload = json.dumps(report).encode("utf-8")

            url = f"{self.api_url}/api/reports"
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-PG-Client-Version": self.client_version,
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("status") == "ok"

        except (urllib.error.URLError, json.JSONDecodeError) as e:
            logger.debug("Failed to report threat: %s", e)
            return False

    # -------------------------------------------------------------------------
    # Health Check
    # -------------------------------------------------------------------------

    def health_check(self) -> Optional[Dict]:
        """
        Check API server health and availability.

        Returns:
            Health status dict, or None if server is unreachable.
        """
        try:
            url = f"{self.api_url}/api/health"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            logger.warning("Health check failed: %s", e)
            return None
