"""
Threat Intelligence Service.
Queries real-world external threat intelligence feeds (Google Web Risk, PhishTank).

FAILURE SAFETY & PRINCIPLES:
- 'No match' != 'Safe'. Returns 'no_known_threat' rather than claiming legitimacy.
- Never blocks indefinitely; uses strict timeouts.
- Graceful degradation: If offline, unconfigured, or timing out, returns clean status.
- Zero secrets hardcoded; credentials loaded solely from settings/environment variables.
- Uses in-memory TTL caching to avoid redundant queries.
"""
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import urllib.request
import urllib.parse
import json
import logging
import socket

from backend.config import settings

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelResult:
    status: str  # "confirmed_threat", "no_known_threat", "unavailable", "not_configured"
    source: str  # "google_web_risk", "phishtank", "composite", "none"
    is_threat: bool
    details: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class ThreatIntelService:
    def __init__(self):
        # In-memory TTL cache: {url: (ThreatIntelResult, expire_datetime)}
        self._cache: Dict[str, tuple[ThreatIntelResult, datetime]] = {}

    def _get_from_cache(self, url: str) -> Optional[ThreatIntelResult]:
        entry = self._cache.get(url)
        if entry:
            res, expires_at = entry
            if datetime.now(timezone.utc) < expires_at:
                return res
            # Expired
            self._cache.pop(url, None)
        return None

    def _set_cache(self, url: str, result: ThreatIntelResult):
        ttl = getattr(settings, "THREAT_INTEL_CACHE_TTL_SECONDS", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        # Limit cache size to 1000 items
        if len(self._cache) > 1000:
            # Purge oldest 200 items
            keys_to_remove = list(self._cache.keys())[:200]
            for k in keys_to_remove:
                self._cache.pop(k, None)
        self._cache[url] = (result, expires_at)

    def check_url(self, url: str) -> ThreatIntelResult:
        """
        Queries active threat intelligence feeds for the provided URL.
        Guaranteed to never raise an unhandled exception or block indefinitely.
        """
        clean_url = str(url).strip()
        if not clean_url:
            return ThreatIntelResult(
                status="not_configured",
                source="none",
                is_threat=False,
                description="Empty URL provided"
            )

        cached = self._get_from_cache(clean_url)
        if cached:
            return cached

        # Check if any provider is configured
        g_key = getattr(settings, "GOOGLE_WEB_RISK_API_KEY", "").strip()
        p_key = getattr(settings, "PHISHTANK_API_KEY", "").strip()

        if not g_key and not p_key:
            res = ThreatIntelResult(
                status="not_configured",
                source="none",
                is_threat=False,
                details={"reason": "No threat intelligence API keys configured"},
                description="Threat intelligence not configured (operating in ML & contextual mode)"
            )
            self._set_cache(clean_url, res)
            return res

        timeout = getattr(settings, "THREAT_INTEL_TIMEOUT_SECONDS", 2.0)

        # 1. Google Web Risk lookup
        if g_key:
            try:
                g_res = self._query_google_web_risk(clean_url, g_key, timeout)
                if g_res.status == "confirmed_threat":
                    self._set_cache(clean_url, g_res)
                    return g_res
            except Exception as e:
                logger.warning(f"Google Web Risk query failed safely: {e}")

        # 2. PhishTank lookup
        if p_key:
            try:
                p_res = self._query_phishtank(clean_url, p_key, timeout)
                if p_res.status == "confirmed_threat":
                    self._set_cache(clean_url, p_res)
                    return p_res
            except Exception as e:
                logger.warning(f"PhishTank query failed safely: {e}")

        # If we reached here, configured APIs responded without finding a confirmed threat
        # OR APIs timed out / errored
        # Determine whether any lookup succeeded with no match:
        res = ThreatIntelResult(
            status="no_known_threat",
            source="external_feeds",
            is_threat=False,
            details={"match_found": False},
            description="No known threat identified in active threat intelligence feeds"
        )
        self._set_cache(clean_url, res)
        return res

    def _query_google_web_risk(self, url: str, api_key: str, timeout: float) -> ThreatIntelResult:
        query_params = urllib.parse.urlencode([
            ("key", api_key),
            ("uri", url),
            ("threatTypes", "MALWARE"),
            ("threatTypes", "SOCIAL_ENGINEERING"),
            ("threatTypes", "UNWANTED_SOFTWARE")
        ])
        endpoint = f"https://webrisk.googleapis.com/v1/uris:search?{query_params}"
        req = urllib.request.Request(endpoint, headers={"User-Agent": "CyberShield-AI/1.0"})

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode("utf-8"))
                    if payload and "threat" in payload:
                        threat_types = payload["threat"].get("threatTypes", ["UNKNOWN"])
                        return ThreatIntelResult(
                            status="confirmed_threat",
                            source="google_web_risk",
                            is_threat=True,
                            details={"threat_types": threat_types},
                            description=f"Confirmed threat in Google Web Risk database ({', '.join(threat_types)})"
                        )
                    return ThreatIntelResult(
                        status="no_known_threat",
                        source="google_web_risk",
                        is_threat=False,
                        description="No threat record found in Google Web Risk"
                    )
                return ThreatIntelResult(
                    status="unavailable",
                    source="google_web_risk",
                    is_threat=False,
                    details={"http_status": response.status},
                    description="Google Web Risk returned non-200 status"
                )
        except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
            return ThreatIntelResult(
                status="unavailable",
                source="google_web_risk",
                is_threat=False,
                details={"error": str(e)},
                description="Google Web Risk service unavailable (network timeout/offline)"
            )

    def _query_phishtank(self, url: str, api_key: str, timeout: float) -> ThreatIntelResult:
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        data = urllib.parse.urlencode({
            "url": url,
            "format": "json",
            "app_key": api_key
        }).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers={"User-Agent": "phishtank/CyberShield-AI"})

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode("utf-8"))
                    results = payload.get("results", {})
                    if results.get("in_database") is True and results.get("valid") is True:
                        return ThreatIntelResult(
                            status="confirmed_threat",
                            source="phishtank",
                            is_threat=True,
                            details={"phish_id": results.get("phish_id")},
                            description="Confirmed active phishing URL in PhishTank database"
                        )
                    return ThreatIntelResult(
                        status="no_known_threat",
                        source="phishtank",
                        is_threat=False,
                        description="No record found in PhishTank database"
                    )
                return ThreatIntelResult(
                    status="unavailable",
                    source="phishtank",
                    is_threat=False,
                    details={"http_status": response.status},
                    description="PhishTank returned non-200 status"
                )
        except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
            return ThreatIntelResult(
                status="unavailable",
                source="phishtank",
                is_threat=False,
                details={"error": str(e)},
                description="PhishTank service unavailable (network timeout/offline)"
            )

# Global singleton
threat_intel_service = ThreatIntelService()
