"""
Domain Reputation and Popularity Evaluation Service.
Provides domain authority and ranking evidence (e.g., Tranco/Umbrella top-domain metrics).

CRITICAL POLICY:
Domain popularity is NOT proof of safety.
Established domain -> positive supporting evidence (reduces apex-domain false-positive penalty).
Unknown domain -> neutral / unknown evidence.
Known malicious domain -> strong negative evidence.
A malicious path or credential-harvesting subfolder on a popular domain MUST remain detectable.
"""
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import json
import logging

from backend.config import settings

logger = logging.getLogger(__name__)

TOP_DOMAINS_PATH = settings.DATA_DIR / "reputation" / "top_domains.json"

@dataclass
class DomainReputationResult:
    domain: str
    registered_domain: str
    status: str  # "established", "unknown", "malicious"
    rank: Optional[int]
    description: str
    is_established: bool
    reputation_score: float  # [0.0, 1.0] where 1.0 = high authority, 0.5 = neutral, 0.0 = suspicious/malicious

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class DomainReputationService:
    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or TOP_DOMAINS_PATH
        self.top_domains: Dict[str, int] = {}
        self._load_top_domains()

    def _load_top_domains(self):
        if self.data_path.exists():
            try:
                with open(self.data_path, "r", encoding="utf-8") as f:
                    self.top_domains = json.load(f)
                logger.info(f"Loaded {len(self.top_domains)} top domains into reputation service.")
            except Exception as e:
                logger.warning(f"Could not load top domains from {self.data_path}: {e}")
                self.top_domains = {}
        else:
            logger.info("Top domains dataset not found; operating in neutral reputation mode.")

    @staticmethod
    def extract_domains(url: str) -> tuple[str, str]:
        """
        Extracts both clean hostname and registered domain (apex domain) from URL.
        Example: 'https://sub.bank.github.com/repo' -> ('sub.bank.github.com', 'github.com')
        """
        raw = str(url).strip()
        if not (raw.startswith("http://") or raw.startswith("https://")):
            raw = "http://" + raw
        try:
            netloc = urlparse(raw).netloc.split(":")[0].lower()
            if netloc.startswith("www."):
                netloc = netloc[4:]
        except Exception:
            netloc = ""

        if not netloc:
            return "", ""

        parts = netloc.split(".")
        if len(parts) >= 2:
            # Handle standard two-part TLDs (e.g., co.uk, com.au) vs normal (example.com)
            two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au", "co.in", "gov.in", "ac.in"}
            joined_last_two = ".".join(parts[-2:])
            if joined_last_two in two_part_tlds and len(parts) >= 3:
                registered = ".".join(parts[-3:])
            else:
                registered = ".".join(parts[-2:])
        else:
            registered = netloc

        return netloc, registered

    def evaluate(self, url: str) -> DomainReputationResult:
        """
        Evaluates domain popularity and authority evidence.
        """
        hostname, reg_domain = self.extract_domains(url)

        if not hostname:
            return DomainReputationResult(
                domain="",
                registered_domain="",
                status="unknown",
                rank=None,
                description="Invalid or missing domain structure",
                is_established=False,
                reputation_score=0.5
            )

        # Check registered domain first, then full hostname
        rank = self.top_domains.get(reg_domain) or self.top_domains.get(hostname)

        if rank is not None:
            # Domain is verified in the established/popular top registry
            score = max(0.60, min(1.0, 1.0 - (rank / 100000.0)))
            return DomainReputationResult(
                domain=hostname,
                registered_domain=reg_domain,
                status="established",
                rank=rank,
                description=f"Established domain in global authority index (Rank #{rank:,})",
                is_established=True,
                reputation_score=round(score, 3)
            )

        return DomainReputationResult(
            domain=hostname,
            registered_domain=reg_domain,
            status="unknown",
            rank=None,
            description="Standard unranked domain (neutral reputation signal)",
            is_established=False,
            reputation_score=0.5
        )

# Global singleton
domain_reputation_service = DomainReputationService()
