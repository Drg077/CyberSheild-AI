"""Best-effort domain registration, DNS, and TLS verification.

This service never fetches the submitted web page. It queries IANA's RDAP
bootstrap registry and the selected registry, resolves DNS, and optionally
performs a certificate-verifying TLS handshake. These checks establish
registration/connectivity facts, not that a site is benign.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from ipaddress import ip_address
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
import json
import logging
import socket
import ssl
import threading

from risk_engine.domain_reputation import domain_reputation_service

logger = logging.getLogger(__name__)

IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
LOOKUP_TIMEOUT_SECONDS = 2.5
CACHE_SECONDS = 600
RESERVED_EXAMPLE_DOMAINS = {"example.com", "example.net", "example.org"}


@dataclass
class DomainVerificationResult:
    domain: str
    registered_domain: str
    registration_status: str
    registration_date: Optional[str]
    domain_age_days: Optional[int]
    dns_status: str
    dns_addresses: list[str]
    tls_status: str
    tls_issuer: Optional[str]
    tls_expires_at: Optional[str]
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DomainVerificationService:
    def __init__(self):
        self._cache: Dict[str, tuple[DomainVerificationResult, datetime]] = {}
        self._rdap_services: Optional[Dict[str, str]] = None
        self._lock = threading.Lock()

    def _cached(self, domain: str) -> Optional[DomainVerificationResult]:
        with self._lock:
            item = self._cache.get(domain)
            if item and datetime.now(timezone.utc) < item[1]:
                return item[0]
            self._cache.pop(domain, None)
        return None

    def _store(self, domain: str, result: DomainVerificationResult) -> DomainVerificationResult:
        with self._lock:
            if len(self._cache) > 1000:
                self._cache.clear()
            self._cache[domain] = (
                result,
                datetime.now(timezone.utc) + timedelta(seconds=CACHE_SECONDS),
            )
        return result

    def _bootstrap(self) -> Dict[str, str]:
        if self._rdap_services is not None:
            return self._rdap_services
        request = Request(IANA_RDAP_BOOTSTRAP, headers={"Accept": "application/json", "User-Agent": "CyberShield-AI/1.0"})
        with urlopen(request, timeout=LOOKUP_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
        services: Dict[str, str] = {}
        for suffixes, base_urls in data.get("services", []):
            https_urls = [base for base in base_urls if base.startswith("https://")]
            if not https_urls:
                continue
            for suffix in suffixes:
                services[str(suffix).lower()] = https_urls[0]
        self._rdap_services = services
        return services

    def _rdap_record(self, domain: str) -> tuple[str, Optional[str], Optional[int], str]:
        try:
            tld = domain.rsplit(".", 1)[-1].lower()
            base = self._bootstrap().get(tld)
            if not base:
                return "unsupported", None, None, "No RDAP service is listed for this top-level domain."
            endpoint = base.rstrip("/") + "/domain/" + quote(domain, safe=".-")
            request = Request(endpoint, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "CyberShield-AI/1.0"})
            with urlopen(request, timeout=LOOKUP_TIMEOUT_SECONDS) as response:
                record = json.loads(response.read().decode("utf-8"))
            created = next((event.get("eventDate") for event in record.get("events", []) if event.get("eventAction", "").lower() in {"registration", "registered"}), None)
            age_days = None
            if created:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = max(0, (datetime.now(timezone.utc) - created_dt).days)
            return "registered", created, age_days, "Registry returned a domain registration record."
        except HTTPError as exc:
            if exc.code == 404:
                return "not_found", None, None, "The authoritative RDAP service returned no registration record."
            return "unavailable", None, None, f"RDAP service returned HTTP {exc.code}."
        except (URLError, TimeoutError, socket.timeout, OSError, ValueError, json.JSONDecodeError) as exc:
            logger.info("RDAP lookup unavailable for %s: %s", domain, exc)
            return "unavailable", None, None, "Registration lookup was unavailable or timed out."

    @staticmethod
    def _resolve(host: str) -> tuple[str, list[str]]:
        try:
            ip = ip_address(host)
            return "ip_literal", [str(ip)]
        except ValueError:
            pass
        try:
            results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addresses = sorted({result[4][0] for result in results})
            return ("resolves", addresses) if addresses else ("no_records", [])
        except socket.gaierror as exc:
            if exc.errno == socket.EAI_NONAME:
                return "no_records", []
            return "unavailable", []
        except OSError:
            return "unavailable", []

    @staticmethod
    def _check_tls(host: str, addresses: list[str], use_https: bool) -> tuple[str, Optional[str], Optional[str]]:
        if not use_https:
            return "not_checked_http", None, None
        if not addresses:
            return "not_checked_no_dns", None, None
        public_addresses = []
        for address in addresses:
            try:
                if ip_address(address).is_global:
                    public_addresses.append(address)
            except ValueError:
                continue
        if not public_addresses:
            return "not_checked_non_public_address", None, None

        context = ssl.create_default_context()
        last_status = "unavailable"
        for address in public_addresses[:2]:
            raw_socket = None
            try:
                raw_socket = socket.create_connection((address, 443), timeout=LOOKUP_TIMEOUT_SECONDS)
                with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                    cert = tls_socket.getpeercert()
                issuer_parts = [value for group in cert.get("issuer", ()) for key, value in group if key in {"organizationName", "commonName"}]
                issuer = ", ".join(issuer_parts) or "Issuer not disclosed"
                expires = cert.get("notAfter")
                expiry_iso = parsedate_to_datetime(expires).astimezone(timezone.utc).isoformat() if expires else None
                return "valid", issuer, expiry_iso
            except ssl.SSLCertVerificationError:
                last_status = "invalid"
            except (OSError, ssl.SSLError, TimeoutError):
                last_status = "unavailable"
            finally:
                if raw_socket is not None:
                    try:
                        raw_socket.close()
                    except OSError:
                        pass
        return last_status, None, None

    def evaluate(self, url: str) -> DomainVerificationResult:
        parsed = urlsplit(url if "://" in str(url) else f"https://{url}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return DomainVerificationResult("", "", "invalid", None, None, "invalid", [], "not_checked", None, None, "No valid hostname was supplied.")

        cached = self._cached(host)
        if cached:
            return cached

        _, registered_domain = domain_reputation_service.extract_domains(url)
        try:
            ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            registration_status, registration_date, age_days = "not_applicable", None, None
            registration_description = "IP address supplied; domain registration does not apply."
        elif host in RESERVED_EXAMPLE_DOMAINS or registered_domain in RESERVED_EXAMPLE_DOMAINS:
            registration_status, registration_date, age_days = "reserved", None, None
            registration_description = "IANA reserves this example domain for documentation; it is not a production identity."
        elif host.rsplit(".", 1)[-1] in {"test", "invalid", "localhost", "example"}:
            registration_status, registration_date, age_days = "reserved", None, None
            registration_description = "This top-level name is reserved for testing or documentation."
        else:
            registration_status, registration_date, age_days, registration_description = self._rdap_record(registered_domain)

        dns_status, addresses = self._resolve(host)
        tls_status, tls_issuer, tls_expires = self._check_tls(host, addresses, parsed.scheme.lower() == "https")

        if registration_status == "registered":
            description = registration_description
        elif registration_status == "reserved":
            description = registration_description
        elif registration_status == "not_found" and dns_status == "no_records":
            description = "No domain registration record or public DNS address was found."
        else:
            description = "Domain verification is incomplete: " + registration_description

        return self._store(host, DomainVerificationResult(
            domain=host,
            registered_domain=registered_domain,
            registration_status=registration_status,
            registration_date=registration_date,
            domain_age_days=age_days,
            dns_status=dns_status,
            dns_addresses=addresses,
            tls_status=tls_status,
            tls_issuer=tls_issuer,
            tls_expires_at=tls_expires,
            description=description,
        ))


domain_verification_service = DomainVerificationService()
