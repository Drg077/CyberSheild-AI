"""Keep API tests deterministic and offline; domain lookups have unit tests."""
import pytest
from backend.services.domain_verification_service import (
    DomainVerificationResult,
    domain_verification_service,
)


@pytest.fixture(autouse=True)
def disable_live_domain_verification(monkeypatch):
    def unavailable(url):
        return DomainVerificationResult(
            domain="test.invalid",
            registered_domain="test.invalid",
            registration_status="registered",
            registration_date=None,
            domain_age_days=None,
            dns_status="resolves",
            dns_addresses=["203.0.113.10"],
            tls_status="valid",
            tls_issuer=None,
            tls_expires_at=None,
            description="Deterministic offline test response.",
        )

    monkeypatch.setattr(domain_verification_service, "evaluate", unavailable)
