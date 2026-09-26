"""
Comprehensive Automated Tests for URL Hardening, Threat Intelligence,
Domain Reputation, and Evidence-Based Three-State Assessment.

All external API interactions are strictly mocked to guarantee 100% offline, deterministic execution.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.threat_intel_service import ThreatIntelService, ThreatIntelResult
from risk_engine.domain_reputation import DomainReputationService, DomainReputationResult
from risk_engine.thresholds import SeverityLevel
from risk_engine.decision_policy import DecisionPolicy

client = TestClient(app)

def test_unranked_security_update_domain_is_not_called_legitimate():
    """Unknown reputation plus phishing-like lexical evidence stays cautious."""
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "https://portal-security-update.net"}
    )
    assert response.status_code == 200
    data = response.json()

    assert data["prediction"] == "Suspicious / Unknown"
    assert data["final_assessment"] == "SUSPICIOUS / UNKNOWN"
    assert data["severity"] == "Medium"
    assert data["decision"] == "CAUTION"
    assert data["domain_reputation"]["status"] == "unknown"
    assert data["context_score"] >= 0.3
    assert data["prediction_likelihood_label"] == "Model Phishing Likelihood"

@pytest.mark.parametrize("url", [
    "https://view-shared-document.com",
    "https://portal-security-update.net",
])
def test_unranked_suspicious_domain_stays_unknown(url):
    response = client.post("/api/v1/analyze/url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "Suspicious / Unknown"
    assert data["final_assessment"] == "SUSPICIOUS / UNKNOWN"
    assert data["severity"] == "Medium"
    assert data["decision"] == "CAUTION"

@pytest.mark.parametrize("text", ["hello", "fake url", "????????????????????????????????/"])
def test_plain_text_is_rejected_as_not_a_url(text):
    response = client.post("/api/v1/analyze/url", json={"url": text})
    assert response.status_code == 422

def test_unverified_status_keeps_domain_cautious_without_fake_model_probability():
    from backend.services.domain_verification_service import DomainVerificationResult

    unavailable = DomainVerificationResult(
        domain="example.com",
        registered_domain="example.com",
        registration_status="reserved",
        registration_date=None,
        domain_age_days=None,
        dns_status="resolves",
        dns_addresses=["203.0.113.10"],
        tls_status="valid",
        tls_issuer="Test CA",
        tls_expires_at=None,
        description="Reserved documentation domain.",
    )
    with patch("backend.services.threat_service.domain_verification_service.evaluate", return_value=unavailable):
        response = client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "Suspicious / Unknown"
    assert 15 <= data["risk_score"] < 30
    assert data["prediction_likelihood"] == data["probability"]
    assert data["prediction_likelihood_label"] == "Model Phishing Likelihood"
    assert data["domain_verification"]["registration_status"] == "reserved"

def test_url_score_breakdown_matches_returned_values_and_history():
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "https://portal-security-update.net/account/login"},
    )
    assert response.status_code == 200
    data = response.json()
    breakdown = data["risk_score_breakdown"]

    assert breakdown["model_phishing_probability"] == data["probability"]
    assert breakdown["context_score"] == data["context_score"]
    assert breakdown["feature_risk"] >= 0
    assert breakdown["domain_evidence_capped"] <= 30
    assert breakdown["model_input"] == "complete URL"
    assert breakdown["displayed_likelihood"] == data["prediction_likelihood"]

    detail = client.get(f"/api/v1/history/{data['id']}")
    assert detail.status_code == 200
    assert detail.json()["risk_score_breakdown"] == breakdown

def test_document_sharing_language_on_unknown_domain_is_cautioned():
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "https://view-shared-document.com"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["context_score"] >= 0.3
    assert data["risk_score"] >= 30.0
    assert data["severity"] == "Medium"
    assert data["decision"] == "CAUTION"
    assert data["prediction"] == "Suspicious / Unknown"
    assert data["context_score"] >= 0.1

def test_long_google_search_query_does_not_inflate_phishing_probability():
    url = (
        "https://www.google.com/search?q=ai&sca_esv=fac01c4ba4c5f10b"
        "&sxsrf=APpeQnsb2A-Ee_6q1QMYOpNeDv3dViJykw%3A1790351631251"
        "&source=chrome.rb&fbs=ABfTbFVyMZGZf1hfvX9uKjN_-G8cxpBkeIeqYwoCbfNVc4vKE6A5_9xraAmHsehE8ybQankQszSTTs2KnlnrcKQ4m3m_Zushp240ZRsrcGAW0iGFG-xMnl5cxfdF99oXgi9-d_n8y7ZSiS4jKj6TFJpnML4CXFUC7YW9EgWXrKTZefLvFjrsWQtq6cAzVZlD8iCOgFjyDl6SW5EPgmPJKuJqfq1515L8iw"
        "&vsint=&aep=1&ntc=1&cs=1&sa=X&ved=2ahUKEwifrIPIi4qXAxVGjeEIHerFMwYQ2J8OegQIEhAD"
        "&biw=1210&bih=740&dpr=2&mstk=AUtExfALFA10s-QBDFr-jfoIRYW67qhj28zmvaxz7denqpAy4vpDS4Lj0H_61yzuXekw1xkpKyJ1eyqCKOEcKqhEBrYJsXJW3KT4SfruRwzjo3V5wOhh6Zu45nkeSCeozCh7GI5jycKwATTM6ai15fY0BxpaoU-ZrjkzqqxsoHvEIkQPxLFt2Kh1KUGh0SPqAMq8BcgtfjuvLirU1uXjz3_neNcQKI63Cu-svMw6S2-DudVkfOaMjkvuPXZhy3cQnIuHHeAL-2JW007KZw"
        "&csuir=1&mtid=EZm2atioFNOphvcPrsuL6As&udm=50"
    )
    response = client.post("/api/v1/analyze/url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "Legitimate"
    assert data["final_assessment"] == "LIKELY LEGITIMATE"
    assert data["probability"] < 0.55
    assert data["domain_reputation"]["is_established"] is True
    assert data["context_score"] == 0.0
    assert data["detector_probabilities"]["p_raw_phishing"] > data["probability"]

def test_combined_strong_ip_url_context_reaches_high_risk():
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "http://192.168.1.1/update-account-bank-security/login.php?user=admin&token=123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["context_score"] >= 0.8
    assert data["risk_score"] >= 60
    assert data["severity"] in ["High", "Critical"]
    assert data["prediction"] == "Phishing"

def test_hardened_legitimate_apex_domain():
    """Verify legitimate apex domain (github.com) receives appropriate risk moderation."""
    response = client.post("/api/v1/analyze/url", json={"url": "https://github.com"})
    assert response.status_code == 200
    data = response.json()

    assert data["target"] == "https://github.com"
    # Should not be blindly blocked as Critical/Malicious
    assert data["decision"] in ["ALLOW", "CAUTION"]
    assert data["domain_reputation"]["status"] == "established"
    assert data["final_assessment"] in ["LIKELY LEGITIMATE", "SUSPICIOUS / UNKNOWN"]
    assert len(data["top_features"]) == 5

def test_hardened_legitimate_repo_path():
    """Verify legitimate deep path on established domain evaluates as Low / Likely Legitimate."""
    response = client.post("/api/v1/analyze/url", json={"url": "https://github.com/Drg077/CyberSheild-AI"})
    assert response.status_code == 200
    data = response.json()

    assert data["severity"] == "Low"
    assert data["decision"] == "ALLOW"
    assert data["risk_score"] < 25.0
    assert data["final_assessment"] == "LIKELY LEGITIMATE"
    assert data["domain_reputation"]["is_established"] is True

def test_hardened_legitimate_kernel_repo():
    """Verify https://github.com/torvalds/linux evaluates as Low / Likely Legitimate."""
    response = client.post("/api/v1/analyze/url", json={"url": "https://github.com/torvalds/linux"})
    assert response.status_code == 200
    data = response.json()

    assert data["severity"] == "Low"
    assert data["decision"] == "ALLOW"
    assert data["risk_score"] < 25.0
    assert data["final_assessment"] == "LIKELY LEGITIMATE"

def test_suspicious_ip_login_url():
    """Strong IP and credential evidence reaches the 70–89 High band."""
    response = client.post("/api/v1/analyze/url", json={"url": "http://192.168.1.1/login.php"})
    assert response.status_code == 200
    data = response.json()

    assert data["severity"] == "High"
    assert data["decision"] == "WARN"
    assert 70.0 <= data["risk_score"] < 90.0
    assert data["final_assessment"] == "MALICIOUS"

def test_deceptive_subdomain_phishing():
    """Verify paypal deceptive subdomain URL evaluates as Critical / Block / Malicious."""
    response = client.post("/api/v1/analyze/url", json={"url": "https://paypal.com.verify-account.info/login"})
    assert response.status_code == 200
    data = response.json()

    assert data["severity"] in ["High", "Critical"]
    assert data["decision"] in ["WARN", "BLOCK"]
    assert data["final_assessment"] == "MALICIOUS"

def test_threat_intel_unconfigured_default():
    """Verify default behavior when threat intelligence API keys are absent."""
    service = ThreatIntelService()
    res = service.check_url("https://example-test-bank.com")
    assert res.status == "not_configured"
    assert res.is_threat is False
    assert "not configured" in res.description.lower()

def test_threat_intel_mocked_confirmed_threat():
    """Verify confirmed threat from external intelligence feed overrides to Malicious."""
    mock_result = ThreatIntelResult(
        status="confirmed_threat",
        source="google_web_risk",
        is_threat=True,
        details={"threat_types": ["SOCIAL_ENGINEERING"]},
        description="Confirmed threat in Google Web Risk database (SOCIAL_ENGINEERING)"
    )

    with patch("backend.services.threat_service.threat_intel_service.check_url", return_value=mock_result):
        response = client.post("/api/v1/analyze/url", json={"url": "https://subtle-phish-domain.com/auth"})
        assert response.status_code == 200
        data = response.json()

        assert data["threat_intel"]["status"] == "confirmed_threat"
        assert data["threat_intel"]["is_threat"] is True
        assert data["risk_score"] >= 90.0
        assert data["severity"] == "Critical"
        assert data["final_assessment"] == "MALICIOUS"

def test_threat_intel_mocked_no_known_threat():
    """Verify 'no known threat' does NOT claim guaranteed legitimacy."""
    mock_result = ThreatIntelResult(
        status="no_known_threat",
        source="google_web_risk",
        is_threat=False,
        description="No threat record found in Google Web Risk"
    )

    with patch("backend.services.threat_service.threat_intel_service.check_url", return_value=mock_result):
        response = client.post("/api/v1/analyze/url", json={"url": "https://unknown-unregistered-site-test.xyz"})
        assert response.status_code == 200
        data = response.json()

        assert data["threat_intel"]["status"] == "no_known_threat"
        assert data["threat_intel"]["is_threat"] is False
        assert "no threat record found" in data["threat_intel"]["description"].lower()

def test_threat_intel_mocked_timeout_failure_safety():
    """Verify network timeout degrades gracefully to unavailable without raising 500 error."""
    mock_result = ThreatIntelResult(
        status="unavailable",
        source="google_web_risk",
        is_threat=False,
        details={"error": "timed out"},
        description="Google Web Risk service unavailable (network timeout/offline)"
    )

    with patch("backend.services.threat_service.threat_intel_service.check_url", return_value=mock_result):
        response = client.post("/api/v1/analyze/url", json={"url": "https://normal-check-bank.com"})
        assert response.status_code == 200
        data = response.json()

        assert data["threat_intel"]["status"] == "unavailable"
        assert data["threat_intel"]["is_threat"] is False

def test_conflicting_evidence_popular_domain_with_threat_intel_hit():
    """Verify that a confirmed threat intelligence hit on a popular domain is NOT excused."""
    mock_hit = ThreatIntelResult(
        status="confirmed_threat",
        source="phishtank",
        is_threat=True,
        details={"phish_id": 99999},
        description="Confirmed active phishing URL in PhishTank database"
    )

    with patch("backend.services.threat_service.threat_intel_service.check_url", return_value=mock_hit):
        response = client.post("/api/v1/analyze/url", json={"url": "https://github.com/compromised-account/phish"})
        assert response.status_code == 200
        data = response.json()

        assert data["domain_reputation"]["is_established"] is True
        assert data["threat_intel"]["is_threat"] is True
        # Confirmed threat MUST override domain popularity!
        assert data["severity"] == "Critical"
        assert data["final_assessment"] == "MALICIOUS"

def test_shap_explanation_integrity_with_evidence():
    """Verify SHAP attributions continue to explain the 20 model features independently."""
    response = client.post("/api/v1/analyze/url", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()

    assert "evidence_breakdown" in data
    assert "ml_evidence" in data["evidence_breakdown"]
    assert "threat_intel_evidence" in data["evidence_breakdown"]
    assert "domain_evidence" in data["evidence_breakdown"]
    assert "final_assessment" in data["evidence_breakdown"]
    assert len(data["top_features"]) == 5
    for feat in data["top_features"]:
        assert "feature" in feat
        assert "shap_value" in feat
        assert "absolute_impact" in feat
