import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

def test_health_endpoint():
    """Verify health endpoint returns healthy status and metadata."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["phishing_model_loaded"] is True
    assert data["malware_model_loaded"] is True
    assert "message_model_loaded" in data
    assert data["url_schema_version"] == "v1.0.0"
    assert data["message_schema_version"] == "v1.0.0"


def test_analyze_legitimate_url():
    """Verify legitimate banking URL returns Low Risk and ALLOW decision."""
    payload = {"url": "https://www.hdfcbank.com"}
    response = client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["input_type"] == "URL"
    assert data["target"] == "https://www.hdfcbank.com"
    assert data["prediction"] == "Legitimate"
    assert data["probability"] < 0.20
    assert data["risk_score"] < 30.0
    assert data["severity"] == "Low"
    assert data["decision"] == "ALLOW"
    assert len(data["top_features"]) == 5
    assert len(data["reasons"]) == 5
    assert "Safe to proceed" in data["recommendation"]

def test_analyze_phishing_url():
    """Verify suspicious phishing URL returns High/Critical Risk and Warning/Block."""
    payload = {"url": "http://192.168.1.1/update-account-bank-security/login.php?user=admin&token=123"}
    response = client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["input_type"] == "URL"
    assert data["prediction"] == "Phishing"
    assert data["probability"] > 0.70
    assert data["risk_score"] >= 60.0
    assert data["severity"] in ["High", "Critical"]
    assert data["decision"] in ["WARN", "BLOCK"]
    assert len(data["top_features"]) == 5

def test_analyze_url_empty_validation():
    """Verify validation error when URL is empty or whitespace."""
    response = client.post("/api/v1/analyze/url", json={"url": "   "})
    assert response.status_code in [400, 422]

def test_analyze_url_oversized_validation():
    """Verify validation error when URL exceeds maximum allowed limit."""
    oversized_url = "https://bank.com/" + "a" * 3000
    response = client.post("/api/v1/analyze/url", json={"url": oversized_url})
    assert response.status_code in [400, 422]

def test_analyze_unusual_punycode_url():
    """Verify handling of unusual punycode homograph attack URL."""
    puny_url = "https://xn--e1afmkfd.xn--80akhbyknj4f"
    response = client.post("/api/v1/analyze/url", json={"url": puny_url})
    assert response.status_code == 200
    data = response.json()
    assert 0.0 <= data["risk_score"] <= 100.0

def test_history_endpoints():
    """Verify prediction records are recorded in database and retrievable via GET /api/v1/history."""
    client.post("/api/v1/analyze/url", json={"url": "https://www.chase.com"})
    
    response = client.get("/api/v1/history?limit=10")
    assert response.status_code == 200
    items = response.json()
    assert len(items) > 0
    assert "target" in items[0]
    assert "risk_score" in items[0]
    
    rec_id = items[0]["id"]
    detail_res = client.get(f"/api/v1/history/{rec_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == rec_id

def test_file_upload_unsupported_format():
    """Verify rejection of non-PE file extensions."""
    files = {"file": ("test.txt", b"This is a text file, not a PE executable", "text/plain")}
    response = client.post("/api/v1/analyze/file", files=files)
    assert response.status_code == 400
    assert "Unsupported file format" in response.json()["detail"]

def test_file_upload_empty_file():
    """Verify safe rejection when uploaded file is 0 bytes."""
    files = {"file": ("empty.exe", b"", "application/octet-stream")}
    response = client.post("/api/v1/analyze/file", files=files)
    assert response.status_code == 400
    assert "not a valid PE" in response.json()["detail"]

def test_file_upload_corrupt_binary():
    """Verify safe error response for corrupt binary."""
    files = {"file": ("corrupt.exe", b"NOT_A_PE_HEADER" * 20, "application/octet-stream")}
    response = client.post("/api/v1/analyze/file", files=files)
    assert response.status_code == 400
    assert "not a valid PE" in response.json()["detail"]

def test_file_upload_valid_benign_pe():
    """Verify static analysis on valid real benign PE binary."""
    pe_file = FIXTURES_DIR / "real_benign_sample.exe"
    assert pe_file.exists()
    
    with open(pe_file, "rb") as f:
        files = {"file": ("real_benign_sample.exe", f, "application/x-msdownload")}
        response = client.post("/api/v1/analyze/file", files=files)
        
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "FILE"
    assert data["prediction"] == "Benign"
    assert data["target"] == "real_benign_sample.exe"
    assert data["file_sha256"] is not None
    assert len(data["file_sha256"]) == 64
    assert data["risk_score"] < 40.0
    assert len(data["top_features"]) == 5
    assert len(data["reasons"]) == 5

def test_file_upload_malicious_benchmark_pe():
    """Verify static analysis on malicious benchmark PE binary."""
    pe_file = FIXTURES_DIR / "malicious_pe_benchmark.exe"
    assert pe_file.exists()
    
    with open(pe_file, "rb") as f:
        files = {"file": ("malicious_pe_benchmark.exe", f, "application/x-msdownload")}
        response = client.post("/api/v1/analyze/file", files=files)
        
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "FILE"
    assert data["prediction"] == "Malicious"
    assert data["target"] == "malicious_pe_benchmark.exe"
    assert data["risk_score"] >= 70.0
    assert data["decision"] in ["WARN", "QUARANTINE"]

def test_analyze_legitimate_message():
    """Verify legitimate message returns Low/Medium Risk and ALLOW/CAUTION decision."""
    payload = {"text": "Hello John, your monthly credit card statement is now available in your online portal for review. Thank you for banking with us."}
    response = client.post("/api/v1/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["input_type"] == "MESSAGE"
    assert data["risk_score"] < 50.0
    assert len(data["top_features"]) == 5
    assert len(data["reasons"]) == 5
    assert "reasons" in data

def test_analyze_phishing_message():
    """Verify high-urgency credential phishing message returns High/Critical Risk and highlights."""
    payload = {"text": "Dear Customer, your bank account has been suspended immediately! Please verify your password and OTP within 24 hours at http://verify-bank.com to avoid permanent closure."}
    response = client.post("/api/v1/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["input_type"] == "MESSAGE"
    assert data["risk_score"] >= 60.0
    assert data["severity"] in ["High", "Critical"]
    assert data["decision"] in ["WARN", "BLOCK", "QUARANTINE"]
    assert "highlighted_spans" in data
    assert len(data["highlighted_spans"]) > 0

def test_analyze_message_validation():
    """Verify validation on empty, too short (< 10 chars), and oversized (> 10000 chars) messages."""
    # Too short
    res_short = client.post("/api/v1/analyze/message", json={"text": "hi"})
    assert res_short.status_code in [400, 422]
    
    # Whitespace only
    res_ws = client.post("/api/v1/analyze/message", json={"text": "          "})
    assert res_ws.status_code in [400, 422]
    
    # Oversized
    res_over = client.post("/api/v1/analyze/message", json={"text": "A" * 10005})
    assert res_over.status_code in [400, 422]

def test_indicators_legitimate_url():
    """Verify Unified Risk, Legitimate Likelihood, and Contextual Risk on legitimate URL."""
    res = client.post("/api/v1/analyze/url", json={"url": "https://www.hdfcbank.com"})
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert "prediction_likelihood" in data
    assert "prediction_likelihood_label" in data
    assert "context_score" in data
    assert data["prediction"] == "Legitimate"
    assert data["prediction_likelihood_label"] == "Legitimate Likelihood"
    # When probability is low, legitimate likelihood is high (1 - p)
    assert data["prediction_likelihood"] >= 0.75
    assert 0.0 <= data["context_score"] <= 1.0

def test_indicators_phishing_url():
    """Verify Unified Risk, Phishing Likelihood, and Contextual Risk on phishing URL."""
    url = "http://192.168.1.1/update-account-bank-security/login.php?user=admin&token=123"
    res = client.post("/api/v1/analyze/url", json={"url": url})
    assert res.status_code == 200
    data = res.json()
    assert data["prediction"] == "Phishing"
    assert data["prediction_likelihood_label"] == "Phishing Likelihood"
    assert data["prediction_likelihood"] >= 0.70
    assert data["context_score"] >= 0.50
    assert data["risk_score"] >= 60.0

def test_indicators_benign_pe_file():
    """Verify indicators on benign PE file."""
    pe_file = FIXTURES_DIR / "real_benign_sample.exe"
    with open(pe_file, "rb") as f:
        res = client.post("/api/v1/analyze/file", files={"file": ("real_benign_sample.exe", f, "application/octet-stream")})
    assert res.status_code == 200
    data = res.json()
    assert data["prediction"] == "Benign"
    assert data["prediction_likelihood_label"] == "Legitimate Likelihood"
    assert data["prediction_likelihood"] >= 0.70
    assert "context_score" in data
    assert 0.0 <= data["context_score"] <= 1.0

def test_indicators_malicious_pe_file():
    """Verify indicators on malicious PE file."""
    pe_file = FIXTURES_DIR / "malicious_pe_benchmark.exe"
    with open(pe_file, "rb") as f:
        res = client.post("/api/v1/analyze/file", files={"file": ("malicious_pe_benchmark.exe", f, "application/octet-stream")})
    assert res.status_code == 200
    data = res.json()
    assert data["prediction"] == "Malicious"
    assert data["prediction_likelihood_label"] == "Malware Likelihood"
    assert data["prediction_likelihood"] >= 0.80
    assert "context_score" in data

def test_indicators_in_history():
    """Verify history items contain context_score and prediction_likelihood."""
    res = client.get("/api/v1/history?limit=5")
    assert res.status_code == 200
    items = res.json()
    assert len(items) > 0
    first = items[0]
    assert "context_score" in first
    assert "prediction_likelihood" in first
    assert "prediction_likelihood_label" in first

def test_debiased_real_time_url_accuracy():
    """
    Verify real-time prediction accuracy >= 85% across diverse apex, subdomains,
    and genuine phishing URLs without false-positive apex domain bias.
    """
    eval_cases = [
        ("https://github.com", "Legitimate"),
        ("github.com", "Legitimate"),
        ("https://google.com", "Legitimate"),
        ("https://amazon.com", "Legitimate"),
        ("https://netflix.com", "Legitimate"),
        ("https://apple.com", "Legitimate"),
        ("https://www.hdfcbank.com", "Legitimate"),
        ("http://192.168.1.1/update", "Phishing"),
        ("http://paypal-security-update.tk/login.php", "Phishing"),
        ("http://apple-iforget.com/verify", "Phishing")
    ]
    correct = 0
    for url, expected in eval_cases:
        res = client.post("/api/v1/analyze/url", json={"url": url})
        assert res.status_code == 200
        data = res.json()
        if data["prediction"] == expected:
            correct += 1
    accuracy = correct / len(eval_cases)
    assert accuracy >= 0.85, f"Expected real-time accuracy >= 85%, got {accuracy * 100:.1f}%"



