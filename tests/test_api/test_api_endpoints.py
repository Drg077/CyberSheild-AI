import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app
from database.db_session import SessionLocal
from database.models import ThreatAnalysisRecord

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
    assert data["url_schema_version"] == "v1.0.0"

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
    """Verify validation error when URL is empty."""
    response = client.post("/api/v1/analyze/url", json={"url": ""})
    assert response.status_code == 422

def test_history_endpoints():
    """Verify prediction records are recorded in database and retrievable via GET /api/v1/history."""
    # Run a test scan to ensure history exists
    client.post("/api/v1/analyze/url", json={"url": "https://www.chase.com"})
    
    response = client.get("/api/v1/history?limit=10")
    assert response.status_code == 200
    items = response.json()
    assert len(items) > 0
    assert "target" in items[0]
    assert "risk_score" in items[0]
    
    # Test detail lookup
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

def test_file_upload_corrupt_binary():
    """Verify safe error response for corrupt binary."""
    files = {"file": ("corrupt.exe", b"NOT_A_PE_HEADER" * 20, "application/octet-stream")}
    response = client.post("/api/v1/analyze/file", files=files)
    assert response.status_code == 400
    assert "not a valid PE" in response.json()["detail"]

def test_file_upload_valid_pe():
    """Verify static analysis on valid test PE binary."""
    pe_file = FIXTURES_DIR / "sample_benign.exe"
    assert pe_file.exists()
    
    with open(pe_file, "rb") as f:
        files = {"file": ("sample_benign.exe", f, "application/x-msdownload")}
        response = client.post("/api/v1/analyze/file", files=files)
        
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "FILE"
    assert data["target"] == "sample_benign.exe"
    assert data["file_sha256"] is not None
    assert len(data["file_sha256"]) == 64
    assert 0.0 <= data["risk_score"] <= 100.0
    assert len(data["top_features"]) == 5
    assert len(data["reasons"]) == 5
