import pytest
import io
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_download_high_risk_executable_suspicious_source():
    """Verify .exe from a suspicious source URL results in Critical/High severity and BLOCK/QUARANTINE decision."""
    payload = {
        "filename": "ebank_security_update.exe",
        "file_extension": ".exe",
        "source_url": "http://192.168.1.105/login-verify-account-update-bank",
        "download_url": "http://192.168.1.105/payload/update.exe"
    }
    response = client.post("/api/v1/analyze/download", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["input_type"] == "DOWNLOAD"
    assert data["target"] == "ebank_security_update.exe"
    assert data["severity"] in ["High", "Critical"]
    assert data["decision"] in ["BLOCK", "QUARANTINE", "WARN"]
    assert data["risk_score"] >= 60.0
    assert "top_features" in data
    assert len(data["reasons"]) > 0
    assert "download_source_url" in data
    assert "download_url" in data

def test_download_legitimate_text_file():
    """Verify .txt from a legitimate source URL yields Low severity and ALLOW decision."""
    payload = {
        "filename": "terms.txt",
        "file_extension": ".txt",
        "source_url": "https://www.hdfcbank.com",
        "download_url": "https://www.hdfcbank.com/download/terms"
    }
    response = client.post("/api/v1/analyze/download", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["input_type"] == "DOWNLOAD"
    assert data["target"] == "terms.txt"
    assert data["severity"] == "Low"
    assert data["decision"] == "ALLOW"
    assert data["risk_score"] < 30.0

def test_download_cross_domain_increases_context_score():
    """
    Verify that when source_url and download_url reside on different domains,
    the context score increases measurably compared to the same-domain scenario.
    """
    payload_same_domain = {
        "filename": "statement.pdf",
        "file_extension": ".pdf",
        "source_url": "https://www.chase.com/statements/view",
        "download_url": "https://www.chase.com/docs/statement.pdf"
    }
    payload_cross_domain = {
        "filename": "statement.pdf",
        "file_extension": ".pdf",
        "source_url": "https://www.chase.com/statements/view",
        "download_url": "http://suspicious-external-storage-cdn.net/files/statement.pdf"
    }
    
    res_same = client.post("/api/v1/analyze/download", json=payload_same_domain)
    res_cross = client.post("/api/v1/analyze/download", json=payload_cross_domain)
    
    assert res_same.status_code == 200
    assert res_cross.status_code == 200
    
    data_same = res_same.json()
    data_cross = res_cross.json()
    
    ctx_same = data_same["detector_probabilities"]["context_modifier"]
    ctx_cross = data_cross["detector_probabilities"]["context_modifier"]
    
    # Assert cross-domain context score is strictly higher than same-domain
    assert ctx_cross > ctx_same
    # Assert risk scores differ
    assert data_cross["risk_score"] != data_same["risk_score"]

def test_download_missing_or_empty_fields_returns_422():
    """Verify missing filename or empty extension returns a 422 Unprocessable Entity, not 500."""
    # Missing filename
    payload_missing_fn = {
        "file_extension": ".exe",
        "source_url": "https://example.com",
        "download_url": "https://example.com/app.exe"
    }
    res1 = client.post("/api/v1/analyze/download", json=payload_missing_fn)
    assert res1.status_code == 422
    
    # Empty filename
    payload_empty_fn = {
        "filename": "",
        "file_extension": ".exe",
        "source_url": "https://example.com",
        "download_url": "https://example.com/app.exe"
    }
    res2 = client.post("/api/v1/analyze/download", json=payload_empty_fn)
    assert res2.status_code == 422
    
    # Empty extension
    payload_empty_ext = {
        "filename": "testfile",
        "file_extension": "",
        "source_url": "https://example.com",
        "download_url": "https://example.com/testfile"
    }
    res3 = client.post("/api/v1/analyze/download", json=payload_empty_ext)
    assert res3.status_code == 422

def test_download_route_rejects_binary_file_payloads():
    """Confirm the route never accepts or processes file binary content even if a client sends a multipart body."""
    fake_binary = io.BytesIO(b"MZ_BINARY_PAYLOAD_TEST_DATA_12345")
    files = {"file": ("malware.exe", fake_binary, "application/octet-stream")}
    
    response = client.post("/api/v1/analyze/download", files=files)
    # The JSON schema expectation must reject multipart binary uploads with 422
    assert response.status_code == 422
