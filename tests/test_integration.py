"""
End-to-End Integration Tests covering all 4 core demonstration scenarios:
Scenario 1: Legitimate Banking URL -> Low Risk / Allow
Scenario 2: Phishing URL -> High/Critical Risk / Warning or Block
Scenario 3: Benign PE Binary -> Low Risk / Allow
Scenario 4: Malicious PE Benchmark File -> High/Critical Risk / Quarantine or Block
ALL 4 SCENARIOS EXECUTE THROUGH THE ACTUAL HTTP API PIPELINE.
"""
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

def test_scenario_1_legitimate_banking_url():
    """
    SCENARIO 1: Legitimate URL
    Flow: User supplies authentic banking URL -> Extracted Features -> Model Prediction -> Risk Engine -> SHAP -> Low Risk / ALLOW.
    """
    url = "https://www.hdfcbank.com"
    response = client.post("/api/v1/analyze/url", json={"url": url})
    assert response.status_code == 200
    res = response.json()
    
    assert res["input_type"] == "URL"
    assert res["target"] == url
    assert res["prediction"] == "Legitimate"
    assert res["probability"] < 0.25
    assert res["risk_score"] < 30.0
    assert res["severity"] == "Low"
    assert res["decision"] == "ALLOW"
    assert len(res["reasons"]) > 0
    assert len(res["top_features"]) == 5
    assert "Safe to proceed" in res["recommendation"]
    print(f"\n[SCENARIO 1 VERIFIED] {url} -> Risk: {res['risk_score']}/100, Severity: {res['severity']}, Action: {res['decision']}")

def test_scenario_2_phishing_url():
    """
    SCENARIO 2: Phishing URL
    Flow: User supplies deceptive IP banking URL -> Extracted Features -> Model Prediction -> Risk Engine -> SHAP -> Elevated Threat / WARN or BLOCK.
    """
    url = "http://192.168.1.1/update-account-bank-security/login.php?user=admin&token=123"
    response = client.post("/api/v1/analyze/url", json={"url": url})
    assert response.status_code == 200
    res = response.json()
    
    assert res["input_type"] == "URL"
    assert res["target"] == url
    assert res["prediction"] == "Phishing"
    assert res["probability"] > 0.70
    assert res["risk_score"] >= 60.0
    assert res["severity"] in ["High", "Critical"]
    assert res["decision"] in ["WARN", "BLOCK"]
    assert len(res["reasons"]) > 0
    assert "Do NOT enter" in res["recommendation"] or "Immediate Intervention" in res["recommendation"]
    print(f"\n[SCENARIO 2 VERIFIED] {url} -> Risk: {res['risk_score']}/100, Severity: {res['severity']}, Action: {res['decision']}")

def test_scenario_3_benign_pe_file():
    """
    SCENARIO 3: Benign PE File
    Flow: User uploads real signed Windows binary -> Safe Static Extraction -> Malware Model -> Risk Engine -> Low Risk / ALLOW.
    """
    sample_path = FIXTURES_DIR / "real_benign_sample.exe"
    assert sample_path.exists(), "Missing real_benign_sample.exe"
    
    with open(sample_path, "rb") as f:
        response = client.post(
            "/api/v1/analyze/file",
            files={"file": ("real_benign_sample.exe", f, "application/octet-stream")}
        )
    assert response.status_code == 200
    res = response.json()
    
    assert res["input_type"] == "FILE"
    assert res["target"] == "real_benign_sample.exe"
    assert res["prediction"] == "Benign"
    assert res["probability"] < 0.30
    assert res["risk_score"] < 40.0
    assert res["severity"] in ["Low", "Medium"]
    assert res["decision"] in ["ALLOW", "CAUTION"]
    assert res["file_sha256"] is not None
    assert len(res["file_sha256"]) == 64
    print(f"\n[SCENARIO 3 VERIFIED] real_benign_sample.exe -> Threat Prob: {res['probability']*100:.1f}%, Risk: {res['risk_score']}/100, Severity: {res['severity']}, Action: {res['decision']}")

def test_scenario_4_malicious_pe_threat_scenario():
    """
    SCENARIO 4: Malicious PE Threat Scenario
    Flow: User uploads actual safe malicious benchmark PE binary -> Safe Static Extraction -> Malware Model -> Risk Engine -> Critical Threat / QUARANTINE.
    """
    malware_path = FIXTURES_DIR / "malicious_pe_benchmark.exe"
    assert malware_path.exists(), "Missing malicious_pe_benchmark.exe fixture"
    
    with open(malware_path, "rb") as f:
        response = client.post(
            "/api/v1/analyze/file",
            files={"file": ("malicious_pe_benchmark.exe", f, "application/octet-stream")}
        )
    assert response.status_code == 200
    res = response.json()
    
    assert res["input_type"] == "FILE"
    assert res["target"] == "malicious_pe_benchmark.exe"
    assert res["prediction"] == "Malicious"
    assert res["probability"] > 0.80
    assert res["risk_score"] >= 70.0
    assert res["severity"] in ["High", "Critical"]
    assert res["decision"] in ["WARN", "QUARANTINE"]
    assert len(res["reasons"]) > 0
    assert len(res["top_features"]) == 5
    assert res["file_sha256"] is not None
    assert len(res["file_sha256"]) == 64
    print(f"\n[SCENARIO 4 VERIFIED] malicious_pe_benchmark.exe -> Threat Prob: {res['probability']*100:.1f}%, Risk: {res['risk_score']}/100, Severity: {res['severity']}, Action: {res['decision']}")
