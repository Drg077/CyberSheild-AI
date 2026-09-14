"""
End-to-End Integration Tests covering all 4 core demonstration scenarios:
Scenario 1: Legitimate Banking URL -> Low Risk / Allow
Scenario 2: Phishing URL -> High/Critical Risk / Warning or Block
Scenario 3: Benign PE Binary -> Low Risk / Allow
Scenario 4: Malicious PE Threat Scenario -> High/Critical Risk / Block or Quarantine
"""
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import pandas as pd
from backend.main import app
from database.db_session import SessionLocal
from database.models import ThreatAnalysisRecord
from feature_extraction.url_features import extract_url_features_df
from backend.services.threat_service import ThreatService

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
    assert any("IP" in r or "Keywords" in r or "characters" in r for r in res["reasons"])
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
    Flow: Static extraction of verified malware vector from test partition -> Risk Engine -> SHAP -> Critical Severity / QUARANTINE.
    """
    test_malware_file = Path(__file__).resolve().parent.parent / "data" / "processed" / "malware" / "X_test.csv"
    y_test_file = Path(__file__).resolve().parent.parent / "data" / "processed" / "malware" / "y_test.csv"
    
    X_test = pd.read_csv(test_malware_file)
    y_test = pd.read_csv(y_test_file).squeeze("columns")
    
    # Pick a confirmed malicious vector
    malware_sample = X_test[y_test == 1].iloc[[0]]
    
    db = SessionLocal()
    try:
        res = ThreatService.analyze_file(
            features_df=malware_sample,
            filename="trojan_sample_benchmark.exe",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            db=db
        )
    finally:
        db.close()
        
    assert res.input_type == "FILE"
    assert res.prediction == "Malicious"
    assert res.probability > 0.80
    assert res.risk_score >= 70.0
    assert res.severity in ["High", "Critical"]
    assert res.decision in ["WARN", "QUARANTINE"]
    assert len(res.reasons) > 0
    assert len(res.top_features) == 5
    print(f"\n[SCENARIO 4 VERIFIED] trojan_sample_benchmark.exe -> Threat Prob: {res.probability*100:.1f}%, Risk: {res.risk_score}/100, Severity: {res.severity}, Action: {res.decision}")
