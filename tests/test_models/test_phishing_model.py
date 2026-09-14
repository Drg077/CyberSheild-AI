import pytest
import joblib
import json
from pathlib import Path
import numpy as np
import pandas as pd
from feature_extraction.feature_contract import URLFeatureContract
from feature_extraction.url_features import extract_url_features_dict, extract_url_features_df

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = BASE_DIR / "models" / "phishing" / "model" / "phishing_model.joblib"
META_PATH = BASE_DIR / "models" / "phishing" / "metadata" / "metadata.json"

@pytest.fixture(scope="module")
def loaded_artifacts():
    assert MODEL_PATH.exists(), f"Missing model at {MODEL_PATH}"
    assert META_PATH.exists(), f"Missing metadata at {META_PATH}"
    
    model = joblib.load(MODEL_PATH)
    with open(META_PATH, "r") as f:
        meta = json.load(f)
    return model, meta

def test_model_artifact_integrity(loaded_artifacts):
    """Verify saved metadata integrity and feature contract schema alignment."""
    model, meta = loaded_artifacts
    assert meta["model_version"] == "v1.0.0"
    assert meta["task"] == "phishing_url_prediction"
    assert meta["feature_schema_version"] == URLFeatureContract.SCHEMA_VERSION
    assert meta["features"] == URLFeatureContract.FEATURE_NAMES
    assert "champion_metrics" in meta
    assert meta["champion_metrics"]["recall"] > 0.90

def test_phishing_inference_legitimate_url(loaded_artifacts):
    """Verify inference on legitimate banking URLs produces low phishing probability."""
    model, _ = loaded_artifacts
    legit_urls = [
        "https://www.hdfcbank.com",
        "https://www.sbi.co.in",
        "https://www.google.com"
    ]
    feat_df = extract_url_features_df(legit_urls)
    probs = model.predict_proba(feat_df)[:, 1]
    for url, prob in zip(legit_urls, probs):
        assert 0.0 <= prob <= 1.0
        assert prob < 0.20, f"Expected low phishing prob for {url}, got {prob}"

def test_phishing_inference_suspicious_url(loaded_artifacts):
    """Verify inference on highly suspicious IP-based banking phish produces high probability."""
    model, _ = loaded_artifacts
    phish_urls = [
        "http://192.168.1.1/update-account-bank-security/login.php?user=admin&token=123",
        "http://phishing-banking-update.xyz.tk/verify/login.html"
    ]
    feat_df = extract_url_features_df(phish_urls)
    probs = model.predict_proba(feat_df)[:, 1]
    for url, prob in zip(phish_urls, probs):
        assert 0.0 <= prob <= 1.0
        assert prob > 0.70, f"Expected high phishing prob for {url}, got {prob}"

def test_feature_order_mismatch_prevention(loaded_artifacts):
    """Ensure feature order validation prevents misaligned predictions."""
    model, _ = loaded_artifacts
    sample = extract_url_features_df(["https://example.com"])
    cols = list(sample.columns)
    cols.reverse()
    reversed_df = sample[cols]
    
    aligned_df = URLFeatureContract.validate_and_align(reversed_df)
    assert list(aligned_df.columns) == URLFeatureContract.FEATURE_NAMES
