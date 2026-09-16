"""
Adversarial URL Perturbation Robustness Test Suite.
Evaluates phishing detector resilience against adversarial evasion attacks:
1. Homograph / Character Substitution (l->1, o->0, rn->m, etc.)
2. Benign Subdomain Injection (e.g. legitimate-brand.phishing-domain.com)
3. Deep Path and Query Padding
Calculates baseline vs adversarial recall and F1 delta, ensuring recall remains above the documented floor (>= 0.80).
"""
import pytest
import re
import pandas as pd
import numpy as np
import joblib
from backend.config import settings
from feature_extraction.url_features import extract_url_features_df

# Minimum acceptable recall under adversarial perturbation
ADVERSARIAL_RECALL_FLOOR = 0.80

REPRESENTATIVE_PHISHING_URLS = [
    "http://192.168.1.1/update-account-bank-security/login.php?user=admin&token=123",
    "http://phishing-banking-update.xyz.tk/verify/login.html",
    "http://secure-login-hdfc-ebank.com.account-update.xyz/signin",
    "http://wellsfargo.com.security-verify.org/auth/login",
    "http://paypal-account-verification-service.info/webscr?cmd=_login-run",
    "http://chase-security-alert-update.net/identity/verify",
    "http://bankofamerica-auth-notice.com/online/signon",
    "http://appleid.apple.com.verify-identity.biz/login.php",
    "http://netflix-billing-update-required.xyz/account/login",
    "http://citibank-cardholder-protection.info/ebanking/auth"
]

def apply_homograph_substitution(url: str) -> str:
    """Substitutes characters with visual lookalikes."""
    subs = {"l": "1", "o": "0", "rn": "m", "w": "vv"}
    res = url
    for k, v in subs.items():
        res = res.replace(k, v)
    return res

def apply_benign_subdomain_injection(url: str) -> str:
    """Prepends deceptive brand tokens to the domain."""
    if "://" in url:
        scheme, rest = url.split("://", 1)
        return f"{scheme}://secure-banking-support.official-login.{rest}"
    return f"http://secure-banking-support.official-login.{url}"

def apply_path_padding(url: str) -> str:
    """Appends harmless-looking nested directory paths."""
    pad = "/static/resources/en_US/content/docs/help/portal/overview.html?session=valid"
    if "?" in url:
        base, query = url.split("?", 1)
        return f"{base}{pad}&{query}"
    return f"{url}{pad}"

def test_url_homograph_perturbation_robustness():
    """Verify model maintains high detection recall under homograph substitutions."""
    model = joblib.load(settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib")
    
    # 1. Clean Baseline
    clean_df = extract_url_features_df(REPRESENTATIVE_PHISHING_URLS)
    clean_preds = model.predict(clean_df.values)
    clean_recall = float(np.mean(clean_preds == 1))
    
    # 2. Homograph Perturbed
    perturbed_urls = [apply_homograph_substitution(u) for u in REPRESENTATIVE_PHISHING_URLS]
    pert_df = extract_url_features_df(perturbed_urls)
    pert_preds = model.predict(pert_df.values)
    pert_recall = float(np.mean(pert_preds == 1))
    
    recall_delta = clean_recall - pert_recall
    print(f"\nHomograph Test - Clean Recall: {clean_recall:.2f}, Perturbed Recall: {pert_recall:.2f}, Delta: {recall_delta:.2f}")
    
    assert pert_recall >= ADVERSARIAL_RECALL_FLOOR, (
        f"Model recall dropped below floor under homograph attack: {pert_recall:.2f} < {ADVERSARIAL_RECALL_FLOOR}"
    )

def test_url_subdomain_injection_robustness():
    """Verify model detects phishing even with deceptive benign subdomain injection."""
    model = joblib.load(settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib")
    
    perturbed_urls = [apply_benign_subdomain_injection(u) for u in REPRESENTATIVE_PHISHING_URLS]
    pert_df = extract_url_features_df(perturbed_urls)
    pert_preds = model.predict(pert_df.values)
    pert_recall = float(np.mean(pert_preds == 1))
    
    print(f"\nSubdomain Injection Test - Perturbed Recall: {pert_recall:.2f}")
    assert pert_recall >= ADVERSARIAL_RECALL_FLOOR

def test_url_path_padding_robustness():
    """Verify model detects phishing under path padding attacks."""
    model = joblib.load(settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib")
    
    perturbed_urls = [apply_path_padding(u) for u in REPRESENTATIVE_PHISHING_URLS]
    pert_df = extract_url_features_df(perturbed_urls)
    pert_preds = model.predict(pert_df.values)
    pert_recall = float(np.mean(pert_preds == 1))
    
    print(f"\nPath Padding Test - Perturbed Recall: {pert_recall:.2f}")
    assert pert_recall >= ADVERSARIAL_RECALL_FLOOR
