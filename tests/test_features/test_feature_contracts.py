import pytest
import pandas as pd
import numpy as np
from feature_extraction.feature_contract import (
    URLFeatureContract,
    PEFeatureContract,
    FeatureContractValidationError
)
from feature_extraction.url_features import (
    extract_url_features_dict,
    extract_url_features_df
)

def test_url_contract_definition():
    """Verify URL contract has 20 deterministic features."""
    assert len(URLFeatureContract.FEATURE_NAMES) == 20
    assert "URLLength" in URLFeatureContract.FEATURE_NAMES
    assert "IsDomainIP" in URLFeatureContract.FEATURE_NAMES
    assert "ContainsSuspiciousKeyword" in URLFeatureContract.FEATURE_NAMES

def test_pe_contract_definition():
    """Verify PE contract has 53 deterministic features."""
    assert len(PEFeatureContract.FEATURE_NAMES) == 53
    assert "e_magic" in PEFeatureContract.FEATURE_NAMES
    assert "Machine" in PEFeatureContract.FEATURE_NAMES
    assert "SizeOfImage" in PEFeatureContract.FEATURE_NAMES
    assert "e_res" not in PEFeatureContract.FEATURE_NAMES
    assert "e_res2" not in PEFeatureContract.FEATURE_NAMES

def test_url_contract_missing_column_fails_safely():
    """Verify contract validator raises FeatureContractValidationError on missing columns."""
    df_bad = pd.DataFrame({"URLLength": [50.0], "DomainLength": [20.0]})
    with pytest.raises(FeatureContractValidationError) as excinfo:
        URLFeatureContract.validate_and_align(df_bad)
    assert "URL Feature Contract Mismatch" in str(excinfo.value)

def test_pe_contract_missing_column_fails_safely():
    """Verify PE contract validator raises FeatureContractValidationError on missing columns."""
    df_bad = pd.DataFrame({"e_magic": [23117.0]})
    with pytest.raises(FeatureContractValidationError) as excinfo:
        PEFeatureContract.validate_and_align(df_bad)
    assert "PE Feature Contract Mismatch" in str(excinfo.value)

def test_url_extraction_various_samples():
    """Test feature extraction across standard, IP, and suspicious URLs."""
    # Legitimate-style URL
    f1 = extract_url_features_dict("https://www.google.com/search?q=cybersecurity")
    assert f1["URLLength"] > 0
    assert f1["IsHTTPS"] == 1.0
    assert f1["IsDomainIP"] == 0.0
    assert f1["NoOfQMarkInURL"] == 1.0
    
    # Suspicious IP URL with banking keywords
    f2 = extract_url_features_dict("http://192.168.1.100/secure-banking/login.php?update=now")
    assert f2["IsDomainIP"] == 1.0
    assert f2["IsHTTPS"] == 0.0
    assert f2["ContainsSuspiciousKeyword"] == 1.0
    
    # Empty input handling
    f3 = extract_url_features_dict("")
    assert f3["URLLength"] == 0.0

def test_processed_data_integrity():
    """Verify preprocessed train and test CSVs exist, have correct shape, and have zero NaNs."""
    from backend.config import settings
    
    phish_train_X = pd.read_csv(settings.DATA_DIR / "processed" / "phishing" / "X_train.csv")
    phish_train_y = pd.read_csv(settings.DATA_DIR / "processed" / "phishing" / "y_train.csv")
    assert phish_train_X.shape[1] == 20
    assert len(phish_train_X) == len(phish_train_y)
    assert phish_train_X.isnull().sum().sum() == 0
    
    mal_train_X = pd.read_csv(settings.DATA_DIR / "processed" / "malware" / "X_train.csv")
    mal_train_y = pd.read_csv(settings.DATA_DIR / "processed" / "malware" / "y_train.csv")
    assert mal_train_X.shape[1] == 53
    assert len(mal_train_X) == len(mal_train_y)
    assert mal_train_X.isnull().sum().sum() == 0
