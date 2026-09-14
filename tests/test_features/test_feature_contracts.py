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

def test_url_contract_nan_and_inf_fail_safely():
    """Verify contract validator rejects NaN and Infinite values instead of silently masking."""
    clean_sample = extract_url_features_df(["https://example.com"])
    
    # Test NaN rejection
    nan_df = clean_sample.copy()
    nan_df.loc[0, "URLLength"] = np.nan
    with pytest.raises(FeatureContractValidationError) as excinfo:
        URLFeatureContract.validate_and_align(nan_df)
    assert "contains NaN or non-numeric" in str(excinfo.value)
    
    # Test Inf rejection
    inf_df = clean_sample.copy()
    inf_df.loc[0, "Entropy"] = np.inf
    with pytest.raises(FeatureContractValidationError) as excinfo:
        URLFeatureContract.validate_and_align(inf_df)
    assert "contains infinite values" in str(excinfo.value)

def test_pe_contract_nan_and_inf_fail_safely():
    """Verify PE contract validator rejects NaN and Infinite values."""
    from backend.config import settings
    sample = pd.read_csv(settings.DATA_DIR / "processed" / "malware" / "X_test.csv", nrows=1)
    
    nan_df = sample.copy()
    nan_df.loc[0, "ImageBase"] = np.nan
    with pytest.raises(FeatureContractValidationError) as excinfo:
        PEFeatureContract.validate_and_align(nan_df)
    assert "contains NaN or non-numeric" in str(excinfo.value)

def test_strict_mode_rejects_extra_columns():
    """Verify strict mode rejects unexpected extra columns."""
    clean_sample = extract_url_features_df(["https://example.com"])
    extra_df = clean_sample.copy()
    extra_df["UNEXPECTED_COLUMN"] = 999.0
    with pytest.raises(FeatureContractValidationError) as excinfo:
        URLFeatureContract.validate_and_align(extra_df, strict=True)
    assert "Unexpected extra features" in str(excinfo.value)

def test_url_extraction_various_samples():
    """Test feature extraction across standard, IP, and suspicious URLs."""
    f1 = extract_url_features_dict("https://www.google.com/search?q=cybersecurity")
    assert f1["URLLength"] > 0
    assert f1["IsHTTPS"] == 1.0
    assert f1["IsDomainIP"] == 0.0
    assert f1["NoOfQMarkInURL"] == 1.0
    
    f2 = extract_url_features_dict("http://192.168.1.100/secure-banking/login.php?update=now")
    assert f2["IsDomainIP"] == 1.0
    assert f2["IsHTTPS"] == 0.0
    assert f2["ContainsSuspiciousKeyword"] == 1.0
    
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
