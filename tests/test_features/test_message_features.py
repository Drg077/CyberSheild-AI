import pytest
import pandas as pd
import numpy as np
from feature_extraction.feature_contract import (
    MessageFeatureContract,
    FeatureContractValidationError
)
from feature_extraction.message_features import (
    extract_message_features,
    extract_message_features_df
)

def test_message_contract_definition():
    """Verify MessageFeatureContract has exactly 24 deterministic features."""
    assert len(MessageFeatureContract.FEATURE_NAMES) == 24
    assert "CharCount" in MessageFeatureContract.FEATURE_NAMES
    assert "UrgencyWordCount" in MessageFeatureContract.FEATURE_NAMES
    assert "CredentialRequestCount" in MessageFeatureContract.FEATURE_NAMES
    assert "GreetingGenericFlag" in MessageFeatureContract.FEATURE_NAMES
    assert "ClauseDensity" in MessageFeatureContract.FEATURE_NAMES
    assert "PassiveVoiceCount" in MessageFeatureContract.FEATURE_NAMES

def test_message_contract_missing_column_fails_safely():
    """Verify contract validator raises FeatureContractValidationError on missing columns."""
    df_bad = pd.DataFrame({"CharCount": [120.0], "WordCount": [25.0]})
    with pytest.raises(FeatureContractValidationError) as excinfo:
        MessageFeatureContract.validate_and_align(df_bad)
    assert "Message Feature Contract Mismatch" in str(excinfo.value)

def test_message_contract_nan_and_inf_fail_safely():
    """Verify contract validator rejects NaN and Infinite values instead of silently masking."""
    clean_sample = extract_message_features_df(["Dear customer, please verify your bank account login credentials immediately."])
    
    # Test NaN rejection
    nan_df = clean_sample.copy()
    nan_df.loc[0, "UrgencyWordCount"] = np.nan
    with pytest.raises(FeatureContractValidationError) as excinfo:
        MessageFeatureContract.validate_and_align(nan_df)
    assert "contains NaN or non-numeric" in str(excinfo.value)
    
    # Test Inf rejection
    inf_df = clean_sample.copy()
    inf_df.loc[0, "LexicalDiversity"] = np.inf
    with pytest.raises(FeatureContractValidationError) as excinfo:
        MessageFeatureContract.validate_and_align(inf_df)
    assert "contains infinite values" in str(excinfo.value)

def test_message_strict_mode_rejects_extra_columns():
    """Verify strict mode rejects unexpected extra columns."""
    clean_sample = extract_message_features_df(["Important security alert from your banking portal."])
    extra_df = clean_sample.copy()
    extra_df["UNEXPECTED_FIELD"] = 1.0
    with pytest.raises(FeatureContractValidationError) as excinfo:
        MessageFeatureContract.validate_and_align(extra_df, strict=True)
    assert "Unexpected extra features" in str(excinfo.value)

def test_message_extraction_various_samples():
    """Test feature extraction across standard, phishing, and empty samples."""
    # 1. Urgent credential phishing
    phishing_msg = "Dear Customer, your account has been suspended! Please immediately verify your login password and OTP within 24 hours at http://secure-bank-login.xyz to avoid termination."
    f_phish = extract_message_features(phishing_msg)
    assert f_phish["CharCount"] > 50
    assert f_phish["WordCount"] > 10
    assert f_phish["UrgencyWordCount"] >= 1.0
    assert f_phish["CredentialRequestCount"] >= 1.0
    assert f_phish["GreetingGenericFlag"] == 1.0
    assert f_phish["URLCount"] >= 1.0

    # 2. Legitimate formal notification
    legit_msg = "Hello Dr. Smith, your scheduled monthly statement for October is now available in your document repository. No further action is required on your part."
    f_legit = extract_message_features(legit_msg)
    assert f_legit["CharCount"] > 50
    assert f_legit["GreetingGenericFlag"] == 0.0

    # 3. Empty / Whitespace handling
    f_empty = extract_message_features("")
    assert f_empty["CharCount"] == 0.0
    assert f_empty["WordCount"] == 0.0
    assert all(not np.isnan(v) for v in f_empty.values())

    f_ws = extract_message_features("    \n\t  ")
    assert f_ws["CharCount"] == 0.0
    assert all(not np.isnan(v) for v in f_ws.values())

def test_message_dataframe_batch_extraction():
    """Test batch extraction produces aligned DataFrame matching contract."""
    texts = [
        "Dear user, your OTP code is 987654. Do not share with anyone.",
        "Your monthly credit card statement is ready for review.",
        "URGENT: Verify your bank identity immediately!"
    ]
    df = extract_message_features_df(texts)
    assert df.shape == (3, 24)
    assert list(df.columns) == MessageFeatureContract.FEATURE_NAMES
    assert df.isnull().sum().sum() == 0
