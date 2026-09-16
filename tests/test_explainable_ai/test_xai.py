import pytest
import pandas as pd
from feature_extraction.url_features import extract_url_features_df
from explainable_ai.phishing_explainer import phishing_explainer
from explainable_ai.malware_explainer import malware_explainer
from explainable_ai.explanation_formatter import ExplanationFormatter
from backend.config import settings

def test_phishing_shap_explainer():
    """Verify SHAP explainer produces genuine feature attributions for a URL."""
    test_url = "http://192.168.1.1/secure-banking/login.php?update=now"
    df = extract_url_features_df([test_url])
    
    attributions = phishing_explainer.explain(df, top_k=5)
    assert len(attributions) == 5
    for item in attributions:
        assert "feature" in item
        assert "value" in item
        assert "shap_value" in item
        assert "direction" in item
        assert item["direction"] in ["increases_risk", "decreases_risk"]
        
    formatted = ExplanationFormatter.format_url_explanation(
        attributions, prediction_label="Phishing", probability=0.92
    )
    assert "summary" in formatted
    assert "reasons" in formatted
    assert len(formatted["reasons"]) == 5
    assert "92.0%" in formatted["summary"]

def test_malware_shap_explainer():
    """Verify SHAP explainer produces genuine feature attributions for a PE sample."""
    sample_df = pd.read_csv(settings.DATA_DIR / "processed" / "malware" / "X_test.csv", nrows=1)
    
    attributions = malware_explainer.explain(sample_df, top_k=5)
    assert len(attributions) == 5
    for item in attributions:
        assert "feature" in item
        assert "shap_value" in item
        
    formatted = ExplanationFormatter.format_pe_explanation(
        attributions, prediction_label="Malware", probability=0.95
    )
    assert "summary" in formatted
    assert "reasons" in formatted
    assert len(formatted["reasons"]) == 5
    assert "95.0%" in formatted["summary"]

def test_content_explainer_and_formatter():
    """Verify ContentExplainer produces both SHAP attributions and highlighted spans."""
    from feature_extraction.message_features import extract_message_features_df
    from explainable_ai.content_explainer import content_explainer

    msg = "Dear Customer, your bank account is suspended immediately! Please verify your password and OTP within 24 hours at http://fake-bank-login.xyz."
    df = extract_message_features_df([msg])

    result = content_explainer.explain(text=msg, features_df=df, top_k=5)
    assert "top_features" in result
    assert "highlighted_spans" in result
    assert len(result["top_features"]) == 5

    for item in result["top_features"]:
        assert "feature" in item
        assert "shap_value" in item
        assert "direction" in item

    assert len(result["highlighted_spans"]) > 0
    for span in result["highlighted_spans"]:
        assert "text" in span
        assert "start" in span
        assert "end" in span
        assert "weight" in span
        assert span["start"] < span["end"]

    formatted = ExplanationFormatter.format_message_explanation(
        result["top_features"], prediction_label="ai_phishing", probability=0.96
    )
    assert "summary" in formatted
    assert "reasons" in formatted
    assert "96.0%" in formatted["summary"]
    assert "GenAI-synthesized phishing" in formatted["summary"]

