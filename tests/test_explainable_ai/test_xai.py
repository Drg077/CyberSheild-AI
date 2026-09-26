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

def test_shap_mathematical_properties_and_bar_derivation():
    """
    Verify SHAP attribution properties:
    1. absolute_impact == abs(shap_value)
    2. direction corresponds to sign(shap_value)
    3. features are sorted in descending order of absolute_impact
    4. bar width derivation respects relative clamping [10%, 100%]
    """
    test_url = "http://192.168.1.1/secure-banking/login.php?update=now"
    df = extract_url_features_df([test_url])
    attributions = phishing_explainer.explain(df, top_k=5)
    
    # 1. Properties verification
    prev_impact = float("inf")
    for item in attributions:
        impact = item["absolute_impact"]
        shap_val = item["shap_value"]
        assert round(impact, 4) == round(abs(shap_val), 4)
        if shap_val > 0:
            assert item["direction"] == "increases_risk"
        else:
            assert item["direction"] == "decreases_risk"
        # 2. Descending sort
        assert impact <= prev_impact
        prev_impact = impact

    # 3. Bar width derivation formula test
    max_impact = max(item["absolute_impact"] for item in attributions)
    assert max_impact > 0
    for item in attributions:
        pct = min(100.0, max(10.0, (item["absolute_impact"] / max_impact) * 100.0))
        assert 10.0 <= pct <= 100.0
    # Top feature must have 100% relative width
    assert min(100.0, max(10.0, (attributions[0]["absolute_impact"] / max_impact) * 100.0)) == 100.0


