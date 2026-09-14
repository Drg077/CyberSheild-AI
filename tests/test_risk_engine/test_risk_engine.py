import pytest
from risk_engine.thresholds import ThresholdConfig, SeverityLevel
from risk_engine.risk_score import (
    RiskAnalysisEngine,
    compute_url_context,
    compute_pe_context
)
from risk_engine.decision_policy import DecisionPolicy, SecurityAction

def test_threshold_boundary_mapping():
    """Verify exact boundary behavior of risk score to severity mapping."""
    assert ThresholdConfig.get_severity(0.0) == SeverityLevel.LOW
    assert ThresholdConfig.get_severity(29.0) == SeverityLevel.LOW
    assert ThresholdConfig.get_severity(29.1) == SeverityLevel.MEDIUM
    assert ThresholdConfig.get_severity(59.0) == SeverityLevel.MEDIUM
    assert ThresholdConfig.get_severity(59.1) == SeverityLevel.HIGH
    assert ThresholdConfig.get_severity(79.0) == SeverityLevel.HIGH
    assert ThresholdConfig.get_severity(79.1) == SeverityLevel.CRITICAL
    assert ThresholdConfig.get_severity(100.0) == SeverityLevel.CRITICAL

def test_clamping_out_of_bounds():
    """Verify negative and >100 scores clamp safely."""
    assert ThresholdConfig.get_severity(-15.0) == SeverityLevel.LOW
    assert ThresholdConfig.get_severity(250.0) == SeverityLevel.CRITICAL

def test_url_risk_calculation():
    """Verify URL risk score respects weights and produces correct severity."""
    engine = RiskAnalysisEngine(weight_model=0.85, weight_context=0.15)
    
    # 1. Low risk URL
    low_res = engine.calculate_url_risk(phishing_probability=0.05, context_score=0.0)
    assert low_res.input_type == "URL"
    assert low_res.risk_score < 10.0
    assert low_res.severity == SeverityLevel.LOW
    
    # 2. Critical threat URL with context
    crit_res = engine.calculate_url_risk(phishing_probability=0.95, context_score=0.8)
    # Expected: 100 * (0.85 * 0.95 + 0.15 * 0.8) = 100 * (0.8075 + 0.12) = 92.75 -> 92.8
    assert crit_res.risk_score > 90.0
    assert crit_res.severity == SeverityLevel.CRITICAL

def test_file_risk_calculation():
    """Verify file risk score respects weights and produces correct severity."""
    engine = RiskAnalysisEngine(weight_model=0.85, weight_context=0.15)
    
    # Low risk file
    low_file = engine.calculate_file_risk(malware_probability=0.02, context_score=0.0)
    assert low_file.input_type == "FILE"
    assert low_file.severity == SeverityLevel.LOW
    
    # High risk file
    high_file = engine.calculate_file_risk(malware_probability=0.75, context_score=0.4)
    # Expected: 100 * (0.85*0.75 + 0.15*0.4) = 100 * (0.6375 + 0.06) = 69.8
    assert high_file.severity == SeverityLevel.HIGH
    assert high_file.risk_score == 69.8

def test_decision_policy_mappings():
    """Verify severity levels map to intended security actions and banking advice."""
    # URL decisions
    d_url_low = DecisionPolicy.get_decision("URL", SeverityLevel.LOW)
    assert d_url_low["action"] == SecurityAction.ALLOW.value
    
    d_url_med = DecisionPolicy.get_decision("URL", SeverityLevel.MEDIUM)
    assert d_url_med["action"] == SecurityAction.CAUTION.value
    
    d_url_high = DecisionPolicy.get_decision("URL", SeverityLevel.HIGH)
    assert d_url_high["action"] == SecurityAction.WARN.value
    assert "Do NOT enter passwords" in d_url_high["recommendation"]
    
    d_url_crit = DecisionPolicy.get_decision("URL", SeverityLevel.CRITICAL)
    assert d_url_crit["action"] == SecurityAction.BLOCK.value
    assert "Immediate Intervention" in d_url_crit["recommendation"]
    
    # File decisions
    d_file_crit = DecisionPolicy.get_decision("FILE", SeverityLevel.CRITICAL)
    assert d_file_crit["action"] == SecurityAction.QUARANTINE.value
    assert "quarantined" in d_file_crit["recommendation"]
    assert "Assessment is based on statistical machine-learning" in d_file_crit["disclaimer"]
