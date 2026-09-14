import pytest
from risk_engine.thresholds import ThresholdConfig, SeverityLevel
from risk_engine.risk_score import (
    RiskAnalysisEngine,
    compute_url_context,
    compute_pe_context
)
from risk_engine.decision_policy import DecisionPolicy, SecurityAction

def test_threshold_exact_boundary_mapping():
    """Verify exact boundary behavior of risk score to severity mapping."""
    assert ThresholdConfig.get_severity(0.0) == SeverityLevel.LOW
    assert ThresholdConfig.get_severity(29.0) == SeverityLevel.LOW
    assert ThresholdConfig.get_severity(29.05) == SeverityLevel.MEDIUM
    assert ThresholdConfig.get_severity(59.0) == SeverityLevel.MEDIUM
    assert ThresholdConfig.get_severity(59.05) == SeverityLevel.HIGH
    assert ThresholdConfig.get_severity(79.0) == SeverityLevel.HIGH
    assert ThresholdConfig.get_severity(79.05) == SeverityLevel.CRITICAL
    assert ThresholdConfig.get_severity(100.0) == SeverityLevel.CRITICAL

def test_clamping_out_of_bounds_and_extremes():
    """Verify negative, zero, 100, and extreme out-of-range values clamp safely."""
    assert ThresholdConfig.get_severity(-100.0) == SeverityLevel.LOW
    assert ThresholdConfig.get_severity(-0.01) == SeverityLevel.LOW
    assert ThresholdConfig.get_severity(100.01) == SeverityLevel.CRITICAL
    assert ThresholdConfig.get_severity(9999.0) == SeverityLevel.CRITICAL

def test_distinct_url_and_malware_weights():
    """Verify separate URL and malware weights are strictly respected."""
    engine = RiskAnalysisEngine(
        weight_phishing=0.80,
        weight_phishing_context=0.20,
        weight_malware=0.90,
        weight_malware_context=0.10
    )
    
    # URL scoring with 0.80 / 0.20
    url_res = engine.calculate_url_risk(phishing_probability=0.50, context_score=0.50)
    assert url_res.weights["model"] == 0.80
    assert url_res.weights["context"] == 0.20
    assert url_res.risk_score == 50.0 # 100 * (0.8*0.5 + 0.2*0.5)
    
    # File scoring with 0.90 / 0.10
    file_res = engine.calculate_file_risk(malware_probability=0.50, context_score=0.50)
    assert file_res.weights["model"] == 0.90
    assert file_res.weights["context"] == 0.10
    assert file_res.risk_score == 50.0

def test_url_context_heuristics():
    """Verify URL context computation detects security red flags."""
    ctx_clean = compute_url_context({"IsDomainIP": 0, "ContainsSuspiciousKeyword": 0, "NoOfSubDomain": 0, "IsHTTPS": 1})
    assert ctx_clean == 0.0
    
    ctx_bad = compute_url_context({"IsDomainIP": 1, "ContainsSuspiciousKeyword": 1, "NoOfSubDomain": 3, "IsHTTPS": 0})
    assert ctx_bad == 1.0 # 0.4 + 0.3 + 0.2 + 0.1 = 1.0

def test_pe_context_heuristics():
    """Verify PE context computation detects structural anomalies."""
    ctx_clean = compute_pe_context({"NumberOfSections": 4, "CreationYear": 2021, "SizeOfCode": 4096})
    assert ctx_clean == 0.0
    
    ctx_bad = compute_pe_context({"NumberOfSections": 1, "CreationYear": 1970, "SizeOfCode": 0})
    assert ctx_bad == 1.0 # 0.4 + 0.3 + 0.3 = 1.0

def test_decision_policy_mappings():
    """Verify severity levels map to intended security actions and banking advice."""
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
    
    d_file_crit = DecisionPolicy.get_decision("FILE", SeverityLevel.CRITICAL)
    assert d_file_crit["action"] == SecurityAction.QUARANTINE.value
    assert "quarantined" in d_file_crit["recommendation"]
    assert "Assessment is based on statistical machine-learning" in d_file_crit["disclaimer"]
