"""
Security Decision Policy and Banking Recommendations.
Translates Risk Assessment and Severity into actionable protection decisions.
Communicates uncertainty and actionable guidance to digital banking customers.
"""
from enum import Enum
from typing import Dict, Any
from risk_engine.thresholds import SeverityLevel

class SecurityAction(str, Enum):
    ALLOW = "ALLOW"
    CAUTION = "CAUTION"
    WARN = "WARN"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"

class DecisionPolicy:
    DISCLAIMER: str = (
        "Assessment is based on statistical machine-learning pattern recognition and "
        "static feature evaluation. It represents an estimated threat probability, "
        "not absolute proof of malicious intent."
    )
    
    @classmethod
    def get_decision(cls, input_type: str, severity: SeverityLevel) -> Dict[str, Any]:
        """
        Determines security action, title, banking recommendations, and disclaimers.
        """
        is_file = input_type.upper() == "FILE"
        
        if severity == SeverityLevel.LOW:
            action = SecurityAction.ALLOW
            title = "Low Risk / Likely Safe"
            recommendation = (
                "Safe to proceed under standard banking security hygiene. "
                "Always verify that your bank's official address bar displays a valid lock symbol."
            )
            
        elif severity == SeverityLevel.MEDIUM:
            action = SecurityAction.CAUTION
            title = "Suspicious Indicators Detected"
            recommendation = (
                "Exercise caution. Before entering login credentials, verify that the website "
                "domain matches your official bank URL. For files, do not enable macros or run with administrator privileges."
            )
            
        elif severity == SeverityLevel.HIGH:
            action = SecurityAction.WARN
            title = "High Risk Cyber Threat"
            recommendation = (
                "Strong Warning! Do NOT enter passwords, OTPs, PINs, or bank account details. "
                if not is_file else
                "Strong Warning! Do NOT execute or run this file. It contains anomalous structures typical of malware droppers."
            )
            
        else: # CRITICAL
            action = SecurityAction.QUARANTINE if is_file else SecurityAction.BLOCK
            title = "Critical Threat Detected"
            recommendation = (
                "Immediate Intervention Recommended! The destination link is blocked to prevent "
                "account takeover and credential theft. Contact your bank if you already entered details."
                if not is_file else
                "Critical Malware Alert! File has been quarantined. Do not run or open this file under any circumstances."
            )
            
        return {
            "action": action.value,
            "title": title,
            "recommendation": recommendation,
            "disclaimer": cls.DISCLAIMER
        }
