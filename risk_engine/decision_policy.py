"""
Security Decision Policy and Banking Recommendations.
Translates Risk Assessment and Severity into actionable protection decisions.
Communicates uncertainty and actionable guidance to digital banking customers.
"""
from enum import Enum
from typing import Dict, Any, Optional
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
    def get_decision(
        cls,
        input_type: str,
        severity: SeverityLevel,
        final_assessment: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Determines security action, title, banking recommendations, and disclaimers.
        """
        itype = input_type.upper()
        is_file = itype == "FILE"
        is_download = itype == "DOWNLOAD"
        is_message = itype == "MESSAGE"
        
        if final_assessment == "SUSPICIOUS / UNKNOWN" and severity in [SeverityLevel.LOW, SeverityLevel.MEDIUM]:
            action = SecurityAction.CAUTION
            title = "Unverified URL / Exercise Caution"
            recommendation = (
                "This domain is unverified. Do not enter banking credentials or payment details "
                "unless you independently confirm the address with the organization."
            )
        elif severity == SeverityLevel.LOW:
            action = SecurityAction.ALLOW
            title = "Low Risk / Likely Safe"
            if is_download:
                recommendation = (
                    "Safe to proceed. The downloaded file extension and source domain show no known threat indicators."
                )
            elif is_message:
                recommendation = (
                    "Safe to proceed. The message exhibits standard linguistic patterns without deceptive solicitation."
                )
            else:
                recommendation = (
                    "Safe to proceed under standard banking security hygiene. "
                    "Always verify that your bank's official address bar displays a valid lock symbol."
                )
            
        elif severity == SeverityLevel.MEDIUM:
            action = SecurityAction.CAUTION
            title = "Suspicious Indicators Detected"
            if is_download:
                recommendation = (
                    "Exercise caution. Verify the download source origin. Do not open or enable macros if unexpected."
                )
            elif is_message:
                recommendation = (
                    "Exercise caution. Message exhibits minor persuasive cues. Verify sender identity before responding."
                )
            else:
                recommendation = (
                    "Exercise caution. Before entering login credentials, verify that the website "
                    "domain matches your official bank URL. For files, do not enable macros or run with administrator privileges."
                )
            
        elif severity == SeverityLevel.HIGH:
            action = SecurityAction.WARN
            title = "High Risk Cyber Threat"
            if is_download:
                recommendation = (
                    "Strong Warning! Do not open this file. Scan it manually in the PE Malware Scanner tab before running it."
                )
            elif is_message:
                recommendation = (
                    "Strong Warning! Message shows high likelihood of phishing. Do NOT disclose credentials or click embedded links."
                )
            elif is_file:
                recommendation = (
                    "Strong Warning! Do NOT execute or run this file. It contains anomalous structures typical of malware droppers."
                )
            else:
                recommendation = (
                    "Strong Warning! Do NOT enter passwords, OTPs, PINs, or bank account details."
                )
            
        else: # CRITICAL
            if is_file:
                action = SecurityAction.QUARANTINE
            elif is_download:
                action = SecurityAction.BLOCK
            else:
                action = SecurityAction.BLOCK
                
            title = "Critical Threat Detected"
            if is_download:
                recommendation = (
                    "Critical Download Threat Blocked! Do not open this file. Scan it manually in the PE Malware Scanner tab before running it."
                )
            elif is_file:
                recommendation = (
                    "Critical Malware Alert! File has been quarantined. Do not run or open this file under any circumstances."
                )
            elif is_message:
                recommendation = (
                    "Critical GenAI Phishing Alert! Deceptive communication pattern detected. Do NOT respond or open attachments."
                )
            else:
                recommendation = (
                    "Immediate Intervention Recommended! The destination link is blocked to prevent "
                    "account takeover and credential theft. Contact your bank if you already entered details."
                )
            
        if final_assessment is None:
            if severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                derived_assessment = "MALICIOUS"
            elif severity == SeverityLevel.LOW:
                derived_assessment = "LIKELY LEGITIMATE"
            else:
                derived_assessment = "SUSPICIOUS / UNKNOWN"
        else:
            derived_assessment = final_assessment

        return {
            "action": action.value,
            "title": title,
            "recommendation": recommendation,
            "disclaimer": cls.DISCLAIMER,
            "final_assessment": derived_assessment
        }
