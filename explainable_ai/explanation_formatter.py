"""
Explanation Formatter for Explainable AI (XAI).
Translates raw technical feature names and numerical SHAP values into clear,
human-understandable reasons for digital banking users.
"""
from typing import List, Dict, Any

# Plain-English descriptions for URL features
URL_FEATURE_DESCRIPTIONS = {
    "URLLength": "Total length of the web address ({val:.0f} characters)",
    "DomainLength": "Domain name length ({val:.0f} characters)",
    "IsDomainIP": "Web address directly uses a numeric IP address instead of a recognized domain name",
    "TLDLength": "Top-Level Domain suffix length ({val:.0f} characters)",
    "NoOfSubDomain": "Number of subdomain levels ({val:.0f} subdomains present)",
    "NoOfLettersInURL": "Proportion of standard letters in the address",
    "LetterRatioInURL": "Ratio of alphabetic characters across the address ({val:.1%})",
    "NoOfDegitsInURL": "Count of numeric digits in the address ({val:.0f} digits)",
    "DegitRatioInURL": "Ratio of numbers to letters in the address ({val:.1%})",
    "NoOfEqualsInURL": "Number of parameter assignments ('=') in the web address ({val:.0f})",
    "NoOfQMarkInURL": "Presence of query delimiter symbols ('?')",
    "NoOfAmpersandInURL": "Number of parameter separators ('&') in address ({val:.0f})",
    "NoOfOtherSpecialCharsInURL": "Frequency of symbols and special characters ({val:.0f} characters)",
    "SpacialCharRatioInURL": "Ratio of special characters in the URL ({val:.1%})",
    "IsHTTPS": "Use of HTTPS encryption on the link",
    "HasObfuscation": "Use of hex-encoding or obfuscation symbols in the address",
    "NoOfSlashInURL": "Path nesting depth across URL folders ({val:.0f} slashes)",
    "ContainsSuspiciousKeyword": "Presence of sensitive banking/account keywords (e.g. login, verify, secure, bank)",
    "Entropy": "Randomness and complexity score of address characters ({val:.2f})",
    "CharContinuationRate": "Rate of consecutive repeating character patterns ({val:.2f})"
}

# Plain-English descriptions for Static PE features
PE_FEATURE_DESCRIPTIONS = {
    "e_magic": "DOS executable magic identifier",
    "e_lfanew": "Offset to the PE executable header ({val:.0f} bytes)",
    "Machine": "Target CPU architecture specification ({val:.0f})",
    "NumberOfSections": "Number of executable binary sections ({val:.0f} sections)",
    "CreationYear": "Reported file compilation year ({val:.0f})",
    "Characteristics": "File header execution characteristics flag ({val:.0f})",
    "Magic": "PE Optional Header type (32-bit vs 64-bit)",
    "MajorLinkerVersion": "Compiler linker major version ({val:.0f})",
    "MinorLinkerVersion": "Compiler linker minor version ({val:.0f})",
    "SizeOfCode": "Total raw size of executable code segment ({val:.0f} bytes)",
    "SizeOfInitializedData": "Size of pre-initialized static data ({val:.0f} bytes)",
    "SizeOfUninitializedData": "Size of dynamic uninitialized data segments ({val:.0f} bytes)",
    "AddressOfEntryPoint": "Relative virtual address of execution entry point ({val:.0f})",
    "BaseOfCode": "Base address offset of executable code ({val:.0f})",
    "BaseOfData": "Base address offset of initialized data ({val:.0f})",
    "ImageBase": "Preferred memory load address ({val:.0f})",
    "SectionAlignment": "Alignment of sections when loaded into memory ({val:.0f} bytes)",
    "FileAlignment": "Alignment of sections within disk file ({val:.0f} bytes)",
    "MajorOperatingSystemVersion": "Minimum required operating system version ({val:.0f})",
    "SizeOfImage": "Total virtual memory footprint when loaded ({val:.0f} bytes)",
    "SizeOfHeaders": "Total size of DOS and PE headers ({val:.0f} bytes)",
    "CheckSum": "Internal binary checksum field",
    "Subsystem": "Target Windows execution subsystem type ({val:.0f})",
    "DllCharacteristics": "DLL security mitigation flags ({val:.0f})",
    "SizeOfStackReserve": "Configured stack memory reserve ({val:.0f} bytes)",
    "SizeOfHeapReserve": "Configured heap memory reserve ({val:.0f} bytes)",
    "NumberOfRvaAndSizes": "Count of data directory entries ({val:.0f})"
}

class ExplanationFormatter:
    @classmethod
    def format_url_explanation(
        cls,
        attributions: List[Dict[str, Any]],
        prediction_label: str,
        probability: float
    ) -> Dict[str, Any]:
        """
        Translates raw SHAP attributions into customer-friendly reasons for URL analysis.
        """
        reasons: List[str] = []
        is_threat = prediction_label.lower() in ["phishing", "malicious"] or probability >= 0.5
        
        for item in attributions:
            feat = item["feature"]
            val = item["value"]
            direction = item["direction"]
            shap_val = item["shap_value"]
            
            # Look up description template
            template = URL_FEATURE_DESCRIPTIONS.get(feat, f"Technical metric: {feat}")
            try:
                desc = template.format(val=val)
            except Exception:
                desc = template
                
            if is_threat:
                if direction == "increases_risk":
                    reasons.append(f"• Elevated Risk Factor: {desc} (Impact: +{abs(shap_val):.2f})")
                else:
                    reasons.append(f"• Mitigating Factor: {desc} (Impact: -{abs(shap_val):.2f})")
            else:
                if direction == "decreases_risk":
                    reasons.append(f"• Safety Indicator: {desc} (Impact: -{abs(shap_val):.2f})")
                else:
                    reasons.append(f"• Caution Flag: {desc} (Impact: +{abs(shap_val):.2f})")
                    
        # Summary statement
        if is_threat:
            summary = (
                f"The AI model identified this link as likely phishing with {probability*100:.1f}% confidence. "
                "Key suspicious patterns include abnormal structural attributes and indicators consistent with credential harvesting."
            )
        else:
            summary = (
                f"The AI model classified this address as likely legitimate ({ (1.0 - probability)*100:.1f}% confidence). "
                "Its structural patterns and domain properties align closely with standard authenticated web resources."
            )
            
        return {
            "summary": summary,
            "reasons": reasons,
            "top_features": attributions
        }
        
    @classmethod
    def format_pe_explanation(
        cls,
        attributions: List[Dict[str, Any]],
        prediction_label: str,
        probability: float
    ) -> Dict[str, Any]:
        """
        Translates raw SHAP attributions into customer-friendly reasons for PE File analysis.
        """
        reasons: List[str] = []
        is_threat = prediction_label.lower() in ["malicious", "malware"] or probability >= 0.5
        
        for item in attributions:
            feat = item["feature"]
            val = item["value"]
            direction = item["direction"]
            shap_val = item["shap_value"]
            
            template = PE_FEATURE_DESCRIPTIONS.get(feat, f"PE Header field: {feat}")
            try:
                desc = template.format(val=val)
            except Exception:
                desc = template
                
            if is_threat:
                if direction == "increases_risk":
                    reasons.append(f"• Malicious Structural Indicator: {desc} (Impact: +{abs(shap_val):.2f})")
                else:
                    reasons.append(f"• Benign Structural Indicator: {desc} (Impact: -{abs(shap_val):.2f})")
            else:
                if direction == "decreases_risk":
                    reasons.append(f"• Verified Binary Indicator: {desc} (Impact: -{abs(shap_val):.2f})")
                else:
                    reasons.append(f"• Minor Anomaly: {desc} (Impact: +{abs(shap_val):.2f})")
                    
        if is_threat:
            summary = (
                f"The static AI detector flagged this executable file as potentially malicious with {probability*100:.1f}% confidence. "
                "Its internal binary headers and section layout correlate strongly with known trojan/dropper signatures."
            )
        else:
            summary = (
                f"The static AI detector classified this file as likely benign ({ (1.0 - probability)*100:.1f}% confidence). "
                "Its executable headers, linker characteristics, and section alignment match standard benign Windows binaries."
            )
            
        return {
            "summary": summary,
            "reasons": reasons,
            "top_features": attributions
        }
