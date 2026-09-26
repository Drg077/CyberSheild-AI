"""
Explanation Formatter for Explainable AI (XAI).
Translates raw technical feature names and numerical SHAP values into clear,
human-understandable reasons for digital banking users across URLs, PE Binaries, and Messages.
"""
from typing import List, Dict, Any, Optional

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

# Plain-English descriptions for Message Stylometric features
MESSAGE_FEATURE_DESCRIPTIONS = {
    "CharCount": "Total length of message ({val:.0f} characters)",
    "WordCount": "Total token count ({val:.0f} words)",
    "SentenceCount": "Number of sentences ({val:.0f} sentences)",
    "AvgSentenceLength": "Average sentence length ({val:.1f} words/sentence)",
    "SentenceLengthVariance": "Variance in sentence length structure ({val:.2f})",
    "LexicalDiversity": "Ratio of unique vocabulary to total words ({val:.1%})",
    "AvgWordLength": "Average word character length ({val:.1f} characters)",
    "ImperativeVerbCount": "Frequency of direct imperative commands ({val:.0f})",
    "ClauseDensity": "Subordinate syntactic clause density per sentence ({val:.2f})",
    "FirstPersonPronounRatio": "Frequency of first-person self-references ({val:.1%})",
    "SecondPersonPronounRatio": "Frequency of direct second-person address ({val:.1%})",
    "ThirdPersonPronounRatio": "Frequency of third-person references ({val:.1%})",
    "UrgencyWordCount": "Occurrences of coercive urgency words ({val:.0f})",
    "CredentialRequestCount": "Requests targeting sensitive banking credentials ({val:.0f})",
    "ExclamationRatio": "Frequency of exclamation marks ({val:.2f}/sentence)",
    "UppercaseWordRatio": "Proportion of uppercase emphasis words ({val:.1%})",
    "PunctuationRatio": "Proportion of punctuation symbols ({val:.1%})",
    "DigitRatio": "Proportion of numeric digits ({val:.1%})",
    "URLCount": "Embedded web links detected ({val:.0f})",
    "StopwordRatio": "Proportion of common stopwords ({val:.1%})",
    "FunctionWordRatio": "Proportion of structural function words ({val:.1%})",
    "PassiveVoiceCount": "Occurrences of passive voice constructions ({val:.0f})",
    "ModalVerbCount": "Occurrences of modal obligation auxiliary verbs ({val:.0f})",
    "GreetingGenericFlag": "Presence of generic impersonal greeting"
}

class ExplanationFormatter:
    @classmethod
    def format_url_explanation(
        cls,
        attributions: List[Dict[str, Any]],
        prediction_label: str,
        probability: float,
        threat_intel: Optional[Dict[str, Any]] = None,
        domain_reputation: Optional[Dict[str, Any]] = None,
        final_assessment: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Translates raw SHAP attributions and multi-evidence inputs into customer-friendly reasons for URL analysis.
        Preserves 20-feature SHAP attributions while clearly delineating ML, Context, Threat Intel, and Domain evidence.
        """
        reasons: List[str] = []
        is_threat = prediction_label.lower() in ["phishing", "malicious", "suspicious / unknown"] or probability >= 0.5
        
        # 1. ML Feature Evidence (from SHAP on the 20 model inputs)
        for item in attributions:
            feat = item["feature"]
            val = item["value"]
            direction = item["direction"]
            shap_val = item["shap_value"]
            
            template = URL_FEATURE_DESCRIPTIONS.get(feat, f"Technical metric: {feat}")
            try:
                desc = template.format(val=val)
            except Exception:
                desc = template
                
            if is_threat:
                if direction == "increases_risk":
                    reasons.append(f"• Elevated ML Risk Factor: {desc} (Impact: +{abs(shap_val):.2f})")
                else:
                    reasons.append(f"• Mitigating ML Factor: {desc} (Impact: -{abs(shap_val):.2f})")
            else:
                if direction == "decreases_risk":
                    reasons.append(f"• ML Safety Indicator: {desc} (Impact: -{abs(shap_val):.2f})")
                else:
                    reasons.append(f"• ML Caution Flag: {desc} (Impact: +{abs(shap_val):.2f})")

        # 2. Threat Intelligence Evidence
        threat_intel_desc = "Not configured (ML & heuristic mode)"
        if threat_intel:
            threat_intel_desc = threat_intel.get("description", threat_intel.get("status", "Unavailable"))

        # 3. Domain Reputation Evidence
        domain_desc = "Standard unranked domain"
        if domain_reputation:
            domain_desc = domain_reputation.get("description", "Standard unranked domain")

        # 4. Formulate Summary
        assessment_str = final_assessment or ("MALICIOUS" if is_threat else "LIKELY LEGITIMATE")
        if assessment_str == "MALICIOUS":
            summary = (
                f"The system classified this URL as MALICIOUS with {probability*100:.1f}% estimated threat likelihood. "
                "Suspicious structural patterns and/or external threat intelligence indicate elevated risk of credential theft or fraud."
            )
        elif assessment_str == "SUSPICIOUS / UNKNOWN":
            summary = (
                f"The system classified this URL as SUSPICIOUS / UNKNOWN ({probability*100:.1f}% model likelihood). "
                "Conflicting signals or unverified domain structure warrant caution before submitting sensitive banking information."
            )
        else:
            summary = (
                f"The system classified this address as LIKELY LEGITIMATE ({(1.0 - probability)*100:.1f}% legitimate confidence). "
                "Its structural patterns and domain properties align closely with authenticated resources."
            )

        evidence_breakdown = {
            "ml_evidence": [
                f"{item['feature']}: {'+' if item['direction'] == 'increases_risk' else '-'}{abs(item['shap_value']):.2f}"
                for item in attributions
            ],
            "threat_intel_evidence": threat_intel_desc,
            "domain_evidence": domain_desc,
            "final_assessment": assessment_str
        }
            
        return {
            "summary": summary,
            "reasons": reasons,
            "top_features": attributions,
            "evidence_breakdown": evidence_breakdown
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

    @classmethod
    def format_message_explanation(
        cls,
        attributions: List[Dict[str, Any]],
        prediction_label: str,
        probability: float
    ) -> Dict[str, Any]:
        """
        Translates raw SHAP attributions into customer-friendly reasons for Message / Email threat analysis.
        """
        reasons: List[str] = []
        is_threat = prediction_label.lower() in ["ai_phishing", "human_phishing", "phishing", "malicious"] or probability >= 0.50
        is_genai = "ai" in prediction_label.lower()
        
        for item in attributions:
            feat = item["feature"]
            val = item["value"]
            direction = item["direction"]
            shap_val = item["shap_value"]
            
            template = MESSAGE_FEATURE_DESCRIPTIONS.get(feat, f"Stylometric indicator: {feat}")
            try:
                desc = template.format(val=val)
            except Exception:
                desc = template
                
            if is_threat:
                if direction == "increases_risk":
                    reasons.append(f"• Deceptive Pattern Detected: {desc} (Impact: +{abs(shap_val):.2f})")
                else:
                    reasons.append(f"• Standard Linguistic Pattern: {desc} (Impact: -{abs(shap_val):.2f})")
            else:
                if direction == "decreases_risk":
                    reasons.append(f"• Normal Banking Communication Style: {desc} (Impact: -{abs(shap_val):.2f})")
                else:
                    reasons.append(f"• Minor Anomaly: {desc} (Impact: +{abs(shap_val):.2f})")
                    
        if is_threat:
            threat_type = "GenAI-synthesized phishing" if is_genai else "phishing / social engineering"
            summary = (
                f"The AI threat detector identified this message as likely {threat_type} with {probability*100:.1f}% confidence. "
                "The text exhibits high-urgency keywords, credential solicitation patterns, or stylometric anomalies typical of synthetic lure generation."
            )
        else:
            summary = (
                f"The AI detector classified this message as likely legitimate ({ (1.0 - probability)*100:.1f}% confidence). "
                "Its linguistic structure, vocabulary diversity, and syntax match standard formal communications without deceptive credential prompts."
            )
            
        return {
            "summary": summary,
            "reasons": reasons,
            "top_features": attributions
        }

    @classmethod
    def format_download_explanation(
        cls,
        attributions: List[Dict[str, Any]],
        prediction_label: str,
        probability: float,
        severity_label: str,
        filename: str,
        file_extension: str,
        source_url: str,
        download_url: str,
        is_cross_domain: bool = False,
        extension_risk_tier: float = 0.0
    ) -> Dict[str, Any]:
        """
        Translates raw SHAP attributions and download metadata into clear, customer-friendly explanations
        combining extension risk profile and URL origin evidence.
        """
        reasons: List[str] = []
        clean_ext = file_extension.strip().lower()
        if not clean_ext.startswith(".") and clean_ext:
            clean_ext = "." + clean_ext
            
        # 1. Extension risk description
        if extension_risk_tier >= 2.0:
            reasons.append(f"• High-Risk Payload Type: '{clean_ext}' is an executable/script binary commonly used for malware delivery.")
        elif extension_risk_tier >= 1.0:
            reasons.append(f"• Medium-Risk File Type: '{clean_ext}' archive or document format capable of harboring macros or compressed payloads.")
        else:
            reasons.append(f"• Standard Media/Data Type: '{clean_ext}' is a low-risk media or data format.")

        # 2. Cross-domain mismatch check
        if is_cross_domain:
            reasons.append(f"• Cross-Domain Redirect: The file download was initiated from a different origin domain than the hosting source page.")

        # 3. URL SHAP evidence
        is_threat = severity_label.lower() in ["high", "critical"] or probability >= 0.50
        for item in attributions:
            feat = item.get("feature", "")
            val = item.get("value", 0.0)
            direction = item.get("direction", "")
            shap_val = item.get("shap_value", 0.0)
            template = URL_FEATURE_DESCRIPTIONS.get(feat, f"URL signal: {feat}")
            try:
                desc = template.format(val=val)
            except Exception:
                desc = template
                
            if is_threat and direction == "increases_risk":
                reasons.append(f"• Origin Phishing Indicator: {desc} (Impact: +{abs(shap_val):.2f})")
            elif not is_threat and direction == "decreases_risk":
                reasons.append(f"• Trusted Origin Indicator: {desc} (Impact: -{abs(shap_val):.2f})")

        # 4. Summary formulation
        if severity_label.lower() in ["high", "critical"]:
            ext_desc = f"executable/script file ({clean_ext})" if extension_risk_tier >= 2.0 else f"file ({clean_ext})"
            url_context = "and the download origin demonstrates strong phishing/credential harvesting characteristics" if probability >= 0.5 else "and anomalous redirect indicators were detected"
            summary = (
                f"This is a {severity_label} risk download because it is a {ext_desc} {url_context} ({probability*100:.1f}% origin threat probability)."
            )
        elif severity_label.lower() == "medium":
            summary = (
                f"This download is flagged with Caution/Medium risk due to contextual indicators associated with '{clean_ext}' or cross-domain hosting."
            )
        else:
            summary = (
                f"The AI threat engine evaluated this download as Low Risk / Likely Safe ({(1.0 - probability)*100:.1f}% safety confidence). "
                f"File format '{clean_ext}' and origin URLs match standard non-malicious profiles."
            )

        return {
            "summary": summary,
            "reasons": reasons,
            "top_features": attributions
        }
