"""
URL Feature Extractor.
Extracts 20 deterministic static lexical and structural features directly from a URL string.
CRITICAL: Never fetches, requests, or navigates to the destination URL.
"""
import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List
import pandas as pd
from feature_extraction.feature_contract import URLFeatureContract

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "bank", "banking", "secure", "account", "verify",
    "verification", "update", "wallet", "confirm", "password", "credential",
    "auth", "authenticate", "ebank", "security", "support", "billing", "service"
}

DOCUMENT_SHARING_TERMS = {"share", "shared", "sharing"}
DOCUMENT_TERMS = {"document", "file", "drive", "attachment"}

IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

def calculate_shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not s:
        return 0.0
    length = len(s)
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(round(entropy, 4))

def calculate_char_continuation_rate(s: str) -> float:
    """
    Calculates the character continuation rate:
    Length of longest continuous run of characters of the same category (all letters, all digits, or all special)
    divided by the total length.
    """
    if not s:
        return 0.0
    
    def get_cat(c):
        if c.isalpha(): return 1
        if c.isdigit(): return 2
        return 3
    
    max_run = 1
    current_run = 1
    for i in range(1, len(s)):
        if get_cat(s[i]) == get_cat(s[i-1]):
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1
            
    return float(round(max_run / len(s), 4))

def extract_url_features_dict(url: str) -> Dict[str, Any]:
    """
    Statically extracts all 20 features defined in URLFeatureContract from raw URL string.
    """
    url_str = str(url).strip()
    if not url_str:
        # Default zero-filled vector for empty/invalid input
        return {feat: 0.0 for feat in URLFeatureContract.FEATURE_NAMES}
        
    # Effective URL normalization: ensure valid scheme for feature extraction
    if not (url_str.startswith("http://") or url_str.startswith("https://")):
        clean_first_token = url_str.split("/")[0].split(":")[0]
        if IPV4_PATTERN.match(clean_first_token):
            effective_url = "http://" + url_str
        else:
            effective_url = "https://" + url_str
    else:
        effective_url = url_str
        
    try:
        parsed = urlparse(effective_url)
        netloc = parsed.netloc or ""
        path = parsed.path or ""
    except Exception:
        netloc = ""
        path = ""
        
    # Check IP host
    clean_host = netloc.split(":")[0].lower() if ":" in netloc else netloc.lower()
    is_ip = 1 if IPV4_PATTERN.match(clean_host) else 0
    
    # Subdomain calculation:
    # Standardize host by removing leading www. so apex domains and www-domains are treated equally
    subdomain_host = clean_host[4:] if clean_host.startswith("www.") else clean_host
    domain_len = len(subdomain_host)
    host_parts = subdomain_host.split(".") if subdomain_host else []
    
    # Multi-part public suffixes (e.g., .co.uk, .com.au, .co.in)
    two_part_tlds = {
        "co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au",
        "co.in", "gov.in", "ac.in", "org.in", "edu.au", "co.nz", "com.br"
    }
    
    if len(host_parts) >= 3 and not is_ip:
        last_two = ".".join(host_parts[-2:])
        if last_two in two_part_tlds:
            tld = last_two
            tld_len = len(tld)
            no_of_subdomain = max(0, len(host_parts) - 3)
        else:
            tld = host_parts[-1]
            tld_len = len(tld)
            no_of_subdomain = max(0, len(host_parts) - 2)
    elif len(host_parts) >= 2 and not is_ip:
        tld = host_parts[-1]
        tld_len = len(tld)
        no_of_subdomain = max(0, len(host_parts) - 2)
    elif len(host_parts) == 1 and not is_ip:
        tld_len = 0
        no_of_subdomain = 0
    else:
        tld_len = 0
        no_of_subdomain = 0
        
    # Character counts on effective URL
    url_len = len(effective_url)
    letters = sum(1 for c in effective_url if c.isalpha())
    digits = sum(1 for c in effective_url if c.isdigit())
    equals = effective_url.count("=")
    qmarks = effective_url.count("?")
    ampersands = effective_url.count("&")
    slashes = effective_url.count("/")
    
    special_chars = set("-_@%;~+$!*()[],:")
    other_special = sum(1 for c in effective_url if c in special_chars)
    
    letter_ratio = round(letters / url_len, 4) if url_len > 0 else 0.0
    digit_ratio = round(digits / url_len, 4) if url_len > 0 else 0.0
    special_ratio = round(other_special / url_len, 4) if url_len > 0 else 0.0
    
    is_https = 1 if effective_url.lower().startswith("https://") else 0
    has_obfuscation = 1 if "%" in effective_url or "@" in netloc else 0
    
    url_lower = effective_url.lower()
    has_suspicious_kw = 1 if (
        any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)
        or (
            any(term in url_lower for term in DOCUMENT_SHARING_TERMS)
            and any(term in url_lower for term in DOCUMENT_TERMS)
        )
    ) else 0
    
    entropy = calculate_shannon_entropy(effective_url)
    continuation_rate = calculate_char_continuation_rate(effective_url)
    
    features = {
        "URLLength": float(url_len),
        "DomainLength": float(domain_len),
        "IsDomainIP": float(is_ip),
        "TLDLength": float(tld_len),
        "NoOfSubDomain": float(no_of_subdomain),
        "NoOfLettersInURL": float(letters),
        "LetterRatioInURL": float(letter_ratio),
        "NoOfDegitsInURL": float(digits),
        "DegitRatioInURL": float(digit_ratio),
        "NoOfEqualsInURL": float(equals),
        "NoOfQMarkInURL": float(qmarks),
        "NoOfAmpersandInURL": float(ampersands),
        "NoOfOtherSpecialCharsInURL": float(other_special),
        "SpacialCharRatioInURL": float(special_ratio),
        "IsHTTPS": float(is_https),
        "HasObfuscation": float(has_obfuscation),
        "NoOfSlashInURL": float(slashes),
        "ContainsSuspiciousKeyword": float(has_suspicious_kw),
        "Entropy": float(entropy),
        "CharContinuationRate": float(continuation_rate)
    }
    return features

def extract_url_features_df(urls: List[str]) -> pd.DataFrame:
    """Extracts features for a batch of URLs into an aligned DataFrame."""
    rows = [extract_url_features_dict(u) for u in urls]
    df = pd.DataFrame(rows)
    return URLFeatureContract.validate_and_align(df)
