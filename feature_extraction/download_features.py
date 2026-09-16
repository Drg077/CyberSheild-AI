"""
Download Feature Extractor.
Extracts static lexical and contextual features from file download metadata without ever handling binary content.
CRITICAL: Operates strictly on metadata (filenames, extensions, source/download URLs).
"""
import math
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import pandas as pd

from feature_extraction.feature_contract import DownloadFeatureContract
from feature_extraction.url_features import SUSPICIOUS_KEYWORDS

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".bin"
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"
}

LOW_RISK_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".txt", ".csv"
}

def get_extension_risk_tier(ext: str) -> float:
    """Returns numerical risk tier: 2.0 (High), 1.0 (Medium), 0.0 (Low/Safe)."""
    ext_clean = ext.strip().lower()
    if not ext_clean.startswith(".") and ext_clean:
        ext_clean = "." + ext_clean
        
    if ext_clean in HIGH_RISK_EXTENSIONS:
        return 2.0
    elif ext_clean in MEDIUM_RISK_EXTENSIONS:
        return 1.0
    return 0.0

def calculate_string_entropy(s: str) -> float:
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

def is_cross_domain_redirect(source_url: str, download_url: str) -> float:
    """
    Checks if the source page URL and direct download URL reside on different registered domains.
    """
    if not source_url or not download_url:
        return 0.0
        
    try:
        s_netloc = urlparse(source_url if "://" in source_url else f"http://{source_url}").netloc.lower()
        d_netloc = urlparse(download_url if "://" in download_url else f"http://{download_url}").netloc.lower()
        
        # Remove ports
        s_host = s_netloc.split(":")[0] if ":" in s_netloc else s_netloc
        d_host = d_netloc.split(":")[0] if ":" in d_netloc else d_netloc
        
        if not s_host or not d_host:
            return 0.0
            
        return 1.0 if s_host != d_host else 0.0
    except Exception:
        return 0.0

def extract_download_features_dict(
    filename: str,
    file_extension: str,
    source_url: str,
    download_url: str,
    source_phishing_prob: float = 0.0,
    download_phishing_prob: float = 0.0
) -> Dict[str, float]:
    """
    Extracts all 8 download features defined in DownloadFeatureContract.
    """
    clean_filename = str(filename or "").strip()
    clean_ext = str(file_extension or "").strip()
    if not clean_ext and "." in clean_filename:
        clean_ext = "." + clean_filename.rsplit(".", 1)[-1]
        
    tier = get_extension_risk_tier(clean_ext)
    fn_len = float(len(clean_filename))
    entropy = calculate_string_entropy(clean_filename)
    
    fn_lower = clean_filename.lower()
    has_kw = 1.0 if any(kw in fn_lower for kw in SUSPICIOUS_KEYWORDS) else 0.0
    cross_dom = is_cross_domain_redirect(source_url, download_url)
    
    p_src = max(0.0, min(1.0, float(source_phishing_prob)))
    p_dl = max(0.0, min(1.0, float(download_phishing_prob)))
    max_p = max(p_src, p_dl)
    
    return {
        "ExtensionRiskTier": float(tier),
        "FilenameLength": float(fn_len),
        "FilenameEntropy": float(entropy),
        "ContainsSuspiciousKeyword": float(has_kw),
        "IsCrossDomain": float(cross_dom),
        "SourcePhishingProb": round(float(p_src), 4),
        "DownloadPhishingProb": round(float(p_dl), 4),
        "MaxPhishingProb": round(float(max_p), 4)
    }

def extract_download_features_df(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """Extracts features for a batch of download records and validates against DownloadFeatureContract."""
    rows = [extract_download_features_dict(**r) for r in records]
    df = pd.DataFrame(rows)
    return DownloadFeatureContract.validate_and_align(df)
