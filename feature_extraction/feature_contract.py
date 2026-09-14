"""
Formal Feature Contracts for Phishing URL and Static PE Malware Models.
Ensures 100% strict alignment between training schema and live inference schema.
"""
from typing import List, Dict, Any
import numpy as np
import pandas as pd

class FeatureContractValidationError(Exception):
    """Raised when an inference vector does not match the feature contract."""
    pass

class URLFeatureContract:
    SCHEMA_VERSION: str = "v1.0.0"
    
    # 20 Deterministic URL Features extracted strictly from raw URL string
    FEATURE_NAMES: List[str] = [
        "URLLength",
        "DomainLength",
        "IsDomainIP",
        "TLDLength",
        "NoOfSubDomain",
        "NoOfLettersInURL",
        "LetterRatioInURL",
        "NoOfDegitsInURL",
        "DegitRatioInURL",
        "NoOfEqualsInURL",
        "NoOfQMarkInURL",
        "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL",
        "SpacialCharRatioInURL",
        "IsHTTPS",
        "HasObfuscation",
        "NoOfSlashInURL",
        "ContainsSuspiciousKeyword",
        "Entropy",
        "CharContinuationRate"
    ]
    
    @classmethod
    def validate_and_align(cls, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validates that input DataFrame matches the exact feature schema and column ordering.
        Fails safely if columns are missing or malformed.
        """
        missing = [col for col in cls.FEATURE_NAMES if col not in df.columns]
        if missing:
            raise FeatureContractValidationError(
                f"URL Feature Contract Mismatch! Missing features: {missing}"
            )
        # Select and order exactly according to contract
        df_aligned = df[cls.FEATURE_NAMES].copy()
        
        # Ensure numeric conversion and handle NaN
        for col in cls.FEATURE_NAMES:
            df_aligned[col] = pd.to_numeric(df_aligned[col], errors='coerce').fillna(0.0)
            
        return df_aligned

class PEFeatureContract:
    SCHEMA_VERSION: str = "v1.0.0"
    
    # 53 Raw PE Header features matching pefile attributes exactly
    FEATURE_NAMES: List[str] = [
        # DOS Header (17)
        "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc",
        "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno",
        "e_oemid", "e_oeminfo", "e_lfanew",
        # File Header (7)
        "Machine", "NumberOfSections", "CreationYear", "PointerToSymbolTable",
        "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics",
        # Optional Header (29)
        "Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
        "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
        "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion",
        "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics",
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit",
        "LoaderFlags", "NumberOfRvaAndSizes"
    ]
    
    @classmethod
    def validate_and_align(cls, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validates that input DataFrame matches the exact PE feature schema and column ordering.
        Fails safely if columns are missing or malformed.
        """
        missing = [col for col in cls.FEATURE_NAMES if col not in df.columns]
        if missing:
            raise FeatureContractValidationError(
                f"PE Feature Contract Mismatch! Missing features: {missing}"
            )
        df_aligned = df[cls.FEATURE_NAMES].copy()
        for col in cls.FEATURE_NAMES:
            df_aligned[col] = pd.to_numeric(df_aligned[col], errors='coerce').fillna(0.0)
            
        return df_aligned
