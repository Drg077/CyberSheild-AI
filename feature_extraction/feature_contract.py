"""
Formal Feature Contracts for Phishing URL and Static PE Malware Models.
Ensures strict schema alignment, validates data integrity, and prevents silent conversion of invalid inputs.
"""
from typing import List, Dict, Any
import numpy as np
import pandas as pd

class FeatureContractValidationError(Exception):
    """Raised when an inference vector does not match the feature contract or contains invalid values."""
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
    def validate_and_align(cls, df: pd.DataFrame, strict: bool = False) -> pd.DataFrame:
        """
        Validates that input DataFrame matches the exact feature schema and column ordering.
        Rejects missing columns, unexpected columns (if strict=True), NaNs, and infinite values.
        """
        if not isinstance(df, pd.DataFrame) or df.empty:
            raise FeatureContractValidationError("Input must be a non-empty pandas DataFrame.")
            
        missing = [col for col in cls.FEATURE_NAMES if col not in df.columns]
        if missing:
            raise FeatureContractValidationError(
                f"URL Feature Contract Mismatch! Missing features: {missing}"
            )
            
        if strict:
            extra = [col for col in df.columns if col not in cls.FEATURE_NAMES]
            if extra:
                raise FeatureContractValidationError(
                    f"URL Feature Contract Violation! Unexpected extra features: {extra}"
                )
                
        # Select and order exactly according to contract
        df_aligned = df[cls.FEATURE_NAMES].copy()
        
        # Strict validation: Check for unconvertible, NaN, or Inf values
        for col in cls.FEATURE_NAMES:
            numeric_col = pd.to_numeric(df_aligned[col], errors='coerce')
            if numeric_col.isnull().any():
                raise FeatureContractValidationError(
                    f"Feature Contract Validation Failed: Column '{col}' contains NaN or non-numeric values."
                )
            if np.isinf(numeric_col).any():
                raise FeatureContractValidationError(
                    f"Feature Contract Validation Failed: Column '{col}' contains infinite values."
                )
            df_aligned[col] = numeric_col.astype(float)
            
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
    def validate_and_align(cls, df: pd.DataFrame, strict: bool = False) -> pd.DataFrame:
        """
        Validates that input DataFrame matches the exact PE feature schema and column ordering.
        Rejects missing columns, unexpected columns (if strict=True), NaNs, and infinite values.
        """
        if not isinstance(df, pd.DataFrame) or df.empty:
            raise FeatureContractValidationError("Input must be a non-empty pandas DataFrame.")
            
        missing = [col for col in cls.FEATURE_NAMES if col not in df.columns]
        if missing:
            raise FeatureContractValidationError(
                f"PE Feature Contract Mismatch! Missing features: {missing}"
            )
            
        if strict:
            extra = [col for col in df.columns if col not in cls.FEATURE_NAMES]
            if extra:
                raise FeatureContractValidationError(
                    f"PE Feature Contract Violation! Unexpected extra features: {extra}"
                )
                
        df_aligned = df[cls.FEATURE_NAMES].copy()
        
        for col in cls.FEATURE_NAMES:
            numeric_col = pd.to_numeric(df_aligned[col], errors='coerce')
            if numeric_col.isnull().any():
                raise FeatureContractValidationError(
                    f"Feature Contract Validation Failed: Column '{col}' contains NaN or non-numeric values."
                )
            if np.isinf(numeric_col).any():
                raise FeatureContractValidationError(
                    f"Feature Contract Validation Failed: Column '{col}' contains infinite values."
                )
            df_aligned[col] = numeric_col.astype(float)
            
        return df_aligned
