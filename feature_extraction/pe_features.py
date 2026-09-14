"""
Static PE Malware Feature Extractor.
Extracts 53 raw PE header features using pefile.
CRITICAL: Operates strictly via static binary parsing. NEVER executes the file.
"""
import os
import pefile
from typing import Dict, Any, Union
from pathlib import Path
import pandas as pd
from feature_extraction.feature_contract import PEFeatureContract

class InvalidPEFileError(Exception):
    """Raised when an uploaded file is not a valid Windows PE binary."""
    pass

def file_creation_year(timestamp: int) -> float:
    """Derives creation year from TimeDateStamp safely."""
    try:
        # 1970 + seconds / (86400 * 365.25)
        return float(1970 + ((int(timestamp) / 86400) / 365.25))
    except Exception:
        return 1970.0

def extract_pe_features_from_pe(pe: pefile.PE) -> Dict[str, float]:
    """
    Extracts the 53 raw PE header features matching PEFeatureContract exactly.
    """
    features: Dict[str, float] = {}
    
    # 1. DOS Header (17 features)
    dos = pe.DOS_HEADER
    features["e_magic"] = float(getattr(dos, "e_magic", 0))
    features["e_cblp"] = float(getattr(dos, "e_cblp", 0))
    features["e_cp"] = float(getattr(dos, "e_cp", 0))
    features["e_crlc"] = float(getattr(dos, "e_crlc", 0))
    features["e_cparhdr"] = float(getattr(dos, "e_cparhdr", 0))
    features["e_minalloc"] = float(getattr(dos, "e_minalloc", 0))
    features["e_maxalloc"] = float(getattr(dos, "e_maxalloc", 0))
    features["e_ss"] = float(getattr(dos, "e_ss", 0))
    features["e_sp"] = float(getattr(dos, "e_sp", 0))
    features["e_csum"] = float(getattr(dos, "e_csum", 0))
    features["e_ip"] = float(getattr(dos, "e_ip", 0))
    features["e_cs"] = float(getattr(dos, "e_cs", 0))
    features["e_lfarlc"] = float(getattr(dos, "e_lfarlc", 0))
    features["e_ovno"] = float(getattr(dos, "e_ovno", 0))
    features["e_oemid"] = float(getattr(dos, "e_oemid", 0))
    features["e_oeminfo"] = float(getattr(dos, "e_oeminfo", 0))
    features["e_lfanew"] = float(getattr(dos, "e_lfanew", 0))
    
    # 2. File Header (7 features)
    fh = pe.FILE_HEADER
    features["Machine"] = float(getattr(fh, "Machine", 0))
    features["NumberOfSections"] = float(getattr(fh, "NumberOfSections", 0))
    features["CreationYear"] = file_creation_year(getattr(fh, "TimeDateStamp", 0))
    features["PointerToSymbolTable"] = float(getattr(fh, "PointerToSymbolTable", 0))
    features["NumberOfSymbols"] = float(getattr(fh, "NumberOfSymbols", 0))
    features["SizeOfOptionalHeader"] = float(getattr(fh, "SizeOfOptionalHeader", 0))
    features["Characteristics"] = float(getattr(fh, "Characteristics", 0))
    
    # 3. Optional Header (29 features)
    if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER:
        oh = pe.OPTIONAL_HEADER
        features["Magic"] = float(getattr(oh, "Magic", 0))
        features["MajorLinkerVersion"] = float(getattr(oh, "MajorLinkerVersion", 0))
        features["MinorLinkerVersion"] = float(getattr(oh, "MinorLinkerVersion", 0))
        features["SizeOfCode"] = float(getattr(oh, "SizeOfCode", 0))
        features["SizeOfInitializedData"] = float(getattr(oh, "SizeOfInitializedData", 0))
        features["SizeOfUninitializedData"] = float(getattr(oh, "SizeOfUninitializedData", 0))
        features["AddressOfEntryPoint"] = float(getattr(oh, "AddressOfEntryPoint", 0))
        features["BaseOfCode"] = float(getattr(oh, "BaseOfCode", 0))
        # BaseOfData does not exist in PE32+ (64-bit)
        features["BaseOfData"] = float(getattr(oh, "BaseOfData", 0))
        features["ImageBase"] = float(getattr(oh, "ImageBase", 0))
        features["SectionAlignment"] = float(getattr(oh, "SectionAlignment", 0))
        features["FileAlignment"] = float(getattr(oh, "FileAlignment", 0))
        features["MajorOperatingSystemVersion"] = float(getattr(oh, "MajorOperatingSystemVersion", 0))
        features["MinorOperatingSystemVersion"] = float(getattr(oh, "MinorOperatingSystemVersion", 0))
        features["MajorImageVersion"] = float(getattr(oh, "MajorImageVersion", 0))
        features["MinorImageVersion"] = float(getattr(oh, "MinorImageVersion", 0))
        features["MajorSubsystemVersion"] = float(getattr(oh, "MajorSubsystemVersion", 0))
        features["MinorSubsystemVersion"] = float(getattr(oh, "MinorSubsystemVersion", 0))
        features["SizeOfImage"] = float(getattr(oh, "SizeOfImage", 0))
        features["SizeOfHeaders"] = float(getattr(oh, "SizeOfHeaders", 0))
        features["CheckSum"] = float(getattr(oh, "CheckSum", 0))
        features["Subsystem"] = float(getattr(oh, "Subsystem", 0))
        features["DllCharacteristics"] = float(getattr(oh, "DllCharacteristics", 0))
        features["SizeOfStackReserve"] = float(getattr(oh, "SizeOfStackReserve", 0))
        features["SizeOfStackCommit"] = float(getattr(oh, "SizeOfStackCommit", 0))
        features["SizeOfHeapReserve"] = float(getattr(oh, "SizeOfHeapReserve", 0))
        features["SizeOfHeapCommit"] = float(getattr(oh, "SizeOfHeapCommit", 0))
        features["LoaderFlags"] = float(getattr(oh, "LoaderFlags", 0))
        features["NumberOfRvaAndSizes"] = float(getattr(oh, "NumberOfRvaAndSizes", 0))
    else:
        # Fallback if Optional Header absent
        for name in PEFeatureContract.FEATURE_NAMES[24:]:
            features[name] = 0.0
            
    return features

def extract_pe_features_from_file(file_path_or_bytes: Union[str, Path, bytes]) -> pd.DataFrame:
    """
    Parses a PE file safely from disk or memory, returning an aligned single-row DataFrame.
    """
    try:
        if isinstance(file_path_or_bytes, (str, Path)):
            pe = pefile.PE(str(file_path_or_bytes), fast_load=True)
        elif isinstance(file_path_or_bytes, bytes):
            pe = pefile.PE(data=file_path_or_bytes, fast_load=True)
        else:
            raise InvalidPEFileError("Unsupported input type for PE parsing.")
    except pefile.PEFormatError as e:
        raise InvalidPEFileError(f"File is not a valid PE executable: {str(e)}")
    except Exception as e:
        raise InvalidPEFileError(f"Error reading PE structures: {str(e)}")
        
    try:
        pe.parse_data_directories()
    except Exception:
        pass # Parsing directories is optional for header fields
        
    features_dict = extract_pe_features_from_pe(pe)
    pe.close()
    
    df = pd.DataFrame([features_dict])
    return PEFeatureContract.validate_and_align(df)
