"""
Secure File Handling Service for Untrusted File Uploads.
Enforces size limits, extension validation, path safety, and automatic temporary file cleanup.
"""
import os
import hashlib
import tempfile
from pathlib import Path
from typing import Tuple
from fastapi import UploadFile, HTTPException
from backend.config import settings
from feature_extraction.pe_features import extract_pe_features_from_file, InvalidPEFileError
import pandas as pd

class FileSecurityError(Exception):
    pass

async def process_untrusted_file(upload_file: UploadFile) -> Tuple[pd.DataFrame, str, str]:
    """
    Safely handles an uploaded untrusted binary:
    1. Validates extension and filename
    2. Streams file to secure temp directory while enforcing max size limit
    3. Computes SHA-256 fingerprint
    4. Performs static PE feature extraction
    5. Guarantees immediate deletion of temporary file
    Returns: (features_df, filename, sha256_hash)
    """
    raw_filename = Path(upload_file.filename or "unknown.bin").name # Path traversal protection
    ext = Path(raw_filename).suffix.lower()
    
    if ext not in settings.ALLOWED_PE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Supported formats: {', '.join(settings.ALLOWED_PE_EXTENSIONS)}"
        )
        
    sha256 = hashlib.sha256()
    bytes_read = 0
    
    # Create temporary file with restricted permissions
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        temp_path = tmp.name
        try:
            while chunk := await upload_file.read(65536): # 64KB chunks
                bytes_read += len(chunk)
                if bytes_read > settings.MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB."
                    )
                sha256.update(chunk)
                tmp.write(chunk)
            tmp.flush()
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
            
    # Statically parse PE file
    try:
        features_df = extract_pe_features_from_file(temp_path)
    except InvalidPEFileError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal error during static PE inspection.")
    finally:
        # Guarantee cleanup of untrusted binary from disk
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
                
    return features_df, raw_filename, sha256.hexdigest()
