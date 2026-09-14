import pytest
import sys
from pathlib import Path
from backend.config import settings

def test_python_version():
    """Ensure Python version is >= 3.12."""
    assert sys.version_info >= (3, 12)

def test_core_dependencies():
    """Verify critical ML, XAI, and API dependencies can be imported."""
    import numpy as np
    import pandas as pd
    import sklearn
    import shap
    import pefile
    import fastapi
    import sqlalchemy
    
    assert np.__version__ is not None
    assert pd.__version__ is not None
    assert sklearn.__version__ is not None
    assert shap.__version__ is not None
    assert pefile.__version__ is not None
    assert fastapi.__version__ is not None
    assert sqlalchemy.__version__ is not None

def test_directory_structure():
    """Verify essential project directories exist."""
    base = settings.BASE_DIR
    required_dirs = [
        base / "backend" / "api",
        base / "backend" / "schemas",
        base / "backend" / "services",
        base / "models" / "phishing",
        base / "models" / "malware",
        base / "feature_extraction",
        base / "risk_engine",
        base / "explainable_ai",
        base / "database",
        base / "data" / "raw",
        base / "data" / "processed",
        base / "frontend",
        base / "browser_extension",
        base / "tests"
    ]
    for d in required_dirs:
        assert d.exists() and d.is_dir(), f"Missing directory: {d}"

def test_settings_loaded():
    """Verify settings defaults are populated correctly."""
    assert settings.PROJECT_NAME == "AI-Based Cyber Threat Prediction System"
    assert settings.MAX_UPLOAD_SIZE_MB == 15
    assert settings.WEIGHT_PHISHING == 0.85
    assert settings.WEIGHT_MALWARE == 0.85
