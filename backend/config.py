import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings:
    PROJECT_NAME: str = "AI-Based Cyber Threat Prediction System"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Paths
    BASE_DIR: Path = BASE_DIR
    MODELS_DIR: Path = BASE_DIR / "models"
    DATA_DIR: Path = BASE_DIR / "data"
    DATABASE_PATH: Path = BASE_DIR / "database" / "cyber_threat.db"
    
    # Security
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "15"))
    MAX_UPLOAD_SIZE_BYTES: int = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    ALLOWED_PE_EXTENSIONS: list[str] = [".exe", ".dll", ".sys", ".bin", ".scr"]
    
    # Risk Engine Default Weights (Normalized sum = 1.0)
    WEIGHT_PHISHING: float = float(os.getenv("WEIGHT_PHISHING", "0.85"))
    WEIGHT_PHISHING_CONTEXT: float = float(os.getenv("WEIGHT_PHISHING_CONTEXT", "0.15"))
    WEIGHT_MALWARE: float = float(os.getenv("WEIGHT_MALWARE", "0.85"))
    WEIGHT_MALWARE_CONTEXT: float = float(os.getenv("WEIGHT_MALWARE_CONTEXT", "0.15"))

settings = Settings()
