"""
Configuration and settings for the TrustXCloud FastAPI backend.
All environment variables, directory paths, and ML-to-Frontend mapping thresholds
are centralized here.
"""

import os
from typing import List
from dotenv import load_dotenv

load_dotenv()

# Root directory references
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")

class Settings:
    # API Metadata
    PROJECT_NAME: str = "TrustXCloud Security Intelligence API"
    VERSION: str = "3.0.0"
    API_V1_STR: str = "/api/v1"
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,*").split(",")
        if origin.strip()
    ]

    # AWS & Storage Settings
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    DYNAMODB_TABLE_NAME: str = os.getenv("DYNAMODB_TABLE_NAME", "CloudSecurityDecisions")
    
    # File Paths
    RAW_EVENTS_PATH: str = os.getenv(
        "RAW_EVENTS_PATH",
        os.path.join(DATA_DIR, "processed", "sample_raw_events.json")
    )
    FINAL_METRICS_PATH: str = os.path.join(MODELS_DIR, "final_metrics_v3.json")
    XAI_METRICS_PATH: str = os.path.join(MODELS_DIR, "xai_metrics_v3.json")
    TRAINING_CONFIG_PATH: str = os.path.join(MODELS_DIR, "training_config_v3.json")
    
    # Risk Score & Classification Mapping Thresholds
    # Isolated mapping rules:
    #   threat_probability >= THRESHOLD_CRITICAL (0.85) -> "critical"
    #   threat_probability >= THRESHOLD_HIGH (0.50)     -> "high_risk"
    #   threat_probability >= THRESHOLD_SUSPICIOUS (0.25)-> "suspicious"
    #   threat_probability <  THRESHOLD_SUSPICIOUS      -> "normal"
    THRESHOLD_CRITICAL: float = float(os.getenv("THRESHOLD_CRITICAL", "0.85"))
    THRESHOLD_HIGH: float = float(os.getenv("THRESHOLD_HIGH", "0.50"))
    THRESHOLD_SUSPICIOUS: float = float(os.getenv("THRESHOLD_SUSPICIOUS", "0.25"))
    ALERT_RISK_THRESHOLD: float = float(os.getenv("ALERT_RISK_THRESHOLD", "0.50"))

    # Database Settings
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(DATA_DIR, "trustxcloud.db").replace("\\", "/")
    )

    # Authentication & JWT Configuration
    JWT_SECRET: str = os.getenv("JWT_SECRET", "trustxcloud-secure-default-jwt-secret-key-replace-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRATION_MINUTES: int = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))

    # Google OAuth 2.0 / OpenID Connect Configuration
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/v1/auth/google/callback")


settings = Settings()
