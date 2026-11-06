"""VulnWatch Application Configuration."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        # In development, generate random token; warn if production
        if os.environ.get("FLASK_ENV") == "production":
            raise RuntimeError("CRITICAL: SECRET_KEY environment variable must be set in production mode!")
        SECRET_KEY = secrets.token_hex(32)

    DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "instance" / "app.db"))
    INSTANCE_PATH = BASE_DIR / "instance"
    LOGS_DIR = INSTANCE_PATH / "logs"
    UPLOADS_DIR = INSTANCE_PATH / "uploads"
    DATA_DIR = BASE_DIR / "data"
    MODELS_DIR = BASE_DIR / "models"

    # Max upload limit (150 MB with headroom for the ~100MB dataset)
    MAX_CONTENT_LENGTH = 150 * 1024 * 1024
    ALLOWED_EXTENSIONS = {"csv", "json"}

    # NVD API 2.0 Settings
    NVD_BASE_URL = os.environ.get("NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip() or None
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "15"))
    STALE_AFTER_HOURS = int(os.environ.get("STALE_AFTER_HOURS", "24"))
    # In public access mode (no API key), fetch the last 1 day or max 1000 items to avoid public rate-limit timeouts
    NVD_INITIAL_LOOKBACK_DAYS = int(os.environ.get("NVD_INITIAL_LOOKBACK_DAYS", "1"))

    # Operational
    RECENT_DAYS = int(os.environ.get("RECENT_DAYS", "30"))
    CHUNK_SIZE = int(os.environ.get("CHUNK_SIZE", "5000"))

    # Session & Security Cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"

    @classmethod
    def ensure_directories(cls):
        """Ensure runtime directories exist."""
        cls.INSTANCE_PATH.mkdir(parents=True, exist_ok=True)
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        cls.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        cls.MODELS_DIR.mkdir(parents=True, exist_ok=True)
