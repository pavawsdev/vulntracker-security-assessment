import os


def _load_secret_key() -> str:
    # From a mounted file (Helm) or env var; no fallback, so the app can't run on a known key
    path = os.getenv("JWT_SECRET_KEY_FILE")
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    else:
        value = os.getenv("JWT_SECRET_KEY", "")
    if not value:
        raise RuntimeError(
            "JWT_SECRET_KEY (or JWT_SECRET_KEY_FILE) must be set; refusing to start without a signing key"
        )
    return value


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Configured base URL, not the client-controlled Host header (prevents host-header injection)
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")

SHARE_LINK_TTL_HOURS = 24
SHARE_MAX_PASSWORD_ATTEMPTS = 5
