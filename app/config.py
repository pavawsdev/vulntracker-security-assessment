import os


def _load_secret_key() -> str:
    # Read from a mounted secret file if provided (Helm mounts the secret this way),
    # otherwise from the environment. No hardcoded fallback: the app must fail to
    # start rather than run on a known key.
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


# Overridable so the container can keep the DB on a writable volume (root filesystem is read-only)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Overridable so Kubernetes can point it at the in-cluster notify service
NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Share links use a configured base URL, not the client-controlled Host header (prevents host-header injection)
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
# Share links expire 24 hours after creation
SHARE_LINK_TTL_HOURS = 24
# A password-protected link locks after this many wrong password attempts
SHARE_MAX_PASSWORD_ATTEMPTS = 5
