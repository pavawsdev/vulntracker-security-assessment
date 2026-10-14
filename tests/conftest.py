import os

# The app refuses to start without a signing key (see app/config.py). Set a
# throwaway key for the test run before any app module is imported, so tests
# and CI never depend on a real secret.
os.environ.setdefault("JWT_SECRET_KEY", "test-only-not-a-real-secret")
