# Base image pinned by tag
ARG PYTHON_IMAGE=python:3.11.17-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89

# ---- Build stage: install dependencies into an isolated virtualenv ----
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Runtime dependencies only, test tools live in requirements-dev.txt
COPY requirements.txt .
RUN pip install -r requirements.txt

# ---- Runtime stage: only the venv and app code, no build tooling ----
FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.title="vulntracker-api" \
      org.opencontainers.image.source="https://github.com/pavawsdev/vulntracker-security-assessment"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL="sqlite:////data/vulntracker.db"

# Fixed, non-root UID/GID so Kubernetes runAsUser/fsGroup can match it
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data && chown app:app /data

COPY --from=builder /opt/venv /opt/venv
# App code is owned by root and read-only to the app user, so a compromised process can't modify it
COPY app/ /app/

WORKDIR /app
USER 10001:10001

EXPOSE 8000

# slim has no curl, so probe /health with the Python stdlib
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

# Exec form so uvicorn is PID 1 and receives SIGTERM directly
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
