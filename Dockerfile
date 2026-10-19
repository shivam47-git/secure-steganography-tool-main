# syntax=docker/dockerfile:1.6
# -----------------------------------------------------------------------------
# Secure Image Steganography Tool — production Docker image
# -----------------------------------------------------------------------------
# Build:  docker build -t secure-steg .
# Run:    docker run --rm -p 8501:8501 secure-steg
# -----------------------------------------------------------------------------

FROM python:3.11-slim AS base

# Prevent Python from buffering stdout/stderr & writing .pyc files.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies needed by Pillow's wheels at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libjpeg62-turbo \
        zlib1g \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged user — never run Streamlit as root in production.
RUN useradd --create-home --uid 1000 appuser
WORKDIR /app

# Install Python dependencies first to maximise Docker layer caching.
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the source tree.
COPY . .

# Make sure runtime files are owned by the appuser.
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8501

# Healthcheck — Streamlit's built-in /_stcore/health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://localhost:8501/_stcore/health || exit 1

# Bind to all interfaces so it is reachable from outside the container.
CMD ["streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
