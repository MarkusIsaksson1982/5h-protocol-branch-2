FROM python:3.12-slim

WORKDIR /app

# Install build dependencies for cryptography wheel
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project definition first (layer cache: only invalidated on dep changes)
COPY pyproject.toml ./

# Install the package and all dependencies
# --no-build-isolation ensures pyproject.toml extras work correctly
RUN pip install --no-cache-dir -e ".[test]"

# Copy source after deps (maximises layer cache hits during development)
COPY five_h_proxy/ ./five_h_proxy/
COPY main.py ./

# Copy spec files so the test vector path resolves inside the container
# (spec/ is mounted read-only in compose; COPY here is a fallback for plain docker run)
COPY ../../spec/ ./spec/ 2>/dev/null || true

EXPOSE 8000

# Healthcheck: poll /v1/proxy/health every 10 s
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/v1/proxy/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
