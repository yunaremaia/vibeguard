# VibeGuard Dockerfile
# Security scanner for AI-generated code
# https://github.com/yunaremaia/vibeguard

FROM python:3.12-slim AS base

WORKDIR /app

# Copy project metadata first for better layer caching
COPY pyproject.toml README.md ./

# Install the package
RUN pip install --no-cache-dir .

# Create a non-root user for scanning
RUN useradd --create-home --shell /bin/bash vibescanner
USER vibescanner

# Set the entrypoint
ENTRYPOINT ["vibeguard"]
CMD ["--help"]
