FROM node:20-slim AS frontend-build
WORKDIR /app
COPY src/dashboard/frontend/package*.json ./
RUN npm ci
COPY src/dashboard/frontend/ ./
RUN npm run build

FROM python:3.11-slim

# Install system dependencies for Playwright
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml .
COPY src/ ./src/
COPY config/ ./config/
COPY --from=frontend-build /app/dist ./src/dashboard/frontend/dist

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Install Playwright browsers
RUN playwright install chromium
RUN playwright install-deps chromium

# Create data directories
RUN mkdir -p /app/data/evidence /app/data/fingerprints

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/app/data
ENV EVIDENCE_DIR=/app/data/evidence
ENV CONFIG_DIR=/app/config

# Run as non-root user for security
RUN useradd -m -u 1000 seedbuster
RUN chown -R seedbuster:seedbuster /app
USER seedbuster

# Entry point
CMD ["python", "-m", "src.main"]
