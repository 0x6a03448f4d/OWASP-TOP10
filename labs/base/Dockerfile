# Base Dockerfile for OWASP Top 10 Educational Labs
# This provides a common Python/Flask environment for all labs

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=server.py

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create a non-root user for security
RUN useradd -m -u 1000 labuser && \
    chown -R labuser:labuser /app

# Switch to non-root user
USER labuser

# Expose port 5000
EXPOSE 5000

# Run the application
CMD ["python", "server.py"]
