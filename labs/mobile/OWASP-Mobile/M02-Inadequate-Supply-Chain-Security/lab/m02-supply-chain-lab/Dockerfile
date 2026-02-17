FROM python:3.11-slim

# Create non-root user
RUN groupadd -r labuser && useradd -r -g labuser labuser

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY app/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app/ .

# Change ownership to non-root user
RUN chown -R labuser:labuser /app

# Switch to non-root user
USER labuser

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "server.py"]
