FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app/ .

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "server.py"]
