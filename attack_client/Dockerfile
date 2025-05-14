# Attack Client Dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set entrypoint to Python
ENTRYPOINT ["python"]
CMD ["main.py"]