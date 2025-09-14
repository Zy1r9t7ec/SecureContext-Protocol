# Multi-stage Docker build for SecureContext Protocol
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r scp && useradd -r -g scp scp

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/scp/.local

# Copy application code
COPY authentication_proxy/ ./authentication_proxy/
COPY providers.json .
COPY run.py .

# Create necessary directories and set permissions
RUN mkdir -p /app/logs && \
    chown -R scp:scp /app

# Switch to non-root user
USER scp

# Set environment variables
ENV PATH=/home/scp/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV FLASK_APP=run.py
ENV FLASK_ENV=production

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/enterprise/config || exit 1

# Run the application
CMD ["python", "run.py"]