#!/usr/bin/env python3
"""
Deployment script for the SecureContext Protocol Authentication Proxy.

This script helps deploy the application to various hosting platforms.
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def create_dockerfile():
    """Create a Dockerfile for containerized deployment."""
    dockerfile_content = """FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app \\
    && chown -R app:app /app
USER app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:5000/ || exit 1

# Run application
CMD ["python", "run.py"]
"""
    
    with open('Dockerfile', 'w') as f:
        f.write(dockerfile_content)
    print("✅ Created Dockerfile")

def create_docker_compose():
    """Create docker-compose.yml for local development."""
    compose_content = """version: '3.8'

services:
  scp-auth-proxy:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_HOST=0.0.0.0
      - FLASK_PORT=5000
      - FLASK_DEBUG=false
    env_file:
      - .env
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Optional: Add Redis for production token storage
  # redis:
  #   image: redis:7-alpine
  #   ports:
  #     - "6379:6379"
  #   restart: unless-stopped
"""
    
    with open('docker-compose.yml', 'w') as f:
        f.write(compose_content)
    print("✅ Created docker-compose.yml")

def create_heroku_config():
    """Create Heroku deployment configuration."""
    # Procfile
    with open('Procfile', 'w') as f:
        f.write("web: python run.py\n")
    
    # runtime.txt
    with open('runtime.txt', 'w') as f:
        f.write("python-3.11.6\n")
    
    # app.json for Heroku Button
    app_json = {
        "name": "SecureContext Protocol",
        "description": "Open-source OAuth 2.0 mediation system for AI agents",
        "repository": "https://github.com/yourusername/secure-context-protocol",
        "logo": "https://example.com/logo.png",
        "keywords": ["oauth", "ai", "agents", "authentication", "flask"],
        "env": {
            "FLASK_SECRET_KEY": {
                "description": "A secret key for Flask sessions",
                "generator": "secret"
            },
            "GOOGLE_CLIENT_ID": {
                "description": "Google OAuth Client ID"
            },
            "GOOGLE_CLIENT_SECRET": {
                "description": "Google OAuth Client Secret"
            },
            "MICROSOFT_CLIENT_ID": {
                "description": "Microsoft OAuth Client ID"
            },
            "MICROSOFT_CLIENT_SECRET": {
                "description": "Microsoft OAuth Client Secret"
            }
        },
        "formation": {
            "web": {
                "quantity": 1,
                "size": "basic"
            }
        },
        "addons": [],
        "buildpacks": [
            {
                "url": "heroku/python"
            }
        ]
    }
    
    with open('app.json', 'w') as f:
        json.dump(app_json, f, indent=2)
    
    print("✅ Created Heroku configuration files")

def create_railway_config():
    """Create Railway deployment configuration."""
    railway_json = {
        "build": {
            "builder": "NIXPACKS"
        },
        "deploy": {
            "startCommand": "python run.py",
            "healthcheckPath": "/",
            "healthcheckTimeout": 100,
            "restartPolicyType": "ON_FAILURE",
            "restartPolicyMaxRetries": 10
        }
    }
    
    with open('railway.json', 'w') as f:
        json.dump(railway_json, f, indent=2)
    
    print("✅ Created Railway configuration")

def create_vercel_config():
    """Create Vercel deployment configuration."""
    vercel_json = {
        "version": 2,
        "builds": [
            {
                "src": "run.py",
                "use": "@vercel/python"
            }
        ],
        "routes": [
            {
                "src": "/(.*)",
                "dest": "run.py"
            }
        ],
        "env": {
            "FLASK_HOST": "0.0.0.0",
            "FLASK_PORT": "5000"
        }
    }
    
    with open('vercel.json', 'w') as f:
        json.dump(vercel_json, f, indent=2)
    
    print("✅ Created Vercel configuration")

def create_fly_config():
    """Create Fly.io deployment configuration."""
    fly_toml = """app = "scp-auth-proxy"
primary_region = "dfw"

[build]
  builder = "paketobuildpacks/builder:base"

[env]
  FLASK_HOST = "0.0.0.0"
  FLASK_PORT = "8080"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 0
  processes = ["app"]

[[http_service.checks]]
  interval = "10s"
  grace_period = "5s"
  method = "get"
  path = "/"
  protocol = "http"
  timeout = "2s"
  tls_skip_verify = false

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 256
"""
    
    with open('fly.toml', 'w') as f:
        f.write(fly_toml)
    
    print("✅ Created Fly.io configuration")

def update_gitignore():
    """Update .gitignore for deployment files."""
    gitignore_additions = """
# Deployment
.vercel
.railway
fly.toml.bak
"""
    
    with open('.gitignore', 'a') as f:
        f.write(gitignore_additions)
    
    print("✅ Updated .gitignore")

def print_deployment_instructions():
    """Print deployment instructions for different platforms."""
    instructions = """
🚀 Deployment Instructions

1. DOCKER (Local/Self-hosted)
   docker-compose up --build

2. HEROKU
   heroku create your-app-name
   heroku config:set FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   heroku config:set GOOGLE_CLIENT_ID=your_google_client_id
   heroku config:set GOOGLE_CLIENT_SECRET=your_google_client_secret
   heroku config:set MICROSOFT_CLIENT_ID=your_microsoft_client_id
   heroku config:set MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
   git push heroku main

3. RAILWAY
   railway login
   railway new
   railway up
   # Set environment variables in Railway dashboard

4. FLY.IO
   fly auth login
   fly launch
   fly secrets set FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   fly secrets set GOOGLE_CLIENT_ID=your_google_client_id
   fly secrets set GOOGLE_CLIENT_SECRET=your_google_client_secret
   fly secrets set MICROSOFT_CLIENT_ID=your_microsoft_client_id
   fly secrets set MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
   fly deploy

5. VERCEL (Serverless)
   vercel
   # Set environment variables in Vercel dashboard

⚠️  IMPORTANT: Update OAuth redirect URIs in your provider consoles:
   - Replace localhost:5000 with your deployed domain
   - Use HTTPS for production deployments
"""
    
    print(instructions)

def main():
    """Main deployment setup function."""
    print("🔧 Setting up deployment configurations...")
    
    create_dockerfile()
    create_docker_compose()
    create_heroku_config()
    create_railway_config()
    create_vercel_config()
    create_fly_config()
    update_gitignore()
    
    print("\n✅ All deployment configurations created!")
    print_deployment_instructions()

if __name__ == '__main__':
    main()