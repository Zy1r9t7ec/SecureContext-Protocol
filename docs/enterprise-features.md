# Enterprise Features

This document outlines the enterprise-level features and integrations available in the SecureContext Protocol Authentication Proxy.

## Overview

The SCP includes enterprise-grade features designed for production deployments, including:

- **Configurable Callback URLs** for multi-environment deployments
- **Webhook Notifications** for real-time event monitoring
- **Container Orchestration** support (Docker, Kubernetes)
- **Horizontal Scaling** capabilities
- **Security Hardening** for production environments

## Configurable Callback URLs

### Problem Statement

In enterprise environments, applications are typically deployed across multiple environments (development, staging, production) with different domains. OAuth providers require exact callback URL matches, making it challenging to use the same OAuth application across environments.

### Solution

The SCP supports environment-specific callback URL configuration through the `SCP_CALLBACK_URL_OVERRIDE` environment variable.

### Configuration

```bash
# Development
SCP_BASE_URL=http://localhost:5000
SCP_CALLBACK_URL_OVERRIDE=  # Uses SCP_BASE_URL

# Staging
SCP_BASE_URL=https://staging.example.com
SCP_CALLBACK_URL_OVERRIDE=https://staging.example.com

# Production
SCP_BASE_URL=https://scp.example.com
SCP_CALLBACK_URL_OVERRIDE=https://scp.example.com
```

### OAuth Provider Configuration

Configure your OAuth applications with all environment callback URLs:

**Google OAuth:**
- `http://localhost:5000/oauth/google/callback` (development)
- `https://staging.example.com/oauth/google/callback` (staging)
- `https://scp.example.com/oauth/google/callback` (production)

**Microsoft OAuth:**
- `http://localhost:5000/oauth/microsoft/callback` (development)
- `https://staging.example.com/oauth/microsoft/callback` (staging)
- `https://scp.example.com/oauth/microsoft/callback` (production)

## Webhook Notifications

### Overview

The SCP can send real-time webhook notifications for token lifecycle events, enabling integration with monitoring systems, audit logs, and downstream applications.

### Supported Events

| Event Type | Description | Payload Data |
|------------|-------------|--------------|
| `token_created` | New OAuth token stored | `scope`, `expires_in` |
| `token_retrieved` | Token accessed via API | `client_info` |
| `token_expired` | Token expired and cleaned up | `expired_at` |

### Configuration

```bash
# Enable webhooks
SCP_ENABLE_WEBHOOKS=true
SCP_WEBHOOK_URL=https://your-webhook-endpoint.com/scp-events
SCP_WEBHOOK_SECRET=your-webhook-secret-for-hmac-verification

# Optional: Configure specific events
SCP_WEBHOOK_EVENTS=token_created,token_retrieved,token_expired

# Optional: Retry configuration
SCP_WEBHOOK_TIMEOUT=30
SCP_WEBHOOK_RETRY_COUNT=3
SCP_WEBHOOK_RETRY_DELAY=5
```

### Webhook Payload Format

```json
{
  "event_id": "token_created_abc123_1234567890",
  "event_type": "token_created",
  "timestamp": "2024-01-15T10:30:00Z",
  "session_id": "abc123-def456-ghi789",
  "provider": "google",
  "data": {
    "scope": "profile email https://www.googleapis.com/auth/gmail.readonly",
    "expires_in": 3600
  },
  "metadata": {
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

### Security

Webhooks are secured using HMAC-SHA256 signatures in the `X-SCP-Signature` header:

```python
import hmac
import hashlib

def verify_webhook_signature(payload, signature, secret):
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return f"sha256={expected_signature}" == signature
```

### Testing Webhooks

Use the webhook test endpoint to verify configuration:

```bash
curl -X POST https://your-domain.com/api/enterprise/webhooks/test \
  -H "Content-Type: application/json"
```

## Container Orchestration

### Docker Support

The SCP includes production-ready Docker configurations:

#### Features
- **Multi-stage builds** for optimized image size
- **Non-root user** for security
- **Health checks** for container monitoring
- **Volume mounts** for persistent logs
- **Environment-based configuration**

#### Quick Start
```bash
# Build and run with Docker Compose
cd docker
cp .env.example .env
# Edit .env with your configuration
docker-compose up -d
```

#### Production Services
```bash
# With Redis for token storage
docker-compose --profile redis up -d

# With Nginx reverse proxy
docker-compose --profile nginx up -d
```

### Kubernetes Support

The SCP includes comprehensive Kubernetes manifests:

#### Features
- **Horizontal Pod Autoscaler (HPA)** for automatic scaling
- **Rolling updates** for zero-downtime deployments
- **Health checks** (liveness and readiness probes)
- **Resource limits** and requests
- **Security contexts** and RBAC
- **ConfigMaps and Secrets** for configuration management

#### Quick Start
```bash
# Deploy to Kubernetes
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/hpa.yaml
```

#### Auto-scaling Configuration
```yaml
# Horizontal Pod Autoscaler
spec:
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Horizontal Scaling

### Architecture Considerations

The SCP is designed to be stateless and horizontally scalable:

#### ✅ Scalable Components
- **Stateless design**: No shared state between instances
- **In-memory token storage**: Each instance maintains its own storage
- **Independent OAuth flows**: No coordination required between instances
- **Webhook delivery**: Asynchronous processing with retry logic

#### ⚠️ Scaling Limitations
- **Token isolation**: Tokens stored on one instance aren't accessible from others
- **Session affinity**: Not required but tokens are instance-specific
- **Memory constraints**: Token storage limited by available memory

### Load Balancing

#### Nginx Configuration
```nginx
upstream scp_backend {
    server scp-app-1:5000;
    server scp-app-2:5000;
    server scp-app-3:5000;
    
    # No session affinity required
    ip_hash off;
}
```

#### Kubernetes Service
```yaml
apiVersion: v1
kind: Service
spec:
  sessionAffinity: None  # No session affinity required
  ports:
  - port: 80
    targetPort: 5000
```

### Production Token Storage

For production deployments requiring persistent token storage, consider:

#### Redis Backend (Future Enhancement)
```python
class RedisTokenStorage:
    def __init__(self, redis_url):
        self.redis = redis.from_url(redis_url)
    
    def store_tokens(self, session_id, token_data):
        self.redis.setex(session_id, 3600, json.dumps(token_data))
```

#### Database Backend (Future Enhancement)
```python
class DatabaseTokenStorage:
    def __init__(self, db_url):
        self.db = create_engine(db_url)
    
    def store_tokens(self, session_id, token_data):
        # Store in database with expiration
        pass
```

## Security Features

### Network Security
- **HTTPS enforcement** in production configurations
- **Rate limiting** on OAuth and API endpoints
- **CORS configuration** for cross-origin requests
- **Security headers** (HSTS, CSP, X-Frame-Options)

### Container Security
- **Non-root user** execution
- **Read-only filesystem** where possible
- **Resource limits** to prevent resource exhaustion
- **Security scanning** integration points

### OAuth Security
- **State parameter validation** for CSRF protection
- **Redirect URI validation** to prevent open redirects
- **Token expiration** and automatic cleanup
- **Scope limitation** to minimal necessary permissions

## Monitoring and Observability

### Health Check Endpoints

```bash
# Application health
GET /api/enterprise/config

# Storage statistics
GET /api/storage/stats

# Webhook configuration
GET /api/enterprise/webhooks/info
```

### Metrics Integration

#### Prometheus Support
```yaml
# Kubernetes deployment annotations
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "5000"
  prometheus.io/path: "/api/storage/stats"
```

#### Custom Metrics
- Token creation/retrieval rates
- OAuth flow success/failure rates
- Webhook delivery success rates
- Session cleanup statistics

### Logging

#### Structured Logging
```python
logger.info("OAuth flow completed", 
           provider="google", 
           session_id="abc123",
           user_agent="Mozilla/5.0...")
```

#### Log Aggregation
- ELK Stack integration
- Fluentd log forwarding
- Grafana visualization

## Deployment Automation

### Enterprise Deployment Script

The SCP includes an automated deployment script for enterprise environments:

```bash
# Docker deployment
./scripts/deploy-enterprise.sh -t docker -d example.com -w https://webhook.example.com/scp

# Kubernetes deployment
./scripts/deploy-enterprise.sh -t kubernetes -d scp.example.com -n production-scp --enable-webhooks

# Docker Swarm deployment
./scripts/deploy-enterprise.sh -t docker-swarm -e staging -d staging.example.com
```

### Features
- **Automated configuration generation**
- **Environment-specific deployments**
- **Webhook configuration**
- **Post-deployment testing**
- **Security best practices**

## API Endpoints

### Enterprise Configuration
```bash
GET /api/enterprise/config
```
Returns enterprise configuration information (sanitized).

### Webhook Management
```bash
GET /api/enterprise/webhooks/info
POST /api/enterprise/webhooks/test
```
Webhook configuration and testing endpoints.

### Storage Statistics
```bash
GET /api/storage/stats
```
Token storage statistics for monitoring.

## Best Practices

### Production Deployment
1. **Use HTTPS everywhere** - Never deploy without TLS
2. **Implement monitoring** - Set up comprehensive logging and metrics
3. **Regular security updates** - Keep dependencies updated
4. **Backup configurations** - Store secrets securely
5. **Test disaster recovery** - Verify backup/restore procedures

### Scaling Considerations
1. **Monitor memory usage** - Token storage is memory-based
2. **Implement circuit breakers** - Handle external service failures
3. **Use infrastructure as code** - Version control deployments
4. **Set up alerts** - Monitor webhook delivery and OAuth failures
5. **Plan for token persistence** - Consider Redis/database for production

### Security Hardening
1. **Network segmentation** - Isolate SCP from other services
2. **Regular security scans** - Automated vulnerability scanning
3. **Audit logging** - Track all token access events
4. **Principle of least privilege** - Minimal OAuth scopes
5. **Incident response plan** - Prepare for security incidents

## Support and Maintenance

### Troubleshooting
- Check the [Enterprise Deployment Guide](enterprise-deployment.md)
- Review application logs for OAuth flow issues
- Test webhook delivery with the test endpoint
- Verify OAuth provider configurations

### Updates and Patches
- Monitor GitHub releases for security updates
- Test updates in staging before production
- Review changelog for breaking changes
- Backup configurations before updates

### Enterprise Support
For enterprise support, custom deployments, and professional services:
- GitHub Issues for bug reports
- GitHub Discussions for community support
- Enterprise consulting available for custom deployments