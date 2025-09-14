# Enterprise Deployment Guide

This guide covers enterprise-level deployment configurations, horizontal scaling considerations, and production best practices for the SecureContext Protocol Authentication Proxy.

## Table of Contents

1. [Enterprise Configuration](#enterprise-configuration)
2. [Webhook Integration](#webhook-integration)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Horizontal Scaling](#horizontal-scaling)
6. [Security Considerations](#security-considerations)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Troubleshooting](#troubleshooting)

## Enterprise Configuration

### Environment Variables

The SCP supports enterprise-specific configuration through environment variables:

```bash
# Enterprise Integration
SCP_BASE_URL=https://your-domain.com
SCP_CALLBACK_URL_OVERRIDE=https://your-domain.com
SCP_ENVIRONMENT=production

# Webhook Configuration
SCP_ENABLE_WEBHOOKS=true
SCP_WEBHOOK_URL=https://your-webhook-endpoint.com/scp-events
SCP_WEBHOOK_SECRET=your-webhook-secret-for-signature-verification
SCP_WEBHOOK_EVENTS=token_created,token_retrieved,token_expired
SCP_WEBHOOK_TIMEOUT=30
SCP_WEBHOOK_RETRY_COUNT=3
SCP_WEBHOOK_RETRY_DELAY=5
```

### Configurable Callback URLs

For multi-environment deployments, you can override OAuth callback URLs:

- **Development**: `http://localhost:5000`
- **Staging**: `https://staging.your-domain.com`
- **Production**: `https://your-domain.com`

Set `SCP_CALLBACK_URL_OVERRIDE` to ensure OAuth providers redirect to the correct environment.

## Webhook Integration

### Webhook Events

The SCP can send webhook notifications for the following events:

- `token_created`: When a new OAuth token is stored
- `token_retrieved`: When a token is accessed via API
- `token_expired`: When a token expires and is cleaned up

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

### Webhook Security

Webhooks are secured using HMAC-SHA256 signatures:

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

## Docker Deployment

### Basic Docker Setup

1. **Build the Docker image**:
   ```bash
   docker build -f docker/Dockerfile -t scp/authentication-proxy:latest .
   ```

2. **Run with Docker Compose**:
   ```bash
   cd docker
   cp .env.example .env
   # Edit .env with your configuration
   docker-compose up -d
   ```

### Production Docker Configuration

For production deployments, use the provided `docker-compose.yml` with:

- **Multi-stage builds** for smaller image size
- **Non-root user** for security
- **Health checks** for container monitoring
- **Volume mounts** for persistent logs
- **Network isolation** with custom networks

### Optional Services

Enable additional services using Docker Compose profiles:

```bash
# With Redis for token storage
docker-compose --profile redis up -d

# With Nginx reverse proxy
docker-compose --profile nginx up -d

# With both Redis and Nginx
docker-compose --profile redis --profile nginx up -d
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.19+)
- kubectl configured
- Ingress controller (nginx recommended)
- TLS certificates for HTTPS

### Deployment Steps

1. **Create namespace and apply configurations**:
   ```bash
   kubectl apply -f k8s/namespace.yaml
   kubectl apply -f k8s/configmap.yaml
   kubectl apply -f k8s/secret.yaml
   ```

2. **Update secrets with your values**:
   ```bash
   kubectl edit secret scp-secrets -n scp
   ```

3. **Deploy the application**:
   ```bash
   kubectl apply -f k8s/deployment.yaml
   kubectl apply -f k8s/service.yaml
   kubectl apply -f k8s/ingress.yaml
   kubectl apply -f k8s/hpa.yaml
   ```

4. **Verify deployment**:
   ```bash
   kubectl get pods -n scp
   kubectl get svc -n scp
   kubectl get ingress -n scp
   ```

### Kubernetes Features

- **Horizontal Pod Autoscaler (HPA)**: Automatically scales based on CPU/memory usage
- **Rolling updates**: Zero-downtime deployments
- **Health checks**: Liveness and readiness probes
- **Resource limits**: CPU and memory constraints
- **Security context**: Non-root containers with read-only filesystem

## Horizontal Scaling

### Scaling Considerations

The SCP is designed to be stateless and horizontally scalable:

#### ✅ Stateless Design
- **In-memory token storage**: Each instance maintains its own token storage
- **No shared state**: No dependencies on local files or databases
- **Session affinity not required**: Tokens are accessed via session ID

#### ⚠️ Token Storage Limitations
- **Memory-based**: Tokens are lost when instances restart
- **Instance isolation**: Tokens stored on one instance aren't accessible from others
- **Cleanup coordination**: Each instance runs its own cleanup scheduler

### Production Token Storage

For production deployments requiring persistent token storage:

#### Option 1: Redis Backend
```python
# Future enhancement: Redis token storage
class RedisTokenStorage:
    def __init__(self, redis_url):
        self.redis = redis.from_url(redis_url)
    
    def store_tokens(self, session_id, token_data):
        self.redis.setex(session_id, 3600, json.dumps(token_data))
    
    def retrieve_tokens(self, session_id):
        data = self.redis.get(session_id)
        return json.loads(data) if data else None
```

#### Option 2: Database Backend
```python
# Future enhancement: Database token storage
class DatabaseTokenStorage:
    def __init__(self, db_url):
        self.db = create_engine(db_url)
    
    def store_tokens(self, session_id, token_data):
        # Store in database with expiration
        pass
```

### Load Balancing

#### Nginx Configuration
```nginx
upstream scp_backend {
    server scp-app-1:5000;
    server scp-app-2:5000;
    server scp-app-3:5000;
    
    # Health checks
    keepalive 32;
}

server {
    location / {
        proxy_pass http://scp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Kubernetes Service
```yaml
apiVersion: v1
kind: Service
metadata:
  name: scp-app-service
spec:
  type: LoadBalancer
  sessionAffinity: None  # No session affinity required
  ports:
  - port: 80
    targetPort: 5000
  selector:
    app: scp-app
```

### Auto-scaling Configuration

#### Docker Swarm
```yaml
version: '3.8'
services:
  scp-app:
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.1'
          memory: 128M
```

#### Kubernetes HPA
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: scp-app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: scp-app
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

## Security Considerations

### Network Security
- **HTTPS enforcement**: All production traffic over TLS
- **Rate limiting**: Prevent abuse of OAuth endpoints
- **CORS configuration**: Restrict cross-origin requests
- **Security headers**: HSTS, CSP, X-Frame-Options

### Container Security
- **Non-root user**: Containers run as unprivileged user
- **Read-only filesystem**: Prevent runtime modifications
- **Resource limits**: CPU and memory constraints
- **Security scanning**: Regular vulnerability scans

### OAuth Security
- **State parameter validation**: CSRF protection
- **Redirect URI validation**: Prevent open redirects
- **Token expiration**: Automatic cleanup of expired tokens
- **Scope limitation**: Request minimal necessary permissions

## Monitoring and Observability

### Health Checks

The SCP provides health check endpoints:

```bash
# Application health
curl https://your-domain.com/api/enterprise/config

# Storage statistics
curl https://your-domain.com/api/storage/stats

# Webhook configuration
curl https://your-domain.com/api/enterprise/webhooks/info
```

### Metrics Collection

#### Prometheus Integration
```yaml
# Add to deployment annotations
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "5000"
  prometheus.io/path: "/api/storage/stats"
```

#### Custom Metrics
- Token creation rate
- Token retrieval rate
- OAuth flow success/failure rates
- Webhook delivery success rates
- Session cleanup statistics

### Logging

#### Structured Logging
```python
import structlog

logger = structlog.get_logger()
logger.info("OAuth flow completed", 
           provider="google", 
           session_id="abc123",
           user_agent="Mozilla/5.0...")
```

#### Log Aggregation
- **ELK Stack**: Elasticsearch, Logstash, Kibana
- **Fluentd**: Log collection and forwarding
- **Grafana**: Visualization and alerting

## Troubleshooting

### Common Issues

#### 1. OAuth Callback Mismatch
```
Error: redirect_uri_mismatch
```
**Solution**: Ensure `SCP_CALLBACK_URL_OVERRIDE` matches OAuth app configuration.

#### 2. Webhook Delivery Failures
```
Error: Webhook timeout for event token_created_abc123
```
**Solution**: Check webhook endpoint availability and increase timeout.

#### 3. Token Storage Limits
```
Warning: Token storage limit reached, cleaning up expired sessions
```
**Solution**: Implement Redis or database backend for production.

#### 4. Load Balancer Health Checks
```
Error: Health check failed
```
**Solution**: Verify health check endpoint and container startup time.

### Debugging Commands

```bash
# Check pod logs
kubectl logs -f deployment/scp-app -n scp

# Check service endpoints
kubectl get endpoints scp-app-service -n scp

# Test webhook delivery
curl -X POST https://your-domain.com/api/enterprise/webhooks/test

# Check storage statistics
curl https://your-domain.com/api/storage/stats
```

### Performance Tuning

#### Memory Optimization
```python
# Adjust token storage limits
MAX_CONCURRENT_SESSIONS = 1000
CLEANUP_INTERVAL = 300  # 5 minutes
```

#### CPU Optimization
```yaml
# Kubernetes resource requests/limits
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

## Best Practices

1. **Use HTTPS everywhere**: Never deploy without TLS in production
2. **Implement monitoring**: Set up comprehensive logging and metrics
3. **Regular security updates**: Keep dependencies and base images updated
4. **Backup configurations**: Store secrets and configurations securely
5. **Test disaster recovery**: Verify backup and restore procedures
6. **Monitor webhook delivery**: Set up alerts for webhook failures
7. **Implement circuit breakers**: Handle external service failures gracefully
8. **Use infrastructure as code**: Version control all deployment configurations

## Support

For enterprise support and custom deployment assistance:

- **Documentation**: Check the main README and API documentation
- **Issues**: Report bugs and feature requests on GitHub
- **Community**: Join discussions in GitHub Discussions
- **Enterprise**: Contact for custom deployment and scaling assistance