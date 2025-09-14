#!/bin/bash

# SecureContext Protocol Enterprise Deployment Script
# This script helps deploy SCP in various enterprise environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEPLOYMENT_TYPE=""
ENVIRONMENT="production"
NAMESPACE="scp"
DOMAIN=""
WEBHOOK_URL=""
ENABLE_WEBHOOKS="false"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
SecureContext Protocol Enterprise Deployment Script

Usage: $0 [OPTIONS]

Options:
    -t, --type TYPE         Deployment type: docker, kubernetes, docker-swarm
    -e, --environment ENV   Environment: development, staging, production (default: production)
    -d, --domain DOMAIN     Domain name for the deployment
    -w, --webhook-url URL   Webhook URL for notifications
    -n, --namespace NS      Kubernetes namespace (default: scp)
    --enable-webhooks       Enable webhook notifications
    -h, --help              Show this help message

Examples:
    # Docker deployment
    $0 -t docker -d example.com -w https://webhook.example.com/scp

    # Kubernetes deployment
    $0 -t kubernetes -d scp.example.com -n production-scp --enable-webhooks

    # Docker Swarm deployment
    $0 -t docker-swarm -e staging -d staging.example.com

EOF
}

# Function to validate prerequisites
validate_prerequisites() {
    print_status "Validating prerequisites for $DEPLOYMENT_TYPE deployment..."
    
    case $DEPLOYMENT_TYPE in
        "docker")
            if ! command -v docker &> /dev/null; then
                print_error "Docker is not installed or not in PATH"
                exit 1
            fi
            if ! command -v docker-compose &> /dev/null; then
                print_error "Docker Compose is not installed or not in PATH"
                exit 1
            fi
            ;;
        "kubernetes")
            if ! command -v kubectl &> /dev/null; then
                print_error "kubectl is not installed or not in PATH"
                exit 1
            fi
            if ! kubectl cluster-info &> /dev/null; then
                print_error "Cannot connect to Kubernetes cluster"
                exit 1
            fi
            ;;
        "docker-swarm")
            if ! command -v docker &> /dev/null; then
                print_error "Docker is not installed or not in PATH"
                exit 1
            fi
            if ! docker node ls &> /dev/null; then
                print_error "Docker Swarm is not initialized"
                exit 1
            fi
            ;;
    esac
    
    print_success "Prerequisites validated"
}

# Function to generate configuration
generate_config() {
    print_status "Generating configuration for $ENVIRONMENT environment..."
    
    # Create configuration directory
    mkdir -p "deploy-config/$ENVIRONMENT"
    
    # Generate environment file
    cat > "deploy-config/$ENVIRONMENT/.env" << EOF
# SecureContext Protocol Configuration - $ENVIRONMENT
# Generated on $(date)

# Flask Configuration
FLASK_SECRET_KEY=$(openssl rand -hex 32)
FLASK_ENV=$ENVIRONMENT
FLASK_DEBUG=false
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# Enterprise Configuration
SCP_BASE_URL=https://$DOMAIN
SCP_CALLBACK_URL_OVERRIDE=https://$DOMAIN
SCP_ENVIRONMENT=$ENVIRONMENT

# Webhook Configuration
SCP_ENABLE_WEBHOOKS=$ENABLE_WEBHOOKS
SCP_WEBHOOK_URL=$WEBHOOK_URL
SCP_WEBHOOK_SECRET=$(openssl rand -hex 32)
SCP_WEBHOOK_EVENTS=token_created,token_retrieved,token_expired
SCP_WEBHOOK_TIMEOUT=30
SCP_WEBHOOK_RETRY_COUNT=3
SCP_WEBHOOK_RETRY_DELAY=5

# OAuth Provider Configuration (REPLACE WITH YOUR VALUES)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret

# Security Configuration
SESSION_COOKIE_SECURE=true
EOF
    
    print_success "Configuration generated at deploy-config/$ENVIRONMENT/.env"
    print_warning "Please update OAuth credentials in the generated .env file"
}

# Function to deploy with Docker
deploy_docker() {
    print_status "Deploying with Docker Compose..."
    
    # Copy Docker files
    cp -r docker/* "deploy-config/$ENVIRONMENT/"
    cp "deploy-config/$ENVIRONMENT/.env" "deploy-config/$ENVIRONMENT/"
    
    # Update docker-compose.yml with domain
    if [ ! -z "$DOMAIN" ]; then
        sed -i.bak "s/your-domain.com/$DOMAIN/g" "deploy-config/$ENVIRONMENT/docker-compose.yml"
    fi
    
    # Build and start services
    cd "deploy-config/$ENVIRONMENT"
    docker-compose build
    docker-compose up -d
    
    print_success "Docker deployment completed"
    print_status "Application will be available at: https://$DOMAIN"
    print_status "Check status with: docker-compose ps"
}

# Function to deploy with Kubernetes
deploy_kubernetes() {
    print_status "Deploying to Kubernetes..."
    
    # Copy Kubernetes manifests
    cp -r k8s/* "deploy-config/$ENVIRONMENT/"
    
    # Update manifests with configuration
    if [ ! -z "$DOMAIN" ]; then
        sed -i.bak "s/your-domain.com/$DOMAIN/g" "deploy-config/$ENVIRONMENT/ingress.yaml"
        sed -i.bak "s/your-domain.com/$DOMAIN/g" "deploy-config/$ENVIRONMENT/secret.yaml"
    fi
    
    # Update namespace
    sed -i.bak "s/namespace: scp/namespace: $NAMESPACE/g" "deploy-config/$ENVIRONMENT"/*.yaml
    sed -i.bak "s/name: scp$/name: $NAMESPACE/g" "deploy-config/$ENVIRONMENT/namespace.yaml"
    
    # Apply manifests
    cd "deploy-config/$ENVIRONMENT"
    kubectl apply -f namespace.yaml
    kubectl apply -f configmap.yaml
    
    # Create secret with generated values
    kubectl create secret generic scp-secrets \
        --namespace=$NAMESPACE \
        --from-env-file=.env \
        --dry-run=client -o yaml | kubectl apply -f -
    
    kubectl apply -f deployment.yaml
    kubectl apply -f service.yaml
    kubectl apply -f ingress.yaml
    kubectl apply -f hpa.yaml
    
    print_success "Kubernetes deployment completed"
    print_status "Application will be available at: https://$DOMAIN"
    print_status "Check status with: kubectl get pods -n $NAMESPACE"
}

# Function to deploy with Docker Swarm
deploy_docker_swarm() {
    print_status "Deploying with Docker Swarm..."
    
    # Create Docker Swarm stack file
    cat > "deploy-config/$ENVIRONMENT/docker-stack.yml" << EOF
version: '3.8'

services:
  scp-app:
    image: scp/authentication-proxy:latest
    ports:
      - "5000:5000"
    environment:
      - FLASK_SECRET_KEY=\${FLASK_SECRET_KEY}
      - FLASK_ENV=$ENVIRONMENT
      - SCP_BASE_URL=https://$DOMAIN
      - SCP_CALLBACK_URL_OVERRIDE=https://$DOMAIN
      - SCP_ENVIRONMENT=$ENVIRONMENT
      - SCP_ENABLE_WEBHOOKS=$ENABLE_WEBHOOKS
      - SCP_WEBHOOK_URL=$WEBHOOK_URL
      - GOOGLE_CLIENT_ID=\${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=\${GOOGLE_CLIENT_SECRET}
      - MICROSOFT_CLIENT_ID=\${MICROSOFT_CLIENT_ID}
      - MICROSOFT_CLIENT_SECRET=\${MICROSOFT_CLIENT_SECRET}
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
    networks:
      - scp-network

networks:
  scp-network:
    driver: overlay
EOF
    
    # Deploy stack
    cd "deploy-config/$ENVIRONMENT"
    docker stack deploy -c docker-stack.yml scp-stack
    
    print_success "Docker Swarm deployment completed"
    print_status "Application will be available at: https://$DOMAIN"
    print_status "Check status with: docker service ls"
}

# Function to run post-deployment tests
run_tests() {
    print_status "Running post-deployment tests..."
    
    # Wait for application to be ready
    sleep 30
    
    # Test health endpoint
    if curl -f -s "https://$DOMAIN/api/enterprise/config" > /dev/null; then
        print_success "Health check passed"
    else
        print_warning "Health check failed - application may still be starting"
    fi
    
    # Test webhook if enabled
    if [ "$ENABLE_WEBHOOKS" = "true" ]; then
        if curl -f -s -X POST "https://$DOMAIN/api/enterprise/webhooks/test" > /dev/null; then
            print_success "Webhook test passed"
        else
            print_warning "Webhook test failed - check webhook configuration"
        fi
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            DEPLOYMENT_TYPE="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -w|--webhook-url)
            WEBHOOK_URL="$2"
            ENABLE_WEBHOOKS="true"
            shift 2
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --enable-webhooks)
            ENABLE_WEBHOOKS="true"
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "$DEPLOYMENT_TYPE" ]; then
    print_error "Deployment type is required"
    show_usage
    exit 1
fi

if [ -z "$DOMAIN" ]; then
    print_error "Domain is required"
    show_usage
    exit 1
fi

# Validate deployment type
case $DEPLOYMENT_TYPE in
    "docker"|"kubernetes"|"docker-swarm")
        ;;
    *)
        print_error "Invalid deployment type: $DEPLOYMENT_TYPE"
        print_error "Valid types: docker, kubernetes, docker-swarm"
        exit 1
        ;;
esac

# Main deployment flow
print_status "Starting SecureContext Protocol enterprise deployment"
print_status "Deployment type: $DEPLOYMENT_TYPE"
print_status "Environment: $ENVIRONMENT"
print_status "Domain: $DOMAIN"
print_status "Webhooks enabled: $ENABLE_WEBHOOKS"

# Validate prerequisites
validate_prerequisites

# Generate configuration
generate_config

# Deploy based on type
case $DEPLOYMENT_TYPE in
    "docker")
        deploy_docker
        ;;
    "kubernetes")
        deploy_kubernetes
        ;;
    "docker-swarm")
        deploy_docker_swarm
        ;;
esac

# Run post-deployment tests
run_tests

print_success "Enterprise deployment completed successfully!"
print_status "Next steps:"
print_status "1. Update OAuth credentials in deploy-config/$ENVIRONMENT/.env"
print_status "2. Configure DNS to point $DOMAIN to your deployment"
print_status "3. Set up SSL certificates for HTTPS"
print_status "4. Configure monitoring and logging"
print_status "5. Test OAuth flows with real provider credentials"

if [ "$ENABLE_WEBHOOKS" = "true" ]; then
    print_status "6. Verify webhook endpoint is receiving notifications"
fi