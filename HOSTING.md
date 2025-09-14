# SecureContext Protocol - Hosting Guide

This guide covers various options for hosting your SecureContext Protocol Authentication Proxy.

## Quick Start (Local Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your OAuth credentials

# Run locally
python run.py
```

## Hosting Options

### 1. Heroku (Easiest for beginners)

**Pros:** Simple deployment, free tier available, automatic HTTPS
**Cons:** Cold starts, limited free hours

```bash
# Install Heroku CLI first
heroku create your-scp-app

# Set environment variables
heroku config:set FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
heroku config:set GOOGLE_CLIENT_ID=your_google_client_id
heroku config:set GOOGLE_CLIENT_SECRET=your_google_client_secret
heroku config:set MICROSOFT_CLIENT_ID=your_microsoft_client_id
heroku config:set MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret

# Deploy
git push heroku main
```

**Update OAuth redirect URIs to:**
- Google: `https://your-scp-app.herokuapp.com/oauth/google/callback`
- Microsoft: `https://your-scp-app.herokuapp.com/oauth/microsoft/callback`

### 2. Railway (Modern alternative to Heroku)

**Pros:** Better performance than Heroku, generous free tier, automatic HTTPS
**Cons:** Newer platform

```bash
# Install Railway CLI
npm install -g @railway/cli

# Deploy
railway login
railway new
railway up

# Set environment variables in Railway dashboard
```

### 3. Fly.io (Great performance)

**Pros:** Excellent performance, global deployment, reasonable pricing
**Cons:** Slightly more complex setup

```bash
# Install Fly CLI
fly auth login
fly launch

# Set secrets
fly secrets set FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
fly secrets set GOOGLE_CLIENT_ID=your_google_client_id
fly secrets set GOOGLE_CLIENT_SECRET=your_google_client_secret
fly secrets set MICROSOFT_CLIENT_ID=your_microsoft_client_id
fly secrets set MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret

# Deploy
fly deploy
```

### 4. DigitalOcean App Platform

**Pros:** Reliable, good documentation, predictable pricing
**Cons:** No free tier

1. Connect your GitHub repository
2. Set environment variables in the dashboard
3. Deploy automatically on git push

### 5. Google Cloud Run (Serverless)

**Pros:** Pay per use, scales to zero, Google integration
**Cons:** Cold starts, more complex setup

```bash
# Build and deploy
gcloud run deploy scp-auth-proxy \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

### 6. AWS App Runner

**Pros:** AWS ecosystem, automatic scaling
**Cons:** AWS complexity, no free tier

1. Create App Runner service from source code
2. Set environment variables
3. Configure auto-scaling

### 7. Docker (Self-hosted)

**Pros:** Full control, can run anywhere
**Cons:** You manage infrastructure

```bash
# Generate deployment configs
python deploy.py

# Build and run
docker-compose up --build
```

### 8. VPS (Self-hosted)

**Pros:** Full control, cost-effective for high usage
**Cons:** You manage everything

```bash
# On your VPS (Ubuntu/Debian)
sudo apt update
sudo apt install python3 python3-pip nginx certbot

# Clone and setup
git clone your-repo
cd secure-context-protocol
pip3 install -r requirements.txt

# Set up systemd service
sudo cp deployment/scp.service /etc/systemd/system/
sudo systemctl enable scp
sudo systemctl start scp

# Set up nginx reverse proxy
sudo cp deployment/nginx.conf /etc/nginx/sites-available/scp
sudo ln -s /etc/nginx/sites-available/scp /etc/nginx/sites-enabled/
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d yourdomain.com
```

## Environment Variables Setup

For all hosting platforms, you need these environment variables:

```bash
FLASK_SECRET_KEY=your_random_secret_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret

# Optional
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false
```

## OAuth Redirect URI Configuration

**CRITICAL:** Update your OAuth app redirect URIs after deployment:

### Google Cloud Console
1. Go to APIs & Services → Credentials
2. Edit your OAuth 2.0 Client ID
3. Add: `https://yourdomain.com/oauth/google/callback`

### Microsoft Azure Portal
1. Go to Azure Active Directory → App registrations
2. Select your app → Authentication
3. Add: `https://yourdomain.com/oauth/microsoft/callback`

## Security Considerations

### Production Checklist

- [ ] Use HTTPS (required for OAuth)
- [ ] Set strong `FLASK_SECRET_KEY`
- [ ] Disable debug mode (`FLASK_DEBUG=false`)
- [ ] Use environment variables for secrets
- [ ] Set up monitoring and logging
- [ ] Configure proper CORS if needed
- [ ] Consider rate limiting
- [ ] Regular security updates

### Recommended Security Headers

Add these headers in production:

```python
# In your reverse proxy or Flask app
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

## Monitoring and Logging

### Application Monitoring

1. **Health Check Endpoint:** `GET /` returns 200 if healthy
2. **Storage Stats:** `GET /api/storage/stats` for monitoring
3. **Logs:** Application logs OAuth flows and errors

### Recommended Monitoring Tools

- **Uptime:** UptimeRobot, Pingdom
- **Performance:** New Relic, DataDog
- **Logs:** Papertrail, Loggly
- **Errors:** Sentry, Rollbar

## Scaling Considerations

### Horizontal Scaling

For high traffic, consider:

1. **Load Balancer:** Distribute requests across multiple instances
2. **Session Storage:** Use Redis/database instead of in-memory storage
3. **CDN:** CloudFlare for static assets
4. **Database:** PostgreSQL/MySQL for persistent token storage

### Performance Optimization

1. **Caching:** Redis for token caching
2. **Connection Pooling:** For database connections
3. **Async Processing:** For non-critical operations
4. **Compression:** Enable gzip compression

## Cost Estimation

### Free Tier Options
- **Heroku:** 550-1000 dyno hours/month
- **Railway:** $5 credit monthly
- **Fly.io:** 3 shared-cpu-1x machines
- **Vercel:** Generous serverless limits

### Paid Options (Monthly estimates)
- **Heroku Hobby:** $7/month
- **Railway Pro:** $5/month + usage
- **Fly.io:** ~$5-15/month depending on usage
- **DigitalOcean:** $5-12/month
- **VPS:** $5-20/month

## Troubleshooting

### Common Deployment Issues

1. **OAuth Redirect Mismatch**
   - Update redirect URIs in provider consoles
   - Ensure HTTPS in production

2. **Environment Variables**
   - Double-check all required variables are set
   - Verify no typos in variable names

3. **Port Issues**
   - Most platforms expect port from `PORT` env var
   - Set `FLASK_HOST=0.0.0.0` for containerized deployments

4. **Cold Starts**
   - Consider paid tiers for better performance
   - Implement health check endpoints

### Getting Help

1. Check application logs first
2. Verify OAuth app configurations
3. Test locally before deploying
4. Use platform-specific debugging tools

## Next Steps

Once deployed:

1. Test OAuth flows with your deployed URL
2. Set up monitoring and alerts
3. Configure custom domain (optional)
4. Set up CI/CD for automatic deployments
5. Consider implementing additional security measures
6. Scale based on usage patterns

Choose the hosting option that best fits your needs, budget, and technical expertise!