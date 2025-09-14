# SecureContext Protocol - Production Deployment Guide

🚀 **Complete guide for deploying SecureContext Protocol to production**

This guide assumes you have completed development, testing, and cleanup phases. Your application is now ready for production deployment.

## 📋 Pre-Deployment Checklist

### ✅ Development Complete
- [ ] All comprehensive tests pass (`python comprehensive_test.py`)
- [ ] Production cleanup completed (`python cleanup_for_production.py`)
- [ ] All security vulnerabilities addressed
- [ ] OAuth applications configured for production domains
- [ ] Documentation updated and finalized

### ✅ Production Requirements
- [ ] Production domain name registered
- [ ] SSL certificate ready (or platform provides it)
- [ ] Production OAuth credentials obtained
- [ ] Monitoring and logging strategy planned
- [ ] Backup and recovery procedures defined

## 🌐 Deployment Options

### Option 1: Heroku (Recommended for MVP)

**Best for:** Quick deployment, automatic HTTPS, easy scaling

#### Step 1: Prepare Heroku Deployment
```bash
# Install Heroku CLI
# macOS: brew install heroku/brew/heroku
# Windows: Download from heroku.com

# Login to Heroku
heroku login

# Create Heroku app
heroku create your-scp-app-name

# Add buildpack (if needed)
heroku buildpacks:set heroku/python
```

#### Step 2: Configure Environment Variables
```bash
# Set production environment variables
heroku config:set FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
heroku config:set FLASK_ENV=production
heroku config:set FLASK_DEBUG=false

# Set OAuth credentials (replace with your production values)
heroku config:set GOOGLE_CLIENT_ID=your_production_google_client_id
heroku config:set GOOGLE_CLIENT_SECRET=your_production_google_client_secret
heroku config:set MICROSOFT_CLIENT_ID=your_production_microsoft_client_id
heroku config:set MICROSOFT_CLIENT_SECRET=your_production_microsoft_client_secret
```

#### Step 3: Update OAuth Redirect URIs
Update your OAuth applications with production URLs:

**Google Cloud Console:**
- Add: `https://your-scp-app-name.herokuapp.com/oauth/google/callback`

**Microsoft Azure Portal:**
- Add: `https://your-scp-app-name.herokuapp.com/oauth/microsoft/callback`

#### Step 4: Deploy
```bash
# Deploy to Heroku
git add .
git commit -m "Production deployment"
git push heroku main

# Open your app
heroku open
```

#### Step 5: Verify Deployment
```bash
# Check logs
heroku logs --tail

# Test OAuth flows
curl https://your-scp-app-name.herokuapp.com/
```

---

### Option 2: Railway (Modern Alternative)

**Best for:** Better performance than Heroku, generous free tier

#### Step 1: Deploy to Railway
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway new
railway up
```

#### Step 2: Configure Environment Variables
Use Railway dashboard to set:
- `FLASK_SECRET_KEY`
- `FLASK_ENV=production`
- `FLASK_DEBUG=false`
- OAuth credentials

#### Step 3: Update OAuth Redirect URIs
Update with your Railway domain: `https://your-app.railway.app/oauth/{provider}/callback`

---

### Option 3: Fly.io (High Performance)

**Best for:** Global deployment, excellent performance

#### Step 1: Prepare Fly.io Deployment
```bash
# Install Fly CLI
# macOS: brew install flyctl
# Linux: curl -L https://fly.io/install.sh | sh

# Login and launch
fly auth login
fly launch
```

#### Step 2: Configure Secrets
```bash
# Set production secrets
fly secrets set FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
fly secrets set FLASK_ENV=production
fly secrets set FLASK_DEBUG=false
fly secrets set GOOGLE_CLIENT_ID=your_production_google_client_id
fly secrets set GOOGLE_CLIENT_SECRET=your_production_google_client_secret
fly secrets set MICROSOFT_CLIENT_ID=your_production_microsoft_client_id
fly secrets set MICROSOFT_CLIENT_SECRET=your_production_microsoft_client_secret
```

#### Step 3: Deploy
```bash
fly deploy
```

---

### Option 4: DigitalOcean App Platform

**Best for:** Reliable hosting, good documentation

#### Step 1: Create App
1. Go to DigitalOcean App Platform
2. Connect your GitHub repository
3. Configure build settings:
   - Build Command: `pip install -r requirements.txt`
   - Run Command: `python run.py`

#### Step 2: Configure Environment Variables
Add in DigitalOcean dashboard:
- All required environment variables
- Set `FLASK_HOST=0.0.0.0`
- Set `FLASK_PORT=8080`

---

### Option 5: Self-Hosted VPS

**Best for:** Full control, cost-effective for high usage

#### Step 1: Server Setup (Ubuntu 20.04+)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install python3 python3-pip python3-venv nginx certbot python3-certbot-nginx -y

# Create application user
sudo useradd -m -s /bin/bash scp
sudo usermod -aG sudo scp
```

#### Step 2: Deploy Application
```bash
# Switch to application user
sudo su - scp

# Clone repository
git clone https://github.com/yourusername/secure-context-protocol.git
cd secure-context-protocol

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
# Edit .env with production values
```

#### Step 3: Create Systemd Service
```bash
# Create service file
sudo tee /etc/systemd/system/scp.service > /dev/null <<EOF
[Unit]
Description=SecureContext Protocol
After=network.target

[Service]
Type=simple
User=scp
WorkingDirectory=/home/scp/secure-context-protocol
Environment=PATH=/home/scp/secure-context-protocol/venv/bin
ExecStart=/home/scp/secure-context-protocol/venv/bin/python run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable scp
sudo systemctl start scp
sudo systemctl status scp
```

#### Step 4: Configure Nginx
```bash
# Create Nginx configuration
sudo tee /etc/nginx/sites-available/scp > /dev/null <<EOF
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/scp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### Step 5: Setup SSL
```bash
# Get SSL certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

---

## 🔒 Production Security Configuration

### Environment Variables
```bash
# Required production environment variables
FLASK_SECRET_KEY=your_secure_random_key_here
FLASK_ENV=production
FLASK_DEBUG=false
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# OAuth credentials
GOOGLE_CLIENT_ID=your_production_google_client_id
GOOGLE_CLIENT_SECRET=your_production_google_client_secret
MICROSOFT_CLIENT_ID=your_production_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_production_microsoft_client_secret

# Optional production settings
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax
```

### Security Headers
Ensure your deployment includes these security headers:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

### OAuth Security
- ✅ Use HTTPS for all OAuth redirect URIs
- ✅ Validate redirect URIs match exactly
- ✅ Use strong, unique client secrets
- ✅ Regularly rotate OAuth credentials
- ✅ Monitor for suspicious OAuth activity

## 📊 Monitoring and Logging

### Application Monitoring
```bash
# Health check endpoint
curl https://yourdomain.com/

# Storage statistics
curl https://yourdomain.com/api/storage/stats
```

### Recommended Monitoring Tools
- **Uptime Monitoring:** UptimeRobot, Pingdom
- **Application Performance:** New Relic, DataDog
- **Log Management:** Papertrail, Loggly
- **Error Tracking:** Sentry, Rollbar

### Log Configuration
Ensure your application logs include:
- OAuth flow events
- Token storage/retrieval events
- Security events (failed authentications)
- Performance metrics
- Error details

## 🔄 Maintenance and Updates

### Regular Maintenance Tasks
- [ ] Monitor application logs daily
- [ ] Check OAuth credential expiration
- [ ] Update dependencies monthly
- [ ] Review security logs weekly
- [ ] Test backup/recovery procedures monthly
- [ ] Monitor SSL certificate expiration

### Update Procedure
```bash
# 1. Backup current deployment
# 2. Test updates in staging environment
# 3. Deploy updates during low-traffic periods
# 4. Monitor for issues post-deployment
# 5. Rollback if necessary
```

## 📈 Scaling Considerations

### Horizontal Scaling
For high traffic, consider:
- Load balancer (nginx, HAProxy, cloud load balancer)
- Multiple application instances
- Redis for session storage
- Database for persistent token storage

### Performance Optimization
- Enable gzip compression
- Use CDN for static assets
- Implement caching strategies
- Monitor and optimize database queries
- Use connection pooling

## 🆘 Troubleshooting

### Common Production Issues

#### 1. OAuth Redirect URI Mismatch
**Symptoms:** OAuth flows fail with redirect URI errors
**Solution:** 
- Verify redirect URIs in provider consoles match exactly
- Ensure HTTPS is used in production
- Check for trailing slashes in URLs

#### 2. Environment Variables Not Loading
**Symptoms:** Configuration errors on startup
**Solution:**
- Verify all required environment variables are set
- Check for typos in variable names
- Ensure .env file is in correct location (for local deployments)

#### 3. SSL Certificate Issues
**Symptoms:** HTTPS not working, browser security warnings
**Solution:**
- Verify SSL certificate is valid and not expired
- Check certificate chain is complete
- Ensure automatic renewal is configured

#### 4. High Memory Usage
**Symptoms:** Application crashes, out of memory errors
**Solution:**
- Implement token cleanup mechanisms
- Monitor token storage limits
- Consider Redis for token storage
- Optimize session management

### Getting Help
1. Check application logs first
2. Verify OAuth provider status pages
3. Test with curl to isolate issues
4. Review deployment platform documentation
5. Check GitHub issues and discussions

## 🎯 Success Metrics

Your production deployment is successful when:
- ✅ Application loads without errors
- ✅ OAuth flows complete successfully
- ✅ HTTPS is enforced
- ✅ All security headers are present
- ✅ Monitoring and logging are working
- ✅ Performance meets requirements
- ✅ Backup procedures are tested

## 🚀 Post-Deployment Steps

### Immediate (First 24 hours)
1. **Monitor closely** - Watch logs and metrics
2. **Test all flows** - Verify OAuth works with real accounts
3. **Check performance** - Monitor response times and errors
4. **Verify security** - Test HTTPS and security headers

### Short-term (First week)
1. **Set up alerts** - Configure monitoring alerts
2. **Document issues** - Record any problems and solutions
3. **Optimize performance** - Address any performance issues
4. **User feedback** - Gather feedback from initial users

### Long-term (Ongoing)
1. **Regular updates** - Keep dependencies updated
2. **Security reviews** - Regular security assessments
3. **Performance monitoring** - Ongoing performance optimization
4. **Feature development** - Plan and implement new features

## 📞 Support and Resources

### Documentation
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [Flask Production Deployment](https://flask.palletsprojects.com/en/2.3.x/deploying/)
- [OWASP Web Security](https://owasp.org/www-project-top-ten/)

### Community
- GitHub Issues: Report bugs and request features
- GitHub Discussions: Ask questions and share experiences
- Stack Overflow: Technical questions with `secure-context-protocol` tag

---

## 🎉 Congratulations!

Your SecureContext Protocol is now running in production! 🚀

You've successfully deployed a secure, scalable OAuth 2.0 mediation system that enables AI agents to access user data with proper consent and security.

**What's Next?**
- Start building AI agents that use your SCP deployment
- Monitor usage and performance
- Contribute back to the open source project
- Share your experience with the community

**Happy coding with SecureContext Protocol!** 🔐🤖