# SecureContext Protocol (SCP)

🔐 **Secure, user-consented OAuth 2.0 access mediation for AI agents**

An open-source system that enables AI agents to securely access fragmented personalized user data across multiple providers (Google, Microsoft, and more) with proper user consent and token management.

## ⚡ Quick Start

```bash
# One-command setup and start
python start.py
```

That's it! The script will:
- ✅ Check your Python version (3.10+ required)
- 📦 Install dependencies  
- 🔧 Guide you through OAuth setup
- 🧪 Run tests
- 🚀 Start the server at http://localhost:5000

## 🌟 Features

- **Multi-Provider OAuth**: Google, Microsoft, with extensible architecture for more
- **Agent-Ready APIs**: Built specifically for AI agent integration
- **Secure Token Management**: Temporary, in-memory token storage
- **Extensible Architecture**: Easy to add new OAuth providers
- **Framework Integration**: LangChain, CrewAI, AutoGen support
- **Enterprise Ready**: Configurable callbacks, webhooks, horizontal scaling
- **Production Deployment**: Docker, Kubernetes, with comprehensive documentation

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   AI Agents     │    │  SCP Auth Proxy  │    │ OAuth Providers │
│                 │    │                  │    │                 │
│ • LangChain     │◄──►│ • Token Storage  │◄──►│ • Google        │
│ • CrewAI        │    │ • Provider Mgmt  │    │ • Microsoft     │
│ • AutoGen       │    │ • Session Mgmt   │    │ • Future...     │
│ • Custom        │    │ • Audit Logs     │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Usage Examples

### Basic OAuth Flow
1. Visit http://localhost:5000
2. Click "Connect Google Account" or "Connect Microsoft Account"
3. Complete OAuth authorization
4. Get session ID for API access

### Agent Integration
```python
# Using the Python SDK (coming soon)
from scp_sdk import SCPClient

client = SCPClient(base_url="http://localhost:5000")
tokens = client.get_tokens(session_id="your-session-id")

# Use tokens to access user data
gmail_data = client.get_gmail_messages(tokens)
calendar_events = client.get_calendar_events(tokens)
```

### API Access
```bash
# Get tokens for a session
curl http://localhost:5000/api/tokens/SESSION_ID

# Response
{
  "success": true,
  "data": {
    "access_token": "ya29.a0...",
    "refresh_token": "1//04...",
    "expires_at": "2024-01-01T12:00:00",
    "scope": "profile email gmail.readonly",
    "provider": "google"
  }
}
```

## 📋 Manual Setup (Alternative)

If you prefer manual setup:

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set Up OAuth Applications

**Google OAuth:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create OAuth 2.0 Client ID
3. Add redirect URI: `http://localhost:5000/oauth/google/callback`

**Microsoft OAuth:**
1. Go to [Azure Portal](https://portal.azure.com/)
2. Create App Registration
3. Add redirect URI: `http://localhost:5000/oauth/microsoft/callback`

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your OAuth credentials
```

### 4. Run Application
```bash
python run.py
```

## 🧪 Testing

```bash
# Test setup
python test_setup.py

# Run unit tests
python -m pytest tests/

# Test token retrieval
python verify_tokens.py SESSION_ID
```

## 🌐 Deployment

### Quick Deploy Options

**Heroku:**
```bash
heroku create your-app-name
git push heroku main
```

**Railway:**
```bash
railway new
railway up
```

**Docker:**
```bash
python deploy.py  # Generates configs
docker-compose up --build
```

See [HOSTING.md](HOSTING.md) for detailed deployment instructions.

## 🔧 Configuration

### Environment Variables
```bash
# Required
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
FLASK_SECRET_KEY=your_flask_secret_key

# Optional
FLASK_DEBUG=false
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
```

### Adding New Providers
1. Create provider class inheriting from `BaseProvider`
2. Add configuration to `providers.json`
3. Set environment variables
4. Routes and UI automatically generated!

## 🤖 Agent Framework Integration

### LangChain
```python
from scp_tools import SCPTool

gmail_tool = SCPTool(
    name="gmail_reader",
    session_id="user_session_123",
    provider="google"
)

agent = initialize_agent([gmail_tool], llm)
```

### CrewAI
```python
from scp_crew import SCPCrewMember

email_agent = SCPCrewMember(
    role="Email Manager",
    session_id="user_session_123",
    providers=["google", "microsoft"]
)
```

## 🏢 Enterprise Features

SCP includes enterprise-grade features for production deployments:

- **🔗 Configurable Callback URLs**: Multi-environment OAuth support
- **📡 Webhook Notifications**: Real-time token event notifications  
- **🐳 Container Orchestration**: Docker and Kubernetes ready
- **📈 Horizontal Scaling**: Stateless architecture for high availability
- **🔒 Security Hardening**: Production security best practices

See [Enterprise Features Guide](docs/enterprise-features.md) for details.

### Quick Enterprise Deployment

```bash
# Docker deployment
./scripts/deploy-enterprise.sh -t docker -d your-domain.com --enable-webhooks

# Kubernetes deployment  
./scripts/deploy-enterprise.sh -t kubernetes -d scp.your-domain.com -n production
```

## 📚 Documentation

- [Setup Guide](SETUP.md) - Detailed setup instructions
- [Enterprise Features](docs/enterprise-features.md) - Enterprise deployment features
- [Enterprise Deployment](docs/enterprise-deployment.md) - Production deployment guide
- [Hosting Guide](HOSTING.md) - Platform-specific deployment options
- [API Documentation](docs/api.md) - API reference
- [Contributing](CONTRIBUTING.md) - How to contribute

## 🔒 Security

- **Temporary Storage**: Tokens stored in memory, cleared on restart
- **Session Isolation**: Each user gets isolated token storage
- **HTTPS Ready**: Production deployments use HTTPS
- **Audit Logging**: All data access is logged
- **Scope Limitation**: Request only necessary permissions

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding New OAuth Providers
1. Fork the repository
2. Create provider class in `providers/`
3. Add tests
4. Submit pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/secure-context-protocol/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/secure-context-protocol/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/secure-context-protocol/wiki)

## 🗺️ Roadmap

- [ ] **v1.0**: Core OAuth flows (Google, Microsoft) ✅
- [ ] **v1.1**: Agent SDK and framework integrations
- [ ] **v1.2**: Additional providers (GitHub, Slack, etc.)
- [ ] **v1.3**: Production token storage (Redis/DB)
- [ ] **v1.4**: Agent marketplace integration
- [ ] **v2.0**: Advanced workflow orchestration

---

**Built with ❤️ for the AI agent community**
