# Contributing to SecureContext Protocol

Welcome to the SecureContext Protocol (SCP) project! We're excited to have you contribute to building an extensible, secure OAuth 2.0 mediation system for AI agents and applications.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Adding New OAuth Providers](#adding-new-oauth-providers)
- [BaseProvider Interface](#baseprovider-interface)
- [Provider Implementation Guide](#provider-implementation-guide)
- [Testing Guidelines](#testing-guidelines)
- [Code Standards](#code-standards)
- [Submitting Changes](#submitting-changes)

## Getting Started

The SecureContext Protocol uses a pluggable provider architecture that makes it easy to add support for new OAuth 2.0 providers. Each provider implements a standardized interface while handling provider-specific OAuth flow requirements.

### Core Architecture

```
authentication_proxy/
├── providers/
│   ├── base_provider.py      # Abstract base class
│   ├── google_provider.py    # Google OAuth implementation
│   ├── microsoft_provider.py # Microsoft OAuth implementation
│   └── provider_manager.py   # Provider registration system
├── app.py                    # Flask application
└── config.py                 # Configuration management
```

## Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd secure-context-protocol
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your OAuth credentials
   ```

4. **Run tests**
   ```bash
   python -m pytest tests/
   ```

5. **Start development server**
   ```bash
   python start.py
   ```

## Adding New OAuth Providers

Adding a new OAuth provider involves three main steps:

1. **Create a provider class** that inherits from `BaseProvider`
2. **Add provider configuration** to `providers.json`
3. **Set up environment variables** for OAuth credentials
4. **Write tests** for the new provider

### Quick Start Example

Let's add support for GitHub OAuth:

1. **Create `authentication_proxy/providers/github_provider.py`**:

```python
from typing import Dict, Any
import requests
from urllib.parse import urlencode
from .base_provider import BaseProvider, OAuthFlowError

class GitHubProvider(BaseProvider):
    def __init__(self, config: Dict[str, Any]):
        default_config = {
            'authorize_url': 'https://github.com/login/oauth/authorize',
            'token_url': 'https://github.com/login/oauth/access_token',
            'userinfo_url': 'https://api.github.com/user',
            'display_name': 'GitHub Account',
            'scopes': ['user:email', 'repo']
        }
        merged_config = {**default_config, **config}
        super().__init__('github', merged_config)
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': kwargs.get('scope', ' '.join(self.scopes)),
            'state': state
        }
        return f"{self.authorize_url}?{urlencode(params)}"
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        # Implementation details...
        pass
```

2. **Add to `providers.json`**:

```json
{
  "providers": {
    "github": {
      "name": "github",
      "display_name": "GitHub Account",
      "description": "Connect your GitHub account to access repositories and user data",
      "client_id": "env:GITHUB_CLIENT_ID",
      "client_secret": "env:GITHUB_CLIENT_SECRET",
      "scopes": ["user:email", "repo"],
      "provider_class": "GitHubProvider",
      "enabled": true,
      "icon": "github",
      "color": "#333333"
    }
  }
}
```

3. **Add environment variables to `.env`**:

```bash
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
```

## BaseProvider Interface

All OAuth providers must inherit from the `BaseProvider` abstract base class and implement the required methods.

### Required Methods

#### `get_authorization_url(redirect_uri: str, state: str, **kwargs) -> str`

Generates the OAuth authorization URL for redirecting users to the provider's consent screen.

**Parameters:**
- `redirect_uri`: Callback URL for the OAuth flow
- `state`: CSRF protection state parameter
- `**kwargs`: Additional provider-specific parameters

**Returns:** Authorization URL string

**Example:**
```python
def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
    params = {
        'client_id': self.client_id,
        'redirect_uri': redirect_uri,
        'scope': kwargs.get('scope', ' '.join(self.scopes)),
        'response_type': 'code',
        'state': state
    }
    return f"{self.authorize_url}?{urlencode(params)}"
```

#### `exchange_code_for_tokens(code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]`

Exchanges the authorization code for access and refresh tokens.

**Parameters:**
- `code`: Authorization code from OAuth callback
- `redirect_uri`: Callback URL used in authorization request
- `**kwargs`: Additional provider-specific parameters

**Returns:** Token data dictionary with required fields:
- `access_token`: OAuth access token
- `refresh_token`: OAuth refresh token (if available)
- `expires_in`: Token expiration time in seconds
- `scope`: Granted OAuth scopes
- `token_type`: Token type (usually "Bearer")

**Example:**
```python
def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
    token_data = {
        'client_id': self.client_id,
        'client_secret': self.client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri
    }
    
    response = requests.post(self.token_url, data=token_data, timeout=30)
    
    if response.status_code != 200:
        raise OAuthFlowError(f"Token exchange failed: {response.status_code}")
    
    token_response = response.json()
    
    if not self.validate_token_response(token_response):
        raise OAuthFlowError("Invalid token response")
    
    return self.extract_token_data(token_response)
```

### Optional Methods

#### `refresh_access_token(refresh_token: str) -> Optional[Dict[str, Any]]`

Refreshes an access token using a refresh token.

#### `get_user_info(access_token: str) -> Optional[Dict[str, Any]]`

Retrieves user profile information using an access token.

#### `validate_scopes(requested_scopes: List[str]) -> bool`

Validates that requested scopes are supported by the provider.

### Inherited Utilities

The `BaseProvider` class provides several utility methods:

- `generate_state()`: Generate secure CSRF state parameter
- `validate_state(received, stored)`: Validate state parameters
- `parse_oauth_error(error, description)`: Parse OAuth error responses
- `validate_token_response(token_data)`: Validate token response format
- `extract_token_data(token_response)`: Normalize token data

## Provider Implementation Guide

### Step 1: Research the OAuth Provider

Before implementing, research the provider's OAuth 2.0 documentation:

- Authorization endpoint URL
- Token endpoint URL
- Supported scopes
- Required parameters
- Response formats
- Error handling

### Step 2: Create Provider Class

Create a new file in `authentication_proxy/providers/` following the naming convention `{provider_name}_provider.py`.

```python
"""
{Provider Name} OAuth 2.0 provider implementation.

This module implements the {Provider Name} OAuth provider using the BaseProvider interface,
handling {Provider Name}-specific OAuth flow requirements and API interactions.
"""

from typing import Dict, Any, Optional
import requests
from urllib.parse import urlencode
from requests.exceptions import RequestException, ConnectionError, Timeout

from .base_provider import BaseProvider, OAuthFlowError, ProviderConfigurationError


class {ProviderName}Provider(BaseProvider):
    """
    {Provider Name} OAuth 2.0 provider implementation.
    
    This class handles {Provider Name}-specific OAuth flows, including authorization URL generation,
    token exchange, and optional user information retrieval.
    """
    
    def __init__(self, config: Dict[str, Any]):
        # Set default configuration
        default_config = {
            'authorize_url': 'https://provider.com/oauth/authorize',
            'token_url': 'https://provider.com/oauth/token',
            'userinfo_url': 'https://api.provider.com/user',
            'display_name': '{Provider Name} Account',
            'scopes': ['scope1', 'scope2']
        }
        
        merged_config = {**default_config, **config}
        super().__init__('{provider_name}', merged_config)
        
        # Provider-specific configuration
        self.custom_param = config.get('custom_param', 'default_value')
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        # Implementation
        pass
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        # Implementation
        pass
```

### Step 3: Handle Provider-Specific Requirements

Different OAuth providers have unique requirements:

#### Google-specific considerations:
- Requires `access_type=offline` for refresh tokens
- Uses `prompt=consent` to ensure refresh token is returned
- Supports incremental authorization with `include_granted_scopes`

#### Microsoft-specific considerations:
- Uses tenant-specific URLs (common, organizations, consumers)
- Requires `response_mode` parameter
- Different scope format (space-separated vs. array)

#### Common patterns:
- **Headers**: Most providers expect `Content-Type: application/x-www-form-urlencoded`
- **Timeouts**: Always set reasonable timeouts (30 seconds recommended)
- **Error handling**: Parse provider-specific error responses
- **Scope validation**: Validate scopes against provider's supported list

### Step 4: Implement Error Handling

Robust error handling is crucial:

```python
def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
    try:
        # Make token request
        response = requests.post(self.token_url, data=token_data, timeout=30)
        
        if response.status_code != 200:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            error_msg = error_data.get('error_description', f'HTTP {response.status_code}')
            self.logger.error(f"Token exchange failed: {response.status_code} - {error_msg}")
            raise OAuthFlowError(f"Token exchange failed: {error_msg}")
        
        # Process response...
        
    except RequestException as e:
        self.logger.error(f"Network error during token exchange: {e}", exc_info=True)
        if isinstance(e, ConnectionError):
            raise OAuthFlowError("Network connection failed. Please check your internet connection.")
        elif isinstance(e, Timeout):
            raise OAuthFlowError("Request timed out. Please try again.")
        else:
            raise OAuthFlowError(f"Network request failed: {e}")
    except Exception as e:
        self.logger.error(f"Unexpected error during token exchange: {e}", exc_info=True)
        raise OAuthFlowError(f"Token exchange failed: {e}")
```

### Step 5: Add Configuration

Add your provider to `providers.json`:

```json
{
  "providers": {
    "your_provider": {
      "name": "your_provider",
      "display_name": "Your Provider Account",
      "description": "Connect your account to access data",
      "client_id": "env:YOUR_PROVIDER_CLIENT_ID",
      "client_secret": "env:YOUR_PROVIDER_CLIENT_SECRET",
      "scopes": ["scope1", "scope2"],
      "authorize_url": "https://provider.com/oauth/authorize",
      "token_url": "https://provider.com/oauth/token",
      "provider_class": "YourProviderProvider",
      "enabled": true,
      "icon": "your_provider",
      "color": "#ff0000",
      "additional_params": {
        "custom_param": "value"
      }
    }
  }
}
```

### Step 6: Environment Variables

Document required environment variables in `.env.example`:

```bash
# Your Provider OAuth Configuration
YOUR_PROVIDER_CLIENT_ID=your_client_id_here
YOUR_PROVIDER_CLIENT_SECRET=your_client_secret_here
```

## Testing Guidelines

### Unit Tests

Create comprehensive unit tests in `tests/test_{provider_name}_provider.py`:

```python
"""
Unit tests for {Provider Name} OAuth provider.

This module tests {Provider Name}-specific OAuth flow implementation,
including authorization URL generation, token exchange, and error handling.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add the authentication_proxy directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'authentication_proxy'))

from providers.{provider_name}_provider import {ProviderName}Provider
from providers.base_provider import OAuthFlowError, ProviderConfigurationError


class Test{ProviderName}Provider(unittest.TestCase):
    """Test cases for {Provider Name} OAuth provider."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'client_id': 'test_client_id',
            'client_secret': 'test_client_secret',
            'scopes': ['scope1', 'scope2']
        }
        self.provider = {ProviderName}Provider(self.config)
    
    def test_initialization(self):
        """Test provider initialization."""
        self.assertEqual(self.provider.name, '{provider_name}')
        self.assertEqual(self.provider.client_id, 'test_client_id')
        self.assertEqual(self.provider.client_secret, 'test_client_secret')
    
    def test_get_authorization_url(self):
        """Test authorization URL generation."""
        redirect_uri = 'http://localhost:5000/callback'
        state = 'test_state'
        
        auth_url = self.provider.get_authorization_url(redirect_uri, state)
        
        self.assertIn(self.provider.authorize_url, auth_url)
        self.assertIn('client_id=test_client_id', auth_url)
        self.assertIn('state=test_state', auth_url)
        self.assertIn('redirect_uri=', auth_url)
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_success(self, mock_post):
        """Test successful token exchange."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'expires_in': 3600,
            'scope': 'scope1 scope2'
        }
        mock_post.return_value = mock_response
        
        result = self.provider.exchange_code_for_tokens('test_code', 'http://localhost:5000/callback')
        
        self.assertEqual(result['access_token'], 'test_access_token')
        self.assertEqual(result['refresh_token'], 'test_refresh_token')
        self.assertEqual(result['expires_in'], 3600)
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_error(self, mock_post):
        """Test token exchange error handling."""
        # Mock error response
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            'error': 'invalid_grant',
            'error_description': 'Invalid authorization code'
        }
        mock_post.return_value = mock_response
        
        with self.assertRaises(OAuthFlowError):
            self.provider.exchange_code_for_tokens('invalid_code', 'http://localhost:5000/callback')
    
    def test_validate_scopes(self):
        """Test scope validation."""
        valid_scopes = ['scope1', 'scope2']
        invalid_scopes = ['invalid_scope']
        
        self.assertTrue(self.provider.validate_scopes(valid_scopes))
        self.assertFalse(self.provider.validate_scopes(invalid_scopes))


if __name__ == '__main__':
    unittest.main()
```

### Integration Tests

Add integration tests to `tests/test_integration.py` to test the complete OAuth flow:

```python
def test_{provider_name}_oauth_flow(self):
    """Test complete {Provider Name} OAuth flow."""
    # Test authorization endpoint
    response = self.client.get('/oauth/{provider_name}/authorize')
    self.assertEqual(response.status_code, 302)
    self.assertIn('{provider_domain}', response.location)
    
    # Test callback with mock token exchange
    with self.client.session_transaction() as sess:
        sess['oauth_state'] = 'test_state'
        sess['oauth_provider'] = '{provider_name}'
    
    mock_token_response = {
        'access_token': 'test_token',
        'refresh_token': 'test_refresh',
        'expires_in': 3600,
        'scope': 'scope1 scope2'
    }
    
    with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.validate_state.return_value = True
        mock_provider.exchange_code_for_tokens.return_value = mock_token_response
        mock_get_provider.return_value = mock_provider
        
        response = self.client.get('/oauth/{provider_name}/callback?code=test_code&state=test_state')
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('session_id=', response.location)
```

### Test Coverage Requirements

Ensure your tests cover:

- ✅ Provider initialization with valid/invalid config
- ✅ Authorization URL generation
- ✅ Successful token exchange
- ✅ Token exchange error scenarios
- ✅ Network error handling
- ✅ State parameter validation
- ✅ Scope validation
- ✅ User info retrieval (if implemented)
- ✅ Token refresh (if implemented)

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific provider tests
python -m pytest tests/test_{provider_name}_provider.py

# Run with coverage
python -m pytest tests/ --cov=authentication_proxy --cov-report=html
```

## Code Standards

### Python Style Guide

- Follow PEP 8 style guidelines
- Use type hints for all method parameters and return values
- Include comprehensive docstrings for all classes and methods
- Use meaningful variable and method names

### Documentation Standards

```python
class YourProvider(BaseProvider):
    """
    Your Provider OAuth 2.0 provider implementation.
    
    This class handles Your Provider-specific OAuth flows, including authorization URL generation,
    token exchange, and optional user information retrieval.
    """
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        """
        Generate Your Provider OAuth authorization URL.
        
        Args:
            redirect_uri: Callback URL for OAuth flow
            state: CSRF protection state parameter
            **kwargs: Additional parameters (scope, custom_param, etc.)
            
        Returns:
            Authorization URL for redirecting user to Your Provider OAuth consent screen
            
        Raises:
            OAuthFlowError: If URL generation fails
        """
```

### Error Handling Standards

- Always use appropriate exception types (`OAuthFlowError`, `ProviderConfigurationError`)
- Include detailed error messages for debugging
- Log errors with appropriate levels (ERROR, WARNING, INFO, DEBUG)
- Handle network errors gracefully with user-friendly messages

### Security Standards

- Always validate state parameters for CSRF protection
- Use secure random generation for state parameters
- Validate all input parameters
- Never log sensitive information (tokens, secrets)
- Use HTTPS for all OAuth endpoints in production

## Submitting Changes

### Before Submitting

1. **Run the full test suite**
   ```bash
   python -m pytest tests/
   ```

2. **Check code style**
   ```bash
   flake8 authentication_proxy/
   ```

3. **Update documentation**
   - Add your provider to this CONTRIBUTING.md
   - Update README.md if needed
   - Document any new environment variables

4. **Test manually**
   - Test the complete OAuth flow in a browser
   - Verify error scenarios work correctly
   - Test token retrieval API

### Pull Request Guidelines

1. **Create a feature branch**
   ```bash
   git checkout -b feature/add-{provider-name}-provider
   ```

2. **Commit with clear messages**
   ```bash
   git commit -m "Add {Provider Name} OAuth provider support
   
   - Implement {ProviderName}Provider class with OAuth 2.0 flow
   - Add provider configuration to providers.json
   - Include comprehensive unit and integration tests
   - Update documentation and environment variables"
   ```

3. **Include in your PR**:
   - Provider implementation file
   - Configuration updates
   - Comprehensive tests
   - Documentation updates
   - Example environment variables

4. **PR Description Template**:
   ```markdown
   ## Description
   Adds support for {Provider Name} OAuth 2.0 authentication.
   
   ## Changes
   - [ ] Created `{provider_name}_provider.py` with complete OAuth implementation
   - [ ] Added provider configuration to `providers.json`
   - [ ] Implemented comprehensive unit tests
   - [ ] Added integration tests
   - [ ] Updated documentation
   - [ ] Added environment variable examples
   
   ## Testing
   - [ ] All existing tests pass
   - [ ] New provider tests pass
   - [ ] Manual testing completed
   - [ ] Error scenarios tested
   
   ## OAuth Provider Details
   - **Authorization URL**: https://provider.com/oauth/authorize
   - **Token URL**: https://provider.com/oauth/token
   - **Supported Scopes**: scope1, scope2, scope3
   - **Special Requirements**: [Any unique requirements]
   ```

### Review Process

1. **Automated checks** will run on your PR
2. **Code review** by maintainers
3. **Testing** on development environment
4. **Documentation review**
5. **Merge** after approval

## Getting Help

- **Issues**: Create a GitHub issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check existing provider implementations for examples
- **Testing**: Look at existing test files for patterns

## Provider Examples

### Simple Provider (GitHub-style)

```python
class GitHubProvider(BaseProvider):
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': kwargs.get('scope', ' '.join(self.scopes)),
            'state': state
        }
        return f"{self.authorize_url}?{urlencode(params)}"
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        # Standard OAuth 2.0 token exchange
        pass
```

### Complex Provider (Microsoft-style)

```python
class MicrosoftProvider(BaseProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__('microsoft', config)
        self.tenant = config.get('tenant', 'common')
        # Update URLs with tenant
        if self.tenant != 'common':
            self.authorize_url = f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/authorize'
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        # Microsoft-specific parameters
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': kwargs.get('scope', ' '.join(self.scopes)),
            'response_type': 'code',
            'state': state,
            'response_mode': kwargs.get('response_mode', 'query'),
            'prompt': kwargs.get('prompt', 'select_account')
        }
        return f"{self.authorize_url}?{urlencode(params)}"
```

Thank you for contributing to the SecureContext Protocol! Your contributions help make secure OAuth 2.0 mediation accessible to more developers and AI agent frameworks.