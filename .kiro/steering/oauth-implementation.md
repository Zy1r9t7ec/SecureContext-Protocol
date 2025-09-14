---
inclusion: fileMatch
fileMatchPattern: "**/providers/*.py"
---

# OAuth Provider Implementation Guide

This steering document provides specific guidance for implementing OAuth providers in the Secure Context Protocol.

## Provider Architecture

### Base Provider Interface
All OAuth providers must inherit from `BaseProvider` and implement:
- `get_authorization_url()` - Generate OAuth authorization URL
- `exchange_code_for_tokens()` - Exchange authorization code for tokens
- `refresh_access_token()` - Refresh expired access tokens
- `get_user_info()` - Retrieve user information
- `revoke_tokens()` - Revoke access tokens

### Configuration Requirements
Each provider requires:
- Client ID and Client Secret from environment variables
- Redirect URI configuration
- Scope definitions
- Token endpoint URLs
- User info endpoint URLs

## Implementation Standards

### Error Handling
```python
try:
    # OAuth operation
    pass
except OAuthError as e:
    logger.error(f"OAuth error for {self.provider_name}: {e}")
    raise ProviderError(f"Authentication failed: {e.description}")
except Exception as e:
    logger.error(f"Unexpected error in {self.provider_name}: {e}")
    raise ProviderError("Authentication service temporarily unavailable")
```

### Token Management
- Store tokens securely using TokenStorage class
- Implement automatic token refresh
- Handle token expiration gracefully
- Support token revocation

### Security Considerations
- Validate state parameter for CSRF protection
- Use PKCE when supported by provider
- Sanitize all user inputs
- Log security events appropriately

## Provider-Specific Guidelines

### Google OAuth
- Use Google's discovery document for endpoints
- Request minimal required scopes
- Handle Google-specific error codes
- Support offline access for refresh tokens

### Microsoft OAuth
- Use Microsoft Graph API endpoints
- Handle tenant-specific configurations
- Support both personal and work accounts
- Implement proper scope mapping

## Testing Requirements

### Unit Tests
- Test all provider methods independently
- Mock external API calls
- Test error conditions
- Validate token handling

### Integration Tests
- Test complete OAuth flows
- Verify token refresh functionality
- Test with real provider endpoints (in development)
- Validate user info retrieval

## Reference Implementation

See `authentication_proxy/providers/google_provider.py` and `microsoft_provider.py` for complete examples following these standards.