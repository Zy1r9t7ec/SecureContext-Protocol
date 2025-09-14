# Provider Implementation Example: Adding GitHub OAuth Support

This document provides a complete walkthrough of implementing a new OAuth provider for the SecureContext Protocol. We'll use GitHub as an example to demonstrate all the steps required to add a new provider.

## Table of Contents

- [Overview](#overview)
- [Step 1: Research GitHub OAuth](#step-1-research-github-oauth)
- [Step 2: Create Provider Class](#step-2-create-provider-class)
- [Step 3: Add Configuration](#step-3-add-configuration)
- [Step 4: Environment Setup](#step-4-environment-setup)
- [Step 5: Write Tests](#step-5-write-tests)
- [Step 6: Integration Testing](#step-6-integration-testing)
- [Step 7: Documentation](#step-7-documentation)

## Overview

GitHub OAuth 2.0 provides access to user repositories, profile information, and other GitHub resources. This example will implement a complete GitHub provider that follows the SecureContext Protocol standards.

## Step 1: Research GitHub OAuth

Before implementing, we need to understand GitHub's OAuth 2.0 implementation:

### GitHub OAuth Endpoints
- **Authorization URL**: `https://github.com/login/oauth/authorize`
- **Token URL**: `https://github.com/login/oauth/access_token`
- **User API URL**: `https://api.github.com/user`

### GitHub OAuth Scopes
- `user`: Access to user profile information
- `user:email`: Access to user email addresses
- `repo`: Access to public and private repositories
- `public_repo`: Access to public repositories only
- `gist`: Access to gists
- `notifications`: Access to notifications

### GitHub-Specific Requirements
- Accepts `Accept: application/json` header for JSON responses
- Uses standard OAuth 2.0 flow
- Supports refresh tokens (but they don't expire)
- Requires User-Agent header for API requests

## Step 2: Create Provider Class

Create `authentication_proxy/providers/github_provider.py`:

```python
"""
GitHub OAuth 2.0 provider implementation.

This module implements the GitHub OAuth provider using the BaseProvider interface,
handling GitHub-specific OAuth flow requirements and GitHub API interactions.
"""

from typing import Dict, Any, Optional
import requests
from urllib.parse import urlencode
from requests.exceptions import RequestException, ConnectionError, Timeout

from .base_provider import BaseProvider, OAuthFlowError, ProviderConfigurationError


class GitHubProvider(BaseProvider):
    """
    GitHub OAuth 2.0 provider implementation.
    
    This class handles GitHub-specific OAuth flows, including authorization URL generation,
    token exchange, and user information retrieval through GitHub API.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize GitHub OAuth provider.
        
        Args:
            config: GitHub provider configuration dictionary
            
        Raises:
            ProviderConfigurationError: If configuration is invalid
        """
        # Set default GitHub OAuth URLs if not provided
        default_config = {
            'authorize_url': 'https://github.com/login/oauth/authorize',
            'token_url': 'https://github.com/login/oauth/access_token',
            'userinfo_url': 'https://api.github.com/user',
            'display_name': 'GitHub Account',
            'scopes': [
                'user:email',
                'repo'
            ]
        }
        
        # Merge with provided config
        merged_config = {**default_config, **config}
        
        super().__init__('github', merged_config)
        
        # GitHub-specific configuration
        self.user_agent = config.get('user_agent', 'SecureContext-Protocol/1.0')
        self.api_version = config.get('api_version', '2022-11-28')
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        """
        Generate GitHub OAuth authorization URL.
        
        Args:
            redirect_uri: Callback URL for OAuth flow
            state: CSRF protection state parameter
            **kwargs: Additional parameters (scope, allow_signup, etc.)
            
        Returns:
            Authorization URL for redirecting user to GitHub OAuth consent screen
            
        Raises:
            OAuthFlowError: If URL generation fails
        """
        try:
            # Prepare authorization parameters
            params = {
                'client_id': self.client_id,
                'redirect_uri': redirect_uri,
                'scope': kwargs.get('scope', ' '.join(self.scopes)),
                'state': state,
                'allow_signup': kwargs.get('allow_signup', 'true')
            }
            
            # Build authorization URL
            auth_url = f"{self.authorize_url}?{urlencode(params)}"
            
            self.logger.debug(f"Generated GitHub authorization URL with scopes: {params['scope']}")
            return auth_url
            
        except Exception as e:
            self.logger.error(f"Failed to generate GitHub authorization URL: {e}", exc_info=True)
            raise OAuthFlowError(f"Failed to generate authorization URL: {e}")
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        """
        Exchange authorization code for GitHub OAuth tokens.
        
        Args:
            code: Authorization code from OAuth callback
            redirect_uri: Callback URL used in authorization request
            **kwargs: Additional parameters
            
        Returns:
            Token data dictionary with access_token, refresh_token, expires_in, scope
            
        Raises:
            OAuthFlowError: If token exchange fails
        """
        try:
            # Prepare token exchange request
            token_data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code': code,
                'redirect_uri': redirect_uri
            }
            
            headers = {
                'Accept': 'application/json',
                'User-Agent': self.user_agent
            }
            
            self.logger.debug(f"Exchanging authorization code for GitHub tokens")
            
            # Make token exchange request
            response = requests.post(
                self.token_url,
                data=token_data,
                headers=headers,
                timeout=30
            )
            
            # Check response status
            if response.status_code != 200:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                error_msg = error_data.get('error_description', f'HTTP {response.status_code}')
                self.logger.error(f"GitHub token exchange failed: {response.status_code} - {error_msg}")
                raise OAuthFlowError(f"Token exchange failed: {error_msg}")
            
            # Parse token response
            token_response = response.json()
            
            # GitHub returns error in the JSON response even with 200 status
            if 'error' in token_response:
                error_msg = token_response.get('error_description', token_response.get('error'))
                self.logger.error(f"GitHub token exchange error: {error_msg}")
                raise OAuthFlowError(f"Token exchange failed: {error_msg}")
            
            # Validate token response
            if not self.validate_token_response(token_response):
                raise OAuthFlowError("Invalid token response from GitHub")
            
            # Extract and normalize token data
            normalized_tokens = self.extract_token_data(token_response)
            
            self.logger.info(f"Successfully exchanged code for GitHub tokens - scope: {normalized_tokens['scope']}")
            
            return normalized_tokens
            
        except RequestException as e:
            self.logger.error(f"Network error during GitHub token exchange: {e}", exc_info=True)
            if isinstance(e, ConnectionError):
                raise OAuthFlowError("Network connection failed. Please check your internet connection.")
            elif isinstance(e, Timeout):
                raise OAuthFlowError("Request timed out. Please try again.")
            else:
                raise OAuthFlowError(f"Network request failed: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during GitHub token exchange: {e}", exc_info=True)
            raise OAuthFlowError(f"Token exchange failed: {e}")
    
    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve GitHub user information using access token.
        
        Args:
            access_token: Valid GitHub access token
            
        Returns:
            User information dictionary
            
        Raises:
            OAuthFlowError: If user info retrieval fails
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/vnd.github+json',
                'User-Agent': self.user_agent,
                'X-GitHub-Api-Version': self.api_version
            }
            
            self.logger.debug("Retrieving GitHub user information")
            
            # Make user info request
            response = requests.get(
                self.userinfo_url,
                headers=headers,
                timeout=30
            )
            
            # Check response status
            if response.status_code != 200:
                error_msg = f'HTTP {response.status_code}'
                if response.status_code == 401:
                    error_msg = "Access token expired or invalid"
                elif response.status_code == 403:
                    error_msg = "Rate limit exceeded or insufficient permissions"
                self.logger.error(f"GitHub user info request failed: {error_msg}")
                raise OAuthFlowError(f"User info request failed: {error_msg}")
            
            # Parse user info response
            user_info = response.json()
            
            # Get user email (requires separate API call if not public)
            email = await self._get_user_email(access_token) if not user_info.get('email') else user_info.get('email')
            
            # Normalize user info to match standard format
            normalized_user_info = {
                'id': str(user_info.get('id')),
                'email': email,
                'name': user_info.get('name'),
                'given_name': user_info.get('name', '').split(' ')[0] if user_info.get('name') else None,
                'family_name': ' '.join(user_info.get('name', '').split(' ')[1:]) if user_info.get('name') and len(user_info.get('name', '').split(' ')) > 1 else None,
                'picture': user_info.get('avatar_url'),
                'locale': None,  # GitHub doesn't provide locale
                'verified_email': True,  # GitHub emails are verified
                'login': user_info.get('login'),  # GitHub-specific field
                'html_url': user_info.get('html_url'),  # GitHub-specific field
                'public_repos': user_info.get('public_repos'),  # GitHub-specific field
                'followers': user_info.get('followers'),  # GitHub-specific field
                'following': user_info.get('following')  # GitHub-specific field
            }
            
            self.logger.info(f"Successfully retrieved GitHub user info for user: {normalized_user_info.get('login', 'unknown')}")
            
            return normalized_user_info
            
        except RequestException as e:
            self.logger.error(f"Network error during GitHub user info retrieval: {e}", exc_info=True)
            raise OAuthFlowError(f"User info retrieval network error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during GitHub user info retrieval: {e}", exc_info=True)
            raise OAuthFlowError(f"User info retrieval failed: {e}")
    
    async def _get_user_email(self, access_token: str) -> Optional[str]:
        """
        Get user's primary email address from GitHub API.
        
        Args:
            access_token: Valid GitHub access token
            
        Returns:
            Primary email address or None if not available
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/vnd.github+json',
                'User-Agent': self.user_agent,
                'X-GitHub-Api-Version': self.api_version
            }
            
            response = requests.get(
                'https://api.github.com/user/emails',
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                emails = response.json()
                # Find primary email
                for email_info in emails:
                    if email_info.get('primary', False):
                        return email_info.get('email')
                # If no primary email, return first verified email
                for email_info in emails:
                    if email_info.get('verified', False):
                        return email_info.get('email')
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to retrieve GitHub user email: {e}")
            return None
    
    def validate_scopes(self, requested_scopes: list) -> bool:
        """
        Validate GitHub-specific scopes.
        
        Args:
            requested_scopes: List of OAuth scopes to validate
            
        Returns:
            True if all scopes are valid GitHub scopes, False otherwise
        """
        # GitHub-specific scope validation
        valid_github_scopes = [
            'user',
            'user:email',
            'user:follow',
            'public_repo',
            'repo',
            'repo_deployment',
            'repo:status',
            'delete_repo',
            'notifications',
            'gist',
            'read:repo_hook',
            'write:repo_hook',
            'admin:repo_hook',
            'admin:org_hook',
            'read:org',
            'write:org',
            'admin:org',
            'read:public_key',
            'write:public_key',
            'admin:public_key',
            'read:gpg_key',
            'write:gpg_key',
            'admin:gpg_key',
            'codespace',
            'workflow'
        ]
        
        for scope in requested_scopes:
            if scope not in valid_github_scopes:
                self.logger.warning(f"Invalid GitHub scope: {scope}")
                return False
        
        return True
    
    def get_repository_info(self, access_token: str, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific GitHub repository.
        
        This is a GitHub-specific method that demonstrates how to add
        provider-specific functionality beyond the base OAuth flow.
        
        Args:
            access_token: Valid GitHub access token
            owner: Repository owner (username or organization)
            repo: Repository name
            
        Returns:
            Repository information dictionary or None if not accessible
            
        Raises:
            OAuthFlowError: If repository info retrieval fails
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/vnd.github+json',
                'User-Agent': self.user_agent,
                'X-GitHub-Api-Version': self.api_version
            }
            
            repo_url = f'https://api.github.com/repos/{owner}/{repo}'
            
            self.logger.debug(f"Retrieving GitHub repository info: {owner}/{repo}")
            
            response = requests.get(repo_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                repo_info = response.json()
                
                # Return normalized repository information
                return {
                    'id': repo_info.get('id'),
                    'name': repo_info.get('name'),
                    'full_name': repo_info.get('full_name'),
                    'description': repo_info.get('description'),
                    'private': repo_info.get('private', False),
                    'html_url': repo_info.get('html_url'),
                    'clone_url': repo_info.get('clone_url'),
                    'language': repo_info.get('language'),
                    'stars': repo_info.get('stargazers_count', 0),
                    'forks': repo_info.get('forks_count', 0),
                    'created_at': repo_info.get('created_at'),
                    'updated_at': repo_info.get('updated_at')
                }
            elif response.status_code == 404:
                self.logger.info(f"Repository not found or not accessible: {owner}/{repo}")
                return None
            else:
                error_msg = f'HTTP {response.status_code}'
                self.logger.error(f"GitHub repository info request failed: {error_msg}")
                raise OAuthFlowError(f"Repository info request failed: {error_msg}")
                
        except RequestException as e:
            self.logger.error(f"Network error during GitHub repository info retrieval: {e}")
            raise OAuthFlowError(f"Repository info retrieval network error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during GitHub repository info retrieval: {e}")
            raise OAuthFlowError(f"Repository info retrieval failed: {e}")
```

## Step 3: Add Configuration

Add GitHub provider configuration to `providers.json`:

```json
{
  "providers": {
    "github": {
      "name": "github",
      "display_name": "GitHub Account",
      "description": "Connect your GitHub account to access repositories and user data",
      "client_id": "env:GITHUB_CLIENT_ID",
      "client_secret": "env:GITHUB_CLIENT_SECRET",
      "scopes": [
        "user:email",
        "repo"
      ],
      "authorize_url": "https://github.com/login/oauth/authorize",
      "token_url": "https://github.com/login/oauth/access_token",
      "userinfo_url": "https://api.github.com/user",
      "provider_class": "GitHubProvider",
      "enabled": true,
      "icon": "github",
      "color": "#333333",
      "additional_params": {
        "user_agent": "SecureContext-Protocol/1.0",
        "api_version": "2022-11-28",
        "allow_signup": "true"
      }
    }
  }
}
```

## Step 4: Environment Setup

Add GitHub OAuth credentials to `.env.example`:

```bash
# GitHub OAuth Configuration
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
```

And to your local `.env` file:

```bash
# GitHub OAuth Configuration
GITHUB_CLIENT_ID=Iv1.a1b2c3d4e5f6g7h8
GITHUB_CLIENT_SECRET=1234567890abcdef1234567890abcdef12345678
```

### Setting up GitHub OAuth App

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in the application details:
   - **Application name**: SecureContext Protocol
   - **Homepage URL**: http://localhost:5000
   - **Authorization callback URL**: http://localhost:5000/oauth/github/callback
4. Click "Register application"
5. Copy the Client ID and Client Secret to your `.env` file

## Step 5: Write Tests

Create comprehensive tests in `tests/test_github_provider.py`:

```python
"""
Unit tests for GitHub OAuth provider.

This module tests GitHub-specific OAuth flow implementation,
including authorization URL generation, token exchange, and error handling.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import sys
import os

# Add the authentication_proxy directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'authentication_proxy'))

from providers.github_provider import GitHubProvider
from providers.base_provider import OAuthFlowError, ProviderConfigurationError


class TestGitHubProvider(unittest.TestCase):
    """Test cases for GitHub OAuth provider."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'client_id': 'test_github_client_id',
            'client_secret': 'test_github_client_secret',
            'scopes': ['user:email', 'repo']
        }
        self.provider = GitHubProvider(self.config)
    
    def test_initialization(self):
        """Test GitHub provider initialization."""
        self.assertEqual(self.provider.name, 'github')
        self.assertEqual(self.provider.client_id, 'test_github_client_id')
        self.assertEqual(self.provider.client_secret, 'test_github_client_secret')
        self.assertEqual(self.provider.display_name, 'GitHub Account')
        self.assertIn('github.com', self.provider.authorize_url)
        self.assertIn('github.com', self.provider.token_url)
    
    def test_get_authorization_url(self):
        """Test GitHub authorization URL generation."""
        redirect_uri = 'http://localhost:5000/oauth/github/callback'
        state = 'test_state_123'
        
        auth_url = self.provider.get_authorization_url(redirect_uri, state)
        
        self.assertIn('github.com/login/oauth/authorize', auth_url)
        self.assertIn('client_id=test_github_client_id', auth_url)
        self.assertIn('state=test_state_123', auth_url)
        self.assertIn('scope=user%3Aemail+repo', auth_url)
        self.assertIn('allow_signup=true', auth_url)
    
    def test_get_authorization_url_custom_params(self):
        """Test GitHub authorization URL with custom parameters."""
        redirect_uri = 'http://localhost:5000/oauth/github/callback'
        state = 'test_state_123'
        
        auth_url = self.provider.get_authorization_url(
            redirect_uri, 
            state, 
            scope='public_repo',
            allow_signup='false'
        )
        
        self.assertIn('scope=public_repo', auth_url)
        self.assertIn('allow_signup=false', auth_url)
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_success(self, mock_post):
        """Test successful GitHub token exchange."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'gho_test_access_token',
            'token_type': 'bearer',
            'scope': 'user:email,repo'
        }
        mock_response.headers = {'content-type': 'application/json'}
        mock_post.return_value = mock_response
        
        result = self.provider.exchange_code_for_tokens(
            'test_code', 
            'http://localhost:5000/oauth/github/callback'
        )
        
        # Verify request
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]['data']['client_id'], 'test_github_client_id')
        self.assertEqual(call_args[1]['data']['code'], 'test_code')
        self.assertIn('Accept', call_args[1]['headers'])
        self.assertIn('User-Agent', call_args[1]['headers'])
        
        # Verify response
        self.assertEqual(result['access_token'], 'gho_test_access_token')
        self.assertEqual(result['token_type'], 'Bearer')
        self.assertEqual(result['scope'], 'user:email,repo')
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_github_error(self, mock_post):
        """Test GitHub token exchange with GitHub-specific error."""
        mock_response = MagicMock()
        mock_response.status_code = 200  # GitHub returns 200 even for errors
        mock_response.json.return_value = {
            'error': 'bad_verification_code',
            'error_description': 'The code passed is incorrect or expired.'
        }
        mock_response.headers = {'content-type': 'application/json'}
        mock_post.return_value = mock_response
        
        with self.assertRaises(OAuthFlowError) as context:
            self.provider.exchange_code_for_tokens(
                'invalid_code', 
                'http://localhost:5000/oauth/github/callback'
            )
        
        self.assertIn('The code passed is incorrect or expired', str(context.exception))
    
    @patch('requests.get')
    def test_get_user_info_success(self, mock_get):
        """Test successful GitHub user info retrieval."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'id': 12345,
            'login': 'testuser',
            'name': 'Test User',
            'email': 'test@example.com',
            'avatar_url': 'https://avatars.githubusercontent.com/u/12345',
            'html_url': 'https://github.com/testuser',
            'public_repos': 10,
            'followers': 5,
            'following': 3
        }
        mock_response.headers = {'content-type': 'application/json'}
        mock_get.return_value = mock_response
        
        result = self.provider.get_user_info('gho_test_access_token')
        
        # Verify request
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        self.assertIn('Authorization', call_args[1]['headers'])
        self.assertEqual(call_args[1]['headers']['Authorization'], 'Bearer gho_test_access_token')
        self.assertIn('User-Agent', call_args[1]['headers'])
        self.assertIn('X-GitHub-Api-Version', call_args[1]['headers'])
        
        # Verify response
        self.assertEqual(result['id'], '12345')
        self.assertEqual(result['login'], 'testuser')
        self.assertEqual(result['name'], 'Test User')
        self.assertEqual(result['email'], 'test@example.com')
        self.assertEqual(result['public_repos'], 10)
    
    def test_validate_scopes_valid(self):
        """Test GitHub scope validation with valid scopes."""
        valid_scopes = ['user:email', 'repo', 'public_repo']
        result = self.provider.validate_scopes(valid_scopes)
        self.assertTrue(result)
    
    def test_validate_scopes_invalid(self):
        """Test GitHub scope validation with invalid scopes."""
        invalid_scopes = ['invalid_scope', 'another_invalid']
        result = self.provider.validate_scopes(invalid_scopes)
        self.assertFalse(result)
    
    @patch('requests.get')
    def test_get_repository_info_success(self, mock_get):
        """Test successful GitHub repository info retrieval."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'id': 67890,
            'name': 'test-repo',
            'full_name': 'testuser/test-repo',
            'description': 'A test repository',
            'private': False,
            'html_url': 'https://github.com/testuser/test-repo',
            'clone_url': 'https://github.com/testuser/test-repo.git',
            'language': 'Python',
            'stargazers_count': 15,
            'forks_count': 3,
            'created_at': '2023-01-01T00:00:00Z',
            'updated_at': '2023-12-01T00:00:00Z'
        }
        mock_response.headers = {'content-type': 'application/json'}
        mock_get.return_value = mock_response
        
        result = self.provider.get_repository_info('gho_test_access_token', 'testuser', 'test-repo')
        
        self.assertEqual(result['name'], 'test-repo')
        self.assertEqual(result['language'], 'Python')
        self.assertEqual(result['stars'], 15)
        self.assertEqual(result['forks'], 3)
        self.assertFalse(result['private'])
    
    @patch('requests.get')
    def test_get_repository_info_not_found(self, mock_get):
        """Test GitHub repository info retrieval for non-existent repository."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = self.provider.get_repository_info('gho_test_access_token', 'testuser', 'nonexistent')
        
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
```

## Step 6: Integration Testing

Add integration tests to `tests/test_integration.py`:

```python
def test_github_oauth_flow(self):
    """Test complete GitHub OAuth flow."""
    # Test authorization endpoint
    response = self.client.get('/oauth/github/authorize')
    self.assertEqual(response.status_code, 302)
    self.assertIn('github.com', response.location)
    
    # Verify state was stored in session
    with self.client.session_transaction() as sess:
        self.assertIsNotNone(sess.get('oauth_state'))
        self.assertEqual(sess.get('oauth_provider'), 'github')
    
    # Test callback with mock token exchange
    with self.client.session_transaction() as sess:
        sess['oauth_state'] = 'test_state'
        sess['oauth_provider'] = 'github'
    
    mock_token_response = {
        'access_token': 'gho_test_token',
        'token_type': 'bearer',
        'scope': 'user:email,repo'
    }
    
    with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.validate_state.return_value = True
        mock_provider.exchange_code_for_tokens.return_value = mock_token_response
        mock_get_provider.return_value = mock_provider
        
        response = self.client.get('/oauth/github/callback?code=test_code&state=test_state')
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('session_id=', response.location)
        
        # Extract session ID and verify token was stored
        import re
        session_id_match = re.search(r'session_id=([^&]+)', response.location)
        self.assertIsNotNone(session_id_match)
        session_id = session_id_match.group(1)
        
        # Verify GitHub tokens were stored correctly
        stored_token = TokenStorage.retrieve_tokens(session_id)
        self.assertIsNotNone(stored_token)
        self.assertEqual(stored_token['provider'], 'github')
        self.assertEqual(stored_token['access_token'], 'gho_test_token')

def test_github_error_scenarios(self):
    """Test GitHub-specific error scenarios."""
    # Test user denial
    response = self.client.get('/oauth/github/callback?error=access_denied')
    self.assertEqual(response.status_code, 302)
    self.assertIn('error=access_denied', response.location)
    
    # Test invalid client
    response = self.client.get('/oauth/github/callback?error=unauthorized_client')
    self.assertEqual(response.status_code, 302)
    self.assertIn('error=unauthorized_client', response.location)
```

## Step 7: Documentation

Update the main README.md to include GitHub in the supported providers list:

```markdown
## Supported OAuth Providers

- **Google**: Gmail, Calendar, Drive access
- **Microsoft**: Outlook Mail, Calendar, OneDrive access  
- **GitHub**: Repository, user profile, and organization access

## Environment Variables

```bash
# GitHub OAuth Configuration
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
```

Add GitHub-specific documentation to the provider configuration section.

## Testing the Implementation

### Manual Testing

1. **Start the development server**:
   ```bash
   python start.py
   ```

2. **Visit the web interface**: http://localhost:5000

3. **Click "Connect GitHub Account"** and verify:
   - Redirects to GitHub OAuth consent screen
   - Shows correct scopes (user:email, repo)
   - After authorization, redirects back with session ID
   - Session ID can be used to retrieve tokens

4. **Test the token retrieval**:
   ```bash
   python verify_tokens.py <session_id>
   ```

### Automated Testing

Run the complete test suite:

```bash
# Run all tests
python -m pytest tests/

# Run GitHub-specific tests
python -m pytest tests/test_github_provider.py -v

# Run integration tests
python -m pytest tests/test_integration.py::TestIntegration::test_github_oauth_flow -v
```

## Common Issues and Solutions

### Issue 1: GitHub returns 200 with error in JSON

**Problem**: GitHub returns HTTP 200 even for OAuth errors, with error details in the JSON response.

**Solution**: Always check for `error` field in the JSON response:

```python
if 'error' in token_response:
    error_msg = token_response.get('error_description', token_response.get('error'))
    raise OAuthFlowError(f"Token exchange failed: {error_msg}")
```

### Issue 2: User email not available

**Problem**: GitHub user profile API doesn't always return email address.

**Solution**: Make a separate API call to `/user/emails` endpoint:

```python
async def _get_user_email(self, access_token: str) -> Optional[str]:
    # Implementation to fetch user emails
```

### Issue 3: Rate limiting

**Problem**: GitHub API has rate limits that can affect user info retrieval.

**Solution**: Handle 403 responses gracefully and provide meaningful error messages:

```python
elif response.status_code == 403:
    error_msg = "Rate limit exceeded or insufficient permissions"
```

## Next Steps

After implementing the GitHub provider:

1. **Submit a Pull Request** following the contribution guidelines
2. **Add more GitHub-specific features** like repository listing, issue access
3. **Consider implementing webhook support** for real-time updates
4. **Add support for GitHub Enterprise** with custom domain configuration

This example demonstrates the complete process of adding a new OAuth provider to the SecureContext Protocol. The same pattern can be followed for any OAuth 2.0 provider.