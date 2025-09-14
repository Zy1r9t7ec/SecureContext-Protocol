#!/usr/bin/env python3
"""
Live Provider Extensibility Test

This script demonstrates adding a new provider to the running SCP system
and testing its integration with the existing infrastructure.
"""

import sys
import os
import json
import tempfile
import time
import requests
import subprocess
from pathlib import Path

# Add authentication_proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'authentication_proxy'))

def create_test_provider_config():
    """Create a test provider configuration."""
    return {
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
                "provider_class": "GitHubProvider",
                "enabled": True,
                "icon": "github",
                "color": "#333333"
            },
            "google": {
                "name": "google",
                "display_name": "Google Account",
                "description": "Connect your Google account to access Gmail and Calendar data",
                "client_id": "env:GOOGLE_CLIENT_ID",
                "client_secret": "env:GOOGLE_CLIENT_SECRET",
                "scopes": [
                    "profile",
                    "email",
                    "https://www.googleapis.com/auth/gmail.readonly",
                    "https://www.googleapis.com/auth/calendar.readonly"
                ],
                "authorize_url": "https://accounts.google.com/o/oauth2/auth",
                "token_url": "https://oauth2.googleapis.com/token",
                "provider_class": "GoogleProvider",
                "enabled": True,
                "icon": "google",
                "color": "#4285f4"
            },
            "microsoft": {
                "name": "microsoft",
                "display_name": "Microsoft Account",
                "description": "Connect your Microsoft account to access Outlook Mail and Calendar data",
                "client_id": "env:MICROSOFT_CLIENT_ID",
                "client_secret": "env:MICROSOFT_CLIENT_SECRET",
                "scopes": [
                    "User.Read",
                    "Mail.Read",
                    "Calendars.Read"
                ],
                "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                "provider_class": "MicrosoftProvider",
                "enabled": True,
                "icon": "microsoft",
                "color": "#0078d4"
            }
        },
        "settings": {
            "default_session_timeout": 3600,
            "max_concurrent_sessions": 1000,
            "enable_audit_logging": True,
            "auto_cleanup_expired_sessions": True
        }
    }

def create_github_provider():
    """Create a GitHub provider implementation."""
    github_provider_code = '''
"""
GitHub OAuth 2.0 provider implementation for SecureContext Protocol.
"""

from typing import Dict, Any
import requests
from urllib.parse import urlencode
from .base_provider import BaseProvider, OAuthFlowError


class GitHubProvider(BaseProvider):
    """
    GitHub OAuth 2.0 provider implementation.
    
    This provider handles OAuth flows for GitHub authentication,
    allowing access to user repositories and profile information.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize GitHub provider."""
        super().__init__('github', config)
        
        # GitHub-specific URLs
        self.authorize_url = 'https://github.com/login/oauth/authorize'
        self.token_url = 'https://github.com/login/oauth/access_token'
        self.userinfo_url = 'https://api.github.com/user'
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        """Generate GitHub OAuth authorization URL."""
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'state': state,
            'scope': ' '.join(self.scopes) if self.scopes else '',
            'response_type': 'code'
        }
        
        # Add any additional parameters
        params.update(kwargs)
        
        # Remove empty parameters
        params = {k: v for k, v in params.items() if v}
        
        return f"{self.authorize_url}?{urlencode(params)}"
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        """Exchange authorization code for GitHub access token."""
        try:
            # GitHub token exchange
            token_data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code': code,
                'redirect_uri': redirect_uri
            }
            
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'SecureContext-Protocol/1.0'
            }
            
            # For testing, return mock tokens instead of making real request
            if code.startswith('test_'):
                return {
                    'access_token': f'github_access_token_{code}',
                    'token_type': 'bearer',
                    'scope': ' '.join(self.scopes) if self.scopes else 'user:email,repo'
                }
            
            # In real implementation, would make actual request:
            # response = requests.post(self.token_url, data=token_data, headers=headers)
            # if response.status_code != 200:
            #     raise OAuthFlowError(f'Token exchange failed: {response.text}')
            # return response.json()
            
            # For demo purposes, return mock response
            return {
                'access_token': f'github_mock_token_{code}',
                'token_type': 'bearer',
                'scope': ' '.join(self.scopes) if self.scopes else 'user:email,repo'
            }
            
        except requests.RequestException as e:
            raise OAuthFlowError(f'Network error during token exchange: {e}')
        except Exception as e:
            raise OAuthFlowError(f'Token exchange failed: {e}')
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Retrieve GitHub user information."""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
                'User-Agent': 'SecureContext-Protocol/1.0'
            }
            
            # For testing, return mock user info
            if access_token.startswith('github_'):
                return {
                    'id': 12345,
                    'login': 'testuser',
                    'name': 'Test User',
                    'email': 'test@example.com',
                    'avatar_url': 'https://github.com/images/error/octocat_happy.gif',
                    'html_url': 'https://github.com/testuser'
                }
            
            # In real implementation:
            # response = requests.get(self.userinfo_url, headers=headers)
            # if response.status_code != 200:
            #     raise OAuthFlowError(f'User info retrieval failed: {response.text}')
            # return response.json()
            
            # For demo purposes, return mock response
            return {
                'id': 12345,
                'login': 'mockuser',
                'name': 'Mock GitHub User',
                'email': 'mock@github.com',
                'avatar_url': 'https://github.com/images/error/octocat_happy.gif'
            }
            
        except requests.RequestException as e:
            raise OAuthFlowError(f'Network error during user info retrieval: {e}')
        except Exception as e:
            raise OAuthFlowError(f'User info retrieval failed: {e}')
    
    def _get_provider_metadata(self) -> Dict[str, Any]:
        """Get GitHub provider specific metadata."""
        return {
            'icon_url': 'https://github.com/favicon.ico',
            'documentation_url': 'https://docs.github.com/en/developers/apps/building-oauth-apps',
            'website_url': 'https://github.com',
            'rate_limits': {
                'requests_per_hour': 5000,
                'burst_limit': 100
            },
            'supported_scopes': [
                'user', 'user:email', 'user:follow',
                'repo', 'repo:status', 'repo_deployment',
                'public_repo', 'repo:invite',
                'security_events', 'admin:repo_hook',
                'write:repo_hook', 'read:repo_hook',
                'admin:org', 'write:org', 'read:org',
                'admin:public_key', 'write:public_key', 'read:public_key',
                'admin:org_hook', 'gist', 'notifications',
                'delete_repo', 'write:discussion', 'read:discussion'
            ]
        }
'''
    return github_provider_code

def test_provider_extensibility():
    """Test adding a new provider to the system."""
    print("🧪 Testing Live Provider Extensibility")
    print("=" * 50)
    
    # Set up test environment
    os.environ['FLASK_SECRET_KEY'] = 'test_secret_key_for_extensibility'
    os.environ['GITHUB_CLIENT_ID'] = 'test_github_client_id'
    os.environ['GITHUB_CLIENT_SECRET'] = 'test_github_client_secret'
    os.environ['GOOGLE_CLIENT_ID'] = 'test_google_client_id'
    os.environ['GOOGLE_CLIENT_SECRET'] = 'test_google_client_secret'
    os.environ['MICROSOFT_CLIENT_ID'] = 'test_microsoft_client_id'
    os.environ['MICROSOFT_CLIENT_SECRET'] = 'test_microsoft_client_secret'
    
    try:
        # Step 1: Create GitHub provider file
        print("1. Creating GitHub provider implementation...")
        
        github_provider_path = Path('authentication_proxy/providers/github_provider.py')
        with open(github_provider_path, 'w') as f:
            f.write(create_github_provider())
        
        print("✓ GitHub provider file created")
        
        # Step 2: Create updated providers.json with GitHub
        print("2. Creating updated provider configuration...")
        
        config_data = create_test_provider_config()
        
        # Backup original providers.json
        original_providers_path = Path('providers.json')
        backup_path = Path('providers.json.backup')
        
        if original_providers_path.exists():
            original_providers_path.rename(backup_path)
        
        # Write new configuration
        with open('providers.json', 'w') as f:
            json.dump(config_data, f, indent=2)
        
        print("✓ Provider configuration updated with GitHub")
        
        # Step 3: Test provider manager integration
        print("3. Testing provider manager integration...")
        
        from authentication_proxy.providers.provider_manager import ProviderManager
        from authentication_proxy.config import Config
        
        # Reload configuration
        config = Config()
        manager = ProviderManager(config=config)
        
        # Register providers from config
        manager.register_providers_from_config()
        
        # Verify GitHub provider is registered
        github_provider = manager.get_provider('github')
        if github_provider:
            print("✓ GitHub provider registered successfully")
            print(f"  - Display name: {github_provider.display_name}")
            print(f"  - Scopes: {github_provider.scopes}")
        else:
            print("✗ GitHub provider not found")
            return False
        
        # Step 4: Test provider functionality
        print("4. Testing GitHub provider functionality...")
        
        # Test authorization URL generation
        auth_url = github_provider.get_authorization_url(
            'http://localhost:5000/oauth/github/callback',
            'test_state_123'
        )
        
        if 'github.com' in auth_url and 'test_github_client_id' in auth_url:
            print("✓ Authorization URL generated correctly")
        else:
            print("✗ Authorization URL generation failed")
            return False
        
        # Test token exchange
        try:
            tokens = github_provider.exchange_code_for_tokens(
                'test_auth_code',
                'http://localhost:5000/oauth/github/callback'
            )
            
            if 'access_token' in tokens and tokens['access_token'].startswith('github_'):
                print("✓ Token exchange working")
            else:
                print("✗ Token exchange failed")
                return False
        except Exception as e:
            print(f"✗ Token exchange error: {e}")
            return False
        
        # Test user info retrieval
        try:
            user_info = github_provider.get_user_info('github_test_token')
            
            if 'login' in user_info and 'email' in user_info:
                print("✓ User info retrieval working")
            else:
                print("✗ User info retrieval failed")
                return False
        except Exception as e:
            print(f"✗ User info retrieval error: {e}")
            return False
        
        # Step 5: Test provider info generation
        print("5. Testing provider info generation...")
        
        provider_info = manager.get_provider_info()
        github_info = None
        
        for info in provider_info:
            if info['name'] == 'github':
                github_info = info
                break
        
        if github_info:
            print("✓ GitHub provider info generated")
            print(f"  - Authorization URL: {github_info['authorization_url']}")
            print(f"  - Supports refresh: {github_info['supports_refresh']}")
            print(f"  - Icon URL: {github_info['metadata']['icon_url']}")
        else:
            print("✗ GitHub provider info not found")
            return False
        
        # Step 6: Test route generation
        print("6. Testing OAuth route generation...")
        
        from unittest.mock import MagicMock
        
        mock_app = MagicMock()
        mock_app.add_url_rule = MagicMock()
        mock_app.route = MagicMock(return_value=lambda f: f)
        
        manager.register_routes(mock_app)
        
        # Check if GitHub routes were registered
        call_args_list = mock_app.add_url_rule.call_args_list
        route_patterns = [call[0][0] for call in call_args_list]
        
        github_routes = [route for route in route_patterns if 'github' in route]
        
        if '/oauth/github/authorize' in route_patterns and '/oauth/github/callback' in route_patterns:
            print("✓ GitHub OAuth routes registered")
            print(f"  - Found {len(github_routes)} GitHub routes")
        else:
            print("✗ GitHub OAuth routes not registered")
            return False
        
        # Step 7: Test provider removal
        print("7. Testing provider removal...")
        
        removal_result = manager.unregister_provider('github')
        if removal_result:
            print("✓ GitHub provider removed successfully")
            
            # Verify removal
            github_provider_after = manager.get_provider('github')
            if github_provider_after is None:
                print("✓ Provider removal verified")
            else:
                print("✗ Provider still exists after removal")
                return False
        else:
            print("✗ Provider removal failed")
            return False
        
        print("\n✅ All provider extensibility tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Provider extensibility test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        print("\n🧹 Cleaning up test files...")
        
        # Remove GitHub provider file
        github_provider_path = Path('authentication_proxy/providers/github_provider.py')
        if github_provider_path.exists():
            github_provider_path.unlink()
            print("✓ GitHub provider file removed")
        
        # Restore original providers.json
        backup_path = Path('providers.json.backup')
        if backup_path.exists():
            backup_path.rename('providers.json')
            print("✓ Original providers.json restored")
        
        # Clean up environment variables
        for var in ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET']:
            if var in os.environ:
                del os.environ[var]
        
        print("✓ Cleanup completed")

if __name__ == '__main__':
    success = test_provider_extensibility()
    sys.exit(0 if success else 1)