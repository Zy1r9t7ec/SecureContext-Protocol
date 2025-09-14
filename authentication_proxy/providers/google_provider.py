"""
Google OAuth 2.0 provider implementation.

This module implements the Google OAuth provider using the BaseProvider interface,
handling Google-specific OAuth flow requirements and API interactions.
"""

from typing import Dict, Any, Optional
import requests
from urllib.parse import urlencode
from authlib.common.errors import AuthlibBaseError
from requests.exceptions import RequestException, ConnectionError, Timeout

from .base_provider import BaseProvider, OAuthFlowError, ProviderConfigurationError


class GoogleProvider(BaseProvider):
    """
    Google OAuth 2.0 provider implementation.
    
    This class handles Google-specific OAuth flows, including authorization URL generation,
    token exchange, and optional user information retrieval.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Google OAuth provider.
        
        Args:
            config: Google provider configuration dictionary
            
        Raises:
            ProviderConfigurationError: If configuration is invalid
        """
        # Set default Google OAuth URLs if not provided
        default_config = {
            'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
            'token_url': 'https://oauth2.googleapis.com/token',
            'userinfo_url': 'https://www.googleapis.com/oauth2/v2/userinfo',
            'display_name': 'Google Account',
            'scopes': [
                'profile',
                'email', 
                'https://www.googleapis.com/auth/gmail.readonly',
                'https://www.googleapis.com/auth/calendar.readonly'
            ]
        }
        
        # Merge with provided config
        merged_config = {**default_config, **config}
        
        super().__init__('google', merged_config)
        
        # Google-specific configuration
        self.access_type = config.get('access_type', 'offline')
        self.prompt = config.get('prompt', 'consent')
        self.include_granted_scopes = config.get('include_granted_scopes', True)
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        """
        Generate Google OAuth authorization URL.
        
        Args:
            redirect_uri: Callback URL for OAuth flow
            state: CSRF protection state parameter
            **kwargs: Additional parameters (scope, access_type, prompt, etc.)
            
        Returns:
            Authorization URL for redirecting user to Google OAuth consent screen
            
        Raises:
            OAuthFlowError: If URL generation fails
        """
        try:
            # Prepare authorization parameters
            params = {
                'client_id': self.client_id,
                'redirect_uri': redirect_uri,
                'scope': kwargs.get('scope', ' '.join(self.scopes)),
                'response_type': 'code',
                'state': state,
                'access_type': kwargs.get('access_type', self.access_type),
                'prompt': kwargs.get('prompt', self.prompt)
            }
            
            # Add include_granted_scopes if enabled
            if kwargs.get('include_granted_scopes', self.include_granted_scopes):
                params['include_granted_scopes'] = 'true'
            
            # Build authorization URL
            auth_url = f"{self.authorize_url}?{urlencode(params)}"
            
            self.logger.debug(f"Generated Google authorization URL with scopes: {params['scope']}")
            return auth_url
            
        except Exception as e:
            self.logger.error(f"Failed to generate Google authorization URL: {e}", exc_info=True)
            raise OAuthFlowError(f"Failed to generate authorization URL: {e}")
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        """
        Exchange authorization code for Google OAuth tokens.
        
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
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            self.logger.debug(f"Exchanging authorization code for Google tokens")
            
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
                self.logger.error(f"Google token exchange failed: {response.status_code} - {error_msg}")
                raise OAuthFlowError(f"Token exchange failed: {error_msg}")
            
            # Parse token response
            token_response = response.json()
            
            # Validate token response
            if not self.validate_token_response(token_response):
                raise OAuthFlowError("Invalid token response from Google")
            
            # Extract and normalize token data
            normalized_tokens = self.extract_token_data(token_response)
            
            self.logger.info(f"Successfully exchanged code for Google tokens - expires_in: {normalized_tokens['expires_in']}")
            
            return normalized_tokens
            
        except RequestException as e:
            self.logger.error(f"Network error during Google token exchange: {e}", exc_info=True)
            if isinstance(e, ConnectionError):
                raise OAuthFlowError("Network connection failed. Please check your internet connection.")
            elif isinstance(e, Timeout):
                raise OAuthFlowError("Request timed out. Please try again.")
            else:
                raise OAuthFlowError(f"Network request failed: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Google token exchange: {e}", exc_info=True)
            raise OAuthFlowError(f"Token exchange failed: {e}")
    
    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh Google access token using refresh token.
        
        Args:
            refresh_token: Refresh token from previous OAuth flow
            
        Returns:
            New token data dictionary
            
        Raises:
            OAuthFlowError: If token refresh fails
        """
        try:
            # Prepare refresh token request
            refresh_data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            self.logger.debug("Refreshing Google access token")
            
            # Make refresh token request
            response = requests.post(
                self.token_url,
                data=refresh_data,
                headers=headers,
                timeout=30
            )
            
            # Check response status
            if response.status_code != 200:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                error_msg = error_data.get('error_description', f'HTTP {response.status_code}')
                self.logger.error(f"Google token refresh failed: {response.status_code} - {error_msg}")
                raise OAuthFlowError(f"Token refresh failed: {error_msg}")
            
            # Parse refresh response
            refresh_response = response.json()
            
            # Validate refresh response
            if not refresh_response.get('access_token'):
                raise OAuthFlowError("Invalid refresh token response from Google")
            
            # Extract and normalize refreshed token data
            refreshed_tokens = {
                'access_token': refresh_response.get('access_token', ''),
                'refresh_token': refresh_token,  # Keep original refresh token
                'expires_in': int(refresh_response.get('expires_in', 3600)),
                'scope': refresh_response.get('scope', ' '.join(self.scopes)),
                'token_type': refresh_response.get('token_type', 'Bearer')
            }
            
            self.logger.info(f"Successfully refreshed Google access token - expires_in: {refreshed_tokens['expires_in']}")
            
            return refreshed_tokens
            
        except RequestException as e:
            self.logger.error(f"Network error during Google token refresh: {e}", exc_info=True)
            raise OAuthFlowError(f"Token refresh network error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Google token refresh: {e}", exc_info=True)
            raise OAuthFlowError(f"Token refresh failed: {e}")
    
    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve Google user information using access token.
        
        Args:
            access_token: Valid Google access token
            
        Returns:
            User information dictionary
            
        Raises:
            OAuthFlowError: If user info retrieval fails
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            self.logger.debug("Retrieving Google user information")
            
            # Make user info request
            response = requests.get(
                self.userinfo_url,
                headers=headers,
                timeout=30
            )
            
            # Check response status
            if response.status_code != 200:
                error_msg = f'HTTP {response.status_code}'
                self.logger.error(f"Google user info request failed: {error_msg}")
                raise OAuthFlowError(f"User info request failed: {error_msg}")
            
            # Parse user info response
            user_info = response.json()
            
            # Normalize user info
            normalized_user_info = {
                'id': user_info.get('id'),
                'email': user_info.get('email'),
                'name': user_info.get('name'),
                'given_name': user_info.get('given_name'),
                'family_name': user_info.get('family_name'),
                'picture': user_info.get('picture'),
                'locale': user_info.get('locale'),
                'verified_email': user_info.get('verified_email', False)
            }
            
            self.logger.info(f"Successfully retrieved Google user info for user: {normalized_user_info.get('email', 'unknown')}")
            
            return normalized_user_info
            
        except RequestException as e:
            self.logger.error(f"Network error during Google user info retrieval: {e}", exc_info=True)
            raise OAuthFlowError(f"User info retrieval network error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Google user info retrieval: {e}", exc_info=True)
            raise OAuthFlowError(f"User info retrieval failed: {e}")
    
    def validate_scopes(self, requested_scopes: list) -> bool:
        """
        Validate Google-specific scopes.
        
        Args:
            requested_scopes: List of OAuth scopes to validate
            
        Returns:
            True if all scopes are valid Google scopes, False otherwise
        """
        # Google-specific scope validation
        valid_google_scopes = [
            'profile',
            'email',
            'openid',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/calendar.readonly',
            'https://www.googleapis.com/auth/calendar.events',
            'https://www.googleapis.com/auth/drive.readonly',
            'https://www.googleapis.com/auth/drive.file',
            'https://www.googleapis.com/auth/contacts.readonly',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
        
        for scope in requested_scopes:
            if scope not in valid_google_scopes:
                self.logger.warning(f"Invalid Google scope: {scope}")
                return False
        
        return True
    
    def _get_provider_metadata(self) -> Dict[str, Any]:
        """
        Get Google-specific provider metadata.
        
        Returns:
            Google provider metadata dictionary
        """
        return {
            'icon_url': 'https://developers.google.com/identity/images/g-logo.png',
            'documentation_url': 'https://developers.google.com/identity/protocols/oauth2',
            'website_url': 'https://accounts.google.com',
            'rate_limits': {
                'requests_per_day': 1000000,
                'requests_per_100_seconds': 100,
                'description': 'Google OAuth API rate limits'
            },
            'supported_data_types': [
                'profile',
                'email',
                'gmail',
                'calendar',
                'drive',
                'contacts'
            ],
            'token_lifetime': {
                'access_token': '1 hour',
                'refresh_token': 'indefinite (until revoked)'
            },
            'security_features': [
                'pkce_support',
                'state_parameter',
                'https_required',
                'token_revocation'
            ]
        }