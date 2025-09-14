"""
Microsoft OAuth 2.0 provider implementation.

This module implements the Microsoft OAuth provider using the BaseProvider interface,
handling Microsoft-specific OAuth flow requirements and Microsoft Graph API interactions.
"""

from typing import Dict, Any, Optional
import requests
from urllib.parse import urlencode
from authlib.common.errors import AuthlibBaseError
from requests.exceptions import RequestException, ConnectionError, Timeout

from .base_provider import BaseProvider, OAuthFlowError, ProviderConfigurationError


class MicrosoftProvider(BaseProvider):
    """
    Microsoft OAuth 2.0 provider implementation.
    
    This class handles Microsoft-specific OAuth flows, including authorization URL generation,
    token exchange, and optional user information retrieval through Microsoft Graph API.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Microsoft OAuth provider.
        
        Args:
            config: Microsoft provider configuration dictionary
            
        Raises:
            ProviderConfigurationError: If configuration is invalid
        """
        # Set default Microsoft OAuth URLs if not provided
        default_config = {
            'authorize_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'userinfo_url': 'https://graph.microsoft.com/v1.0/me',
            'display_name': 'Microsoft Account',
            'scopes': [
                'User.Read',
                'Mail.Read', 
                'Calendars.Read'
            ]
        }
        
        # Merge with provided config
        merged_config = {**default_config, **config}
        
        super().__init__('microsoft', merged_config)
        
        # Microsoft-specific configuration
        self.tenant = config.get('tenant', 'common')
        self.response_mode = config.get('response_mode', 'query')
        self.prompt = config.get('prompt', 'select_account')
        
        # Update URLs with tenant if specified
        if self.tenant != 'common':
            self.authorize_url = f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/authorize'
            self.token_url = f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token'
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        """
        Generate Microsoft OAuth authorization URL.
        
        Args:
            redirect_uri: Callback URL for OAuth flow
            state: CSRF protection state parameter
            **kwargs: Additional parameters (scope, prompt, response_mode, etc.)
            
        Returns:
            Authorization URL for redirecting user to Microsoft OAuth consent screen
            
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
                'response_mode': kwargs.get('response_mode', self.response_mode),
                'prompt': kwargs.get('prompt', self.prompt)
            }
            
            # Build authorization URL
            auth_url = f"{self.authorize_url}?{urlencode(params)}"
            
            self.logger.debug(f"Generated Microsoft authorization URL with scopes: {params['scope']}")
            return auth_url
            
        except Exception as e:
            self.logger.error(f"Failed to generate Microsoft authorization URL: {e}", exc_info=True)
            raise OAuthFlowError(f"Failed to generate authorization URL: {e}")
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        """
        Exchange authorization code for Microsoft OAuth tokens.
        
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
                'redirect_uri': redirect_uri,
                'scope': ' '.join(self.scopes)
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            self.logger.debug(f"Exchanging authorization code for Microsoft tokens")
            
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
                error_code = error_data.get('error', 'token_exchange_failed')
                self.logger.error(f"Microsoft token exchange failed: {response.status_code} - {error_msg}")
                raise OAuthFlowError(f"Token exchange failed: {error_msg}")
            
            # Parse token response
            token_response = response.json()
            
            # Validate token response
            if not self.validate_token_response(token_response):
                raise OAuthFlowError("Invalid token response from Microsoft")
            
            # Extract and normalize token data
            normalized_tokens = self.extract_token_data(token_response)
            
            self.logger.info(f"Successfully exchanged code for Microsoft tokens - expires_in: {normalized_tokens['expires_in']}")
            
            return normalized_tokens
            
        except RequestException as e:
            self.logger.error(f"Network error during Microsoft token exchange: {e}", exc_info=True)
            if isinstance(e, ConnectionError):
                raise OAuthFlowError("Network connection failed. Please check your internet connection.")
            elif isinstance(e, Timeout):
                raise OAuthFlowError("Request timed out. Please try again.")
            else:
                raise OAuthFlowError(f"Network request failed: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Microsoft token exchange: {e}", exc_info=True)
            raise OAuthFlowError(f"Token exchange failed: {e}")
    
    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh Microsoft access token using refresh token.
        
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
                'grant_type': 'refresh_token',
                'scope': ' '.join(self.scopes)
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            self.logger.debug("Refreshing Microsoft access token")
            
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
                self.logger.error(f"Microsoft token refresh failed: {response.status_code} - {error_msg}")
                raise OAuthFlowError(f"Token refresh failed: {error_msg}")
            
            # Parse refresh response
            refresh_response = response.json()
            
            # Validate refresh response
            if not refresh_response.get('access_token'):
                raise OAuthFlowError("Invalid refresh token response from Microsoft")
            
            # Extract and normalize refreshed token data
            refreshed_tokens = {
                'access_token': refresh_response.get('access_token', ''),
                'refresh_token': refresh_response.get('refresh_token', refresh_token),  # Microsoft may return new refresh token
                'expires_in': int(refresh_response.get('expires_in', 3600)),
                'scope': refresh_response.get('scope', ' '.join(self.scopes)),
                'token_type': refresh_response.get('token_type', 'Bearer')
            }
            
            self.logger.info(f"Successfully refreshed Microsoft access token - expires_in: {refreshed_tokens['expires_in']}")
            
            return refreshed_tokens
            
        except RequestException as e:
            self.logger.error(f"Network error during Microsoft token refresh: {e}", exc_info=True)
            raise OAuthFlowError(f"Token refresh network error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Microsoft token refresh: {e}", exc_info=True)
            raise OAuthFlowError(f"Token refresh failed: {e}")
    
    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve Microsoft user information using access token via Microsoft Graph API.
        
        Args:
            access_token: Valid Microsoft access token
            
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
            
            self.logger.debug("Retrieving Microsoft user information")
            
            # Make user info request to Microsoft Graph
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
                    error_msg = "Insufficient permissions to access user info"
                self.logger.error(f"Microsoft user info request failed: {error_msg}")
                raise OAuthFlowError(f"User info request failed: {error_msg}")
            
            # Parse user info response
            user_info = response.json()
            
            # Normalize user info to match Google format
            normalized_user_info = {
                'id': user_info.get('id'),
                'email': user_info.get('mail') or user_info.get('userPrincipalName'),
                'name': user_info.get('displayName'),
                'given_name': user_info.get('givenName'),
                'family_name': user_info.get('surname'),
                'picture': None,  # Microsoft Graph requires separate request for photo
                'locale': user_info.get('preferredLanguage'),
                'verified_email': True  # Microsoft accounts are verified by default
            }
            
            self.logger.info(f"Successfully retrieved Microsoft user info for user: {normalized_user_info.get('email', 'unknown')}")
            
            return normalized_user_info
            
        except RequestException as e:
            self.logger.error(f"Network error during Microsoft user info retrieval: {e}", exc_info=True)
            raise OAuthFlowError(f"User info retrieval network error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Microsoft user info retrieval: {e}", exc_info=True)
            raise OAuthFlowError(f"User info retrieval failed: {e}")
    
    def validate_scopes(self, requested_scopes: list) -> bool:
        """
        Validate Microsoft-specific scopes.
        
        Args:
            requested_scopes: List of OAuth scopes to validate
            
        Returns:
            True if all scopes are valid Microsoft Graph scopes, False otherwise
        """
        # Microsoft Graph-specific scope validation
        valid_microsoft_scopes = [
            'User.Read',
            'User.ReadWrite',
            'User.ReadBasic.All',
            'Mail.Read',
            'Mail.ReadWrite',
            'Mail.Send',
            'Calendars.Read',
            'Calendars.ReadWrite',
            'Contacts.Read',
            'Contacts.ReadWrite',
            'Files.Read',
            'Files.ReadWrite',
            'Sites.Read.All',
            'Directory.Read.All',
            'Group.Read.All',
            'openid',
            'profile',
            'email',
            'offline_access'
        ]
        
        for scope in requested_scopes:
            if scope not in valid_microsoft_scopes:
                self.logger.warning(f"Invalid Microsoft scope: {scope}")
                return False
        
        return True
    
    def get_user_photo(self, access_token: str) -> Optional[bytes]:
        """
        Retrieve Microsoft user profile photo.
        
        This is a Microsoft-specific method to get user profile photos
        through Microsoft Graph API.
        
        Args:
            access_token: Valid Microsoft access token
            
        Returns:
            User profile photo as bytes or None if not available
            
        Raises:
            OAuthFlowError: If photo retrieval fails
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'image/*'
            }
            
            photo_url = 'https://graph.microsoft.com/v1.0/me/photo/$value'
            
            self.logger.debug("Retrieving Microsoft user profile photo")
            
            # Make photo request
            response = requests.get(
                photo_url,
                headers=headers,
                timeout=30
            )
            
            # Check response status
            if response.status_code == 200:
                self.logger.info("Successfully retrieved Microsoft user profile photo")
                return response.content
            elif response.status_code == 404:
                self.logger.info("No profile photo available for Microsoft user")
                return None
            else:
                self.logger.warning(f"Failed to retrieve Microsoft user photo: HTTP {response.status_code}")
                return None
                
        except RequestException as e:
            self.logger.warning(f"Network error during Microsoft photo retrieval: {e}")
            return None
        except Exception as e:
            self.logger.warning(f"Unexpected error during Microsoft photo retrieval: {e}")
            return None
    
    def _get_provider_metadata(self) -> Dict[str, Any]:
        """
        Get Microsoft-specific provider metadata.
        
        Returns:
            Microsoft provider metadata dictionary
        """
        return {
            'icon_url': 'https://docs.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png',
            'documentation_url': 'https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow',
            'website_url': 'https://login.microsoftonline.com',
            'rate_limits': {
                'requests_per_second': 10,
                'requests_per_minute': 600,
                'description': 'Microsoft Graph API rate limits'
            },
            'supported_data_types': [
                'profile',
                'email',
                'mail',
                'calendar',
                'contacts',
                'files',
                'sites',
                'groups'
            ],
            'token_lifetime': {
                'access_token': '1 hour',
                'refresh_token': '90 days (rolling)'
            },
            'security_features': [
                'pkce_support',
                'state_parameter',
                'https_required',
                'token_revocation',
                'conditional_access'
            ],
            'graph_api_version': 'v1.0',
            'tenant_support': 'multi_tenant'
        }