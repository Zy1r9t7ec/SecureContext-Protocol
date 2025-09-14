"""
Base provider interface for OAuth 2.0 providers.

This module defines the abstract base class that all OAuth providers must implement,
providing a standardized interface for OAuth flow handling, token management,
and provider configuration validation.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
import logging
import secrets
import uuid
from urllib.parse import urlencode, urlparse, parse_qs
from authlib.common.errors import AuthlibBaseError
from requests.exceptions import RequestException


class ProviderConfigurationError(Exception):
    """Raised when provider configuration is invalid."""
    pass


class OAuthFlowError(Exception):
    """Raised when OAuth flow encounters an error."""
    pass


class BaseProvider(ABC):
    """
    Abstract base class for OAuth 2.0 providers.
    
    This class defines the standard interface that all OAuth providers must implement
    to integrate with the SecureContext Protocol Authentication Proxy. It provides
    common utilities for OAuth flow handling and validation.
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Initialize the OAuth provider.
        
        Args:
            name: Provider name (e.g., 'google', 'microsoft')
            config: Provider configuration dictionary
            
        Raises:
            ProviderConfigurationError: If configuration is invalid
        """
        self.name = name
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{name}")
        
        # Validate configuration
        self._validate_config()
        
        # Extract common configuration values
        self.client_id = config['client_id']
        self.client_secret = config['client_secret']
        self.scopes = config.get('scopes', [])
        self.authorize_url = config.get('authorize_url')
        self.token_url = config.get('token_url')
        self.userinfo_url = config.get('userinfo_url')
        self.display_name = config.get('display_name', name.title())
        
        self.logger.info(f"Initialized {self.display_name} OAuth provider")
    
    def _validate_config(self) -> None:
        """
        Validate provider configuration.
        
        Raises:
            ProviderConfigurationError: If required configuration is missing or invalid
        """
        required_fields = ['client_id', 'client_secret']
        missing_fields = []
        
        for field in required_fields:
            if not self.config.get(field):
                missing_fields.append(field)
        
        if missing_fields:
            raise ProviderConfigurationError(
                f"Missing required configuration for {self.name} provider: {', '.join(missing_fields)}"
            )
        
        # Validate client_id and client_secret are strings
        if not isinstance(self.config['client_id'], str):
            raise ProviderConfigurationError(f"client_id must be a string for {self.name} provider")
        
        if not isinstance(self.config['client_secret'], str):
            raise ProviderConfigurationError(f"client_secret must be a string for {self.name} provider")
        
        # Validate scopes if provided
        scopes = self.config.get('scopes')
        if scopes is not None and not isinstance(scopes, list):
            raise ProviderConfigurationError(f"scopes must be a list for {self.name} provider")
        
        # Validate URLs if provided
        url_fields = ['authorize_url', 'token_url', 'userinfo_url']
        for field in url_fields:
            url = self.config.get(field)
            if url and not self._is_valid_url(url):
                raise ProviderConfigurationError(f"Invalid {field} for {self.name} provider: {url}")
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def generate_state(self) -> str:
        """
        Generate a secure state parameter for CSRF protection.
        
        Returns:
            Cryptographically secure state parameter
        """
        return secrets.token_urlsafe(32)
    
    def validate_state(self, received_state: str, stored_state: str) -> bool:
        """
        Validate OAuth state parameter to prevent CSRF attacks.
        
        Args:
            received_state: State parameter received from OAuth callback
            stored_state: State parameter stored in session
            
        Returns:
            True if state is valid, False otherwise
        """
        if not received_state or not stored_state:
            self.logger.error(f"Missing state parameter - received: {bool(received_state)}, stored: {bool(stored_state)}")
            return False
        
        if received_state != stored_state:
            self.logger.error(f"State mismatch - received: {received_state[:10]}..., expected: {stored_state[:10]}...")
            return False
        
        return True
    
    def parse_oauth_error(self, error: str, error_description: str = None) -> Tuple[str, str]:
        """
        Parse and standardize OAuth error responses.
        
        Args:
            error: OAuth error code
            error_description: Optional error description
            
        Returns:
            Tuple of (error_code, user_friendly_message)
        """
        error_messages = {
            'access_denied': 'You cancelled the authorization. Please try again if you want to connect your account.',
            'invalid_request': 'Invalid authorization request. Please try again.',
            'unauthorized_client': 'Application not authorized. Please contact support.',
            'unsupported_response_type': 'Configuration error. Please contact support.',
            'invalid_scope': 'Invalid permissions requested. Please contact support.',
            'server_error': f'{self.display_name} server error. Please try again later.',
            'temporarily_unavailable': f'{self.display_name} service is temporarily unavailable. Please try again later.'
        }
        
        user_message = error_messages.get(error, error_description or 'OAuth authorization failed')
        
        self.logger.warning(f"OAuth error for {self.name}: {error} - {error_description}")
        
        return error, user_message
    
    def validate_token_response(self, token_data: Dict[str, Any]) -> bool:
        """
        Validate OAuth token response.
        
        Args:
            token_data: Token response from OAuth provider
            
        Returns:
            True if token response is valid, False otherwise
        """
        if not token_data:
            self.logger.error(f"Empty token response from {self.name}")
            return False
        
        if not token_data.get('access_token'):
            self.logger.error(f"Missing access_token in response from {self.name}")
            return False
        
        # Validate expires_in if present
        expires_in = token_data.get('expires_in')
        if expires_in is not None:
            try:
                expires_in = int(expires_in)
                if expires_in <= 0:
                    self.logger.warning(f"Invalid expires_in value from {self.name}: {expires_in}")
                    return False
            except (ValueError, TypeError):
                self.logger.warning(f"Non-numeric expires_in value from {self.name}: {expires_in}")
                return False
        
        return True
    
    def extract_token_data(self, token_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and normalize token data from OAuth response.
        
        Args:
            token_response: Raw token response from OAuth provider
            
        Returns:
            Normalized token data dictionary
        """
        return {
            'access_token': token_response.get('access_token', ''),
            'refresh_token': token_response.get('refresh_token', ''),
            'expires_in': int(token_response.get('expires_in', 3600)),
            'scope': token_response.get('scope', ' '.join(self.scopes)),
            'token_type': token_response.get('token_type', 'Bearer')
        }
    
    @abstractmethod
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        """
        Generate OAuth authorization URL.
        
        Args:
            redirect_uri: Callback URL for OAuth flow
            state: CSRF protection state parameter
            **kwargs: Additional provider-specific parameters
            
        Returns:
            Authorization URL for redirecting user to OAuth consent screen
            
        Raises:
            OAuthFlowError: If URL generation fails
        """
        pass
    
    @abstractmethod
    def exchange_code_for_tokens(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        """
        Exchange authorization code for access and refresh tokens.
        
        Args:
            code: Authorization code from OAuth callback
            redirect_uri: Callback URL used in authorization request
            **kwargs: Additional provider-specific parameters
            
        Returns:
            Token data dictionary with access_token, refresh_token, expires_in, scope
            
        Raises:
            OAuthFlowError: If token exchange fails
        """
        pass
    
    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh access token using refresh token.
        
        This is an optional method that providers can implement if they support
        token refresh functionality.
        
        Args:
            refresh_token: Refresh token from previous OAuth flow
            
        Returns:
            New token data dictionary or None if not supported
            
        Raises:
            OAuthFlowError: If token refresh fails
        """
        self.logger.info(f"Token refresh not implemented for {self.name} provider")
        return None
    
    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user information using access token.
        
        This is an optional method that providers can implement to fetch
        user profile information.
        
        Args:
            access_token: Valid access token
            
        Returns:
            User information dictionary or None if not supported
            
        Raises:
            OAuthFlowError: If user info retrieval fails
        """
        self.logger.info(f"User info retrieval not implemented for {self.name} provider")
        return None
    
    def validate_scopes(self, requested_scopes: List[str]) -> bool:
        """
        Validate that requested scopes are supported by this provider.
        
        Args:
            requested_scopes: List of OAuth scopes to validate
            
        Returns:
            True if all scopes are supported, False otherwise
        """
        if not self.scopes:
            # If no scopes configured, assume all are valid
            return True
        
        for scope in requested_scopes:
            if scope not in self.scopes:
                self.logger.warning(f"Unsupported scope '{scope}' for {self.name} provider")
                return False
        
        return True
    
    def get_provider_info(self) -> Dict[str, Any]:
        """
        Get provider information for API responses and UI display.
        
        Returns:
            Provider information dictionary with comprehensive metadata
        """
        # Get provider-specific metadata
        provider_metadata = self._get_provider_metadata()
        
        base_info = {
            'name': self.name,
            'display_name': self.display_name,
            'type': 'oauth2',
            'status': 'active',
            'scopes': self.scopes,
            'authorization_url': f'/oauth/{self.name}/authorize',
            'callback_url': f'/oauth/{self.name}/callback',
            'supports_refresh': hasattr(self, 'refresh_access_token') and callable(getattr(self, 'refresh_access_token')),
            'supports_user_info': hasattr(self, 'get_user_info') and callable(getattr(self, 'get_user_info')),
            'oauth_version': '2.0',
            'metadata': {
                'icon_url': provider_metadata.get('icon_url'),
                'documentation_url': provider_metadata.get('documentation_url'),
                'website_url': provider_metadata.get('website_url'),
                'supported_features': self._get_supported_features(),
                'rate_limits': provider_metadata.get('rate_limits', {}),
                'token_endpoint': self.token_url,
                'authorization_endpoint': self.authorize_url,
                'userinfo_endpoint': self.userinfo_url
            }
        }
        
        # Add provider-specific metadata
        base_info['metadata'].update(provider_metadata)
        
        return base_info
    
    def _get_provider_metadata(self) -> Dict[str, Any]:
        """
        Get provider-specific metadata. Override in subclasses for custom metadata.
        
        Returns:
            Provider-specific metadata dictionary
        """
        return {
            'icon_url': None,
            'documentation_url': None,
            'website_url': None,
            'rate_limits': {}
        }
    
    def _get_supported_features(self) -> List[str]:
        """
        Get list of supported features for this provider.
        
        Returns:
            List of supported feature names
        """
        features = ['oauth2_authorization_code']
        
        if hasattr(self, 'refresh_access_token') and callable(getattr(self, 'refresh_access_token')):
            features.append('token_refresh')
        
        if hasattr(self, 'get_user_info') and callable(getattr(self, 'get_user_info')):
            features.append('user_info')
        
        if hasattr(self, 'revoke_token') and callable(getattr(self, 'revoke_token')):
            features.append('token_revocation')
        
        return features
    
    def __str__(self) -> str:
        """String representation of the provider."""
        return f"{self.__class__.__name__}(name='{self.name}', display_name='{self.display_name}')"
    
    def __repr__(self) -> str:
        """Detailed string representation of the provider."""
        return (f"{self.__class__.__name__}(name='{self.name}', "
                f"display_name='{self.display_name}', scopes={self.scopes})")