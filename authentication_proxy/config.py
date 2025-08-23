"""
Configuration module for the SecureContext Protocol Authentication Proxy.

This module handles environment variable loading, OAuth client configuration,
and Flask application settings with proper validation.
"""

import os
import sys
from typing import Dict, Any, Optional
from dotenv import load_dotenv


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


class Config:
    """Configuration class for the Authentication Proxy application."""
    
    def __init__(self):
        """Initialize configuration by loading environment variables."""
        # Load environment variables from .env file
        load_dotenv()
        
        # Validate and load all required configuration
        self._validate_required_env_vars()
        self._load_flask_config()
        self._load_oauth_config()
    
    def _validate_required_env_vars(self) -> None:
        """Validate that all required environment variables are present."""
        required_vars = [
            'GOOGLE_CLIENT_ID',
            'GOOGLE_CLIENT_SECRET', 
            'MICROSOFT_CLIENT_ID',
            'MICROSOFT_CLIENT_SECRET',
            'FLASK_SECRET_KEY'
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            error_msg = (
                f"Missing required environment variables: {', '.join(missing_vars)}\n"
                f"Please ensure these variables are set in your .env file or environment.\n"
                f"See .env.example for the required format."
            )
            raise ConfigurationError(error_msg)
    
    def _load_flask_config(self) -> None:
        """Load Flask application configuration settings."""
        self.FLASK_CONFIG = {
            'SECRET_KEY': os.getenv('FLASK_SECRET_KEY'),
            'DEBUG': os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
            'HOST': os.getenv('FLASK_HOST', '127.0.0.1'),
            'PORT': int(os.getenv('FLASK_PORT', '5000')),
            'SESSION_COOKIE_SECURE': os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true',
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Lax'
        }
    
    def _load_oauth_config(self) -> None:
        """Load OAuth client configuration for Google and Microsoft providers."""
        self.OAUTH_CONFIG = {
            'google': {
                'client_id': os.getenv('GOOGLE_CLIENT_ID'),
                'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
                'scopes': ['profile', 'email', 'https://www.googleapis.com/auth/gmail.readonly', 
                          'https://www.googleapis.com/auth/calendar.readonly'],
                'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
                'token_url': 'https://oauth2.googleapis.com/token',
                'userinfo_url': 'https://www.googleapis.com/oauth2/v2/userinfo'
            },
            'microsoft': {
                'client_id': os.getenv('MICROSOFT_CLIENT_ID'),
                'client_secret': os.getenv('MICROSOFT_CLIENT_SECRET'),
                'scopes': ['User.Read', 'Mail.Read', 'Calendars.Read'],
                'authorize_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                'userinfo_url': 'https://graph.microsoft.com/v1.0/me'
            }
        }
    
    def get_oauth_config(self, provider: str) -> Optional[Dict[str, Any]]:
        """
        Get OAuth configuration for a specific provider.
        
        Args:
            provider: The OAuth provider name ('google' or 'microsoft')
            
        Returns:
            OAuth configuration dictionary or None if provider not found
            
        Raises:
            ConfigurationError: If provider is not supported
        """
        if provider not in self.OAUTH_CONFIG:
            raise ConfigurationError(f"Unsupported OAuth provider: {provider}")
        
        return self.OAUTH_CONFIG[provider]
    
    def get_flask_config(self) -> Dict[str, Any]:
        """
        Get Flask application configuration.
        
        Returns:
            Flask configuration dictionary
        """
        return self.FLASK_CONFIG.copy()
    
    def validate_oauth_credentials(self, provider: str) -> bool:
        """
        Validate that OAuth credentials are properly configured for a provider.
        
        Args:
            provider: The OAuth provider name ('google' or 'microsoft')
            
        Returns:
            True if credentials are valid, False otherwise
        """
        try:
            config = self.get_oauth_config(provider)
            return bool(config['client_id'] and config['client_secret'])
        except ConfigurationError:
            return False


# Global configuration instance
try:
    config = Config()
except ConfigurationError as e:
    print(f"Configuration Error: {e}", file=sys.stderr)
    sys.exit(1)


def get_config() -> Config:
    """
    Get the global configuration instance.
    
    Returns:
        The global Config instance
    """
    return config