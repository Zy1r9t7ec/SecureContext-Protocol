"""
OAuth provider system for the SecureContext Protocol Authentication Proxy.

This package provides a pluggable architecture for OAuth 2.0 providers,
allowing easy integration of new authentication endpoints through a
standardized interface.
"""

from .base_provider import BaseProvider, ProviderConfigurationError, OAuthFlowError
from .provider_manager import ProviderManager, ProviderManagerError
from .google_provider import GoogleProvider
from .microsoft_provider import MicrosoftProvider

__all__ = [
    'BaseProvider', 
    'ProviderManager', 
    'GoogleProvider', 
    'MicrosoftProvider',
    'ProviderConfigurationError', 
    'OAuthFlowError', 
    'ProviderManagerError'
]