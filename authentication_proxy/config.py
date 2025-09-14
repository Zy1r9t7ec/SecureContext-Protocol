"""
Configuration module for the SecureContext Protocol Authentication Proxy.

This module handles environment variable loading, OAuth client configuration,
Flask application settings, and dynamic provider configuration loading with
proper validation and environment variable reference support.
"""

import os
import sys
import json
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


class Config:
    """Configuration class for the Authentication Proxy application."""
    
    def __init__(self, providers_config_path: str = "providers.json"):
        """
        Initialize configuration by loading environment variables and provider configurations.
        
        Args:
            providers_config_path: Path to the providers configuration file
        """
        # Load environment variables from .env file
        load_dotenv()
        
        # Store configuration paths
        self.providers_config_path = providers_config_path
        
        # Load all configuration
        self._load_flask_config()
        self._load_provider_configurations()
        self._validate_required_env_vars()
    
    def _validate_required_env_vars(self) -> None:
        """Validate that all required environment variables are present for enabled providers."""
        # Always require Flask secret key
        required_vars = ['FLASK_SECRET_KEY']
        
        # Add provider-specific environment variables for enabled providers
        for provider_name, provider_config in self.PROVIDER_CONFIGS.items():
            if provider_config.get('enabled', True):
                # Extract environment variable names from provider config
                client_id_ref = provider_config.get('client_id', '')
                client_secret_ref = provider_config.get('client_secret', '')
                
                if client_id_ref.startswith('env:'):
                    required_vars.append(client_id_ref[4:])  # Remove 'env:' prefix
                if client_secret_ref.startswith('env:'):
                    required_vars.append(client_secret_ref[4:])  # Remove 'env:' prefix
        
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
        
        # Enterprise integration configuration
        self.ENTERPRISE_CONFIG = {
            'BASE_URL': os.getenv('SCP_BASE_URL', f"http://{self.FLASK_CONFIG['HOST']}:{self.FLASK_CONFIG['PORT']}"),
            'CALLBACK_URL_OVERRIDE': os.getenv('SCP_CALLBACK_URL_OVERRIDE'),
            'WEBHOOK_URL': os.getenv('SCP_WEBHOOK_URL'),
            'WEBHOOK_SECRET': os.getenv('SCP_WEBHOOK_SECRET'),
            'WEBHOOK_EVENTS': os.getenv('SCP_WEBHOOK_EVENTS', 'token_created,token_retrieved,token_expired').split(','),
            'ENVIRONMENT': os.getenv('SCP_ENVIRONMENT', 'development'),
            'ENABLE_WEBHOOKS': os.getenv('SCP_ENABLE_WEBHOOKS', 'False').lower() == 'true',
            'WEBHOOK_TIMEOUT': int(os.getenv('SCP_WEBHOOK_TIMEOUT', '30')),
            'WEBHOOK_RETRY_COUNT': int(os.getenv('SCP_WEBHOOK_RETRY_COUNT', '3')),
            'WEBHOOK_RETRY_DELAY': int(os.getenv('SCP_WEBHOOK_RETRY_DELAY', '5'))
        }
    
    def _load_provider_configurations(self) -> None:
        """Load provider configurations from JSON file with environment variable resolution."""
        try:
            with open(self.providers_config_path, 'r') as f:
                config_data = json.load(f)
            
            # Store raw provider configurations
            self.PROVIDER_CONFIGS = config_data.get('providers', {})
            self.PROVIDER_SETTINGS = config_data.get('settings', {})
            
            # Process provider configurations and resolve environment variables
            self.OAUTH_CONFIG = {}
            for provider_name, provider_config in self.PROVIDER_CONFIGS.items():
                processed_config = self._process_provider_config(provider_config.copy())
                self.OAUTH_CONFIG[provider_name] = processed_config
                
        except FileNotFoundError:
            raise ConfigurationError(f"Provider configuration file not found: {self.providers_config_path}")
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in provider configuration file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading provider configurations: {e}")
    
    def _process_provider_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process provider configuration by resolving environment variable references.
        
        Args:
            config: Raw provider configuration dictionary
            
        Returns:
            Processed configuration with environment variables resolved
        """
        processed_config = {}
        
        for key, value in config.items():
            if isinstance(value, str) and value.startswith('env:'):
                # Resolve environment variable reference
                env_var_name = value[4:]  # Remove 'env:' prefix
                env_value = os.getenv(env_var_name)
                if env_value is None and config.get('enabled', True):
                    # Only raise error for enabled providers
                    raise ConfigurationError(f"Environment variable {env_var_name} not found for provider {config.get('name', 'unknown')}")
                processed_config[key] = env_value
            else:
                processed_config[key] = value
        
        return processed_config
    
    def get_oauth_config(self, provider: str) -> Optional[Dict[str, Any]]:
        """
        Get OAuth configuration for a specific provider.
        
        Args:
            provider: The OAuth provider name
            
        Returns:
            OAuth configuration dictionary or None if provider not found
            
        Raises:
            ConfigurationError: If provider is not supported or disabled
        """
        if provider not in self.OAUTH_CONFIG:
            raise ConfigurationError(f"Unsupported OAuth provider: {provider}")
        
        # Check if provider is enabled
        if not self.is_provider_enabled(provider):
            raise ConfigurationError(f"OAuth provider is disabled: {provider}")
        
        return self.OAUTH_CONFIG[provider]
    
    def get_flask_config(self) -> Dict[str, Any]:
        """
        Get Flask application configuration.
        
        Returns:
            Flask configuration dictionary
        """
        return self.FLASK_CONFIG.copy()
    
    def get_enterprise_config(self) -> Dict[str, Any]:
        """
        Get enterprise integration configuration.
        
        Returns:
            Enterprise configuration dictionary
        """
        return self.ENTERPRISE_CONFIG.copy()
    
    def get_callback_url(self, provider: str) -> str:
        """
        Get the OAuth callback URL for a provider, supporting environment-specific overrides.
        
        Args:
            provider: Provider name
            
        Returns:
            Complete callback URL for the provider
        """
        if self.ENTERPRISE_CONFIG['CALLBACK_URL_OVERRIDE']:
            base_url = self.ENTERPRISE_CONFIG['CALLBACK_URL_OVERRIDE'].rstrip('/')
        else:
            base_url = self.ENTERPRISE_CONFIG['BASE_URL'].rstrip('/')
        
        return f"{base_url}/oauth/{provider}/callback"
    
    def is_webhook_enabled(self) -> bool:
        """
        Check if webhook notifications are enabled.
        
        Returns:
            True if webhooks are enabled, False otherwise
        """
        return self.ENTERPRISE_CONFIG['ENABLE_WEBHOOKS'] and bool(self.ENTERPRISE_CONFIG['WEBHOOK_URL'])
    
    def validate_oauth_credentials(self, provider: str) -> bool:
        """
        Validate that OAuth credentials are properly configured for a provider.
        
        Args:
            provider: The OAuth provider name
            
        Returns:
            True if credentials are valid, False otherwise
        """
        try:
            config = self.get_oauth_config(provider)
            return bool(config['client_id'] and config['client_secret'])
        except ConfigurationError:
            return False
    
    def get_enabled_providers(self) -> List[str]:
        """
        Get list of enabled provider names.
        
        Returns:
            List of enabled provider names
        """
        return [
            provider_name for provider_name, config in self.PROVIDER_CONFIGS.items()
            if config.get('enabled', True)
        ]
    
    def is_provider_enabled(self, provider: str) -> bool:
        """
        Check if a provider is enabled.
        
        Args:
            provider: Provider name
            
        Returns:
            True if provider is enabled, False otherwise
        """
        if provider not in self.PROVIDER_CONFIGS:
            return False
        return self.PROVIDER_CONFIGS[provider].get('enabled', True)
    
    def enable_provider(self, provider: str) -> bool:
        """
        Enable a provider.
        
        Args:
            provider: Provider name
            
        Returns:
            True if provider was enabled, False if provider not found
        """
        if provider in self.PROVIDER_CONFIGS:
            self.PROVIDER_CONFIGS[provider]['enabled'] = True
            # Reprocess the configuration
            processed_config = self._process_provider_config(self.PROVIDER_CONFIGS[provider].copy())
            self.OAUTH_CONFIG[provider] = processed_config
            return True
        return False
    
    def disable_provider(self, provider: str) -> bool:
        """
        Disable a provider.
        
        Args:
            provider: Provider name
            
        Returns:
            True if provider was disabled, False if provider not found
        """
        if provider in self.PROVIDER_CONFIGS:
            self.PROVIDER_CONFIGS[provider]['enabled'] = False
            return True
        return False
    
    def get_provider_settings(self) -> Dict[str, Any]:
        """
        Get global provider settings.
        
        Returns:
            Provider settings dictionary
        """
        return self.PROVIDER_SETTINGS.copy()
    
    def get_all_provider_configs(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all provider configurations (raw, before environment variable resolution).
        
        Returns:
            Dictionary of provider configurations
        """
        return self.PROVIDER_CONFIGS.copy()
    
    def reload_provider_configurations(self) -> None:
        """
        Reload provider configurations from file.
        
        Raises:
            ConfigurationError: If configuration loading fails
        """
        self._load_provider_configurations()
        self._validate_required_env_vars()
    
    def save_provider_configurations(self) -> None:
        """
        Save current provider configurations to file.
        
        Raises:
            ConfigurationError: If saving fails
        """
        try:
            config_data = {
                'providers': self.PROVIDER_CONFIGS,
                'settings': self.PROVIDER_SETTINGS
            }
            
            with open(self.providers_config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
                
        except Exception as e:
            raise ConfigurationError(f"Error saving provider configurations: {e}")


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