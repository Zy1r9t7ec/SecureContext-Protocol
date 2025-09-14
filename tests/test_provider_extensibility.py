"""
Unit tests for provider extensibility and provider manager functionality.

This module tests the provider manager's ability to dynamically register providers,
validate configurations, and handle extensibility features including mock providers
for testing the plugin architecture.
"""

import unittest
import json
import uuid
import tempfile
import os
from unittest.mock import patch, MagicMock, Mock
import sys

# Add the authentication_proxy directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'authentication_proxy'))

from providers.provider_manager import ProviderManager, ProviderManagerError
from providers.base_provider import BaseProvider, ProviderConfigurationError, OAuthFlowError
from config import Config


class MockProvider(BaseProvider):
    """
    Mock OAuth provider for testing extensibility.
    
    This provider implements the BaseProvider interface for testing
    dynamic provider registration and extensibility features.
    """
    
    def __init__(self, config):
        """Initialize mock provider with test configuration."""
        # Set name before calling parent constructor
        name = config.get('name', 'mock')
        super().__init__(name, config)
        
        # Mock provider specific attributes
        self.authorize_url = config.get('authorize_url', 'https://mock.example.com/oauth/authorize')
        self.token_url = config.get('token_url', 'https://mock.example.com/oauth/token')
        self.userinfo_url = config.get('userinfo_url', 'https://mock.example.com/api/user')
        
        # Track method calls for testing
        self.method_calls = {
            'get_authorization_url': 0,
            'exchange_code_for_tokens': 0,
            'refresh_access_token': 0,
            'get_user_info': 0
        }
    
    def get_authorization_url(self, redirect_uri, state, **kwargs):
        """Generate mock authorization URL."""
        self.method_calls['get_authorization_url'] += 1
        
        from urllib.parse import urlencode
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'state': state,
            'response_type': 'code',
            'scope': ' '.join(self.scopes) if self.scopes else ''
        }
        
        # Add any additional parameters
        params.update(kwargs)
        
        # Remove empty parameters
        params = {k: v for k, v in params.items() if v}
        
        return f"{self.authorize_url}?{urlencode(params)}"
    
    def exchange_code_for_tokens(self, code, redirect_uri, **kwargs):
        """Mock token exchange."""
        self.method_calls['exchange_code_for_tokens'] += 1
        
        if code == 'invalid_code':
            raise OAuthFlowError('Invalid authorization code')
        
        if code == 'network_error':
            from requests.exceptions import ConnectionError
            raise ConnectionError('Network connection failed')
        
        # Return mock token response
        return {
            'access_token': f'mock_access_token_{code}',
            'refresh_token': f'mock_refresh_token_{code}',
            'expires_in': 3600,
            'scope': ' '.join(self.scopes) if self.scopes else 'mock_scope',
            'token_type': 'Bearer'
        }
    
    def refresh_access_token(self, refresh_token):
        """Mock token refresh."""
        self.method_calls['refresh_access_token'] += 1
        
        if refresh_token == 'invalid_refresh':
            raise OAuthFlowError('Invalid refresh token')
        
        return {
            'access_token': f'new_mock_access_token_{refresh_token}',
            'refresh_token': f'new_mock_refresh_token_{refresh_token}',
            'expires_in': 3600,
            'scope': ' '.join(self.scopes) if self.scopes else 'mock_scope',
            'token_type': 'Bearer'
        }
    
    def get_user_info(self, access_token):
        """Mock user info retrieval."""
        self.method_calls['get_user_info'] += 1
        
        if access_token == 'invalid_token':
            raise OAuthFlowError('Invalid access token')
        
        return {
            'id': 'mock_user_123',
            'email': 'mock@example.com',
            'name': 'Mock User',
            'login': 'mockuser'
        }


class TestProviderExtensibility(unittest.TestCase):
    """Test cases for provider extensibility and manager functionality."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create mock Flask app
        self.mock_app = MagicMock()
        self.mock_app.provider_manager = None
        
        # Create mock config
        self.mock_config = MagicMock()
        self.mock_config.get_provider_settings.return_value = {
            'auto_register_providers': True
        }
        self.mock_config.get_enabled_providers.return_value = ['google', 'microsoft']
        self.mock_config.get_oauth_config.side_effect = self._mock_get_oauth_config
        
        # Create provider manager
        self.provider_manager = ProviderManager(config=self.mock_config)
        
        # Mock provider configurations
        self.valid_mock_config = {
            'name': 'mock',
            'client_id': 'mock_client_id',
            'client_secret': 'mock_client_secret',
            'scopes': ['mock_scope1', 'mock_scope2'],
            'display_name': 'Mock Provider',
            'authorize_url': 'https://mock.example.com/oauth/authorize',
            'token_url': 'https://mock.example.com/oauth/token'
        }
        
        self.google_config = {
            'name': 'google',
            'client_id': 'google_client_id',
            'client_secret': 'google_client_secret',
            'scopes': ['profile', 'email'],
            'display_name': 'Google Account'
        }
        
        self.microsoft_config = {
            'name': 'microsoft',
            'client_id': 'microsoft_client_id',
            'client_secret': 'microsoft_client_secret',
            'scopes': ['User.Read', 'Mail.Read'],
            'display_name': 'Microsoft Account'
        }
    
    def _mock_get_oauth_config(self, provider_name):
        """Mock OAuth configuration retrieval."""
        configs = {
            'google': self.google_config,
            'microsoft': self.microsoft_config,
            'mock': self.valid_mock_config
        }
        return configs.get(provider_name, {})
    
    # Provider Manager Initialization Tests
    
    def test_provider_manager_initialization(self):
        """Test provider manager initialization."""
        manager = ProviderManager()
        
        # Verify built-in providers are registered
        self.assertIn('google', manager.provider_classes)
        self.assertIn('microsoft', manager.provider_classes)
        
        # Verify initial state
        self.assertEqual(len(manager.providers), 0)
        self.assertIsNone(manager.app)
    
    def test_provider_manager_init_app(self):
        """Test provider manager Flask app initialization."""
        manager = ProviderManager()
        manager.init_app(self.mock_app, self.mock_config)
        
        # Verify app is set
        self.assertEqual(manager.app, self.mock_app)
        self.assertEqual(manager.config, self.mock_config)
        self.assertEqual(self.mock_app.provider_manager, manager)
    
    def test_provider_manager_builtin_provider_registration(self):
        """Test that built-in providers are properly registered."""
        manager = ProviderManager()
        
        # Verify Google provider class is registered
        self.assertIn('google', manager.provider_classes)
        # Import using the same path as the provider manager
        from providers.google_provider import GoogleProvider
        self.assertEqual(manager.provider_classes['google'], GoogleProvider)
        
        # Verify Microsoft provider class is registered
        self.assertIn('microsoft', manager.provider_classes)
        from providers.microsoft_provider import MicrosoftProvider
        self.assertEqual(manager.provider_classes['microsoft'], MicrosoftProvider)
    
    # Dynamic Provider Registration Tests
    
    def test_register_provider_class_success(self):
        """Test successful provider class registration."""
        manager = ProviderManager()
        
        # Register mock provider class
        manager.register_provider_class('mock', MockProvider)
        
        # Verify registration
        self.assertIn('mock', manager.provider_classes)
        self.assertEqual(manager.provider_classes['mock'], MockProvider)
    
    def test_register_provider_class_invalid_inheritance(self):
        """Test provider class registration with invalid inheritance."""
        manager = ProviderManager()
        
        # Create invalid provider class
        class InvalidProvider:
            pass
        
        # Should raise error for invalid inheritance
        with self.assertRaises(ProviderManagerError) as context:
            manager.register_provider_class('invalid', InvalidProvider)
        
        self.assertIn('must inherit from BaseProvider', str(context.exception))
    
    def test_register_provider_instance_success(self):
        """Test successful provider instance registration."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        
        # Register provider instance
        provider = manager.register_provider('mock', self.valid_mock_config)
        
        # Verify registration
        self.assertIn('mock', manager.providers)
        self.assertIsInstance(provider, MockProvider)
        self.assertEqual(provider.name, 'mock')
        self.assertEqual(provider.client_id, 'mock_client_id')
    
    def test_register_provider_unknown_class(self):
        """Test provider registration with unknown provider class."""
        manager = ProviderManager()
        
        # Try to register provider with unknown class
        with self.assertRaises(ProviderManagerError) as context:
            manager.register_provider('unknown', {
                'client_id': 'test_id',
                'client_secret': 'test_secret'
            })
        
        self.assertIn('Failed to import provider class', str(context.exception))
    
    def test_register_provider_configuration_error(self):
        """Test provider registration with invalid configuration."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        
        # Try to register with invalid config (missing client_secret)
        invalid_config = {
            'client_id': 'test_id'
            # Missing client_secret
        }
        
        with self.assertRaises(ProviderManagerError) as context:
            manager.register_provider('mock', invalid_config)
        
        self.assertIn('Failed to register provider mock', str(context.exception))
    
    def test_register_provider_from_config(self):
        """Test registering providers from configuration."""
        manager = ProviderManager(config=self.mock_config)
        
        # Mock the provider classes to avoid import issues
        manager.provider_classes['google'] = MockProvider
        manager.provider_classes['microsoft'] = MockProvider
        
        # Register providers from config
        manager.register_providers_from_config()
        
        # Verify providers were registered
        self.assertIn('google', manager.providers)
        self.assertIn('microsoft', manager.providers)
        self.assertEqual(len(manager.providers), 2)
    
    def test_register_provider_from_config_partial_failure(self):
        """Test registering providers from config with partial failures."""
        # Mock config that returns invalid config for one provider
        mock_config = MagicMock()
        mock_config.get_provider_settings.return_value = {'auto_register_providers': True}
        mock_config.get_enabled_providers.return_value = ['google', 'invalid']
        
        def mock_oauth_config(provider):
            if provider == 'google':
                return self.google_config
            elif provider == 'invalid':
                return {'client_id': 'test'}  # Missing client_secret
            return {}
        
        mock_config.get_oauth_config.side_effect = mock_oauth_config
        
        manager = ProviderManager(config=mock_config)
        manager.provider_classes['google'] = MockProvider
        manager.provider_classes['invalid'] = MockProvider
        
        # Should not raise exception, but continue with valid providers
        manager.register_providers_from_config()
        
        # Verify only valid provider was registered
        self.assertIn('google', manager.providers)
        self.assertNotIn('invalid', manager.providers)
    
    # Provider Configuration Validation Tests
    
    def test_validate_provider_config_success(self):
        """Test successful provider configuration validation."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        
        # Validate valid configuration
        result = manager.validate_provider_config('mock', self.valid_mock_config)
        self.assertTrue(result)
    
    def test_validate_provider_config_invalid(self):
        """Test provider configuration validation with invalid config."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        
        # Validate invalid configuration
        invalid_config = {
            'client_id': 'test_id'
            # Missing client_secret
        }
        
        result = manager.validate_provider_config('mock', invalid_config)
        self.assertFalse(result)
    
    def test_validate_provider_config_unknown_provider(self):
        """Test provider configuration validation with unknown provider."""
        manager = ProviderManager()
        
        # Validate config for unknown provider
        result = manager.validate_provider_config('unknown', self.valid_mock_config)
        self.assertFalse(result)
    
    def test_validate_provider_config_exception_handling(self):
        """Test provider configuration validation exception handling."""
        manager = ProviderManager()
        
        # Create mock provider class that raises unexpected exception
        class ExceptionProvider(BaseProvider):
            def __init__(self, config):
                raise RuntimeError('Unexpected error')
            
            def get_authorization_url(self, redirect_uri, state, **kwargs):
                pass
            
            def exchange_code_for_tokens(self, code, redirect_uri, **kwargs):
                pass
        
        manager.register_provider_class('exception', ExceptionProvider)
        
        # Should handle exception gracefully
        result = manager.validate_provider_config('exception', self.valid_mock_config)
        self.assertFalse(result)
    
    # Provider Management Tests
    
    def test_get_provider_success(self):
        """Test successful provider retrieval."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        provider = manager.register_provider('mock', self.valid_mock_config)
        
        # Retrieve provider
        retrieved_provider = manager.get_provider('mock')
        self.assertEqual(retrieved_provider, provider)
    
    def test_get_provider_not_found(self):
        """Test provider retrieval for non-existent provider."""
        manager = ProviderManager()
        
        # Try to get non-existent provider
        result = manager.get_provider('nonexistent')
        self.assertIsNone(result)
    
    def test_get_all_providers(self):
        """Test retrieving all registered providers."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        
        # Register multiple providers using the same class
        provider1 = manager.register_provider('mock', {
            **self.valid_mock_config,
            'name': 'mock'
        })
        
        # Register another provider with different name but same class
        manager.register_provider_class('mock2', MockProvider)
        provider2 = manager.register_provider('mock2', {
            **self.valid_mock_config,
            'name': 'mock2'
        })
        
        # Get all providers
        all_providers = manager.get_all_providers()
        
        self.assertEqual(len(all_providers), 2)
        self.assertIn('mock', all_providers)
        self.assertIn('mock2', all_providers)
        self.assertEqual(all_providers['mock'], provider1)
        self.assertEqual(all_providers['mock2'], provider2)
    
    def test_get_provider_info(self):
        """Test getting provider information for API responses."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        manager.register_provider('mock', self.valid_mock_config)
        
        # Get provider info
        provider_info = manager.get_provider_info()
        
        self.assertIsInstance(provider_info, list)
        self.assertEqual(len(provider_info), 1)
        
        info = provider_info[0]
        self.assertEqual(info['name'], 'mock')
        self.assertEqual(info['display_name'], 'Mock Provider')
        self.assertEqual(info['scopes'], ['mock_scope1', 'mock_scope2'])
        self.assertIn('supports_refresh', info)
        self.assertIn('supports_user_info', info)
    
    def test_unregister_provider_success(self):
        """Test successful provider unregistration."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        manager.register_provider('mock', self.valid_mock_config)
        
        # Verify provider is registered
        self.assertIn('mock', manager.providers)
        
        # Unregister provider
        result = manager.unregister_provider('mock')
        self.assertTrue(result)
        
        # Verify provider is removed
        self.assertNotIn('mock', manager.providers)
    
    def test_unregister_provider_not_found(self):
        """Test unregistering non-existent provider."""
        manager = ProviderManager()
        
        # Try to unregister non-existent provider
        result = manager.unregister_provider('nonexistent')
        self.assertFalse(result)
    
    def test_reload_provider_success(self):
        """Test successful provider reload with new configuration."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        
        # Register initial provider
        original_provider = manager.register_provider('mock', self.valid_mock_config)
        self.assertEqual(original_provider.display_name, 'Mock Provider')
        
        # Reload with new config
        new_config = {
            **self.valid_mock_config,
            'display_name': 'Updated Mock Provider'
        }
        
        reloaded_provider = manager.reload_provider('mock', new_config)
        
        # Verify provider was reloaded
        self.assertNotEqual(reloaded_provider, original_provider)
        self.assertEqual(reloaded_provider.display_name, 'Updated Mock Provider')
        self.assertEqual(manager.get_provider('mock'), reloaded_provider)
    
    def test_reload_providers_from_config(self):
        """Test reloading all providers from updated configuration."""
        manager = ProviderManager(config=self.mock_config)
        manager.provider_classes['google'] = MockProvider
        manager.provider_classes['microsoft'] = MockProvider
        
        # Register initial providers
        manager.register_providers_from_config()
        initial_count = len(manager.providers)
        
        # Mock config reload
        self.mock_config.reload_provider_configurations = MagicMock()
        
        # Reload providers
        manager.reload_providers_from_config()
        
        # Verify reload was called
        self.mock_config.reload_provider_configurations.assert_called_once()
        
        # Verify providers were reloaded
        self.assertEqual(len(manager.providers), initial_count)
    
    def test_get_provider_stats(self):
        """Test getting provider statistics."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        
        # Initially empty
        stats = manager.get_provider_stats()
        self.assertEqual(stats['total_providers'], 0)
        self.assertEqual(len(stats['provider_names']), 0)
        
        # Register providers
        manager.register_provider('mock', {
            **self.valid_mock_config,
            'name': 'mock'
        })
        manager.register_provider_class('mock2', MockProvider)
        manager.register_provider('mock2', {
            **self.valid_mock_config,
            'name': 'mock2'
        })
        
        # Check updated stats
        stats = manager.get_provider_stats()
        self.assertEqual(stats['total_providers'], 2)
        self.assertIn('mock', stats['provider_names'])
        self.assertIn('mock2', stats['provider_names'])
        self.assertIn('mock', stats['provider_classes'])
        self.assertEqual(len(stats['providers_info']), 2)
    
    # Route Registration Tests
    
    def test_register_routes_success(self):
        """Test successful route registration for providers."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        manager.register_provider('mock', self.valid_mock_config)
        
        # Mock Flask app
        mock_app = MagicMock()
        mock_app.add_url_rule = MagicMock()
        mock_app.route = MagicMock()  # Mock the route decorator
        
        # Register routes
        manager.register_routes(mock_app)
        
        # Verify routes were registered
        # Should have 2 routes per provider (authorize + callback) via add_url_rule
        expected_calls = 2  # 2 for mock provider (authorize + callback)
        self.assertEqual(mock_app.add_url_rule.call_count, expected_calls)
        
        # Verify route patterns
        call_args_list = mock_app.add_url_rule.call_args_list
        route_patterns = [call[0][0] for call in call_args_list]
        
        self.assertIn('/oauth/mock/authorize', route_patterns)
        self.assertIn('/oauth/mock/callback', route_patterns)
        
        # Verify API route was registered via @app.route decorator
        mock_app.route.assert_called_once_with('/api/providers')
    
    def test_register_routes_no_providers(self):
        """Test route registration with no providers."""
        manager = ProviderManager()
        
        # Mock Flask app
        mock_app = MagicMock()
        mock_app.add_url_rule = MagicMock()
        
        # Register routes (should handle gracefully)
        manager.register_routes(mock_app)
        
        # Should not register any routes when no providers are registered
        self.assertEqual(mock_app.add_url_rule.call_count, 0)
    
    def test_register_routes_multiple_providers(self):
        """Test route registration with multiple providers."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        manager.register_provider_class('mock2', MockProvider)
        
        # Register multiple providers
        manager.register_provider('mock', {
            **self.valid_mock_config,
            'name': 'mock'
        })
        manager.register_provider('mock2', {
            **self.valid_mock_config,
            'name': 'mock2'
        })
        
        # Mock Flask app
        mock_app = MagicMock()
        mock_app.add_url_rule = MagicMock()
        mock_app.route = MagicMock()  # Mock the route decorator
        
        # Register routes
        manager.register_routes(mock_app)
        
        # Verify routes were registered for both providers
        # Should have 2 routes per provider via add_url_rule
        expected_calls = 4  # 2*2 for providers (authorize + callback each)
        self.assertEqual(mock_app.add_url_rule.call_count, expected_calls)
        
        # Verify API route was registered via @app.route decorator
        mock_app.route.assert_called_once_with('/api/providers')
    
    # Mock Provider Functionality Tests
    
    def test_mock_provider_initialization(self):
        """Test mock provider initialization."""
        provider = MockProvider(self.valid_mock_config)
        
        self.assertEqual(provider.name, 'mock')
        self.assertEqual(provider.client_id, 'mock_client_id')
        self.assertEqual(provider.client_secret, 'mock_client_secret')
        self.assertEqual(provider.scopes, ['mock_scope1', 'mock_scope2'])
        self.assertEqual(provider.display_name, 'Mock Provider')
    
    def test_mock_provider_authorization_url(self):
        """Test mock provider authorization URL generation."""
        provider = MockProvider(self.valid_mock_config)
        
        redirect_uri = 'http://localhost:5000/callback'
        state = 'test_state'
        
        auth_url = provider.get_authorization_url(redirect_uri, state)
        
        # Verify URL structure
        self.assertIn('mock.example.com', auth_url)
        self.assertIn('client_id=mock_client_id', auth_url)
        self.assertIn('state=test_state', auth_url)
        self.assertIn('response_type=code', auth_url)
        
        # Verify method was tracked
        self.assertEqual(provider.method_calls['get_authorization_url'], 1)
    
    def test_mock_provider_token_exchange_success(self):
        """Test mock provider successful token exchange."""
        provider = MockProvider(self.valid_mock_config)
        
        result = provider.exchange_code_for_tokens('test_code', 'http://localhost:5000/callback')
        
        # Verify response structure
        self.assertIn('access_token', result)
        self.assertIn('refresh_token', result)
        self.assertIn('expires_in', result)
        self.assertIn('scope', result)
        self.assertEqual(result['access_token'], 'mock_access_token_test_code')
        self.assertEqual(result['expires_in'], 3600)
        
        # Verify method was tracked
        self.assertEqual(provider.method_calls['exchange_code_for_tokens'], 1)
    
    def test_mock_provider_token_exchange_error(self):
        """Test mock provider token exchange error handling."""
        provider = MockProvider(self.valid_mock_config)
        
        # Test invalid code error
        with self.assertRaises(OAuthFlowError):
            provider.exchange_code_for_tokens('invalid_code', 'http://localhost:5000/callback')
        
        # Test network error
        with self.assertRaises(Exception):  # ConnectionError
            provider.exchange_code_for_tokens('network_error', 'http://localhost:5000/callback')
    
    def test_mock_provider_token_refresh(self):
        """Test mock provider token refresh functionality."""
        provider = MockProvider(self.valid_mock_config)
        
        result = provider.refresh_access_token('test_refresh_token')
        
        # Verify response structure
        self.assertIn('access_token', result)
        self.assertIn('refresh_token', result)
        self.assertEqual(result['access_token'], 'new_mock_access_token_test_refresh_token')
        
        # Verify method was tracked
        self.assertEqual(provider.method_calls['refresh_access_token'], 1)
    
    def test_mock_provider_token_refresh_error(self):
        """Test mock provider token refresh error handling."""
        provider = MockProvider(self.valid_mock_config)
        
        with self.assertRaises(OAuthFlowError):
            provider.refresh_access_token('invalid_refresh')
    
    def test_mock_provider_user_info(self):
        """Test mock provider user info retrieval."""
        provider = MockProvider(self.valid_mock_config)
        
        result = provider.get_user_info('test_access_token')
        
        # Verify response structure
        self.assertIn('id', result)
        self.assertIn('email', result)
        self.assertIn('name', result)
        self.assertEqual(result['email'], 'mock@example.com')
        
        # Verify method was tracked
        self.assertEqual(provider.method_calls['get_user_info'], 1)
    
    def test_mock_provider_user_info_error(self):
        """Test mock provider user info error handling."""
        provider = MockProvider(self.valid_mock_config)
        
        with self.assertRaises(OAuthFlowError):
            provider.get_user_info('invalid_token')
    
    def test_mock_provider_method_tracking(self):
        """Test that mock provider tracks method calls correctly."""
        provider = MockProvider(self.valid_mock_config)
        
        # Initially all counts should be zero
        for method, count in provider.method_calls.items():
            self.assertEqual(count, 0)
        
        # Call methods and verify tracking
        provider.get_authorization_url('http://test.com', 'state')
        self.assertEqual(provider.method_calls['get_authorization_url'], 1)
        
        provider.exchange_code_for_tokens('code', 'http://test.com')
        self.assertEqual(provider.method_calls['exchange_code_for_tokens'], 1)
        
        provider.refresh_access_token('refresh')
        self.assertEqual(provider.method_calls['refresh_access_token'], 1)
        
        provider.get_user_info('token')
        self.assertEqual(provider.method_calls['get_user_info'], 1)
    
    # Integration Tests
    
    def test_end_to_end_provider_registration_and_usage(self):
        """Test complete provider registration and usage workflow."""
        manager = ProviderManager()
        
        # Step 1: Register provider class
        manager.register_provider_class('mock', MockProvider)
        self.assertIn('mock', manager.provider_classes)
        
        # Step 2: Validate configuration
        is_valid = manager.validate_provider_config('mock', self.valid_mock_config)
        self.assertTrue(is_valid)
        
        # Step 3: Register provider instance
        provider = manager.register_provider('mock', self.valid_mock_config)
        self.assertIsInstance(provider, MockProvider)
        
        # Step 4: Use provider functionality
        auth_url = provider.get_authorization_url('http://test.com', 'state')
        self.assertIsInstance(auth_url, str)
        
        tokens = provider.exchange_code_for_tokens('code', 'http://test.com')
        self.assertIn('access_token', tokens)
        
        # Step 5: Get provider info
        info = manager.get_provider_info()
        self.assertEqual(len(info), 1)
        self.assertEqual(info[0]['name'], 'mock')
        
        # Step 6: Unregister provider
        result = manager.unregister_provider('mock')
        self.assertTrue(result)
        self.assertNotIn('mock', manager.providers)
    
    def test_concurrent_provider_operations(self):
        """Test concurrent provider operations for thread safety."""
        import threading
        import time
        
        manager = ProviderManager()
        
        results = []
        errors = []
        
        def register_provider_worker(worker_id):
            """Worker function for concurrent provider registration."""
            try:
                # Register provider class first
                provider_name = f'mock_{worker_id}'
                manager.register_provider_class(provider_name, MockProvider)
                
                config = {
                    **self.valid_mock_config,
                    'name': provider_name,
                    'client_id': f'client_{worker_id}'
                }
                provider = manager.register_provider(provider_name, config)
                results.append((worker_id, provider.name))
            except Exception as e:
                errors.append((worker_id, e))
        
        # Create multiple threads
        threads = []
        for worker_id in range(5):
            thread = threading.Thread(target=register_provider_worker, args=(worker_id,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify no errors occurred
        self.assertEqual(len(errors), 0, f"Errors occurred during concurrent operations: {errors}")
        
        # Verify all providers were registered
        self.assertEqual(len(results), 5)
        self.assertEqual(len(manager.providers), 5)
        
        # Verify all provider names are unique
        provider_names = [result[1] for result in results]
        self.assertEqual(len(set(provider_names)), 5)
    
    def test_provider_manager_error_recovery(self):
        """Test provider manager error recovery and resilience."""
        manager = ProviderManager()
        manager.register_provider_class('mock', MockProvider)
        
        # Register valid provider
        valid_provider = manager.register_provider('mock', self.valid_mock_config)
        self.assertIn('mock', manager.providers)
        
        # Try to register invalid provider (should not affect valid one)
        manager.register_provider_class('invalid', MockProvider)
        try:
            manager.register_provider('invalid', {'client_id': 'test'})  # Missing client_secret
        except ProviderManagerError:
            pass  # Expected
        
        # Verify valid provider is still registered and functional
        self.assertIn('mock', manager.providers)
        self.assertEqual(manager.get_provider('mock'), valid_provider)
        
        # Verify invalid provider was not registered
        self.assertNotIn('invalid', manager.providers)
        
        # Verify manager is still functional
        stats = manager.get_provider_stats()
        self.assertEqual(stats['total_providers'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)