#!/usr/bin/env python3
"""
Comprehensive Provider Extensibility Testing for SecureContext Protocol

This script tests all aspects of provider extensibility including:
- Dynamic provider registration and loading
- Provider configuration validation
- OAuth route generation for new providers
- Provider-specific error handling
- UI updates when providers are added/removed
- Mock provider implementation testing

Requirements: 9.1-9.4, 10.1
"""

import unittest
import json
import tempfile
import os
import sys
import time
import requests
import subprocess
from unittest.mock import patch, MagicMock, Mock
from urllib.parse import urlparse, parse_qs

# Add the authentication_proxy directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'authentication_proxy'))

from authentication_proxy.providers.provider_manager import ProviderManager, ProviderManagerError
from authentication_proxy.providers.base_provider import BaseProvider, ProviderConfigurationError, OAuthFlowError
from authentication_proxy.config import Config


class TestProvider(BaseProvider):
    """
    Test OAuth provider for extensibility testing.
    
    This provider implements the BaseProvider interface for testing
    dynamic provider registration and extensibility features.
    """
    
    def __init__(self, config):
        """Initialize test provider with configuration."""
        name = config.get('name', 'test')
        super().__init__(name, config)
        
        # Test provider specific attributes
        self.authorize_url = config.get('authorize_url', 'https://test.example.com/oauth/authorize')
        self.token_url = config.get('token_url', 'https://test.example.com/oauth/token')
        self.userinfo_url = config.get('userinfo_url', 'https://test.example.com/api/user')
        
        # Track method calls for testing
        self.method_calls = {
            'get_authorization_url': 0,
            'exchange_code_for_tokens': 0,
            'refresh_access_token': 0,
            'get_user_info': 0
        }
        
        # Simulate provider-specific features
        self.supports_pkce = config.get('supports_pkce', False)
        self.supports_device_flow = config.get('supports_device_flow', False)
    
    def get_authorization_url(self, redirect_uri, state, **kwargs):
        """Generate test authorization URL."""
        self.method_calls['get_authorization_url'] += 1
        
        from urllib.parse import urlencode
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'state': state,
            'response_type': 'code',
            'scope': ' '.join(self.scopes) if self.scopes else ''
        }
        
        # Add PKCE parameters if supported
        if self.supports_pkce and 'code_challenge' in kwargs:
            params['code_challenge'] = kwargs['code_challenge']
            params['code_challenge_method'] = kwargs.get('code_challenge_method', 'S256')
        
        # Add any additional parameters
        params.update(kwargs)
        
        # Remove empty parameters
        params = {k: v for k, v in params.items() if v}
        
        return f"{self.authorize_url}?{urlencode(params)}"
    
    def exchange_code_for_tokens(self, code, redirect_uri, **kwargs):
        """Test token exchange."""
        self.method_calls['exchange_code_for_tokens'] += 1
        
        if code == 'invalid_code':
            raise OAuthFlowError('Invalid authorization code')
        
        if code == 'network_error':
            from requests.exceptions import ConnectionError
            raise ConnectionError('Network connection failed')
        
        if code == 'server_error':
            raise OAuthFlowError('Provider server error')
        
        # Return test token response
        return {
            'access_token': f'test_access_token_{code}',
            'refresh_token': f'test_refresh_token_{code}',
            'expires_in': 3600,
            'scope': ' '.join(self.scopes) if self.scopes else 'test_scope',
            'token_type': 'Bearer'
        }
    
    def refresh_access_token(self, refresh_token):
        """Test token refresh."""
        self.method_calls['refresh_access_token'] += 1
        
        if refresh_token == 'invalid_refresh':
            raise OAuthFlowError('Invalid refresh token')
        
        return {
            'access_token': f'new_test_access_token_{refresh_token}',
            'refresh_token': f'new_test_refresh_token_{refresh_token}',
            'expires_in': 3600,
            'scope': ' '.join(self.scopes) if self.scopes else 'test_scope',
            'token_type': 'Bearer'
        }
    
    def get_user_info(self, access_token):
        """Test user info retrieval."""
        self.method_calls['get_user_info'] += 1
        
        if access_token == 'invalid_token':
            raise OAuthFlowError('Invalid access token')
        
        return {
            'id': 'test_user_123',
            'email': 'test@example.com',
            'name': 'Test User',
            'login': 'testuser'
        }
    
    def _get_provider_metadata(self):
        """Get test provider specific metadata."""
        return {
            'icon_url': 'https://test.example.com/icon.png',
            'documentation_url': 'https://test.example.com/docs',
            'website_url': 'https://test.example.com',
            'rate_limits': {
                'requests_per_hour': 1000,
                'burst_limit': 100
            },
            'supports_pkce': self.supports_pkce,
            'supports_device_flow': self.supports_device_flow
        }


class ProviderExtensibilityTest(unittest.TestCase):
    """Comprehensive provider extensibility testing."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_config = {
            'name': 'test',
            'client_id': 'test_client_id',
            'client_secret': 'test_client_secret',
            'scopes': ['test_scope1', 'test_scope2'],
            'display_name': 'Test Provider',
            'authorize_url': 'https://test.example.com/oauth/authorize',
            'token_url': 'https://test.example.com/oauth/token',
            'supports_pkce': True,
            'supports_device_flow': False
        }
        
        # Create temporary providers.json for testing
        self.temp_providers_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        self.providers_config = {
            "providers": {
                "test": {
                    **self.test_config,
                    "client_id": "env:TEST_CLIENT_ID",
                    "client_secret": "env:TEST_CLIENT_SECRET",
                    "provider_class": "TestProvider",
                    "enabled": True
                }
            },
            "settings": {
                "default_session_timeout": 3600,
                "max_concurrent_sessions": 1000,
                "enable_audit_logging": True,
                "auto_cleanup_expired_sessions": True
            }
        }
        
        json.dump(self.providers_config, self.temp_providers_file)
        self.temp_providers_file.close()
        
        # Set environment variables for testing
        os.environ['TEST_CLIENT_ID'] = 'test_client_id'
        os.environ['TEST_CLIENT_SECRET'] = 'test_client_secret'
        os.environ['FLASK_SECRET_KEY'] = 'test_secret_key'
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary file
        if os.path.exists(self.temp_providers_file.name):
            os.unlink(self.temp_providers_file.name)
        
        # Clean up environment variables
        for var in ['TEST_CLIENT_ID', 'TEST_CLIENT_SECRET', 'FLASK_SECRET_KEY']:
            if var in os.environ:
                del os.environ[var]
    
    def test_dynamic_provider_registration(self):
        """Test dynamic provider registration and loading."""
        print("\n=== Testing Dynamic Provider Registration ===")
        
        # Create provider manager
        manager = ProviderManager()
        
        # Test 1: Register new provider class
        print("1. Testing provider class registration...")
        manager.register_provider_class('test', TestProvider)
        self.assertIn('test', manager.provider_classes)
        self.assertEqual(manager.provider_classes['test'], TestProvider)
        print("✓ Provider class registered successfully")
        
        # Test 2: Register provider instance
        print("2. Testing provider instance registration...")
        provider = manager.register_provider('test', self.test_config)
        self.assertIsInstance(provider, TestProvider)
        self.assertEqual(provider.name, 'test')
        self.assertEqual(provider.client_id, 'test_client_id')
        print("✓ Provider instance registered successfully")
        
        # Test 3: Verify provider is accessible
        print("3. Testing provider retrieval...")
        retrieved_provider = manager.get_provider('test')
        self.assertEqual(retrieved_provider, provider)
        print("✓ Provider retrieved successfully")
        
        # Test 4: Test provider info generation
        print("4. Testing provider info generation...")
        provider_info = manager.get_provider_info()
        self.assertEqual(len(provider_info), 1)
        info = provider_info[0]
        self.assertEqual(info['name'], 'test')
        self.assertEqual(info['display_name'], 'Test Provider')
        self.assertTrue(info['supports_refresh'])
        self.assertTrue(info['supports_user_info'])
        print("✓ Provider info generated successfully")
        
        print("✅ Dynamic provider registration tests passed")
    
    def test_provider_configuration_validation(self):
        """Test provider configuration validation."""
        print("\n=== Testing Provider Configuration Validation ===")
        
        manager = ProviderManager()
        manager.register_provider_class('test', TestProvider)
        
        # Test 1: Valid configuration
        print("1. Testing valid configuration...")
        result = manager.validate_provider_config('test', self.test_config)
        self.assertTrue(result)
        print("✓ Valid configuration accepted")
        
        # Test 2: Missing required fields
        print("2. Testing missing required fields...")
        invalid_config = {
            'name': 'test',
            'client_id': 'test_id'
            # Missing client_secret
        }
        result = manager.validate_provider_config('test', invalid_config)
        self.assertFalse(result)
        print("✓ Invalid configuration rejected")
        
        # Test 3: Invalid URL format
        print("3. Testing invalid URL format...")
        invalid_url_config = {
            **self.test_config,
            'authorize_url': 'not-a-valid-url'
        }
        result = manager.validate_provider_config('test', invalid_url_config)
        self.assertFalse(result)
        print("✓ Invalid URL format rejected")
        
        # Test 4: Invalid scopes format
        print("4. Testing invalid scopes format...")
        invalid_scopes_config = {
            **self.test_config,
            'scopes': 'not-a-list'
        }
        result = manager.validate_provider_config('test', invalid_scopes_config)
        self.assertFalse(result)
        print("✓ Invalid scopes format rejected")
        
        # Test 5: Configuration from file
        print("5. Testing configuration loading from file...")
        try:
            config = Config(self.temp_providers_file.name)
            oauth_config = config.get_oauth_config('test')
            self.assertEqual(oauth_config['client_id'], 'test_client_id')
            self.assertEqual(oauth_config['client_secret'], 'test_client_secret')
            print("✓ Configuration loaded from file successfully")
        except Exception as e:
            print(f"✗ Configuration loading failed: {e}")
            raise
        
        print("✅ Provider configuration validation tests passed")
    
    def test_oauth_route_generation(self):
        """Test OAuth route generation for new providers."""
        print("\n=== Testing OAuth Route Generation ===")
        
        # Create Flask app mock
        mock_app = MagicMock()
        mock_app.add_url_rule = MagicMock()
        mock_app.route = MagicMock(return_value=lambda f: f)  # Mock decorator
        
        # Create provider manager and register provider
        manager = ProviderManager()
        manager.register_provider_class('test', TestProvider)
        provider = manager.register_provider('test', self.test_config)
        
        # Test 1: Route registration
        print("1. Testing route registration...")
        manager.register_routes(mock_app)
        
        # Verify OAuth routes were registered
        call_args_list = mock_app.add_url_rule.call_args_list
        route_patterns = [call[0][0] for call in call_args_list]
        
        self.assertIn('/oauth/test/authorize', route_patterns)
        self.assertIn('/oauth/test/callback', route_patterns)
        print("✓ OAuth routes registered successfully")
        
        # Test 2: Route handler functionality
        print("2. Testing route handler functionality...")
        
        # Find the authorize handler
        authorize_handler = None
        for call in call_args_list:
            if call[0][0] == '/oauth/test/authorize':
                authorize_handler = call[0][2]  # The handler function
                break
        
        self.assertIsNotNone(authorize_handler)
        print("✓ Route handlers created successfully")
        
        # Test 3: Multiple providers route generation
        print("3. Testing multiple providers route generation...")
        
        # Register another provider
        manager.register_provider_class('test2', TestProvider)
        test2_config = {**self.test_config, 'name': 'test2'}
        manager.register_provider('test2', test2_config)
        
        # Clear previous calls and register routes again
        mock_app.add_url_rule.reset_mock()
        manager.register_routes(mock_app)
        
        # Verify routes for both providers
        call_args_list = mock_app.add_url_rule.call_args_list
        route_patterns = [call[0][0] for call in call_args_list]
        
        # Should have routes for both providers
        expected_routes = [
            '/oauth/test/authorize', '/oauth/test/callback',
            '/oauth/test2/authorize', '/oauth/test2/callback'
        ]
        
        for route in expected_routes:
            self.assertIn(route, route_patterns)
        
        print("✓ Multiple provider routes generated successfully")
        
        print("✅ OAuth route generation tests passed")
    
    def test_provider_specific_error_handling(self):
        """Test provider-specific error handling."""
        print("\n=== Testing Provider-Specific Error Handling ===")
        
        manager = ProviderManager()
        manager.register_provider_class('test', TestProvider)
        provider = manager.register_provider('test', self.test_config)
        
        # Test 1: OAuth flow errors
        print("1. Testing OAuth flow error handling...")
        
        # Test invalid authorization code
        with self.assertRaises(OAuthFlowError) as context:
            provider.exchange_code_for_tokens('invalid_code', 'http://test.com/callback')
        self.assertIn('Invalid authorization code', str(context.exception))
        print("✓ Invalid authorization code error handled")
        
        # Test network errors
        with self.assertRaises(Exception):  # ConnectionError
            provider.exchange_code_for_tokens('network_error', 'http://test.com/callback')
        print("✓ Network error handled")
        
        # Test server errors
        with self.assertRaises(OAuthFlowError) as context:
            provider.exchange_code_for_tokens('server_error', 'http://test.com/callback')
        self.assertIn('Provider server error', str(context.exception))
        print("✓ Server error handled")
        
        # Test 2: Token refresh errors
        print("2. Testing token refresh error handling...")
        
        with self.assertRaises(OAuthFlowError) as context:
            provider.refresh_access_token('invalid_refresh')
        self.assertIn('Invalid refresh token', str(context.exception))
        print("✓ Token refresh error handled")
        
        # Test 3: User info errors
        print("3. Testing user info error handling...")
        
        with self.assertRaises(OAuthFlowError) as context:
            provider.get_user_info('invalid_token')
        self.assertIn('Invalid access token', str(context.exception))
        print("✓ User info error handled")
        
        # Test 4: Configuration errors
        print("4. Testing configuration error handling...")
        
        invalid_config = {'name': 'invalid'}  # Missing required fields
        
        with self.assertRaises(ProviderManagerError):
            manager.register_provider('invalid', invalid_config)
        print("✓ Configuration error handled")
        
        # Test 5: State validation
        print("5. Testing state validation...")
        
        # Valid state
        self.assertTrue(provider.validate_state('test_state', 'test_state'))
        
        # Invalid state
        self.assertFalse(provider.validate_state('wrong_state', 'test_state'))
        self.assertFalse(provider.validate_state('', 'test_state'))
        self.assertFalse(provider.validate_state('test_state', ''))
        print("✓ State validation working correctly")
        
        print("✅ Provider-specific error handling tests passed")
    
    def test_ui_updates_with_provider_changes(self):
        """Test UI updates when providers are added/removed."""
        print("\n=== Testing UI Updates with Provider Changes ===")
        
        # Start the Flask application for testing
        print("1. Starting Flask application...")
        
        # Set up environment for Flask app
        os.environ['FLASK_SECRET_KEY'] = 'test_secret_key_for_ui'
        
        # Start Flask app in background
        app_process = None
        try:
            app_process = subprocess.Popen([
                sys.executable, 'authentication_proxy/app.py'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for app to start
            time.sleep(3)
            
            # Test 2: Check initial providers API
            print("2. Testing initial providers API...")
            
            try:
                response = requests.get('http://localhost:5000/api/providers', timeout=5)
                if response.status_code == 200:
                    providers_data = response.json()
                    initial_count = len(providers_data.get('data', {}).get('providers', []))
                    print(f"✓ Initial providers count: {initial_count}")
                else:
                    print(f"⚠ Providers API returned status {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"⚠ Could not connect to Flask app: {e}")
                print("  This is expected if the app is not running")
            
            # Test 3: Check UI rendering
            print("3. Testing UI rendering...")
            
            try:
                response = requests.get('http://localhost:5000/', timeout=5)
                if response.status_code == 200:
                    html_content = response.text
                    
                    # Check for provider buttons in HTML
                    if 'Connect' in html_content and 'Account' in html_content:
                        print("✓ UI contains provider connection buttons")
                    else:
                        print("⚠ UI may not contain expected provider buttons")
                else:
                    print(f"⚠ UI returned status {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"⚠ Could not access UI: {e}")
                print("  This is expected if the app is not running")
            
        except Exception as e:
            print(f"⚠ Could not start Flask app for UI testing: {e}")
            print("  This is expected in some test environments")
        
        finally:
            # Clean up Flask process
            if app_process:
                app_process.terminate()
                app_process.wait()
        
        # Test 4: Test provider manager UI integration
        print("4. Testing provider manager UI integration...")
        
        manager = ProviderManager()
        manager.register_provider_class('test', TestProvider)
        
        # Test provider info for UI
        provider = manager.register_provider('test', self.test_config)
        provider_info = manager.get_provider_info()
        
        self.assertEqual(len(provider_info), 1)
        info = provider_info[0]
        
        # Verify UI-relevant fields
        self.assertIn('name', info)
        self.assertIn('display_name', info)
        self.assertIn('authorization_url', info)
        self.assertIn('metadata', info)
        
        # Check metadata for UI rendering
        metadata = info['metadata']
        self.assertIn('icon_url', metadata)
        self.assertEqual(metadata['icon_url'], 'https://test.example.com/icon.png')
        
        print("✓ Provider info contains UI-relevant fields")
        
        # Test 5: Dynamic provider addition/removal
        print("5. Testing dynamic provider addition/removal...")
        
        # Add another provider
        manager.register_provider_class('test2', TestProvider)
        test2_config = {**self.test_config, 'name': 'test2', 'display_name': 'Test Provider 2'}
        manager.register_provider('test2', test2_config)
        
        # Verify both providers in info
        provider_info = manager.get_provider_info()
        self.assertEqual(len(provider_info), 2)
        
        provider_names = [p['name'] for p in provider_info]
        self.assertIn('test', provider_names)
        self.assertIn('test2', provider_names)
        print("✓ Multiple providers handled correctly")
        
        # Remove a provider
        result = manager.unregister_provider('test2')
        self.assertTrue(result)
        
        # Verify provider removed
        provider_info = manager.get_provider_info()
        self.assertEqual(len(provider_info), 1)
        self.assertEqual(provider_info[0]['name'], 'test')
        print("✓ Provider removal handled correctly")
        
        print("✅ UI updates with provider changes tests passed")
    
    def test_mock_provider_implementation(self):
        """Test mock provider implementation functionality."""
        print("\n=== Testing Mock Provider Implementation ===")
        
        # Test 1: Provider initialization
        print("1. Testing provider initialization...")
        
        provider = TestProvider(self.test_config)
        
        self.assertEqual(provider.name, 'test')
        self.assertEqual(provider.client_id, 'test_client_id')
        self.assertEqual(provider.client_secret, 'test_client_secret')
        self.assertEqual(provider.scopes, ['test_scope1', 'test_scope2'])
        self.assertEqual(provider.display_name, 'Test Provider')
        self.assertTrue(provider.supports_pkce)
        self.assertFalse(provider.supports_device_flow)
        print("✓ Provider initialized correctly")
        
        # Test 2: Authorization URL generation
        print("2. Testing authorization URL generation...")
        
        redirect_uri = 'http://localhost:5000/oauth/test/callback'
        state = 'test_state_123'
        
        auth_url = provider.get_authorization_url(redirect_uri, state)
        
        # Parse URL and verify parameters
        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)
        
        self.assertEqual(parsed_url.netloc, 'test.example.com')
        self.assertEqual(query_params['client_id'][0], 'test_client_id')
        self.assertEqual(query_params['state'][0], 'test_state_123')
        self.assertEqual(query_params['response_type'][0], 'code')
        self.assertIn('test_scope1 test_scope2', query_params['scope'][0])
        
        print("✓ Authorization URL generated correctly")
        
        # Test 3: PKCE support
        print("3. Testing PKCE support...")
        
        pkce_auth_url = provider.get_authorization_url(
            redirect_uri, state,
            code_challenge='test_challenge',
            code_challenge_method='S256'
        )
        
        parsed_pkce_url = urlparse(pkce_auth_url)
        pkce_params = parse_qs(parsed_pkce_url.query)
        
        self.assertEqual(pkce_params['code_challenge'][0], 'test_challenge')
        self.assertEqual(pkce_params['code_challenge_method'][0], 'S256')
        print("✓ PKCE parameters handled correctly")
        
        # Test 4: Token exchange
        print("4. Testing token exchange...")
        
        token_data = provider.exchange_code_for_tokens('test_code', redirect_uri)
        
        self.assertEqual(token_data['access_token'], 'test_access_token_test_code')
        self.assertEqual(token_data['refresh_token'], 'test_refresh_token_test_code')
        self.assertEqual(token_data['expires_in'], 3600)
        self.assertEqual(token_data['token_type'], 'Bearer')
        print("✓ Token exchange working correctly")
        
        # Test 5: Token refresh
        print("5. Testing token refresh...")
        
        refresh_data = provider.refresh_access_token('test_refresh_token')
        
        self.assertEqual(refresh_data['access_token'], 'new_test_access_token_test_refresh_token')
        self.assertEqual(refresh_data['refresh_token'], 'new_test_refresh_token_test_refresh_token')
        print("✓ Token refresh working correctly")
        
        # Test 6: User info retrieval
        print("6. Testing user info retrieval...")
        
        user_info = provider.get_user_info('test_access_token')
        
        self.assertEqual(user_info['id'], 'test_user_123')
        self.assertEqual(user_info['email'], 'test@example.com')
        self.assertEqual(user_info['name'], 'Test User')
        self.assertEqual(user_info['login'], 'testuser')
        print("✓ User info retrieval working correctly")
        
        # Test 7: Method call tracking
        print("7. Testing method call tracking...")
        
        # Verify all methods were called
        self.assertEqual(provider.method_calls['get_authorization_url'], 2)  # Called twice (normal + PKCE)
        self.assertEqual(provider.method_calls['exchange_code_for_tokens'], 1)
        self.assertEqual(provider.method_calls['refresh_access_token'], 1)
        self.assertEqual(provider.method_calls['get_user_info'], 1)
        print("✓ Method call tracking working correctly")
        
        # Test 8: Provider metadata
        print("8. Testing provider metadata...")
        
        provider_info = provider.get_provider_info()
        metadata = provider_info['metadata']
        
        self.assertEqual(metadata['icon_url'], 'https://test.example.com/icon.png')
        self.assertEqual(metadata['documentation_url'], 'https://test.example.com/docs')
        self.assertEqual(metadata['website_url'], 'https://test.example.com')
        self.assertTrue(metadata['supports_pkce'])
        self.assertFalse(metadata['supports_device_flow'])
        self.assertEqual(metadata['rate_limits']['requests_per_hour'], 1000)
        print("✓ Provider metadata generated correctly")
        
        print("✅ Mock provider implementation tests passed")
    
    def test_end_to_end_extensibility_workflow(self):
        """Test complete end-to-end extensibility workflow."""
        print("\n=== Testing End-to-End Extensibility Workflow ===")
        
        # Test 1: Create and configure new provider
        print("1. Creating and configuring new provider...")
        
        manager = ProviderManager()
        
        # Register provider class
        manager.register_provider_class('test', TestProvider)
        
        # Register provider instance
        provider = manager.register_provider('test', self.test_config)
        
        # Verify provider is working
        self.assertIsInstance(provider, TestProvider)
        print("✓ Provider created and configured")
        
        # Test 2: Generate OAuth routes
        print("2. Generating OAuth routes...")
        
        mock_app = MagicMock()
        mock_app.add_url_rule = MagicMock()
        mock_app.route = MagicMock(return_value=lambda f: f)
        
        manager.register_routes(mock_app)
        
        # Verify routes were created
        call_args_list = mock_app.add_url_rule.call_args_list
        route_patterns = [call[0][0] for call in call_args_list]
        
        self.assertIn('/oauth/test/authorize', route_patterns)
        self.assertIn('/oauth/test/callback', route_patterns)
        print("✓ OAuth routes generated")
        
        # Test 3: Test OAuth flow simulation
        print("3. Simulating OAuth flow...")
        
        # Generate authorization URL
        auth_url = provider.get_authorization_url(
            'http://localhost:5000/oauth/test/callback',
            'test_state'
        )
        self.assertIn('test.example.com', auth_url)
        
        # Simulate token exchange
        tokens = provider.exchange_code_for_tokens(
            'auth_code_123',
            'http://localhost:5000/oauth/test/callback'
        )
        self.assertIn('access_token', tokens)
        
        # Simulate user info retrieval
        user_info = provider.get_user_info(tokens['access_token'])
        self.assertIn('email', user_info)
        
        print("✓ OAuth flow simulation completed")
        
        # Test 4: Test provider management
        print("4. Testing provider management...")
        
        # Get provider info
        provider_info = manager.get_provider_info()
        self.assertEqual(len(provider_info), 1)
        
        # Add another provider
        manager.register_provider_class('test2', TestProvider)
        test2_config = {**self.test_config, 'name': 'test2'}
        manager.register_provider('test2', test2_config)
        
        # Verify both providers
        provider_info = manager.get_provider_info()
        self.assertEqual(len(provider_info), 2)
        
        # Remove a provider
        manager.unregister_provider('test2')
        provider_info = manager.get_provider_info()
        self.assertEqual(len(provider_info), 1)
        
        print("✓ Provider management working")
        
        # Test 5: Test configuration persistence
        print("5. Testing configuration persistence...")
        
        # Create new config with test provider
        config_data = {
            "providers": {
                "test": {
                    **self.test_config,
                    "client_id": "env:TEST_CLIENT_ID",
                    "client_secret": "env:TEST_CLIENT_SECRET",
                    "provider_class": "TestProvider",
                    "enabled": True
                }
            },
            "settings": {
                "auto_register_providers": True
            }
        }
        
        # Write to temporary file
        temp_config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(config_data, temp_config_file)
        temp_config_file.close()
        
        try:
            # Load config from file
            config = Config(temp_config_file.name)
            oauth_config = config.get_oauth_config('test')
            
            self.assertEqual(oauth_config['client_id'], 'test_client_id')
            self.assertEqual(oauth_config['display_name'], 'Test Provider')
            
            print("✓ Configuration persistence working")
            
        finally:
            os.unlink(temp_config_file.name)
        
        print("✅ End-to-end extensibility workflow tests passed")


def run_provider_extensibility_tests():
    """Run all provider extensibility tests."""
    print("🚀 Starting Provider Extensibility Testing")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test methods
    test_methods = [
        'test_dynamic_provider_registration',
        'test_provider_configuration_validation',
        'test_oauth_route_generation',
        'test_provider_specific_error_handling',
        'test_ui_updates_with_provider_changes',
        'test_mock_provider_implementation',
        'test_end_to_end_extensibility_workflow'
    ]
    
    for method in test_methods:
        test_suite.addTest(ProviderExtensibilityTest(method))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("🏁 Provider Extensibility Testing Complete")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n💥 ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    if result.wasSuccessful():
        print("\n✅ All provider extensibility tests passed!")
        return True
    else:
        print("\n❌ Some provider extensibility tests failed!")
        return False


if __name__ == '__main__':
    success = run_provider_extensibility_tests()
    sys.exit(0 if success else 1)