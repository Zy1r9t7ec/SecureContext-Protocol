"""
Provider Test Template

This template provides a comprehensive testing framework for new OAuth providers.
Copy this file and customize it for your specific provider implementation.

Usage:
1. Copy this file to tests/test_{provider_name}_provider.py
2. Replace all {PROVIDER_NAME} placeholders with your provider name
3. Replace all {provider_name} placeholders with your provider name (lowercase)
4. Customize test data and assertions for your provider's specific requirements
5. Add provider-specific test cases as needed

Example:
- {PROVIDER_NAME} -> GitHub
- {provider_name} -> github
- {ProviderClass} -> GitHubProvider
"""

import unittest
from unittest.mock import patch, MagicMock, Mock
import json
import sys
import os
from requests.exceptions import RequestException, ConnectionError, Timeout

# Add the authentication_proxy directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'authentication_proxy'))

from providers.{provider_name}_provider import {ProviderClass}
from providers.base_provider import BaseProvider, OAuthFlowError, ProviderConfigurationError


class Test{ProviderClass}(unittest.TestCase):
    """
    Comprehensive test suite for {PROVIDER_NAME} OAuth provider.
    
    This test suite covers all aspects of the {PROVIDER_NAME} provider implementation,
    including initialization, OAuth flow, error handling, and edge cases.
    """
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Standard provider configuration
        self.valid_config = {
            'client_id': 'test_client_id_123',
            'client_secret': 'test_client_secret_456',
            'scopes': ['scope1', 'scope2', 'scope3'],
            'display_name': '{PROVIDER_NAME} Test Account'
        }
        
        # Provider-specific configuration (customize as needed)
        self.provider_specific_config = {
            # Add any provider-specific configuration here
            # Example: 'tenant': 'common', 'api_version': 'v2.0'
        }
        
        # Merge configurations
        self.config = {**self.valid_config, **self.provider_specific_config}
        
        # Create provider instance
        self.provider = {ProviderClass}(self.config)
        
        # Test URLs and parameters
        self.test_redirect_uri = 'http://localhost:5000/oauth/{provider_name}/callback'
        self.test_state = 'test_state_parameter_123'
        self.test_code = 'test_authorization_code_456'
        
        # Mock token response (customize for your provider)
        self.mock_token_response = {
            'access_token': 'test_access_token_789',
            'refresh_token': 'test_refresh_token_012',
            'expires_in': 3600,
            'scope': 'scope1 scope2 scope3',
            'token_type': 'Bearer'
        }
        
        # Mock user info response (customize for your provider)
        self.mock_user_info = {
            'id': 'test_user_id_345',
            'email': 'test@example.com',
            'name': 'Test User',
            'login': 'testuser'  # Provider-specific field
        }
    
    # Initialization Tests
    
    def test_initialization_success(self):
        """Test successful provider initialization with valid configuration."""
        provider = {ProviderClass}(self.valid_config)
        
        self.assertEqual(provider.name, '{provider_name}')
        self.assertEqual(provider.client_id, 'test_client_id_123')
        self.assertEqual(provider.client_secret, 'test_client_secret_456')
        self.assertEqual(provider.scopes, ['scope1', 'scope2', 'scope3'])
        self.assertEqual(provider.display_name, '{PROVIDER_NAME} Test Account')
        
        # Test provider-specific attributes
        # Example: self.assertEqual(provider.tenant, 'common')
    
    def test_initialization_with_defaults(self):
        """Test provider initialization uses default values correctly."""
        minimal_config = {
            'client_id': 'test_client_id',
            'client_secret': 'test_client_secret'
        }
        
        provider = {ProviderClass}(minimal_config)
        
        # Verify default values are set
        self.assertIsNotNone(provider.authorize_url)
        self.assertIsNotNone(provider.token_url)
        self.assertIsNotNone(provider.display_name)
        self.assertIsInstance(provider.scopes, list)
    
    def test_initialization_missing_client_id(self):
        """Test provider initialization fails with missing client_id."""
        invalid_config = {
            'client_secret': 'test_client_secret'
        }
        
        with self.assertRaises(ProviderConfigurationError) as context:
            {ProviderClass}(invalid_config)
        
        self.assertIn('client_id', str(context.exception))
    
    def test_initialization_missing_client_secret(self):
        """Test provider initialization fails with missing client_secret."""
        invalid_config = {
            'client_id': 'test_client_id'
        }
        
        with self.assertRaises(ProviderConfigurationError) as context:
            {ProviderClass}(invalid_config)
        
        self.assertIn('client_secret', str(context.exception))
    
    def test_initialization_invalid_scopes(self):
        """Test provider initialization fails with invalid scopes format."""
        invalid_config = {
            'client_id': 'test_client_id',
            'client_secret': 'test_client_secret',
            'scopes': 'invalid_scope_format'  # Should be list, not string
        }
        
        with self.assertRaises(ProviderConfigurationError) as context:
            {ProviderClass}(invalid_config)
        
        self.assertIn('scopes', str(context.exception))
    
    # Authorization URL Tests
    
    def test_get_authorization_url_success(self):
        """Test successful authorization URL generation."""
        auth_url = self.provider.get_authorization_url(self.test_redirect_uri, self.test_state)
        
        # Verify URL structure
        self.assertIsInstance(auth_url, str)
        self.assertTrue(auth_url.startswith(self.provider.authorize_url))
        
        # Verify required parameters are present
        self.assertIn('client_id=test_client_id_123', auth_url)
        self.assertIn('redirect_uri=', auth_url)
        self.assertIn('state=test_state_parameter_123', auth_url)
        self.assertIn('response_type=code', auth_url)
        
        # Verify scopes are included (format may vary by provider)
        # Customize this assertion based on your provider's scope format
        self.assertIn('scope=', auth_url)
    
    def test_get_authorization_url_custom_scope(self):
        """Test authorization URL generation with custom scope."""
        custom_scope = 'custom_scope1 custom_scope2'
        auth_url = self.provider.get_authorization_url(
            self.test_redirect_uri, 
            self.test_state, 
            scope=custom_scope
        )
        
        self.assertIn('scope=custom_scope1', auth_url)
        self.assertIn('custom_scope2', auth_url)
    
    def test_get_authorization_url_provider_specific_params(self):
        """Test authorization URL generation with provider-specific parameters."""
        # Customize this test for your provider's specific parameters
        # Example for Microsoft: prompt, response_mode
        # Example for Google: access_type, prompt
        
        provider_params = {
            # Add provider-specific parameters here
            # Example: 'prompt': 'consent', 'access_type': 'offline'
        }
        
        auth_url = self.provider.get_authorization_url(
            self.test_redirect_uri, 
            self.test_state, 
            **provider_params
        )
        
        # Verify provider-specific parameters are included
        for param, value in provider_params.items():
            self.assertIn(f'{param}={value}', auth_url)
    
    def test_get_authorization_url_error_handling(self):
        """Test authorization URL generation error handling."""
        # Test with invalid parameters that should cause an error
        with patch.object(self.provider, 'authorize_url', None):
            with self.assertRaises(OAuthFlowError):
                self.provider.get_authorization_url(self.test_redirect_uri, self.test_state)
    
    # Token Exchange Tests
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_success(self, mock_post):
        """Test successful authorization code to token exchange."""
        # Mock successful HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_token_response
        mock_response.headers = {'content-type': 'application/json'}
        mock_post.return_value = mock_response
        
        # Execute token exchange
        result = self.provider.exchange_code_for_tokens(self.test_code, self.test_redirect_uri)
        
        # Verify request was made correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        
        # Verify request URL
        self.assertEqual(call_args[1]['data']['client_id'], 'test_client_id_123')
        self.assertEqual(call_args[1]['data']['client_secret'], 'test_client_secret_456')
        self.assertEqual(call_args[1]['data']['code'], self.test_code)
        self.assertEqual(call_args[1]['data']['grant_type'], 'authorization_code')
        self.assertEqual(call_args[1]['data']['redirect_uri'], self.test_redirect_uri)
        
        # Verify response format
        self.assertIsInstance(result, dict)
        self.assertEqual(result['access_token'], 'test_access_token_789')
        self.assertEqual(result['refresh_token'], 'test_refresh_token_012')
        self.assertEqual(result['expires_in'], 3600)
        self.assertEqual(result['scope'], 'scope1 scope2 scope3')
        self.assertEqual(result['token_type'], 'Bearer')
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_http_error(self, mock_post):
        """Test token exchange with HTTP error response."""
        # Mock HTTP error response
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            'error': 'invalid_grant',
            'error_description': 'Invalid authorization code'
        }
        mock_response.headers = {'content-type': 'application/json'}
        mock_post.return_value = mock_response
        
        # Verify exception is raised
        with self.assertRaises(OAuthFlowError) as context:
            self.provider.exchange_code_for_tokens(self.test_code, self.test_redirect_uri)
        
        self.assertIn('Token exchange failed', str(context.exception))
        self.assertIn('Invalid authorization code', str(context.exception))
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_network_error(self, mock_post):
        """Test token exchange with network connection error."""
        mock_post.side_effect = ConnectionError('Network connection failed')
        
        with self.assertRaises(OAuthFlowError) as context:
            self.provider.exchange_code_for_tokens(self.test_code, self.test_redirect_uri)
        
        self.assertIn('Network connection failed', str(context.exception))
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_timeout_error(self, mock_post):
        """Test token exchange with timeout error."""
        mock_post.side_effect = Timeout('Request timed out')
        
        with self.assertRaises(OAuthFlowError) as context:
            self.provider.exchange_code_for_tokens(self.test_code, self.test_redirect_uri)
        
        self.assertIn('Request timed out', str(context.exception))
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_invalid_response(self, mock_post):
        """Test token exchange with invalid token response."""
        # Mock response missing required fields
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'refresh_token': 'test_refresh_token',
            'expires_in': 3600
            # Missing access_token
        }
        mock_response.headers = {'content-type': 'application/json'}
        mock_post.return_value = mock_response
        
        with self.assertRaises(OAuthFlowError) as context:
            self.provider.exchange_code_for_tokens(self.test_code, self.test_redirect_uri)
        
        self.assertIn('Invalid token response', str(context.exception))
    
    @patch('requests.post')
    def test_exchange_code_for_tokens_json_decode_error(self, mock_post):
        """Test token exchange with invalid JSON response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError('Invalid JSON', '', 0)
        mock_response.headers = {'content-type': 'application/json'}
        mock_post.return_value = mock_response
        
        with self.assertRaises(OAuthFlowError):
            self.provider.exchange_code_for_tokens(self.test_code, self.test_redirect_uri)
    
    # Token Refresh Tests (if supported)
    
    @patch('requests.post')
    def test_refresh_access_token_success(self, mock_post):
        """Test successful access token refresh."""
        # Skip if provider doesn't support token refresh
        if not hasattr(self.provider, 'refresh_access_token'):
            self.skipTest('Provider does not support token refresh')
        
        # Mock successful refresh response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'new_access_token_123',
            'refresh_token': 'new_refresh_token_456',  # Some providers return new refresh token
            'expires_in': 3600,
            'scope': 'scope1 scope2 scope3',
            'token_type': 'Bearer'
        }
        mock_response.headers = {'content-type': 'application/json'}
        mock_post.return_value = mock_response
        
        result = self.provider.refresh_access_token('old_refresh_token')
        
        # Verify request
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]['data']['grant_type'], 'refresh_token')
        self.assertEqual(call_args[1]['data']['refresh_token'], 'old_refresh_token')
        
        # Verify response
        self.assertIsInstance(result, dict)
        self.assertEqual(result['access_token'], 'new_access_token_123')
    
    @patch('requests.post')
    def test_refresh_access_token_error(self, mock_post):
        """Test access token refresh with error."""
        # Skip if provider doesn't support token refresh
        if not hasattr(self.provider, 'refresh_access_token'):
            self.skipTest('Provider does not support token refresh')
        
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            'error': 'invalid_grant',
            'error_description': 'Refresh token expired'
        }
        mock_response.headers = {'content-type': 'application/json'}
        mock_post.return_value = mock_response
        
        with self.assertRaises(OAuthFlowError):
            self.provider.refresh_access_token('expired_refresh_token')
    
    # User Info Tests (if supported)
    
    @patch('requests.get')
    def test_get_user_info_success(self, mock_get):
        """Test successful user information retrieval."""
        # Skip if provider doesn't support user info
        if not hasattr(self.provider, 'get_user_info'):
            self.skipTest('Provider does not support user info retrieval')
        
        # Mock successful user info response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_user_info
        mock_response.headers = {'content-type': 'application/json'}
        mock_get.return_value = mock_response
        
        result = self.provider.get_user_info('test_access_token')
        
        # Verify request
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        self.assertIn('Authorization', call_args[1]['headers'])
        self.assertEqual(call_args[1]['headers']['Authorization'], 'Bearer test_access_token')
        
        # Verify response (customize based on your provider's user info format)
        self.assertIsInstance(result, dict)
        self.assertIn('id', result)
        self.assertIn('email', result)
    
    @patch('requests.get')
    def test_get_user_info_unauthorized(self, mock_get):
        """Test user info retrieval with unauthorized access token."""
        # Skip if provider doesn't support user info
        if not hasattr(self.provider, 'get_user_info'):
            self.skipTest('Provider does not support user info retrieval')
        
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {'content-type': 'application/json'}
        mock_get.return_value = mock_response
        
        with self.assertRaises(OAuthFlowError):
            self.provider.get_user_info('invalid_access_token')
    
    # Scope Validation Tests
    
    def test_validate_scopes_valid(self):
        """Test scope validation with valid scopes."""
        valid_scopes = ['scope1', 'scope2']
        result = self.provider.validate_scopes(valid_scopes)
        self.assertTrue(result)
    
    def test_validate_scopes_invalid(self):
        """Test scope validation with invalid scopes."""
        invalid_scopes = ['invalid_scope', 'another_invalid_scope']
        result = self.provider.validate_scopes(invalid_scopes)
        self.assertFalse(result)
    
    def test_validate_scopes_mixed(self):
        """Test scope validation with mix of valid and invalid scopes."""
        mixed_scopes = ['scope1', 'invalid_scope']
        result = self.provider.validate_scopes(mixed_scopes)
        self.assertFalse(result)
    
    def test_validate_scopes_empty(self):
        """Test scope validation with empty scope list."""
        empty_scopes = []
        result = self.provider.validate_scopes(empty_scopes)
        self.assertTrue(result)  # Empty list should be valid
    
    # Utility Method Tests
    
    def test_generate_state(self):
        """Test state parameter generation."""
        state1 = self.provider.generate_state()
        state2 = self.provider.generate_state()
        
        # Verify state parameters are strings
        self.assertIsInstance(state1, str)
        self.assertIsInstance(state2, str)
        
        # Verify state parameters are unique
        self.assertNotEqual(state1, state2)
        
        # Verify state parameters have reasonable length
        self.assertGreater(len(state1), 20)
        self.assertGreater(len(state2), 20)
    
    def test_validate_state_success(self):
        """Test successful state parameter validation."""
        test_state = 'test_state_123'
        result = self.provider.validate_state(test_state, test_state)
        self.assertTrue(result)
    
    def test_validate_state_mismatch(self):
        """Test state parameter validation with mismatch."""
        result = self.provider.validate_state('state1', 'state2')
        self.assertFalse(result)
    
    def test_validate_state_missing(self):
        """Test state parameter validation with missing values."""
        result = self.provider.validate_state(None, 'stored_state')
        self.assertFalse(result)
        
        result = self.provider.validate_state('received_state', None)
        self.assertFalse(result)
        
        result = self.provider.validate_state(None, None)
        self.assertFalse(result)
    
    def test_parse_oauth_error(self):
        """Test OAuth error parsing."""
        error_code, user_message = self.provider.parse_oauth_error(
            'access_denied', 
            'User denied access'
        )
        
        self.assertEqual(error_code, 'access_denied')
        self.assertIn('cancelled', user_message.lower())
    
    def test_get_provider_info(self):
        """Test provider information retrieval."""
        info = self.provider.get_provider_info()
        
        self.assertIsInstance(info, dict)
        self.assertEqual(info['name'], '{provider_name}')
        self.assertEqual(info['display_name'], self.provider.display_name)
        self.assertEqual(info['scopes'], self.provider.scopes)
        self.assertIn('supports_refresh', info)
        self.assertIn('supports_user_info', info)
    
    # Provider-Specific Tests
    
    def test_provider_specific_functionality(self):
        """
        Test provider-specific functionality.
        
        Customize this method to test any unique features of your provider.
        Examples:
        - Tenant-specific URLs (Microsoft)
        - Custom authentication flows
        - Provider-specific API endpoints
        - Special parameter handling
        """
        # Add provider-specific tests here
        pass
    
    # Edge Cases and Security Tests
    
    def test_large_scope_list(self):
        """Test handling of large scope lists."""
        large_scope_list = [f'scope_{i}' for i in range(100)]
        
        # This should not crash the provider
        try:
            auth_url = self.provider.get_authorization_url(
                self.test_redirect_uri, 
                self.test_state, 
                scope=' '.join(large_scope_list)
            )
            self.assertIsInstance(auth_url, str)
        except Exception as e:
            self.fail(f"Provider failed to handle large scope list: {e}")
    
    def test_special_characters_in_parameters(self):
        """Test handling of special characters in parameters."""
        special_redirect_uri = 'http://localhost:5000/callback?param=value&other=test'
        special_state = 'state_with_special_chars_!@#$%^&*()'
        
        try:
            auth_url = self.provider.get_authorization_url(special_redirect_uri, special_state)
            self.assertIsInstance(auth_url, str)
        except Exception as e:
            self.fail(f"Provider failed to handle special characters: {e}")
    
    def test_unicode_handling(self):
        """Test handling of Unicode characters."""
        unicode_state = 'state_with_unicode_测试_🔒'
        
        try:
            auth_url = self.provider.get_authorization_url(self.test_redirect_uri, unicode_state)
            self.assertIsInstance(auth_url, str)
        except Exception as e:
            self.fail(f"Provider failed to handle Unicode characters: {e}")
    
    # Performance Tests
    
    def test_multiple_authorization_urls(self):
        """Test generating multiple authorization URLs quickly."""
        import time
        
        start_time = time.time()
        
        for i in range(100):
            state = f'state_{i}'
            auth_url = self.provider.get_authorization_url(self.test_redirect_uri, state)
            self.assertIsInstance(auth_url, str)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete within reasonable time (adjust threshold as needed)
        self.assertLess(duration, 1.0, "Authorization URL generation is too slow")
    
    def test_concurrent_state_generation(self):
        """Test concurrent state parameter generation."""
        import threading
        
        states = []
        
        def generate_states():
            for _ in range(10):
                states.append(self.provider.generate_state())
        
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=generate_states)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify all states are unique
        self.assertEqual(len(states), len(set(states)), "Generated states are not unique")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)