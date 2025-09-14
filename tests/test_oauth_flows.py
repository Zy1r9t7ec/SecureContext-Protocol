"""
Unit tests for OAuth flow handlers.

This module tests OAuth authorization endpoints, callback handling, token exchange,
and error scenarios including user denial and invalid codes.
"""

import unittest
import json
import uuid
from unittest.mock import patch, MagicMock, Mock
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from authentication_proxy.app import create_app, TokenStorage, token_storage, storage_lock
from authlib.common.errors import AuthlibBaseError
from requests.exceptions import RequestException, ConnectionError, Timeout


class TestOAuthFlows(unittest.TestCase):
    """Test cases for OAuth flow handlers."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create test app
        self.app, self.socketio = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        # Clear token storage before each test
        with storage_lock:
            token_storage.clear()
    
    def tearDown(self):
        """Clean up after each test method."""
        # Clear token storage after each test
        with storage_lock:
            token_storage.clear()
    
    # Google OAuth Authorization Tests
    
    def test_google_authorize_success(self):
        """Test successful Google OAuth authorization initiation."""
        # Test the authorization endpoint with real provider
        response = self.client.get('/oauth/google/authorize')
        
        # Verify redirect response
        self.assertEqual(response.status_code, 302)
        self.assertIn('accounts.google.com', response.location)
        
        # Verify state was stored in session
        with self.client.session_transaction() as sess:
            self.assertIsNotNone(sess.get('oauth_state'))
            self.assertEqual(sess.get('oauth_provider'), 'google')
    
    def test_google_authorize_authlib_error(self):
        """Test Google OAuth authorization with Authlib error."""
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.display_name = 'Google Account'
            mock_provider.generate_state.return_value = 'test_state_token'
            # Mock OAuth flow error during authorization
            from authentication_proxy.providers.base_provider import OAuthFlowError
            mock_provider.get_authorization_url.side_effect = OAuthFlowError("OAuth authorization failed")
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/authorize')
            
            # Should redirect to index with error
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=oauth_flow_error', response.location)
    
    def test_google_authorize_unexpected_error(self):
        """Test Google OAuth authorization with unexpected error."""
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.display_name = 'Google Account'
            mock_provider.generate_state.return_value = 'test_state_token'
            mock_provider.get_authorization_url.side_effect = Exception('Unexpected error')
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/authorize')
            
            # Should redirect to index with error
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=authorization_error', response.location)
    
    # Google OAuth Callback Tests
    
    def test_google_callback_user_denial(self):
        """Test Google OAuth callback when user denies access."""
        response = self.client.get('/oauth/google/callback?error=access_denied&error_description=User%20denied%20access')
        
        # Should redirect to index with access denied error
        self.assertEqual(response.status_code, 302)
        self.assertIn('error=access_denied', response.location)
        self.assertIn('You+cancelled+the+authorization', response.location)
    
    def test_google_callback_invalid_request_error(self):
        """Test Google OAuth callback with invalid request error."""
        response = self.client.get('/oauth/google/callback?error=invalid_request&error_description=Invalid%20request')
        
        # Should redirect to index with invalid request error
        self.assertEqual(response.status_code, 302)
        self.assertIn('error=invalid_request', response.location)
    
    def test_google_callback_unauthorized_client_error(self):
        """Test Google OAuth callback with unauthorized client error."""
        response = self.client.get('/oauth/google/callback?error=unauthorized_client')
        
        # Should redirect to index with unauthorized client error
        self.assertEqual(response.status_code, 302)
        self.assertIn('error=unauthorized_client', response.location)
    
    def test_google_callback_missing_state(self):
        """Test Google OAuth callback with missing state parameter."""
        response = self.client.get('/oauth/google/callback?code=test_code')
        
        # Should redirect to index with missing state error
        self.assertEqual(response.status_code, 302)
        self.assertIn('error=missing_state', response.location)
    
    def test_google_callback_session_expired(self):
        """Test Google OAuth callback when session state is missing."""
        response = self.client.get('/oauth/google/callback?code=test_code&state=test_state')
        
        # Should redirect to index with session expired error
        self.assertEqual(response.status_code, 302)
        self.assertIn('error=session_expired', response.location)
    
    def test_google_callback_state_mismatch(self):
        """Test Google OAuth callback with state parameter mismatch."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'stored_state'
            sess['oauth_provider'] = 'google'  # Set provider to avoid provider mismatch
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = False  # State validation fails
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/callback?code=test_code&state=different_state')
            
            # Should redirect to index with state mismatch error
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=state_mismatch', response.location)
    
    def test_google_callback_successful_token_exchange(self):
        """Test successful Google OAuth callback with token exchange."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['oauth_provider'] = 'google'
        
        # Mock the Google provider token exchange
        mock_token_response = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'expires_in': 3600,
            'scope': 'profile email'
        }
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            mock_provider.exchange_code_for_tokens.return_value = mock_token_response
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/callback?code=test_code&state=test_state')
            
            # Should redirect to index with session ID
            self.assertEqual(response.status_code, 302)
            # Check that a session_id parameter exists (any valid UUID4)
            self.assertIn('session_id=', response.location)
            
            # Extract and validate the session ID
            import re
            session_id_match = re.search(r'session_id=([^&]+)', response.location)
            self.assertIsNotNone(session_id_match)
            session_id = session_id_match.group(1)
            
            # Verify it's a valid UUID4
            import uuid
            try:
                parsed_uuid = uuid.UUID(session_id)
                self.assertEqual(parsed_uuid.version, 4)
            except ValueError:
                self.fail(f"Session ID {session_id} is not a valid UUID4")
            
            # Verify token was actually stored by trying to retrieve it
            stored_token = TokenStorage.retrieve_tokens(session_id)
            self.assertIsNotNone(stored_token)
            self.assertEqual(stored_token['provider'], 'google')
            self.assertEqual(stored_token['access_token'], 'test_access_token')
    
    def test_google_callback_token_exchange_failure(self):
        """Test Google OAuth callback when token exchange fails."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['oauth_provider'] = 'google'
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            from authentication_proxy.providers.base_provider import OAuthFlowError
            mock_provider.exchange_code_for_tokens.side_effect = OAuthFlowError("Token exchange failed")
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/callback?code=test_code&state=test_state')
            
            # Should redirect to index with OAuth flow error
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=oauth_flow_error', response.location)
    
    def test_google_callback_missing_access_token(self):
        """Test Google OAuth callback when access token is missing from response."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['oauth_provider'] = 'google'
        
        mock_token_response = {
            'refresh_token': 'test_refresh_token',
            'expires_in': 3600,
            'scope': 'profile email'
            # Missing access_token
        }
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            mock_provider.exchange_code_for_tokens.return_value = mock_token_response
            mock_get_provider.return_value = mock_provider
            
            # This should cause a ValueError when storing tokens due to missing access_token
            response = self.client.get('/oauth/google/callback?code=test_code&state=test_state')
            
            # Should redirect to index with callback error
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=callback_error', response.location)
    
    def test_google_callback_authlib_error(self):
        """Test Google OAuth callback with Authlib error during token exchange."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['oauth_provider'] = 'google'
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            from authentication_proxy.providers.base_provider import OAuthFlowError
            mock_provider.exchange_code_for_tokens.side_effect = OAuthFlowError("Authlib error")
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/callback?code=test_code&state=test_state')
            
            # Should redirect to index with OAuth flow error
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=oauth_flow_error', response.location)
    
    # Microsoft OAuth Authorization Tests
    
    @patch('authentication_proxy.app.secrets.token_urlsafe')
    def test_microsoft_authorize_success(self, mock_token_urlsafe):
        """Test successful Microsoft OAuth authorization initiation."""
        mock_token_urlsafe.return_value = 'test_state_token'
        
        # Mock the Microsoft provider to return a proper authorization URL
        mock_auth_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test&state=test_state_token'
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.display_name = 'Microsoft Account'
            mock_provider.generate_state.return_value = 'test_state_token'
            mock_provider.get_authorization_url.return_value = mock_auth_url
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/microsoft/authorize')
            
            # Verify redirect response
            self.assertEqual(response.status_code, 302)
            self.assertIn('login.microsoftonline.com', response.location)
            
            # Verify provider methods were called
            mock_provider.generate_state.assert_called_once()
            mock_provider.get_authorization_url.assert_called_once()
            
            # Verify state was stored in session
            with self.client.session_transaction() as sess:
                self.assertEqual(sess.get('oauth_state'), 'test_state_token')
                self.assertEqual(sess.get('oauth_provider'), 'microsoft')
    
    def test_microsoft_authorize_authlib_error(self):
        """Test Microsoft OAuth authorization with Authlib error."""
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.display_name = 'Microsoft Account'
            mock_provider.generate_state.return_value = 'test_state_token'
            from authentication_proxy.providers.base_provider import OAuthFlowError
            mock_provider.get_authorization_url.side_effect = OAuthFlowError("OAuth authorization failed")
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/microsoft/authorize')
            
            # Should redirect to index with error
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=oauth_flow_error', response.location)
    
    # Microsoft OAuth Callback Tests
    
    def test_microsoft_callback_user_denial(self):
        """Test Microsoft OAuth callback when user denies access."""
        response = self.client.get('/oauth/microsoft/callback?error=access_denied')
        
        # Should redirect to index with access denied error
        self.assertEqual(response.status_code, 302)
        self.assertIn('error=access_denied', response.location)
    
    def test_microsoft_callback_successful_token_exchange(self):
        """Test successful Microsoft OAuth callback with token exchange."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['oauth_provider'] = 'microsoft'
        
        # Mock the Microsoft provider token exchange
        mock_token_response = {
            'access_token': 'ms_access_token',
            'refresh_token': 'ms_refresh_token',
            'expires_in': 7200,
            'scope': 'User.Read Mail.Read'
        }
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            mock_provider.exchange_code_for_tokens.return_value = mock_token_response
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/microsoft/callback?code=test_code&state=test_state')
            
            # Should redirect to index with session ID
            self.assertEqual(response.status_code, 302)
            self.assertIn('session_id=', response.location)
            
            # Extract and validate the session ID
            import re
            session_id_match = re.search(r'session_id=([^&]+)', response.location)
            self.assertIsNotNone(session_id_match)
            session_id = session_id_match.group(1)
            
            # Verify token was actually stored by trying to retrieve it
            stored_token = TokenStorage.retrieve_tokens(session_id)
            self.assertIsNotNone(stored_token)
            self.assertEqual(stored_token['provider'], 'microsoft')
            self.assertEqual(stored_token['access_token'], 'ms_access_token')
    
    def test_microsoft_callback_state_validation(self):
        """Test Microsoft OAuth callback state validation."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'stored_state'
            sess['oauth_provider'] = 'microsoft'  # Set provider to avoid provider mismatch
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = False  # State validation fails
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/microsoft/callback?code=test_code&state=different_state')
            
            # Should redirect to index with state mismatch error
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=state_mismatch', response.location)
    
    # Network Error Tests
    
    def test_google_callback_connection_error(self):
        """Test Google OAuth callback with network connection error."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['oauth_provider'] = 'google'
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            mock_provider.exchange_code_for_tokens.side_effect = ConnectionError('Network error')
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/callback?code=test_code&state=test_state')
            
            # Should redirect to index with callback error (generic error handling)
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=callback_error', response.location)
    
    def test_microsoft_callback_timeout_error(self):
        """Test Microsoft OAuth callback with timeout error."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['oauth_provider'] = 'microsoft'
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            from requests.exceptions import Timeout
            mock_provider.exchange_code_for_tokens.side_effect = Timeout('Request timeout')
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/microsoft/callback?code=test_code&state=test_state')
            
            # Should redirect to index with callback error (generic error handling)
            self.assertEqual(response.status_code, 302)
            self.assertIn('error=callback_error', response.location)
    
    # Edge Cases and Security Tests
    
    def test_oauth_state_cleared_after_callback(self):
        """Test that OAuth state is cleared from session after callback."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['oauth_provider'] = 'google'
        
        mock_token_response = {
            'access_token': 'test_token',
            'refresh_token': 'test_refresh',
            'expires_in': 3600,
            'scope': 'test'
        }
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            mock_provider.exchange_code_for_tokens.return_value = mock_token_response
            mock_get_provider.return_value = mock_provider
            
            with patch('authentication_proxy.app.TokenStorage.store_tokens', return_value='session_id'):
                response = self.client.get('/oauth/google/callback?code=test_code&state=test_state')
                
                # Verify state was cleared from session
                with self.client.session_transaction() as sess:
                    self.assertNotIn('oauth_state', sess)
                    self.assertNotIn('oauth_provider', sess)
    
    def test_oauth_callback_with_empty_code(self):
        """Test OAuth callback with empty authorization code."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
        
        response = self.client.get('/oauth/google/callback?code=&state=test_state')
        
        # Should handle gracefully (depends on OAuth client implementation)
        self.assertEqual(response.status_code, 302)
    
    def test_oauth_callback_with_malformed_parameters(self):
        """Test OAuth callback with malformed parameters."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
        
        # Test with malformed state parameter
        response = self.client.get('/oauth/google/callback?code=test_code&state=')
        
        # Should redirect with missing state error
        self.assertEqual(response.status_code, 302)
        self.assertIn('error=missing_state', response.location)
    
    def test_multiple_oauth_flows_isolation(self):
        """Test that multiple OAuth flows don't interfere with each other."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'google_state'
            sess['oauth_provider'] = 'google'
        
        # Test Google callback
        mock_token_response = {
            'access_token': 'google_token',
            'refresh_token': 'google_refresh',
            'expires_in': 3600,
            'scope': 'google_scope'
        }
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            mock_provider.exchange_code_for_tokens.return_value = mock_token_response
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/callback?code=google_code&state=google_state')
            
            # Should redirect to index with session ID
            self.assertEqual(response.status_code, 302)
            self.assertIn('session_id=', response.location)
            
            # Extract session ID and verify token was stored
            import re
            session_id_match = re.search(r'session_id=([^&]+)', response.location)
            self.assertIsNotNone(session_id_match)
            session_id = session_id_match.group(1)
            
            # Verify Google tokens were stored correctly
            stored_token = TokenStorage.retrieve_tokens(session_id)
            self.assertIsNotNone(stored_token)
            self.assertEqual(stored_token['provider'], 'google')
            self.assertEqual(stored_token['access_token'], 'google_token')
    
    def test_oauth_error_handling_comprehensive(self):
        """Test comprehensive OAuth error handling scenarios."""
        error_scenarios = [
            ('invalid_request', 'invalid_request'),
            ('unauthorized_client', 'unauthorized_client'),
            ('unsupported_response_type', 'unsupported_response_type'),
            ('invalid_scope', 'invalid_scope'),
            ('server_error', 'server_error'),
            ('temporarily_unavailable', 'temporarily_unavailable')
        ]
        
        for error_code, expected_error in error_scenarios:
            with self.subTest(error_code=error_code):
                response = self.client.get(f'/oauth/google/callback?error={error_code}&error_description=Test%20error')
                
                self.assertEqual(response.status_code, 302)
                self.assertIn(f'error={expected_error}', response.location)


if __name__ == '__main__':
    unittest.main()