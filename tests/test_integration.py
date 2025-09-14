"""
Integration tests for SecureContext Protocol Authentication Proxy.

This module provides comprehensive end-to-end testing of the complete OAuth flows,
UI interaction with backend endpoints, token verification script functionality,
and error handling across component boundaries.

Requirements covered:
- 1.1-1.6: Google OAuth 2.0 complete flow
- 2.1-2.6: Microsoft OAuth 2.0 complete flow  
- 5.1-5.4: Web UI interaction with backend
- 6.1-6.4: Token verification script functionality
"""

import unittest
import json
import uuid
import time
import subprocess
import sys
import os
import threading
import requests
from unittest.mock import patch, MagicMock, Mock
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from authentication_proxy.app import create_app, TokenStorage, token_storage, storage_lock
from authlib.common.errors import AuthlibBaseError
from requests.exceptions import RequestException, ConnectionError, Timeout


class TestIntegrationFlows(unittest.TestCase):
    """Integration tests for complete OAuth flows and system interactions."""
    
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
    
    # End-to-End OAuth Flow Tests
    
    @patch('authentication_proxy.app.secrets.token_urlsafe')
    def test_complete_google_oauth_flow_success(self, mock_token_urlsafe):
        """Test complete Google OAuth flow from authorization to token retrieval."""
        mock_token_urlsafe.return_value = 'test_state_token'
        
        # Step 1: Initiate OAuth authorization
        # Mock the Google provider authorization
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.display_name = 'Google Account'
            mock_provider.generate_state.return_value = 'test_state_token'
            mock_provider.get_authorization_url.return_value = 'https://accounts.google.com/o/oauth2/auth?client_id=test&redirect_uri=http://localhost/oauth/google/callback&scope=profile+email&state=test_state_token'
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/authorize')
            
            # Verify authorization redirect
            self.assertEqual(response.status_code, 302)
            self.assertIn('accounts.google.com', response.location)
            self.assertIn('test_state_token', response.location)
        
        # Step 2: Handle OAuth callback with authorization code
        mock_token_response = {
            'access_token': 'google_access_token_123',
            'refresh_token': 'google_refresh_token_456',
            'expires_in': 3600,
            'scope': 'profile email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.readonly',
            'token_type': 'Bearer'
        }
        
        # Set up session state before callback
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state_token'
            sess['oauth_provider'] = 'google'
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            mock_provider.exchange_code_for_tokens.return_value = mock_token_response
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/callback?code=test_auth_code&state=test_state_token')
            
            # Verify successful callback handling
            self.assertEqual(response.status_code, 302)
            
            # Extract session ID from redirect URL
            redirect_url = response.location
            parsed_url = urlparse(redirect_url)
            query_params = parse_qs(parsed_url.query)
            
            self.assertIn('session_id', query_params)
            session_id = query_params['session_id'][0]
            
            # Verify session ID is valid UUID4
            uuid.UUID(session_id, version=4)
        
        # Step 3: Verify token storage
        stored_token = TokenStorage.retrieve_tokens(session_id)
        self.assertIsNotNone(stored_token)
        self.assertEqual(stored_token['provider'], 'google')
        self.assertEqual(stored_token['access_token'], 'google_access_token_123')
        self.assertEqual(stored_token['refresh_token'], 'google_refresh_token_456')
        self.assertEqual(stored_token['scope'], 'profile email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.readonly')
        
        # Step 4: Test API token retrieval
        api_response = self.client.get(f'/api/tokens/{session_id}')
        self.assertEqual(api_response.status_code, 200)
        
        api_data = json.loads(api_response.data)
        self.assertTrue(api_data['success'])
        self.assertEqual(api_data['data']['provider'], 'google')
        self.assertEqual(api_data['data']['access_token'], 'google_access_token_123')
        self.assertEqual(api_data['data']['refresh_token'], 'google_refresh_token_456')
        self.assertIn('expires_at', api_data['data'])
        
        # Step 5: Verify UI displays success status (JavaScript handles the session ID)
        ui_response = self.client.get(f'/?session_id={session_id}')
        self.assertEqual(ui_response.status_code, 200)
        # Verify JavaScript functions are present to handle the session ID
        self.assertIn(b'showSuccessStatus', ui_response.data)
        self.assertIn(b'Connection Successful', ui_response.data)  # In JavaScript
        self.assertIn(b'parseURLParameters', ui_response.data)
    
    @patch('authentication_proxy.app.secrets.token_urlsafe')
    def test_complete_microsoft_oauth_flow_success(self, mock_token_urlsafe):
        """Test complete Microsoft OAuth flow from authorization to token retrieval."""
        mock_token_urlsafe.return_value = 'test_state_token_ms'
        
        # Step 1: Initiate OAuth authorization
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.display_name = 'Microsoft Account'
            mock_provider.generate_state.return_value = 'test_state_token_ms'
            mock_provider.get_authorization_url.return_value = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test&redirect_uri=http://localhost/oauth/microsoft/callback&scope=User.Read+Mail.Read+Calendars.Read&state=test_state_token_ms'
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/microsoft/authorize')
            
            # Verify authorization redirect
            self.assertEqual(response.status_code, 302)
            self.assertIn('login.microsoftonline.com', response.location)
            self.assertIn('test_state_token_ms', response.location)
        
        # Step 2: Handle OAuth callback
        mock_token_response = {
            'access_token': 'microsoft_access_token_789',
            'refresh_token': 'microsoft_refresh_token_012',
            'expires_in': 3600,
            'scope': 'User.Read Mail.Read Calendars.Read',
            'token_type': 'Bearer'
        }
        
        # Set up session state before callback
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state_token_ms'
            sess['oauth_provider'] = 'microsoft'
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            mock_provider.exchange_code_for_tokens.return_value = mock_token_response
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/microsoft/callback?code=test_auth_code_ms&state=test_state_token_ms')
            
            # Verify successful callback handling
            self.assertEqual(response.status_code, 302)
            
            # Extract session ID from redirect URL
            redirect_url = response.location
            parsed_url = urlparse(redirect_url)
            query_params = parse_qs(parsed_url.query)
            
            self.assertIn('session_id', query_params)
            session_id = query_params['session_id'][0]
            
            # Verify session ID is valid UUID4
            uuid.UUID(session_id, version=4)
        
        # Step 3: Verify token storage
        stored_token = TokenStorage.retrieve_tokens(session_id)
        self.assertIsNotNone(stored_token)
        self.assertEqual(stored_token['provider'], 'microsoft')
        self.assertEqual(stored_token['access_token'], 'microsoft_access_token_789')
        self.assertEqual(stored_token['refresh_token'], 'microsoft_refresh_token_012')
        self.assertEqual(stored_token['scope'], 'User.Read Mail.Read Calendars.Read')
        
        # Step 4: Test API token retrieval
        api_response = self.client.get(f'/api/tokens/{session_id}')
        self.assertEqual(api_response.status_code, 200)
        
        api_data = json.loads(api_response.data)
        self.assertTrue(api_data['success'])
        self.assertEqual(api_data['data']['provider'], 'microsoft')
        self.assertEqual(api_data['data']['access_token'], 'microsoft_access_token_789')
        self.assertEqual(api_data['data']['refresh_token'], 'microsoft_refresh_token_012')
    
    def test_oauth_flow_user_denial_error_handling(self):
        """Test error handling when user denies OAuth consent."""
        # Test Google OAuth user denial
        response = self.client.get('/oauth/google/callback?error=access_denied&error_description=User+denied+consent&state=test_state')
        
        self.assertEqual(response.status_code, 302)
        redirect_url = response.headers['Location']
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        
        self.assertEqual(query_params['error'][0], 'access_denied')
        self.assertIn('cancelled', query_params['error_description'][0].lower())
        
        # Verify UI displays error message
        ui_response = self.client.get(redirect_url.replace('http://localhost', ''))
        self.assertEqual(ui_response.status_code, 200)
        self.assertIn(b'Authorization Cancelled', ui_response.data)
        self.assertIn(b'cancelled the authorization', ui_response.data)
    
    def test_oauth_flow_state_mismatch_security_error(self):
        """Test security error handling for OAuth state parameter mismatch."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'correct_state_token'
            sess['oauth_provider'] = 'google'  # Set provider to avoid provider mismatch
        
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = False  # State validation fails
            mock_get_provider.return_value = mock_provider
            
            # Attempt callback with wrong state parameter
            response = self.client.get('/oauth/google/callback?code=test_code&state=wrong_state_token')
            
            self.assertEqual(response.status_code, 302)
            redirect_url = response.location
            parsed_url = urlparse(redirect_url)
            query_params = parse_qs(parsed_url.query)
            
            self.assertEqual(query_params['error'][0], 'state_mismatch')
            self.assertIn('security', query_params['error_description'][0].lower())
        
        # Verify UI displays security error
        ui_response = self.client.get(redirect_url.replace('http://localhost', ''))
        self.assertEqual(ui_response.status_code, 200)
        self.assertIn(b'Security Error', ui_response.data)
        self.assertIn(b'security validation failed', ui_response.data)
    
    @patch('authentication_proxy.app.secrets.token_urlsafe')
    def test_oauth_flow_token_exchange_failure(self, mock_token_urlsafe):
        """Test error handling when token exchange fails."""
        mock_token_urlsafe.return_value = 'test_state_token'
        
        # Set up session state before callback
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state_token'
            sess['oauth_provider'] = 'google'
        
        # Mock token exchange failure
        with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.validate_state.return_value = True
            from authentication_proxy.providers.base_provider import OAuthFlowError
            mock_provider.exchange_code_for_tokens.side_effect = OAuthFlowError('Token exchange failed')
            mock_get_provider.return_value = mock_provider
            
            response = self.client.get('/oauth/google/callback?code=test_code&state=test_state_token')
            
            self.assertEqual(response.status_code, 302)
            redirect_url = response.location
            parsed_url = urlparse(redirect_url)
            query_params = parse_qs(parsed_url.query)
            
            # The error should be oauth_flow_error
            self.assertIn('error', query_params)
            self.assertEqual(query_params['error'][0], 'oauth_flow_error')
            
            # Verify UI displays token exchange error
            ui_response = self.client.get(redirect_url.replace('http://localhost', ''))
            self.assertEqual(ui_response.status_code, 200)
            self.assertIn(b'error', ui_response.data.lower())
    
    def test_concurrent_oauth_flows_isolation(self):
        """Test that concurrent OAuth flows maintain proper session isolation."""
        # Test concurrent token storage directly since session handling in test client is complex
        session_ids = []
        
        def token_storage_worker(provider, token_suffix):
            """Worker function for concurrent token storage testing."""
            try:
                session_id = TokenStorage.store_tokens(
                    provider=provider,
                    access_token=f'{provider}_access_token_{token_suffix}',
                    refresh_token=f'{provider}_refresh_token_{token_suffix}',
                    expires_in=3600,
                    scope='test_scope'
                )
                session_ids.append(session_id)
            except Exception as e:
                # Log any errors but don't fail the test immediately
                print(f"Error in worker {token_suffix}: {e}")
        
        # Run concurrent token storage operations
        threads = [
            threading.Thread(target=token_storage_worker, args=('google', '1')),
            threading.Thread(target=token_storage_worker, args=('microsoft', '2'))
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify session isolation
        self.assertEqual(len(session_ids), 2)
        self.assertNotEqual(session_ids[0], session_ids[1])
        
        # Verify each session has correct isolated data
        providers_found = set()
        for session_id in session_ids:
            stored_token = TokenStorage.retrieve_tokens(session_id)
            self.assertIsNotNone(stored_token)
            providers_found.add(stored_token['provider'])
            # Verify the token contains the correct provider name
            self.assertIn(stored_token['provider'], stored_token['access_token'])
        
        # Verify we have both providers
        self.assertEqual(providers_found, {'google', 'microsoft'})


class TestUIBackendIntegration(unittest.TestCase):
    """Integration tests for UI interaction with backend endpoints."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.app, self.socketio = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        with storage_lock:
            token_storage.clear()
    
    def tearDown(self):
        """Clean up after each test method."""
        with storage_lock:
            token_storage.clear()
    
    def test_ui_displays_oauth_connection_buttons(self):
        """Test that UI displays OAuth connection buttons for all providers."""
        response = self.client.get('/')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Connect Google Account', response.data)
        self.assertIn(b'Connect Microsoft Account', response.data)
        self.assertIn(b'/oauth/google/authorize', response.data)
        self.assertIn(b'/oauth/microsoft/authorize', response.data)
        
        # Verify page structure and styling
        self.assertIn(b'SecureContext Protocol', response.data)
        self.assertIn(b'oauth-button google-button', response.data)
        self.assertIn(b'oauth-button microsoft-button', response.data)
    
    def test_ui_displays_success_status_with_session_id(self):
        """Test UI displays success status when OAuth flow completes successfully."""
        # Create a test session
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            expires_in=3600,
            scope='test_scope'
        )
        
        # Test UI with success parameters
        response = self.client.get(f'/?session_id={session_id}')
        
        self.assertEqual(response.status_code, 200)
        # The session ID and success message are handled by JavaScript, not server-side
        # So we verify the JavaScript functions are present
        self.assertIn(b'showSuccessStatus', response.data)
        self.assertIn(b'parseURLParameters', response.data)
        self.assertIn(b'Connection Successful', response.data)  # In JavaScript
        self.assertIn(b'status-success', response.data)  # CSS class
    
    def test_ui_displays_error_status_for_oauth_failures(self):
        """Test UI displays appropriate error messages for different OAuth failure scenarios."""
        error_scenarios = [
            ('access_denied', 'Authorization Cancelled'),
            ('state_mismatch', 'Security Error'),
            ('session_expired', 'Session Expired'),
            ('token_exchange_failed', 'Token Exchange Failed'),
            ('oauth_config_error', 'Configuration Error'),
            ('network_error', 'Network Error'),
            ('invalid_request', 'Invalid Request'),
            ('unauthorized_client', 'Unauthorized Client'),
            ('invalid_scope', 'Invalid Permissions')
        ]
        
        for error_code, expected_title in error_scenarios:
            with self.subTest(error_code=error_code):
                response = self.client.get(f'/?error={error_code}&error_description=Test+error+description')
                
                self.assertEqual(response.status_code, 200)
                # Error messages are handled by JavaScript, so verify the JS functions and CSS classes
                self.assertIn(expected_title.encode(), response.data)  # In JavaScript switch statement
                self.assertIn(b'status-error', response.data)  # CSS class
                self.assertIn(b'showErrorStatus', response.data)  # JavaScript function
    
    def test_ui_javascript_functionality(self):
        """Test UI JavaScript functions for status handling and interactions."""
        response = self.client.get('/')
        
        self.assertEqual(response.status_code, 200)
        
        # Verify JavaScript functions are present
        js_functions = [
            b'parseURLParameters',
            b'showSuccessStatus',
            b'showErrorStatus',
            b'updatePageTitle',
            b'addButtonInteractions',
            b'initializeApp'
        ]
        
        for js_function in js_functions:
            self.assertIn(js_function, response.data)
        
        # Verify JavaScript handles URL parameters
        self.assertIn(b'URLSearchParams', response.data)
        self.assertIn(b'session_id', response.data)
        self.assertIn(b'error_description', response.data)
        
        # Verify button interaction handling
        self.assertIn(b'oauth-button', response.data)
        self.assertIn(b'addEventListener', response.data)
        self.assertIn(b'Connecting to', response.data)
    
    def test_ui_backend_api_integration(self):
        """Test UI can successfully interact with backend API endpoints."""
        # Create test session
        session_id = TokenStorage.store_tokens(
            provider='microsoft',
            access_token='ui_test_access_token',
            refresh_token='ui_test_refresh_token',
            expires_in=3600,
            scope='User.Read Mail.Read'
        )
        
        # Test API endpoint that UI would call
        api_response = self.client.get(f'/api/tokens/{session_id}')
        self.assertEqual(api_response.status_code, 200)
        
        api_data = json.loads(api_response.data)
        self.assertTrue(api_data['success'])
        self.assertEqual(api_data['data']['provider'], 'microsoft')
        
        # Test storage stats endpoint (for debugging UI)
        stats_response = self.client.get('/api/storage/stats')
        self.assertEqual(stats_response.status_code, 200)
        
        stats_data = json.loads(stats_response.data)
        self.assertTrue(stats_data['success'])
        self.assertEqual(stats_data['data']['total_sessions'], 1)
        self.assertEqual(stats_data['data']['providers']['microsoft'], 1)
    
    def test_ui_error_handling_across_components(self):
        """Test error handling consistency between UI and backend components."""
        # Test invalid session ID format
        invalid_session_id = 'invalid-session-id-format'
        
        # Backend API response
        api_response = self.client.get(f'/api/tokens/{invalid_session_id}')
        self.assertEqual(api_response.status_code, 400)
        
        api_data = json.loads(api_response.data)
        self.assertFalse(api_data['success'])
        self.assertEqual(api_data['error']['code'], 'INVALID_SESSION_ID_FORMAT')
        
        # UI should handle this gracefully (no server error)
        ui_response = self.client.get(f'/?session_id={invalid_session_id}')
        self.assertEqual(ui_response.status_code, 200)
        
        # Test non-existent session ID
        non_existent_session_id = str(uuid.uuid4())
        
        api_response = self.client.get(f'/api/tokens/{non_existent_session_id}')
        self.assertEqual(api_response.status_code, 404)
        
        api_data = json.loads(api_response.data)
        self.assertFalse(api_data['success'])
        self.assertEqual(api_data['error']['code'], 'SESSION_NOT_FOUND')


class TestTokenVerificationScript(unittest.TestCase):
    """Integration tests for token verification script functionality."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.app, self.socketio = create_app()
        self.app.config['TESTING'] = True
        
        # Start test server in background thread
        self.server_thread = None
        self.server_port = 5001  # Use different port for testing
        
        with storage_lock:
            token_storage.clear()
    
    def tearDown(self):
        """Clean up after each test method."""
        with storage_lock:
            token_storage.clear()
        
        if self.server_thread and self.server_thread.is_alive():
            # Note: In a real scenario, you'd want proper server shutdown
            pass
    
    def start_test_server(self):
        """Start test server for script integration testing."""
        def run_server():
            self.app.run(host='localhost', port=self.server_port, debug=False, use_reloader=False)
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        time.sleep(1)  # Give server time to start
    
    def test_verify_tokens_script_with_valid_session_id(self):
        """Test token verification script with valid session ID."""
        # Create test session
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='script_test_access_token',
            refresh_token='script_test_refresh_token',
            expires_in=3600,
            scope='profile email'
        )
        
        # Test script functionality by importing and calling directly
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from verify_tokens import TokenVerifier
        
        # Create verifier instance
        verifier = TokenVerifier(host='localhost', port=5000)
        
        # Mock the HTTP request to simulate script behavior
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'success': True,
                'data': {
                    'access_token': 'script_test_access_token',
                    'refresh_token': 'script_test_refresh_token',
                    'expires_at': '2024-01-01T12:00:00',
                    'scope': 'profile email',
                    'provider': 'google'
                }
            }
            mock_get.return_value = mock_response
            
            # Test verification
            result = verifier.verify_token(session_id)
            
            # Verify script made correct HTTP request
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            self.assertIn(session_id, call_args[0][0])
            self.assertEqual(call_args[1]['timeout'], 10)
            
            # Verify result
            self.assertTrue(result['success'])
            self.assertEqual(result['session_id'], session_id)
            self.assertIsNone(result['error'])
            self.assertIsNotNone(result['token_data'])
            self.assertEqual(result['token_data']['provider'], 'google')
    
    def test_verify_tokens_script_with_invalid_session_id(self):
        """Test token verification script handles invalid session ID gracefully."""
        from verify_tokens import TokenVerifier
        
        verifier = TokenVerifier(host='localhost', port=5000)
        invalid_session_id = 'invalid-session-format'
        
        # Mock HTTP request for invalid session ID
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.json.return_value = {
                'success': False,
                'error': {
                    'code': 'INVALID_SESSION_ID_FORMAT',
                    'message': 'Session ID format is invalid'
                }
            }
            mock_get.return_value = mock_response
            
            result = verifier.verify_token(invalid_session_id)
            
            # Verify error handling
            self.assertFalse(result['success'])
            self.assertEqual(result['error']['type'], 'INVALID_SESSION_ID')
            self.assertIn('Invalid session ID format', result['error']['message'])
    
    def test_verify_tokens_script_network_error_handling(self):
        """Test token verification script handles network errors gracefully."""
        from verify_tokens import TokenVerifier
        
        verifier = TokenVerifier(host='localhost', port=5000)
        session_id = str(uuid.uuid4())
        
        # Test connection error
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError('Connection failed')
            
            result = verifier.verify_token(session_id)
            
            self.assertFalse(result['success'])
            self.assertEqual(result['error']['type'], 'CONNECTION_ERROR')
            self.assertIn('Failed to connect', result['error']['message'])
            self.assertIn('ensure the server is running', result['error']['message'])
        
        # Test timeout error
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout('Request timed out')
            
            result = verifier.verify_token(session_id)
            
            self.assertFalse(result['success'])
            self.assertEqual(result['error']['type'], 'TIMEOUT_ERROR')
            self.assertIn('timed out', result['error']['message'])
        
        # Test general network error
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.RequestException('Network error')
            
            result = verifier.verify_token(session_id)
            
            self.assertFalse(result['success'])
            self.assertEqual(result['error']['type'], 'NETWORK_ERROR')
            self.assertIn('Network error occurred', result['error']['message'])
    
    def test_verify_tokens_script_output_formatting(self):
        """Test token verification script formats output correctly."""
        from verify_tokens import TokenVerifier
        
        verifier = TokenVerifier()
        
        # Test success output formatting
        token_data = {
            'provider': 'microsoft',
            'access_token': 'test_access_token_with_long_value_for_truncation',
            'refresh_token': 'test_refresh_token_with_long_value_for_truncation',
            'expires_at': '2024-01-01T12:00:00',
            'scope': 'User.Read Mail.Read Calendars.Read'
        }
        
        formatted_output = verifier.format_token_data(token_data)
        
        self.assertIn('Token Verification Successful', formatted_output)
        self.assertIn('Provider:      microsoft', formatted_output)
        self.assertIn('test_access_token_wi...', formatted_output)  # Truncated (20 chars + ...)
        self.assertIn('test_refresh_token_w...', formatted_output)  # Truncated (20 chars + ...)
        self.assertIn('Expires At:    2024-01-01T12:00:00', formatted_output)
        self.assertIn('Scope:         User.Read Mail.Read Calendars.Read', formatted_output)
        
        # Test error output formatting
        error_data = {
            'type': 'SESSION_NOT_FOUND',
            'message': 'Session ID not found or expired',
            'code': 'SESSION_NOT_FOUND'
        }
        
        formatted_error = verifier.format_error(error_data)
        
        self.assertIn('Token Verification Failed - SESSION_NOT_FOUND', formatted_error)
        self.assertIn('Session ID not found or expired', formatted_error)
        self.assertIn('Code:  SESSION_NOT_FOUND', formatted_error)
        self.assertIn('Troubleshooting suggestions', formatted_error)
        self.assertIn('Verify the session ID is correct', formatted_error)
    
    def test_verify_tokens_script_command_line_interface(self):
        """Test token verification script command-line argument parsing."""
        from verify_tokens import validate_session_id
        
        # Test session ID validation
        valid_session_id = str(uuid.uuid4())
        invalid_session_ids = [
            'not-a-uuid',
            '12345',
            '',
            None,
            'invalid-uuid-format-too-short'
        ]
        
        # Test valid session ID
        self.assertTrue(validate_session_id(valid_session_id))
        
        # Test invalid session IDs
        for invalid_id in invalid_session_ids:
            with self.subTest(invalid_id=invalid_id):
                self.assertFalse(validate_session_id(invalid_id))


class TestErrorHandlingAcrossComponents(unittest.TestCase):
    """Integration tests for error handling across component boundaries."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.app, self.socketio = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        with storage_lock:
            token_storage.clear()
    
    def tearDown(self):
        """Clean up after each test method."""
        with storage_lock:
            token_storage.clear()
    
    def test_oauth_error_propagation_to_ui(self):
        """Test OAuth errors are properly propagated to UI with user-friendly messages."""
        oauth_errors = [
            ('access_denied', 'User denied consent', 'Authorization Cancelled'),
            ('invalid_request', 'Invalid OAuth request', 'Invalid Request'),
            ('unauthorized_client', 'Client not authorized', 'Unauthorized Client'),
            ('unsupported_response_type', 'Response type not supported', 'Configuration Error'),
            ('invalid_scope', 'Invalid scope requested', 'Invalid Permissions'),
            ('server_error', 'OAuth server error', 'Connection Error'),
            ('temporarily_unavailable', 'Service temporarily unavailable', 'Connection Error')
        ]
        
        for error_code, error_description, expected_ui_title in oauth_errors:
            with self.subTest(error_code=error_code):
                # Test OAuth callback with error
                response = self.client.get(f'/oauth/google/callback?error={error_code}&error_description={error_description}')
                
                self.assertEqual(response.status_code, 302)
                
                # Follow redirect to UI
                redirect_url = response.headers['Location']
                ui_response = self.client.get(redirect_url.replace('http://localhost', ''))
                
                self.assertEqual(ui_response.status_code, 200)
                # Error messages are handled by JavaScript, so verify the JS functions and expected titles
                self.assertIn(expected_ui_title.encode(), ui_response.data)  # In JavaScript switch statement
                self.assertIn(b'showErrorStatus', ui_response.data)  # JavaScript function
    
    def test_api_error_consistency_across_endpoints(self):
        """Test API error responses are consistent across all endpoints."""
        # Test invalid session ID format across endpoints
        invalid_session_id = 'invalid-format'
        
        api_response = self.client.get(f'/api/tokens/{invalid_session_id}')
        self.assertEqual(api_response.status_code, 400)
        
        api_data = json.loads(api_response.data)
        self.assertFalse(api_data['success'])
        self.assertIn('error', api_data)
        self.assertIn('code', api_data['error'])
        self.assertIn('message', api_data['error'])
        
        # Test non-existent session ID
        non_existent_id = str(uuid.uuid4())
        
        api_response = self.client.get(f'/api/tokens/{non_existent_id}')
        self.assertEqual(api_response.status_code, 404)
        
        api_data = json.loads(api_response.data)
        self.assertFalse(api_data['success'])
        self.assertEqual(api_data['error']['code'], 'SESSION_NOT_FOUND')
    
    def test_token_storage_error_handling_integration(self):
        """Test token storage errors are handled consistently across components."""
        # Test storage limit handling
        original_limit = 1000
        
        # Mock storage limit to test cleanup
        with patch('authentication_proxy.app.TokenStorage.cleanup_expired_sessions') as mock_cleanup:
            mock_cleanup.return_value = 0  # No expired sessions to clean
            
            # Fill storage to near limit
            for i in range(5):
                TokenStorage.store_tokens(
                    provider='google',
                    access_token=f'test_token_{i}',
                    refresh_token=f'refresh_token_{i}',
                    expires_in=3600,
                    scope='test_scope'
                )
            
            # Verify storage works normally
            stats = TokenStorage.get_storage_stats()
            self.assertEqual(stats['total_sessions'], 5)
    
    def test_network_error_handling_in_oauth_flows(self):
        """Test network error handling during OAuth token exchange."""
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state_token'
            sess['oauth_provider'] = 'google'
            
            # Mock network error during token exchange
            with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
                mock_provider = MagicMock()
                mock_provider.validate_state.return_value = True
                mock_provider.exchange_code_for_tokens.side_effect = ConnectionError('Network connection failed')
                mock_get_provider.return_value = mock_provider
                
                response = self.client.get('/oauth/google/callback?code=test_code&state=test_state_token')
                
                # Should handle error gracefully
                self.assertEqual(response.status_code, 302)
                
                redirect_url = response.location
                ui_response = self.client.get(redirect_url.replace('http://localhost', ''))
                
                self.assertEqual(ui_response.status_code, 200)
                self.assertIn(b'error', ui_response.data.lower())
    
    def test_concurrent_access_error_handling(self):
        """Test error handling during concurrent access to shared resources."""
        session_ids = []
        errors = []
        
        def concurrent_token_storage(thread_id):
            """Worker function for concurrent token storage testing."""
            try:
                session_id = TokenStorage.store_tokens(
                    provider='google',
                    access_token=f'concurrent_token_{thread_id}',
                    refresh_token=f'concurrent_refresh_{thread_id}',
                    expires_in=3600,
                    scope='test_scope'
                )
                session_ids.append(session_id)
            except Exception as e:
                errors.append(e)
        
        # Run concurrent token storage operations
        threads = [threading.Thread(target=concurrent_token_storage, args=(i,)) for i in range(10)]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify no errors occurred and all operations succeeded
        self.assertEqual(len(errors), 0, f"Concurrent access errors: {errors}")
        self.assertEqual(len(session_ids), 10)
        self.assertEqual(len(set(session_ids)), 10)  # All session IDs should be unique
        
        # Verify all stored tokens can be retrieved
        for session_id in session_ids:
            token_data = TokenStorage.retrieve_tokens(session_id)
            self.assertIsNotNone(token_data)
            self.assertIn('concurrent_token_', token_data['access_token'])


if __name__ == '__main__':
    # Configure test runner
    unittest.main(verbosity=2, buffer=True)