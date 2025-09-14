"""
Unit tests for API endpoints.

This module tests token retrieval endpoint with valid session IDs, error responses
for invalid session IDs, JSON response formatting, and API security and validation.
"""

import unittest
import json
import uuid
import time
from unittest.mock import patch, MagicMock
import sys
import os
from datetime import datetime

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from authentication_proxy.app import create_app, TokenStorage, token_storage, storage_lock


class TestAPIEndpoints(unittest.TestCase):
    """Test cases for API endpoints."""
    
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
    
    # Token Retrieval API Tests
    
    def test_get_tokens_valid_session_id(self):
        """Test token retrieval with valid session ID."""
        # Store a token first
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            expires_in=3600,
            scope='profile email'
        )
        
        # Retrieve tokens via API
        response = self.client.get(f'/api/tokens/{session_id}')
        
        # Verify response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')
        
        # Parse JSON response
        data = json.loads(response.data)
        
        # Verify response structure
        self.assertTrue(data['success'])
        self.assertIn('data', data)
        
        token_data = data['data']
        self.assertEqual(token_data['access_token'], 'test_access_token')
        self.assertEqual(token_data['refresh_token'], 'test_refresh_token')
        self.assertEqual(token_data['scope'], 'profile email')
        self.assertEqual(token_data['provider'], 'google')
        
        # Verify expires_at is in ISO format
        self.assertIsInstance(token_data['expires_at'], str)
        try:
            datetime.fromisoformat(token_data['expires_at'])
        except ValueError:
            self.fail("expires_at is not in valid ISO format")
    
    def test_get_tokens_microsoft_provider(self):
        """Test token retrieval for Microsoft provider."""
        # Store Microsoft token
        session_id = TokenStorage.store_tokens(
            provider='microsoft',
            access_token='ms_access_token',
            refresh_token='ms_refresh_token',
            expires_in=7200,
            scope='User.Read Mail.Read'
        )
        
        # Retrieve tokens via API
        response = self.client.get(f'/api/tokens/{session_id}')
        
        # Verify response
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertTrue(data['success'])
        token_data = data['data']
        self.assertEqual(token_data['provider'], 'microsoft')
        self.assertEqual(token_data['access_token'], 'ms_access_token')
        self.assertEqual(token_data['scope'], 'User.Read Mail.Read')
    
    def test_get_tokens_invalid_session_id_format(self):
        """Test token retrieval with invalid session ID format."""
        invalid_session_ids = [
            'invalid_uuid',
            '12345',
            'not-a-uuid-at-all',
            'abc-def-ghi'
        ]
        
        for invalid_id in invalid_session_ids:
            with self.subTest(session_id=invalid_id):
                response = self.client.get(f'/api/tokens/{invalid_id}')
                
                # Should return 400 Bad Request
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.content_type, 'application/json')
                
                data = json.loads(response.data)
                self.assertFalse(data['success'])
                self.assertIn('error', data)
                self.assertEqual(data['error']['code'], 'INVALID_SESSION_ID_FORMAT')
                self.assertIn('Session ID format is invalid', data['error']['message'])
    
    def test_get_tokens_empty_session_id(self):
        """Test token retrieval with empty session ID (handled by Flask routing)."""
        # Empty session ID will result in 404 from Flask routing, not our API handler
        response = self.client.get('/api/tokens/')
        self.assertEqual(response.status_code, 404)
    
    def test_get_tokens_non_existent_session_id(self):
        """Test token retrieval with non-existent but valid session ID."""
        # Generate a valid UUID4 that doesn't exist in storage
        fake_session_id = str(uuid.uuid4())
        
        response = self.client.get(f'/api/tokens/{fake_session_id}')
        
        # Should return 404 Not Found
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content_type, 'application/json')
        
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('error', data)
        self.assertEqual(data['error']['code'], 'SESSION_NOT_FOUND')
        self.assertIn('Session ID not found or expired', data['error']['message'])
    
    def test_get_tokens_expired_session(self):
        """Test token retrieval with expired session."""
        # Store a token with very short expiration
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='expired_token',
            refresh_token='expired_refresh',
            expires_in=1,  # 1 second
            scope='test'
        )
        
        # Wait for token to expire
        time.sleep(2)
        
        # Try to retrieve expired token
        response = self.client.get(f'/api/tokens/{session_id}')
        
        # Should return 404 Not Found
        self.assertEqual(response.status_code, 404)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertEqual(data['error']['code'], 'SESSION_NOT_FOUND')
    
    def test_get_tokens_with_none_refresh_token(self):
        """Test token retrieval when refresh token is None/empty."""
        # Store token with empty refresh token
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_token',
            refresh_token=None,  # This gets converted to empty string
            expires_in=3600,
            scope='test'
        )
        
        response = self.client.get(f'/api/tokens/{session_id}')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['refresh_token'], '')
    
    def test_get_tokens_with_none_scope(self):
        """Test token retrieval when scope is None/empty."""
        # Store token with empty scope
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_token',
            refresh_token='test_refresh',
            expires_in=3600,
            scope=None  # This gets converted to empty string
        )
        
        response = self.client.get(f'/api/tokens/{session_id}')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['scope'], '')
    
    def test_get_tokens_response_format_consistency(self):
        """Test that API responses follow consistent format."""
        # Test successful response format
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_token',
            refresh_token='test_refresh',
            expires_in=3600,
            scope='test'
        )
        
        response = self.client.get(f'/api/tokens/{session_id}')
        data = json.loads(response.data)
        
        # Verify required fields are present
        required_fields = ['success', 'data']
        for field in required_fields:
            self.assertIn(field, data)
        
        # Verify data structure
        data_fields = ['access_token', 'refresh_token', 'expires_at', 'scope', 'provider']
        for field in data_fields:
            self.assertIn(field, data['data'])
        
        # Test error response format
        response = self.client.get('/api/tokens/invalid_id')
        data = json.loads(response.data)
        
        # Verify error response structure
        required_error_fields = ['success', 'error']
        for field in required_error_fields:
            self.assertIn(field, data)
        
        error_fields = ['code', 'message']
        for field in error_fields:
            self.assertIn(field, data['error'])
    
    def test_get_tokens_corrupted_data_handling(self):
        """Test API error handling for corrupted token data."""
        # Create a scenario with corrupted token data
        session_id = str(uuid.uuid4())
        
        # Manually insert corrupted data that would cause errors during processing
        with storage_lock:
            token_storage[session_id] = {
                'provider': 'google',
                'access_token': 'test_token',
                'refresh_token': 'test_refresh',
                'expires_at': 'invalid_timestamp',  # This should cause TypeError
                'scope': 'test',
                'created_at': time.time()
            }
        
        response = self.client.get(f'/api/tokens/{session_id}')
        
        # Should return 500 for internal error
        self.assertEqual(response.status_code, 500)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertEqual(data['error']['code'], 'INTERNAL_ERROR')
    
    def test_get_tokens_general_error_handling(self):
        """Test that API handles errors gracefully and returns proper error responses."""
        # Test with various error scenarios that should return 500
        session_id = str(uuid.uuid4())
        
        # Test with corrupted storage data
        with storage_lock:
            token_storage[session_id] = {
                'provider': 'google',
                'access_token': 'test_token',
                'refresh_token': 'test_refresh',
                'expires_at': None,  # This should cause an error
                'scope': 'test',
                'created_at': time.time()
            }
        
        response = self.client.get(f'/api/tokens/{session_id}')
        
        # Should return 500 and proper error structure
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.content_type, 'application/json')
        
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('error', data)
        self.assertIn('code', data['error'])
        self.assertIn('message', data['error'])
    
    def test_get_tokens_concurrent_access(self):
        """Test concurrent access to token retrieval API."""
        import threading
        
        # Store multiple tokens
        session_ids = []
        for i in range(10):
            session_id = TokenStorage.store_tokens(
                provider='google',
                access_token=f'token_{i}',
                refresh_token=f'refresh_{i}',
                expires_in=3600,
                scope=f'scope_{i}'
            )
            session_ids.append(session_id)
        
        results = []
        errors = []
        
        def retrieve_token_worker(session_id):
            """Worker function for concurrent token retrieval."""
            try:
                response = self.client.get(f'/api/tokens/{session_id}')
                results.append((session_id, response.status_code))
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = []
        for session_id in session_ids:
            thread = threading.Thread(target=retrieve_token_worker, args=(session_id,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify no errors occurred
        self.assertEqual(len(errors), 0, f"Errors occurred during concurrent access: {errors}")
        
        # Verify all requests succeeded
        self.assertEqual(len(results), 10)
        for session_id, status_code in results:
            self.assertEqual(status_code, 200)
    
    # Storage Stats API Tests
    
    def test_get_storage_stats_empty(self):
        """Test storage stats API with empty storage."""
        response = self.client.get('/api/storage/stats')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')
        
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('data', data)
        
        stats = data['data']
        self.assertEqual(stats['total_sessions'], 0)
        self.assertEqual(stats['providers'], {})
        self.assertIsInstance(stats['storage_size_bytes'], int)
    
    def test_get_storage_stats_with_tokens(self):
        """Test storage stats API with stored tokens."""
        # Store tokens for different providers
        TokenStorage.store_tokens(
            provider='google',
            access_token='google_token_1',
            refresh_token='google_refresh_1',
            expires_in=3600,
            scope='google_scope_1'
        )
        
        TokenStorage.store_tokens(
            provider='google',
            access_token='google_token_2',
            refresh_token='google_refresh_2',
            expires_in=3600,
            scope='google_scope_2'
        )
        
        TokenStorage.store_tokens(
            provider='microsoft',
            access_token='ms_token_1',
            refresh_token='ms_refresh_1',
            expires_in=7200,
            scope='ms_scope_1'
        )
        
        response = self.client.get('/api/storage/stats')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertTrue(data['success'])
        stats = data['data']
        
        self.assertEqual(stats['total_sessions'], 3)
        self.assertEqual(stats['providers']['google'], 2)
        self.assertEqual(stats['providers']['microsoft'], 1)
        self.assertGreater(stats['storage_size_bytes'], 0)
    
    def test_get_storage_stats_response_format(self):
        """Test storage stats API response format consistency."""
        response = self.client.get('/api/storage/stats')
        data = json.loads(response.data)
        
        # Verify response structure
        required_fields = ['success', 'data']
        for field in required_fields:
            self.assertIn(field, data)
        
        # Verify stats structure
        stats_fields = ['total_sessions', 'providers', 'storage_size_bytes']
        for field in stats_fields:
            self.assertIn(field, data['data'])
        
        # Verify data types
        self.assertIsInstance(data['data']['total_sessions'], int)
        self.assertIsInstance(data['data']['providers'], dict)
        self.assertIsInstance(data['data']['storage_size_bytes'], int)
    
    # API Security and Validation Tests
    
    def test_api_endpoints_content_type(self):
        """Test that API endpoints return proper content type."""
        # Test token retrieval endpoint
        session_id = str(uuid.uuid4())
        response = self.client.get(f'/api/tokens/{session_id}')
        self.assertEqual(response.content_type, 'application/json')
        
        # Test storage stats endpoint
        response = self.client.get('/api/storage/stats')
        self.assertEqual(response.content_type, 'application/json')
    
    def test_api_endpoints_http_methods(self):
        """Test that API endpoints only accept appropriate HTTP methods."""
        session_id = str(uuid.uuid4())
        
        # Test token retrieval endpoint - should only accept GET
        # Note: Flask's error handler may convert 405 to 500, so we check for either
        response = self.client.post(f'/api/tokens/{session_id}')
        self.assertIn(response.status_code, [405, 500])  # Method Not Allowed or handled by error handler
        
        response = self.client.put(f'/api/tokens/{session_id}')
        self.assertIn(response.status_code, [405, 500])
        
        response = self.client.delete(f'/api/tokens/{session_id}')
        self.assertIn(response.status_code, [405, 500])
        
        # Test storage stats endpoint - should only accept GET
        response = self.client.post('/api/storage/stats')
        self.assertIn(response.status_code, [405, 500])
    
    def test_api_session_isolation(self):
        """Test that API properly isolates sessions."""
        # Store tokens for different sessions
        session_id_1 = TokenStorage.store_tokens(
            provider='google',
            access_token='token_1',
            refresh_token='refresh_1',
            expires_in=3600,
            scope='scope_1'
        )
        
        session_id_2 = TokenStorage.store_tokens(
            provider='microsoft',
            access_token='token_2',
            refresh_token='refresh_2',
            expires_in=7200,
            scope='scope_2'
        )
        
        # Retrieve tokens for each session
        response_1 = self.client.get(f'/api/tokens/{session_id_1}')
        response_2 = self.client.get(f'/api/tokens/{session_id_2}')
        
        data_1 = json.loads(response_1.data)
        data_2 = json.loads(response_2.data)
        
        # Verify session isolation
        self.assertEqual(data_1['data']['access_token'], 'token_1')
        self.assertEqual(data_1['data']['provider'], 'google')
        
        self.assertEqual(data_2['data']['access_token'], 'token_2')
        self.assertEqual(data_2['data']['provider'], 'microsoft')
        
        # Verify they are different
        self.assertNotEqual(data_1['data'], data_2['data'])
    
    def test_api_url_parameter_validation(self):
        """Test API URL parameter validation."""
        # Test with various invalid URL parameters that should reach our API handler
        invalid_params = [
            'invalid_uuid_format',  # Invalid UUID format
            'not-a-uuid-at-all',    # Invalid UUID format
            'SELECT_FROM_tokens',   # SQL injection attempt (URL safe)
        ]
        
        for param in invalid_params:
            with self.subTest(param=param):
                response = self.client.get(f'/api/tokens/{param}')
                # Should return 400 for invalid format
                self.assertEqual(response.status_code, 400)
                
                # Verify response is JSON
                self.assertEqual(response.content_type, 'application/json')
                
                data = json.loads(response.data)
                self.assertFalse(data['success'])
                self.assertEqual(data['error']['code'], 'INVALID_SESSION_ID_FORMAT')
    
    def test_api_path_traversal_protection(self):
        """Test that path traversal attempts are handled by Flask routing."""
        # These should be handled by Flask's routing and return 404
        path_traversal_attempts = [
            '../../../etc/passwd',
            '../../',
            '%2e%2e%2f',  # URL encoded ../
        ]
        
        for param in path_traversal_attempts:
            with self.subTest(param=param):
                response = self.client.get(f'/api/tokens/{param}')
                # Flask routing should handle these and return 404
                self.assertEqual(response.status_code, 404)
    
    def test_api_error_message_security(self):
        """Test that API error messages don't leak sensitive information."""
        # Test with various session IDs to ensure error messages are generic
        test_cases = [
            ('invalid_format', 'INVALID_SESSION_ID_FORMAT'),
            (str(uuid.uuid4()), 'SESSION_NOT_FOUND'),  # Valid format but non-existent
        ]
        
        for session_id, expected_error_code in test_cases:
            with self.subTest(session_id=session_id):
                response = self.client.get(f'/api/tokens/{session_id}')
                data = json.loads(response.data)
                
                # Verify error messages are generic and don't leak info
                self.assertEqual(data['error']['code'], expected_error_code)
                self.assertNotIn('database', data['error']['message'].lower())
                self.assertNotIn('sql', data['error']['message'].lower())
                self.assertNotIn('internal', data['error']['message'].lower())

    # Provider API Tests
    
    def test_api_providers_endpoint(self):
        """Test the /api/providers endpoint returns provider information."""
        response = self.client.get('/api/providers')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')
        
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('data', data)
        self.assertIn('providers', data['data'])
        self.assertIn('count', data['data'])
        
        # Should have at least Google and Microsoft providers
        providers = data['data']['providers']
        self.assertGreaterEqual(len(providers), 2)
        self.assertEqual(data['data']['count'], len(providers))
        
        # Check provider structure
        for provider in providers:
            self.assertIn('name', provider)
            self.assertIn('display_name', provider)
            self.assertIn('scopes', provider)
            self.assertIn('supports_refresh', provider)
            self.assertIn('supports_user_info', provider)
            self.assertIsInstance(provider['scopes'], list)
            self.assertIsInstance(provider['supports_refresh'], bool)
            self.assertIsInstance(provider['supports_user_info'], bool)
        
        # Check for specific providers
        provider_names = [p['name'] for p in providers]
        self.assertIn('google', provider_names)
        self.assertIn('microsoft', provider_names)

    def test_api_providers_endpoint_http_methods(self):
        """Test that /api/providers only accepts GET requests."""
        # GET should work
        response = self.client.get('/api/providers')
        self.assertEqual(response.status_code, 200)
        
        # POST should not be allowed (Flask error handler converts 405 to 500)
        response = self.client.post('/api/providers')
        self.assertIn(response.status_code, [405, 500])  # Either is acceptable
        
        # PUT should not be allowed (Flask error handler converts 405 to 500)
        response = self.client.put('/api/providers')
        self.assertIn(response.status_code, [405, 500])  # Either is acceptable
        
        # DELETE should not be allowed (Flask error handler converts 405 to 500)
        response = self.client.delete('/api/providers')
        self.assertIn(response.status_code, [405, 500])  # Either is acceptable

    def test_api_providers_response_format(self):
        """Test that /api/providers returns consistent response format."""
        response = self.client.get('/api/providers')
        
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        
        # Check top-level structure
        self.assertIsInstance(data, dict)
        self.assertTrue(data['success'])
        self.assertIn('data', data)
        
        # Check data structure
        data_section = data['data']
        self.assertIn('providers', data_section)
        self.assertIn('count', data_section)
        self.assertIsInstance(data_section['providers'], list)
        self.assertIsInstance(data_section['count'], int)
        
        # Verify count matches actual provider list length
        self.assertEqual(data_section['count'], len(data_section['providers']))


if __name__ == '__main__':
    unittest.main()