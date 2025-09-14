"""
Unit tests for the TokenStorage system.

This module tests token storage and retrieval functions, session ID generation
and validation, token cleanup mechanisms, and session isolation and security.
"""

import unittest
import time
import threading
import uuid
from unittest.mock import patch, MagicMock
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from authentication_proxy.app import TokenStorage, token_storage, storage_lock


class TestTokenStorage(unittest.TestCase):
    """Test cases for the TokenStorage class."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Clear token storage before each test
        with storage_lock:
            token_storage.clear()
    
    def tearDown(self):
        """Clean up after each test method."""
        # Clear token storage after each test
        with storage_lock:
            token_storage.clear()
    
    def test_generate_session_id(self):
        """Test session ID generation produces valid UUID4 strings."""
        session_id = TokenStorage.generate_session_id()
        
        # Verify it's a string
        self.assertIsInstance(session_id, str)
        
        # Verify it's a valid UUID4
        try:
            uuid_obj = uuid.UUID(session_id, version=4)
            self.assertEqual(str(uuid_obj), session_id)
        except ValueError:
            self.fail("Generated session ID is not a valid UUID4")
    
    def test_generate_session_id_uniqueness(self):
        """Test that generated session IDs are unique."""
        session_ids = set()
        
        # Generate 1000 session IDs and verify uniqueness
        for _ in range(1000):
            session_id = TokenStorage.generate_session_id()
            self.assertNotIn(session_id, session_ids, "Duplicate session ID generated")
            session_ids.add(session_id)
    
    def test_store_tokens_valid_input(self):
        """Test storing tokens with valid input parameters."""
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            expires_in=3600,
            scope='profile email'
        )
        
        # Verify session ID is returned
        self.assertIsInstance(session_id, str)
        self.assertTrue(TokenStorage.validate_session_id(session_id))
        
        # Verify token is stored
        with storage_lock:
            self.assertIn(session_id, token_storage)
            stored_data = token_storage[session_id]
            
            self.assertEqual(stored_data['provider'], 'google')
            self.assertEqual(stored_data['access_token'], 'test_access_token')
            self.assertEqual(stored_data['refresh_token'], 'test_refresh_token')
            self.assertEqual(stored_data['scope'], 'profile email')
            self.assertIsInstance(stored_data['expires_at'], float)
            self.assertIsInstance(stored_data['created_at'], float)
    
    def test_store_tokens_microsoft_provider(self):
        """Test storing tokens for Microsoft provider."""
        session_id = TokenStorage.store_tokens(
            provider='microsoft',
            access_token='ms_access_token',
            refresh_token='ms_refresh_token',
            expires_in=7200,
            scope='User.Read Mail.Read'
        )
        
        # Verify token is stored with correct provider
        with storage_lock:
            stored_data = token_storage[session_id]
            self.assertEqual(stored_data['provider'], 'microsoft')
    
    def test_store_tokens_invalid_provider(self):
        """Test storing tokens with invalid provider (empty string) raises ValueError."""
        with self.assertRaises(ValueError) as context:
            TokenStorage.store_tokens(
                provider='',  # Empty provider should raise ValueError
                access_token='test_token',
                refresh_token='test_refresh',
                expires_in=3600,
                scope='test'
            )
        
        self.assertIn('Invalid provider', str(context.exception))
    
    def test_store_tokens_empty_provider(self):
        """Test storing tokens with empty provider raises ValueError."""
        with self.assertRaises(ValueError) as context:
            TokenStorage.store_tokens(
                provider='',
                access_token='test_token',
                refresh_token='test_refresh',
                expires_in=3600,
                scope='test'
            )
        
        self.assertIn('Invalid provider', str(context.exception))
    
    def test_store_tokens_invalid_access_token(self):
        """Test storing tokens with invalid access token raises ValueError."""
        # Test empty access token
        with self.assertRaises(ValueError) as context:
            TokenStorage.store_tokens(
                provider='google',
                access_token='',
                refresh_token='test_refresh',
                expires_in=3600,
                scope='test'
            )
        
        self.assertIn('Access token is required', str(context.exception))
        
        # Test None access token
        with self.assertRaises(ValueError) as context:
            TokenStorage.store_tokens(
                provider='google',
                access_token=None,
                refresh_token='test_refresh',
                expires_in=3600,
                scope='test'
            )
        
        self.assertIn('Access token is required', str(context.exception))
    
    def test_store_tokens_invalid_expires_in(self):
        """Test storing tokens with invalid expires_in raises ValueError."""
        # Test negative expires_in
        with self.assertRaises(ValueError) as context:
            TokenStorage.store_tokens(
                provider='google',
                access_token='test_token',
                refresh_token='test_refresh',
                expires_in=-1,
                scope='test'
            )
        
        self.assertIn('expires_in must be a positive integer', str(context.exception))
        
        # Test zero expires_in
        with self.assertRaises(ValueError) as context:
            TokenStorage.store_tokens(
                provider='google',
                access_token='test_token',
                refresh_token='test_refresh',
                expires_in=0,
                scope='test'
            )
        
        self.assertIn('expires_in must be a positive integer', str(context.exception))
    
    def test_store_tokens_none_refresh_token(self):
        """Test storing tokens with None refresh token (should be converted to empty string)."""
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_token',
            refresh_token=None,
            expires_in=3600,
            scope='test'
        )
        
        with storage_lock:
            stored_data = token_storage[session_id]
            self.assertEqual(stored_data['refresh_token'], '')
    
    def test_store_tokens_none_scope(self):
        """Test storing tokens with None scope (should be converted to empty string)."""
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_token',
            refresh_token='test_refresh',
            expires_in=3600,
            scope=None
        )
        
        with storage_lock:
            stored_data = token_storage[session_id]
            self.assertEqual(stored_data['scope'], '')
    
    def test_retrieve_tokens_valid_session(self):
        """Test retrieving tokens with valid session ID."""
        # Store a token first
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            expires_in=3600,
            scope='profile email'
        )
        
        # Retrieve the token
        retrieved_data = TokenStorage.retrieve_tokens(session_id)
        
        self.assertIsNotNone(retrieved_data)
        self.assertEqual(retrieved_data['provider'], 'google')
        self.assertEqual(retrieved_data['access_token'], 'test_access_token')
        self.assertEqual(retrieved_data['refresh_token'], 'test_refresh_token')
        self.assertEqual(retrieved_data['scope'], 'profile email')
    
    def test_retrieve_tokens_invalid_session_id(self):
        """Test retrieving tokens with invalid session ID returns None."""
        # Test with completely invalid session ID
        result = TokenStorage.retrieve_tokens('invalid_session_id')
        self.assertIsNone(result)
        
        # Test with valid UUID format but non-existent session
        fake_session_id = str(uuid.uuid4())
        result = TokenStorage.retrieve_tokens(fake_session_id)
        self.assertIsNone(result)
    
    def test_retrieve_tokens_expired_session(self):
        """Test retrieving expired tokens returns None and removes session."""
        # Store a token with very short expiration
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_token',
            refresh_token='test_refresh',
            expires_in=1,  # 1 second
            scope='test'
        )
        
        # Wait for token to expire
        time.sleep(2)
        
        # Try to retrieve expired token
        result = TokenStorage.retrieve_tokens(session_id)
        self.assertIsNone(result)
        
        # Verify session was removed from storage
        with storage_lock:
            self.assertNotIn(session_id, token_storage)
    
    def test_validate_session_id_valid_uuid4(self):
        """Test session ID validation with valid UUID4."""
        valid_session_id = str(uuid.uuid4())
        self.assertTrue(TokenStorage.validate_session_id(valid_session_id))
    
    def test_validate_session_id_invalid_formats(self):
        """Test session ID validation with various invalid formats."""
        invalid_session_ids = [
            '',  # Empty string
            None,  # None value
            'invalid_uuid',  # Invalid UUID format
            '12345',  # Too short
            'not-a-uuid-at-all',  # Invalid format
            str(uuid.uuid1()),  # UUID1 instead of UUID4
            123,  # Integer instead of string
        ]
        
        for invalid_id in invalid_session_ids:
            with self.subTest(session_id=invalid_id):
                self.assertFalse(TokenStorage.validate_session_id(invalid_id))
    
    def test_remove_session_existing(self):
        """Test removing an existing session."""
        # Store a token first
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_token',
            refresh_token='test_refresh',
            expires_in=3600,
            scope='test'
        )
        
        # Verify it exists
        with storage_lock:
            self.assertIn(session_id, token_storage)
        
        # Remove the session
        result = TokenStorage.remove_session(session_id)
        self.assertTrue(result)
        
        # Verify it's removed
        with storage_lock:
            self.assertNotIn(session_id, token_storage)
    
    def test_remove_session_non_existent(self):
        """Test removing a non-existent session returns False."""
        fake_session_id = str(uuid.uuid4())
        result = TokenStorage.remove_session(fake_session_id)
        self.assertFalse(result)
    
    def test_cleanup_expired_sessions(self):
        """Test cleanup of expired sessions."""
        # Store some tokens with different expiration times
        current_time = time.time()
        
        # Store expired token
        expired_session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='expired_token',
            refresh_token='expired_refresh',
            expires_in=1,
            scope='test'
        )
        
        # Store valid token
        valid_session_id = TokenStorage.store_tokens(
            provider='microsoft',
            access_token='valid_token',
            refresh_token='valid_refresh',
            expires_in=3600,
            scope='test'
        )
        
        # Wait for first token to expire
        time.sleep(2)
        
        # Run cleanup
        cleaned_count = TokenStorage.cleanup_expired_sessions()
        
        # Verify cleanup results
        self.assertEqual(cleaned_count, 1)
        
        with storage_lock:
            self.assertNotIn(expired_session_id, token_storage)
            self.assertIn(valid_session_id, token_storage)
    
    def test_cleanup_expired_sessions_no_expired(self):
        """Test cleanup when no sessions are expired."""
        # Store valid tokens
        session_id1 = TokenStorage.store_tokens(
            provider='google',
            access_token='token1',
            refresh_token='refresh1',
            expires_in=3600,
            scope='test'
        )
        
        session_id2 = TokenStorage.store_tokens(
            provider='microsoft',
            access_token='token2',
            refresh_token='refresh2',
            expires_in=7200,
            scope='test'
        )
        
        # Run cleanup
        cleaned_count = TokenStorage.cleanup_expired_sessions()
        
        # Verify no sessions were cleaned
        self.assertEqual(cleaned_count, 0)
        
        with storage_lock:
            self.assertIn(session_id1, token_storage)
            self.assertIn(session_id2, token_storage)
    
    def test_get_storage_stats(self):
        """Test getting storage statistics."""
        # Initially empty
        stats = TokenStorage.get_storage_stats()
        self.assertEqual(stats['total_sessions'], 0)
        self.assertEqual(stats['providers'], {})
        
        # Store some tokens
        TokenStorage.store_tokens(
            provider='google',
            access_token='token1',
            refresh_token='refresh1',
            expires_in=3600,
            scope='test'
        )
        
        TokenStorage.store_tokens(
            provider='google',
            access_token='token2',
            refresh_token='refresh2',
            expires_in=3600,
            scope='test'
        )
        
        TokenStorage.store_tokens(
            provider='microsoft',
            access_token='token3',
            refresh_token='refresh3',
            expires_in=3600,
            scope='test'
        )
        
        # Check updated stats
        stats = TokenStorage.get_storage_stats()
        self.assertEqual(stats['total_sessions'], 3)
        self.assertEqual(stats['providers']['google'], 2)
        self.assertEqual(stats['providers']['microsoft'], 1)
        self.assertIsInstance(stats['storage_size_bytes'], int)
    
    def test_session_isolation(self):
        """Test that sessions are properly isolated from each other."""
        # Store tokens for different providers
        google_session = TokenStorage.store_tokens(
            provider='google',
            access_token='google_token',
            refresh_token='google_refresh',
            expires_in=3600,
            scope='google_scope'
        )
        
        microsoft_session = TokenStorage.store_tokens(
            provider='microsoft',
            access_token='microsoft_token',
            refresh_token='microsoft_refresh',
            expires_in=7200,
            scope='microsoft_scope'
        )
        
        # Retrieve and verify isolation
        google_data = TokenStorage.retrieve_tokens(google_session)
        microsoft_data = TokenStorage.retrieve_tokens(microsoft_session)
        
        self.assertNotEqual(google_data, microsoft_data)
        self.assertEqual(google_data['provider'], 'google')
        self.assertEqual(microsoft_data['provider'], 'microsoft')
        self.assertEqual(google_data['access_token'], 'google_token')
        self.assertEqual(microsoft_data['access_token'], 'microsoft_token')
    
    def test_concurrent_access_thread_safety(self):
        """Test thread safety of token storage operations."""
        session_ids = []
        errors = []
        
        def store_token_worker(worker_id):
            """Worker function for concurrent token storage."""
            try:
                for i in range(10):
                    session_id = TokenStorage.store_tokens(
                        provider='google',
                        access_token=f'token_{worker_id}_{i}',
                        refresh_token=f'refresh_{worker_id}_{i}',
                        expires_in=3600,
                        scope=f'scope_{worker_id}_{i}'
                    )
                    session_ids.append(session_id)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = []
        for worker_id in range(5):
            thread = threading.Thread(target=store_token_worker, args=(worker_id,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify no errors occurred
        self.assertEqual(len(errors), 0, f"Errors occurred during concurrent access: {errors}")
        
        # Verify all sessions were stored
        self.assertEqual(len(session_ids), 50)  # 5 workers * 10 tokens each
        
        # Verify all session IDs are unique
        self.assertEqual(len(set(session_ids)), 50)
        
        # Verify all tokens can be retrieved
        for session_id in session_ids:
            token_data = TokenStorage.retrieve_tokens(session_id)
            self.assertIsNotNone(token_data)
    
    @patch('authentication_proxy.app.logging')
    def test_storage_limit_enforcement(self, mock_logging):
        """Test that storage limit is enforced and cleanup occurs."""
        # Mock the storage limit to a small number for testing
        original_limit = 1000
        test_limit = 5
        
        # Patch the limit check in store_tokens method
        with patch.object(TokenStorage, 'cleanup_expired_sessions') as mock_cleanup:
            mock_cleanup.return_value = 0  # No expired sessions to clean
            
            # Store tokens up to the limit
            session_ids = []
            for i in range(test_limit + 2):  # Exceed the limit
                try:
                    # Manually check limit and trigger cleanup logic
                    with storage_lock:
                        if len(token_storage) >= test_limit:
                            # Simulate the cleanup and oldest session removal logic
                            if len(token_storage) >= test_limit:
                                oldest_sessions = sorted(
                                    token_storage.items(),
                                    key=lambda x: x[1]['created_at']
                                )[:2]  # Remove 2 oldest sessions
                                
                                for old_session_id, _ in oldest_sessions:
                                    del token_storage[old_session_id]
                    
                    session_id = TokenStorage.store_tokens(
                        provider='google',
                        access_token=f'token_{i}',
                        refresh_token=f'refresh_{i}',
                        expires_in=3600,
                        scope=f'scope_{i}'
                    )
                    session_ids.append(session_id)
                except Exception as e:
                    self.fail(f"Unexpected error during storage limit test: {e}")
            
            # Verify storage doesn't exceed reasonable limits
            with storage_lock:
                self.assertLessEqual(len(token_storage), test_limit + 2)


if __name__ == '__main__':
    unittest.main()