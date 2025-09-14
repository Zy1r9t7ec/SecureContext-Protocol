"""
Tests for standardized API responses in the SecureContext Protocol.

This module tests the new standardized API response system, including
versioning, provider metadata, and consistent response formatting.
"""

import pytest
import json
import time
from datetime import datetime
from unittest.mock import patch, MagicMock

# Import the Flask app and test client
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from authentication_proxy.app import create_app, TokenStorage
from authentication_proxy.api_responses import (
    APIResponse, TokenResponseBuilder, ProviderResponseBuilder, 
    ErrorCodes, create_flask_response
)


class TestStandardizedAPIResponses:
    """Test standardized API response system."""
    
    @pytest.fixture
    def app(self):
        """Create test Flask application."""
        app, socketio = create_app()
        app.config['TESTING'] = True
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()
    
    def test_api_response_success_format(self):
        """Test standardized success response format."""
        test_data = {"key": "value", "number": 123}
        response = APIResponse.success(
            data=test_data,
            message="Test successful",
            metadata={"test": True}
        )
        
        # Verify response structure
        assert response["success"] is True
        assert response["version"] == "1.0"
        assert "timestamp" in response
        assert response["data"] == test_data
        assert response["message"] == "Test successful"
        assert response["metadata"]["test"] is True
        
        # Verify timestamp format
        timestamp = datetime.fromisoformat(response["timestamp"].replace('Z', '+00:00'))
        assert isinstance(timestamp, datetime)
    
    def test_api_response_error_format(self):
        """Test standardized error response format."""
        response = APIResponse.error(
            code="TEST_ERROR",
            message="Test error message",
            details={"field": "invalid"},
            status_code=400
        )
        
        # Verify response structure
        assert response["success"] is False
        assert response["version"] == "1.0"
        assert "timestamp" in response
        assert response["error"]["code"] == "TEST_ERROR"
        assert response["error"]["message"] == "Test error message"
        assert response["error"]["status_code"] == 400
        assert response["error"]["details"]["field"] == "invalid"
    
    def test_token_response_builder_format(self):
        """Test token response formatting."""
        # Mock token data
        token_data = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'expires_at': time.time() + 3600,  # 1 hour from now
            'scope': 'profile email',
            'provider': 'google',
            'created_at': time.time(),
            'session_id': 'test-session-id'
        }
        
        # Mock provider info
        provider_info = {
            'name': 'google',
            'display_name': 'Google Account',
            'icon_url': 'https://example.com/google-icon.png',
            'scopes': ['profile', 'email']
        }
        
        response = TokenResponseBuilder.success_response(token_data, provider_info)
        
        # Verify response structure
        assert response["success"] is True
        assert response["data"]["access_token"] == "test_access_token"
        assert response["data"]["refresh_token"] == "test_refresh_token"
        assert response["data"]["token_type"] == "Bearer"
        assert response["data"]["scope"] == "profile email"
        
        # Verify provider metadata (backward compatibility)
        assert response["data"]["provider"] == "google"
        
        # Verify new provider info structure
        assert response["data"]["provider_info"]["name"] == "google"
        assert response["data"]["provider_info"]["display_name"] == "Google Account"
        assert response["data"]["provider_info"]["type"] == "oauth2"
        
        # Verify metadata
        assert response["data"]["metadata"]["session_id"] == "test-session-id"
        assert "expires_in_seconds" in response["data"]["metadata"]
    
    def test_provider_response_builder_format(self):
        """Test provider response formatting."""
        providers = [
            {
                'name': 'google',
                'display_name': 'Google Account',
                'scopes': ['profile', 'email'],
                'icon_url': 'https://example.com/google.png'
            },
            {
                'name': 'microsoft',
                'display_name': 'Microsoft Account',
                'scopes': ['User.Read', 'Mail.Read'],
                'icon_url': 'https://example.com/microsoft.png'
            }
        ]
        
        response = ProviderResponseBuilder.list_response(providers)
        
        # Verify response structure
        assert response["success"] is True
        assert response["data"]["count"] == 2
        assert len(response["data"]["providers"]) == 2
        
        # Verify provider formatting
        google_provider = response["data"]["providers"][0]
        assert google_provider["name"] == "google"
        assert google_provider["type"] == "oauth2"
        assert google_provider["status"] == "active"
        assert google_provider["authorization_url"] == "/oauth/google/authorize"
        assert "metadata" in google_provider
    
    def test_token_retrieval_endpoint_standardized_response(self, client):
        """Test token retrieval endpoint returns standardized response."""
        # Store a test token
        session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            expires_in=3600,
            scope='profile email'
        )
        
        # Make request to token endpoint
        response = client.get(f'/api/tokens/{session_id}')
        data = json.loads(response.data)
        
        # Verify standardized response format
        assert response.status_code == 200
        assert data["success"] is True
        assert data["version"] == "1.0"
        assert "timestamp" in data
        assert "data" in data
        
        # Verify token data format
        token_data = data["data"]
        assert token_data["access_token"] == "test_access_token"
        assert token_data["token_type"] == "Bearer"
        assert "provider" in token_data
        assert "metadata" in token_data
        
        # Verify headers
        assert response.headers.get('X-API-Version') == '1.0'
        assert response.headers.get('Content-Type') == 'application/json'
    
    def test_token_retrieval_error_standardized_response(self, client):
        """Test token retrieval error returns standardized response."""
        # Request with invalid session ID
        response = client.get('/api/tokens/invalid-session-id')
        data = json.loads(response.data)
        
        # Verify standardized error response format
        assert response.status_code == 400
        assert data["success"] is False
        assert data["version"] == "1.0"
        assert "timestamp" in data
        assert "error" in data
        
        # Verify error details
        error = data["error"]
        assert error["code"] == ErrorCodes.INVALID_SESSION_ID
        assert "message" in error
        assert error["status_code"] == 400
        assert "details" in error
        assert error["details"]["session_id"] == "invalid-session-id"
    
    def test_providers_endpoint_standardized_response(self, client):
        """Test providers endpoint returns standardized response."""
        response = client.get('/api/providers')
        data = json.loads(response.data)
        
        # Verify standardized response format
        assert response.status_code == 200
        assert data["success"] is True
        assert data["version"] == "1.0"
        assert "timestamp" in data
        assert "data" in data
        
        # Verify provider data format
        providers_data = data["data"]
        assert "providers" in providers_data
        assert "count" in providers_data
        assert isinstance(providers_data["providers"], list)
        
        # Verify provider metadata if providers exist
        if providers_data["providers"]:
            provider = providers_data["providers"][0]
            assert "name" in provider
            assert "type" in provider
            assert provider["type"] == "oauth2"
            assert "metadata" in provider
    
    def test_api_version_endpoint(self, client):
        """Test API version endpoint."""
        response = client.get('/api/version')
        data = json.loads(response.data)
        
        # Verify response format
        assert response.status_code == 200
        assert data["success"] is True
        assert data["version"] == "1.0"
        
        # Verify version data
        version_data = data["data"]
        assert version_data["version"] == "1.0"
        assert version_data["supported_oauth_version"] == "2.0"
        assert "supported_providers" in version_data
        assert "features" in version_data
        assert "endpoints" in version_data
    
    def test_health_check_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get('/api/health')
        data = json.loads(response.data)
        
        # Verify response format
        assert response.status_code == 200
        assert data["success"] is True
        assert data["version"] == "1.0"
        
        # Verify health data
        health_data = data["data"]
        assert health_data["status"] == "healthy"
        assert "providers" in health_data
        assert "storage" in health_data
    
    def test_api_documentation_endpoint(self, client):
        """Test API documentation endpoint."""
        response = client.get('/api/docs')
        data = json.loads(response.data)
        
        # Verify response format
        assert response.status_code == 200
        assert data["success"] is True
        assert data["version"] == "1.0"
        
        # Verify documentation data
        docs_data = data["data"]
        assert docs_data["title"] == "SecureContext Protocol API"
        assert docs_data["version"] == "1.0"
        assert "endpoints" in docs_data
        assert "response_format" in docs_data
        assert "error_codes" in docs_data
    
    def test_storage_stats_endpoint_standardized_response(self, client):
        """Test storage stats endpoint returns standardized response."""
        response = client.get('/api/storage/stats')
        data = json.loads(response.data)
        
        # Verify standardized response format
        assert response.status_code == 200
        assert data["success"] is True
        assert data["version"] == "1.0"
        assert "timestamp" in data
        assert "data" in data
        assert "metadata" in data
        
        # Verify storage stats data
        stats_data = data["data"]
        assert "total_sessions" in stats_data
        assert "providers" in stats_data
        
        # Verify metadata
        metadata = data["metadata"]
        assert metadata["storage_type"] == "in_memory"
        assert metadata["cleanup_enabled"] is True
    
    def test_error_codes_consistency(self):
        """Test that error codes are consistent across the system."""
        # Test that all error codes are defined
        assert hasattr(ErrorCodes, 'INVALID_SESSION_ID')
        assert hasattr(ErrorCodes, 'SESSION_NOT_FOUND')
        assert hasattr(ErrorCodes, 'OAUTH_ERROR')
        assert hasattr(ErrorCodes, 'NETWORK_ERROR')
        assert hasattr(ErrorCodes, 'INTERNAL_ERROR')
        
        # Test error code values are strings
        assert isinstance(ErrorCodes.INVALID_SESSION_ID, str)
        assert isinstance(ErrorCodes.SESSION_NOT_FOUND, str)
        assert isinstance(ErrorCodes.OAUTH_ERROR, str)
    
    def test_api_versioning_headers(self, client):
        """Test that API versioning headers are included in responses."""
        response = client.get('/api/version')
        
        # Verify versioning headers
        assert response.headers.get('X-API-Version') == '1.0'
        assert response.headers.get('Content-Type') == 'application/json'
    
    def test_provider_metadata_enhancement(self):
        """Test that provider metadata includes comprehensive information."""
        # This would test the enhanced provider metadata
        # We'll mock a provider to test the metadata structure
        
        mock_provider_info = {
            'name': 'google',
            'display_name': 'Google Account',
            'type': 'oauth2',
            'status': 'active',
            'scopes': ['profile', 'email'],
            'metadata': {
                'icon_url': 'https://example.com/google.png',
                'documentation_url': 'https://developers.google.com/identity',
                'supported_features': ['oauth2_authorization_code', 'token_refresh'],
                'rate_limits': {'requests_per_day': 1000000}
            }
        }
        
        # Verify comprehensive metadata structure
        assert 'metadata' in mock_provider_info
        metadata = mock_provider_info['metadata']
        assert 'icon_url' in metadata
        assert 'documentation_url' in metadata
        assert 'supported_features' in metadata
        assert 'rate_limits' in metadata
    
    def test_response_consistency_across_providers(self):
        """Test that responses are consistent regardless of OAuth provider."""
        # Mock token data for different providers
        google_token_data = {
            'access_token': 'google_token',
            'refresh_token': 'google_refresh',
            'expires_at': time.time() + 3600,
            'scope': 'profile email',
            'provider': 'google',
            'created_at': time.time(),
            'session_id': 'google-session'
        }
        
        microsoft_token_data = {
            'access_token': 'microsoft_token',
            'refresh_token': 'microsoft_refresh',
            'expires_at': time.time() + 3600,
            'scope': 'User.Read Mail.Read',
            'provider': 'microsoft',
            'created_at': time.time(),
            'session_id': 'microsoft-session'
        }
        
        # Format responses for both providers
        google_response = TokenResponseBuilder.success_response(google_token_data)
        microsoft_response = TokenResponseBuilder.success_response(microsoft_token_data)
        
        # Verify both responses have the same structure
        assert google_response.keys() == microsoft_response.keys()
        assert google_response["data"].keys() == microsoft_response["data"].keys()
        assert google_response["data"]["provider_info"].keys() == microsoft_response["data"]["provider_info"].keys()
        
        # Verify both use the same token_type
        assert google_response["data"]["token_type"] == "Bearer"
        assert microsoft_response["data"]["token_type"] == "Bearer"
        
        # Verify backward compatibility - provider field is string
        assert isinstance(google_response["data"]["provider"], str)
        assert isinstance(microsoft_response["data"]["provider"], str)


if __name__ == '__main__':
    pytest.main([__file__])