"""
Core SCP client for token management and API interaction.
"""

import requests
import time
import logging
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, urlparse
import uuid

from .exceptions import (
    SCPError,
    SCPConnectionError,
    SCPAuthenticationError,
    SCPSessionError,
    SCPTimeoutError,
    SCPValidationError
)
from .retry import RetryConfig, with_retry


class SCPClient:
    """
    Core client for interacting with the SecureContext Protocol Authentication Proxy.
    
    This client provides methods for token retrieval, session management,
    and API interaction with proper error handling and retry mechanisms.
    """
    
    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        retry_config: Optional[RetryConfig] = None,
        user_agent: str = None
    ):
        """
        Initialize the SCP client.
        
        Args:
            base_url: Base URL of the SCP Authentication Proxy
            timeout: Request timeout in seconds
            retry_config: Retry configuration for failed requests
            user_agent: Custom user agent string
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.retry_config = retry_config or RetryConfig()
        self.logger = logging.getLogger(__name__)
        
        # Validate base URL
        parsed_url = urlparse(self.base_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise SCPValidationError(f"Invalid base URL: {base_url}")
        
        # Set up session with default headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or f'SCP-SDK/1.0.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        self.logger.info(f"Initialized SCP client for {self.base_url}")
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to the SCP API with error handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            params: Query parameters
            json_data: JSON request body
            headers: Additional headers
            
        Returns:
            Parsed JSON response
            
        Raises:
            SCPConnectionError: If connection fails
            SCPTimeoutError: If request times out
            SCPAuthenticationError: If authentication fails
            SCPError: For other API errors
        """
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        try:
            self.logger.debug(f"Making {method} request to {url}")
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=request_headers,
                timeout=self.timeout
            )
            
            # Handle different response status codes
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise SCPAuthenticationError(
                    "Authentication failed",
                    error_code="AUTHENTICATION_FAILED",
                    status_code=401
                )
            elif response.status_code == 404:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', {}).get('message', 'Resource not found')
                    error_code = error_data.get('error', {}).get('code', 'NOT_FOUND')
                except:
                    error_message = 'Resource not found'
                    error_code = 'NOT_FOUND'
                
                raise SCPSessionError(
                    error_message,
                    error_code=error_code,
                    status_code=404
                )
            elif response.status_code >= 500:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', {}).get('message', 'Server error')
                    error_code = error_data.get('error', {}).get('code', 'SERVER_ERROR')
                except:
                    error_message = f'Server error (HTTP {response.status_code})'
                    error_code = 'SERVER_ERROR'
                
                raise SCPConnectionError(
                    error_message,
                    error_code=error_code,
                    status_code=response.status_code
                )
            else:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', {}).get('message', f'HTTP {response.status_code}')
                    error_code = error_data.get('error', {}).get('code', 'API_ERROR')
                except:
                    error_message = f'API error (HTTP {response.status_code})'
                    error_code = 'API_ERROR'
                
                raise SCPError(
                    error_message,
                    error_code=error_code,
                    status_code=response.status_code
                )
        
        except requests.exceptions.Timeout:
            raise SCPTimeoutError(
                f"Request to {url} timed out after {self.timeout} seconds",
                error_code="TIMEOUT"
            )
        except requests.exceptions.ConnectionError as e:
            raise SCPConnectionError(
                f"Failed to connect to {url}: {str(e)}",
                error_code="CONNECTION_FAILED"
            )
        except requests.exceptions.RequestException as e:
            raise SCPConnectionError(
                f"Request failed: {str(e)}",
                error_code="REQUEST_FAILED"
            )
    
    @with_retry()
    def get_tokens(self, session_id: str) -> Dict[str, Any]:
        """
        Retrieve OAuth tokens by session ID.
        
        Args:
            session_id: Session ID obtained from OAuth flow
            
        Returns:
            Token data dictionary containing access_token, refresh_token, etc.
            
        Raises:
            SCPValidationError: If session ID format is invalid
            SCPSessionError: If session not found or expired
            SCPConnectionError: If connection fails
        """
        # Validate session ID format
        if not self._validate_session_id(session_id):
            raise SCPValidationError(f"Invalid session ID format: {session_id}")
        
        self.logger.info(f"Retrieving tokens for session {session_id}")
        
        response = self._make_request('GET', f'/api/tokens/{session_id}')
        
        if response.get('success'):
            token_data = response.get('data', {})
            self.logger.info(f"Successfully retrieved tokens for session {session_id}")
            return token_data
        else:
            error_info = response.get('error', {})
            raise SCPError(
                error_info.get('message', 'Failed to retrieve tokens'),
                error_code=error_info.get('code', 'TOKEN_RETRIEVAL_FAILED')
            )
    
    @with_retry()
    def get_providers(self) -> List[Dict[str, Any]]:
        """
        Get list of available OAuth providers.
        
        Returns:
            List of provider information dictionaries
            
        Raises:
            SCPConnectionError: If connection fails
        """
        self.logger.debug("Retrieving available providers")
        
        response = self._make_request('GET', '/api/providers')
        
        if response.get('success'):
            providers_data = response.get('data', {})
            providers = providers_data.get('providers', [])
            self.logger.info(f"Retrieved {len(providers)} available providers")
            return providers
        else:
            error_info = response.get('error', {})
            raise SCPError(
                error_info.get('message', 'Failed to retrieve providers'),
                error_code=error_info.get('code', 'PROVIDER_RETRIEVAL_FAILED')
            )
    
    @with_retry()
    def get_api_version(self) -> Dict[str, Any]:
        """
        Get API version information.
        
        Returns:
            API version and feature information
            
        Raises:
            SCPConnectionError: If connection fails
        """
        self.logger.debug("Retrieving API version information")
        
        response = self._make_request('GET', '/api/version')
        
        if response.get('success'):
            version_data = response.get('data', {})
            self.logger.debug(f"API version: {version_data.get('version', 'unknown')}")
            return version_data
        else:
            error_info = response.get('error', {})
            raise SCPError(
                error_info.get('message', 'Failed to retrieve API version'),
                error_code=error_info.get('code', 'VERSION_RETRIEVAL_FAILED')
            )
    
    @with_retry()
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on the SCP server.
        
        Returns:
            Health status information
            
        Raises:
            SCPConnectionError: If connection fails
        """
        self.logger.debug("Performing health check")
        
        response = self._make_request('GET', '/api/health')
        
        if response.get('success'):
            health_data = response.get('data', {})
            status = health_data.get('status', 'unknown')
            self.logger.debug(f"Health check status: {status}")
            return health_data
        else:
            error_info = response.get('error', {})
            raise SCPError(
                error_info.get('message', 'Health check failed'),
                error_code=error_info.get('code', 'HEALTH_CHECK_FAILED')
            )
    
    def get_authorization_url(self, provider: str) -> str:
        """
        Get OAuth authorization URL for a provider.
        
        Args:
            provider: Provider name (e.g., 'google', 'microsoft')
            
        Returns:
            Authorization URL for the provider
        """
        if not provider:
            raise SCPValidationError("Provider name is required")
        
        return f"{self.base_url}/oauth/{provider}/authorize"
    
    def _validate_session_id(self, session_id: str) -> bool:
        """
        Validate session ID format.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not session_id or not isinstance(session_id, str):
            return False
        
        try:
            # Parse as UUID and validate it's version 4
            parsed_uuid = uuid.UUID(session_id)
            return parsed_uuid.version == 4
        except ValueError:
            return False
    
    def close(self):
        """Close the HTTP session."""
        if self.session:
            self.session.close()
            self.logger.debug("Closed HTTP session")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()