"""
Standardized API response system for the SecureContext Protocol.

This module provides consistent API response formatting, versioning,
and provider metadata handling across all endpoints.
"""

from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timezone
from flask import jsonify, request
import logging


class APIResponse:
    """
    Standardized API response builder for consistent responses across all endpoints.
    
    This class ensures all API responses follow the same format and include
    appropriate metadata, versioning, and error handling.
    """
    
    # Current API version
    API_VERSION = "1.0"
    
    @staticmethod
    def success(data: Any = None, message: Optional[str] = None, 
                metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a standardized success response.
        
        Args:
            data: Response data payload
            message: Optional success message
            metadata: Optional response metadata
            
        Returns:
            Standardized success response dictionary
        """
        response = {
            "success": True,
            "version": APIResponse.API_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "data": data
        }
        
        if message:
            response["message"] = message
            
        if metadata:
            response["metadata"] = metadata
            
        return response
    
    @staticmethod
    def error(code: str, message: str, details: Optional[Dict[str, Any]] = None,
              status_code: int = 400) -> Dict[str, Any]:
        """
        Create a standardized error response.
        
        Args:
            code: Error code identifier
            message: Human-readable error message
            details: Optional error details
            status_code: HTTP status code
            
        Returns:
            Standardized error response dictionary
        """
        response = {
            "success": False,
            "version": APIResponse.API_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "error": {
                "code": code,
                "message": message,
                "status_code": status_code
            }
        }
        
        if details:
            response["error"]["details"] = details
            
        return response
    
    @staticmethod
    def paginated(data: List[Any], page: int = 1, per_page: int = 50,
                  total: Optional[int] = None, message: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a standardized paginated response.
        
        Args:
            data: List of data items
            page: Current page number
            per_page: Items per page
            total: Total number of items (if known)
            message: Optional message
            
        Returns:
            Standardized paginated response dictionary
        """
        pagination_metadata = {
            "page": page,
            "per_page": per_page,
            "count": len(data)
        }
        
        if total is not None:
            pagination_metadata["total"] = total
            pagination_metadata["pages"] = (total + per_page - 1) // per_page
            pagination_metadata["has_next"] = page * per_page < total
            pagination_metadata["has_prev"] = page > 1
        
        return APIResponse.success(
            data=data,
            message=message,
            metadata={"pagination": pagination_metadata}
        )


class TokenResponseBuilder:
    """
    Specialized response builder for token-related API endpoints.
    
    This class provides consistent token response formatting with
    provider metadata and standardized field names.
    """
    
    @staticmethod
    def format_token_response(token_data: Dict[str, Any], 
                            provider_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Format token data into standardized response format.
        
        Args:
            token_data: Raw token data from storage
            provider_info: Optional provider metadata
            
        Returns:
            Formatted token response data
        """
        # Convert expires_at timestamp to ISO format if it's a number
        expires_at = token_data.get('expires_at')
        if isinstance(expires_at, (int, float)):
            expires_at = datetime.fromtimestamp(expires_at).isoformat() + "Z"
        
        # Build standardized token response
        response_data = {
            "access_token": token_data.get('access_token'),
            "refresh_token": token_data.get('refresh_token'),
            "token_type": "Bearer",  # Standard OAuth 2.0 token type
            "expires_at": expires_at,
            "scope": token_data.get('scope', ''),
            "provider": token_data.get('provider'),  # Maintain backward compatibility
            "provider_info": {  # New enhanced provider information
                "name": token_data.get('provider'),
                "display_name": provider_info.get('display_name') if provider_info else None,
                "type": "oauth2"
            }
        }
        
        # Add provider-specific metadata if available
        if provider_info:
            response_data["provider_info"].update({
                "display_name": provider_info.get('display_name'),
                "icon_url": provider_info.get('icon_url'),
                "documentation_url": provider_info.get('documentation_url'),
                "scopes": provider_info.get('scopes', [])
            })
        
        # Add token metadata
        created_at = token_data.get('created_at')
        if isinstance(created_at, (int, float)):
            created_at = datetime.fromtimestamp(created_at).isoformat() + "Z"
        
        response_data["metadata"] = {
            "created_at": created_at,
            "session_id": token_data.get('session_id'),
            "expires_in_seconds": None
        }
        
        # Calculate expires_in_seconds if we have expires_at
        if token_data.get('expires_at'):
            try:
                expires_timestamp = token_data['expires_at']
                current_timestamp = datetime.now(timezone.utc).timestamp()
                expires_in = max(0, int(expires_timestamp - current_timestamp))
                response_data["metadata"]["expires_in_seconds"] = expires_in
            except (ValueError, TypeError):
                pass
        
        return response_data
    
    @staticmethod
    def success_response(token_data: Dict[str, Any], 
                        provider_info: Optional[Dict[str, Any]] = None,
                        message: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a successful token response.
        
        Args:
            token_data: Token data from storage
            provider_info: Provider metadata
            message: Optional success message
            
        Returns:
            Standardized success response with token data
        """
        formatted_data = TokenResponseBuilder.format_token_response(token_data, provider_info)
        
        return APIResponse.success(
            data=formatted_data,
            message=message or "Token retrieved successfully"
        )
    
    @staticmethod
    def error_response(code: str, message: str, session_id: Optional[str] = None,
                      status_code: int = 400) -> Dict[str, Any]:
        """
        Create a standardized token error response.
        
        Args:
            code: Error code
            message: Error message
            session_id: Optional session ID for context
            status_code: HTTP status code
            
        Returns:
            Standardized error response
        """
        details = {}
        if session_id:
            details["session_id"] = session_id
            
        return APIResponse.error(code, message, details, status_code)


class ProviderResponseBuilder:
    """
    Specialized response builder for provider-related API endpoints.
    
    This class provides consistent provider information formatting
    and metadata handling.
    """
    
    @staticmethod
    def format_provider_info(provider_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format provider information into standardized response format.
        
        Args:
            provider_info: Raw provider information
            
        Returns:
            Formatted provider information
        """
        return {
            "name": provider_info.get('name'),
            "display_name": provider_info.get('display_name'),
            "type": "oauth2",
            "status": "active",
            "scopes": provider_info.get('scopes', []),
            "supports_refresh": provider_info.get('supports_refresh', False),
            "supports_user_info": provider_info.get('supports_user_info', False),
            "authorization_url": f"/oauth/{provider_info.get('name')}/authorize",
            "metadata": {
                "icon_url": provider_info.get('icon_url'),
                "documentation_url": provider_info.get('documentation_url'),
                "supported_features": provider_info.get('supported_features', []),
                "rate_limits": provider_info.get('rate_limits', {})
            }
        }
    
    @staticmethod
    def list_response(providers: List[Dict[str, Any]], 
                     message: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a standardized provider list response.
        
        Args:
            providers: List of provider information dictionaries
            message: Optional message
            
        Returns:
            Standardized provider list response
        """
        formatted_providers = [
            ProviderResponseBuilder.format_provider_info(provider)
            for provider in providers
        ]
        
        return APIResponse.success(
            data={
                "providers": formatted_providers,
                "count": len(formatted_providers)
            },
            message=message or f"Retrieved {len(formatted_providers)} providers",
            metadata={
                "api_version": APIResponse.API_VERSION,
                "supported_oauth_version": "2.0"
            }
        )


class ErrorCodes:
    """
    Standardized error codes for consistent error handling across the API.
    """
    
    # Authentication and Authorization Errors
    INVALID_SESSION_ID = "INVALID_SESSION_ID_FORMAT"  # Maintain backward compatibility
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    INVALID_TOKEN = "INVALID_TOKEN"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    
    # OAuth Flow Errors
    OAUTH_ERROR = "OAUTH_ERROR"
    OAUTH_DENIED = "OAUTH_DENIED"
    OAUTH_STATE_MISMATCH = "OAUTH_STATE_MISMATCH"
    OAUTH_INVALID_CODE = "OAUTH_INVALID_CODE"
    
    # Provider Errors
    PROVIDER_NOT_FOUND = "PROVIDER_NOT_FOUND"
    PROVIDER_DISABLED = "PROVIDER_DISABLED"
    PROVIDER_CONFIG_ERROR = "PROVIDER_CONFIG_ERROR"
    
    # Network and System Errors
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT_ERROR = "TIMEOUT_ERROR"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    
    # Validation Errors
    INVALID_REQUEST = "INVALID_REQUEST"
    MISSING_PARAMETER = "MISSING_PARAMETER"
    INVALID_PARAMETER = "INVALID_PARAMETER"
    
    # Storage Errors
    STORAGE_ERROR = "STORAGE_ERROR"
    STORAGE_FULL = "STORAGE_FULL"
    
    # Enterprise/Webhook Errors
    WEBHOOK_ERROR = "WEBHOOK_ERROR"
    WEBHOOK_DISABLED = "WEBHOOK_DISABLED"
    
    # Streaming Errors
    STREAM_NOT_FOUND = "STREAM_NOT_FOUND"
    STREAM_ALREADY_ACTIVE = "STREAM_ALREADY_ACTIVE"
    STREAM_RATE_LIMITED = "STREAM_RATE_LIMITED"
    STREAM_CONFIG_ERROR = "STREAM_CONFIG_ERROR"


def create_flask_response(response_data: Dict[str, Any], status_code: int = 200):
    """
    Create a Flask JSON response with proper headers and status code.
    
    Args:
        response_data: Response data dictionary
        status_code: HTTP status code
        
    Returns:
        Flask JSON response
    """
    response = jsonify(response_data)
    response.status_code = status_code
    
    # Add standard headers
    response.headers['Content-Type'] = 'application/json'
    response.headers['X-API-Version'] = APIResponse.API_VERSION
    response.headers['X-Request-ID'] = getattr(request, 'request_id', 'unknown')
    
    return response


def log_api_request(endpoint: str, method: str, status_code: int, 
                   response_time: Optional[float] = None):
    """
    Log API request for monitoring and debugging.
    
    Args:
        endpoint: API endpoint path
        method: HTTP method
        status_code: Response status code
        response_time: Optional response time in milliseconds
    """
    logger = logging.getLogger(__name__)
    
    log_data = {
        'endpoint': endpoint,
        'method': method,
        'status_code': status_code,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'ip_address': request.remote_addr
    }
    
    if response_time:
        log_data['response_time_ms'] = response_time
    
    logger.info(f"API Request: {method} {endpoint} -> {status_code}", extra=log_data)