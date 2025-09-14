#!/usr/bin/env python3
"""
Token Verification Script for SecureContext Protocol

This script verifies token retrieval functionality by making HTTP requests
to the SCP Authentication Proxy token endpoint and displaying the results.

Usage:
    python verify_tokens.py <session_id> [--host HOST] [--port PORT]

Requirements covered:
- 6.1: Make HTTP request to token endpoint with session ID
- 6.2: Display token information in console when successful
- 6.3: Handle invalid session ID errors gracefully
- 6.4: Provide meaningful error messages for network issues
"""

import argparse
import sys
import json
import requests
from typing import Dict, Any, Optional
from urllib.parse import urljoin


class TokenVerifier:
    """
    Token verification client for SCP Authentication Proxy.
    
    This class handles HTTP communication with the token retrieval endpoint
    and provides formatted output for verification results.
    """
    
    def __init__(self, host: str = 'localhost', port: int = 5000):
        """
        Initialize the token verifier.
        
        Args:
            host: SCP Authentication Proxy host (default: localhost)
            port: SCP Authentication Proxy port (default: 5000)
        """
        self.base_url = f"http://{host}:{port}"
        self.token_endpoint = urljoin(self.base_url, "/api/tokens/")
        
    def verify_token(self, session_id: str) -> Dict[str, Any]:
        """
        Verify token retrieval for a given session ID.
        
        Args:
            session_id: Session ID to verify
            
        Returns:
            Dictionary containing verification results
        """
        result = {
            'success': False,
            'session_id': session_id,
            'error': None,
            'token_data': None
        }
        
        try:
            # Construct the full URL for the token endpoint
            url = urljoin(self.token_endpoint, session_id)
            
            print(f"Making request to: {url}")
            
            # Make HTTP GET request to token endpoint
            response = requests.get(url, timeout=10)
            
            # Parse JSON response
            try:
                response_data = response.json()
            except json.JSONDecodeError as e:
                result['error'] = {
                    'type': 'INVALID_JSON',
                    'message': f'Invalid JSON response from server: {e}',
                    'status_code': response.status_code,
                    'response_text': response.text[:200] + '...' if len(response.text) > 200 else response.text
                }
                return result
            
            # Handle successful response
            if response.status_code == 200:
                if response_data.get('success'):
                    result['success'] = True
                    result['token_data'] = response_data.get('data', {})
                else:
                    result['error'] = {
                        'type': 'API_ERROR',
                        'message': 'API returned success=false',
                        'details': response_data.get('error', {})
                    }
            
            # Handle client errors (4xx)
            elif 400 <= response.status_code < 500:
                error_info = response_data.get('error', {})
                error_code = error_info.get('code', 'UNKNOWN_CLIENT_ERROR')
                error_message = error_info.get('message', 'Client error occurred')
                
                if response.status_code == 400:
                    result['error'] = {
                        'type': 'INVALID_SESSION_ID',
                        'message': f'Invalid session ID format: {error_message}',
                        'code': error_code
                    }
                elif response.status_code == 404:
                    result['error'] = {
                        'type': 'SESSION_NOT_FOUND',
                        'message': f'Session ID not found or expired: {error_message}',
                        'code': error_code
                    }
                else:
                    result['error'] = {
                        'type': 'CLIENT_ERROR',
                        'message': f'Client error ({response.status_code}): {error_message}',
                        'code': error_code,
                        'status_code': response.status_code
                    }
            
            # Handle server errors (5xx)
            elif response.status_code >= 500:
                error_info = response_data.get('error', {})
                result['error'] = {
                    'type': 'SERVER_ERROR',
                    'message': f'Server error ({response.status_code}): {error_info.get("message", "Internal server error")}',
                    'code': error_info.get('code', 'UNKNOWN_SERVER_ERROR'),
                    'status_code': response.status_code
                }
            
            # Handle unexpected status codes
            else:
                result['error'] = {
                    'type': 'UNEXPECTED_STATUS',
                    'message': f'Unexpected status code: {response.status_code}',
                    'status_code': response.status_code,
                    'response_text': response.text[:200] + '...' if len(response.text) > 200 else response.text
                }
                
        except requests.exceptions.ConnectionError as e:
            result['error'] = {
                'type': 'CONNECTION_ERROR',
                'message': f'Failed to connect to SCP Authentication Proxy at {self.base_url}. '
                          f'Please ensure the server is running and accessible.',
                'details': str(e)
            }
            
        except requests.exceptions.Timeout as e:
            result['error'] = {
                'type': 'TIMEOUT_ERROR',
                'message': f'Request timed out after 10 seconds. The server may be overloaded or unreachable.',
                'details': str(e)
            }
            
        except requests.exceptions.RequestException as e:
            result['error'] = {
                'type': 'NETWORK_ERROR',
                'message': f'Network error occurred while connecting to {self.base_url}',
                'details': str(e)
            }
            
        except Exception as e:
            result['error'] = {
                'type': 'UNEXPECTED_ERROR',
                'message': f'An unexpected error occurred: {e}',
                'details': str(e)
            }
        
        return result
    
    def format_token_data(self, token_data: Dict[str, Any]) -> str:
        """
        Format token data for console display.
        
        Args:
            token_data: Token data dictionary from API response
            
        Returns:
            Formatted string for console output
        """
        lines = [
            "✅ Token Verification Successful!",
            "=" * 50,
            f"Provider:      {token_data.get('provider', 'Unknown')}",
            f"Access Token:  {token_data.get('access_token', 'N/A')[:20]}..." if token_data.get('access_token') else "Access Token:  N/A",
            f"Refresh Token: {token_data.get('refresh_token', 'N/A')[:20]}..." if token_data.get('refresh_token') else "Refresh Token: N/A",
            f"Expires At:    {token_data.get('expires_at', 'N/A')}",
            f"Scope:         {token_data.get('scope', 'N/A')}",
            "=" * 50
        ]
        return "\n".join(lines)
    
    def format_error(self, error: Dict[str, Any]) -> str:
        """
        Format error information for console display.
        
        Args:
            error: Error dictionary
            
        Returns:
            Formatted error string for console output
        """
        error_type = error.get('type', 'UNKNOWN_ERROR')
        message = error.get('message', 'An error occurred')
        
        lines = [
            f"❌ Token Verification Failed - {error_type}",
            "=" * 50,
            f"Error: {message}"
        ]
        
        # Add additional details if available
        if 'code' in error:
            lines.append(f"Code:  {error['code']}")
        
        if 'status_code' in error:
            lines.append(f"HTTP Status: {error['status_code']}")
        
        if 'details' in error:
            lines.append(f"Details: {error['details']}")
        
        lines.append("=" * 50)
        
        # Add helpful suggestions based on error type
        if error_type == 'CONNECTION_ERROR':
            lines.extend([
                "",
                "💡 Troubleshooting suggestions:",
                "   • Ensure the SCP Authentication Proxy is running",
                "   • Check if the host and port are correct",
                "   • Verify network connectivity"
            ])
        elif error_type == 'SESSION_NOT_FOUND':
            lines.extend([
                "",
                "💡 Troubleshooting suggestions:",
                "   • Verify the session ID is correct",
                "   • Check if the session has expired",
                "   • Complete a new OAuth flow to get a fresh session ID"
            ])
        elif error_type == 'INVALID_SESSION_ID':
            lines.extend([
                "",
                "💡 Troubleshooting suggestions:",
                "   • Ensure the session ID is a valid UUID4 format",
                "   • Check for any extra characters or spaces",
                "   • Use a session ID from a successful OAuth flow"
            ])
        
        return "\n".join(lines)


def validate_session_id(session_id: str) -> bool:
    """
    Validate session ID format (basic UUID4 check).
    
    Args:
        session_id: Session ID to validate
        
    Returns:
        True if format appears valid, False otherwise
    """
    import uuid
    
    if not session_id or not isinstance(session_id, str):
        return False
    
    try:
        uuid.UUID(session_id, version=4)
        return True
    except ValueError:
        return False


def main():
    """
    Main function for command-line interface.
    
    Handles argument parsing and executes token verification.
    """
    parser = argparse.ArgumentParser(
        description='Verify token retrieval from SCP Authentication Proxy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_tokens.py 12345678-1234-1234-1234-123456789abc
  python verify_tokens.py 12345678-1234-1234-1234-123456789abc --host 192.168.1.100
  python verify_tokens.py 12345678-1234-1234-1234-123456789abc --port 8080
        """
    )
    
    parser.add_argument(
        'session_id',
        help='Session ID to verify (UUID4 format)'
    )
    
    parser.add_argument(
        '--host',
        default='localhost',
        help='SCP Authentication Proxy host (default: localhost)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='SCP Authentication Proxy port (default: 5000)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Basic session ID format validation
    if not validate_session_id(args.session_id):
        print("❌ Invalid session ID format. Expected UUID4 format (e.g., 12345678-1234-1234-1234-123456789abc)")
        print(f"Provided: {args.session_id}")
        sys.exit(1)
    
    if args.verbose:
        print(f"Verifying session ID: {args.session_id}")
        print(f"Target server: {args.host}:{args.port}")
        print()
    
    # Create verifier and perform verification
    verifier = TokenVerifier(host=args.host, port=args.port)
    result = verifier.verify_token(args.session_id)
    
    # Display results
    if result['success']:
        print(verifier.format_token_data(result['token_data']))
        sys.exit(0)
    else:
        print(verifier.format_error(result['error']))
        sys.exit(1)


if __name__ == '__main__':
    main()