"""
Flask application for the SecureContext Protocol Authentication Proxy.

This module implements the core Flask application with session management,
error handling, OAuth flows, and the web UI serving route.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import logging
import sys
import uuid
import time
import threading
import secrets
from typing import Tuple, Dict, Any, Optional
from datetime import datetime, timedelta
from authlib.common.errors import AuthlibBaseError
from requests.exceptions import RequestException, ConnectionError, Timeout

try:
    from .config import get_config, ConfigurationError
except ImportError:
    from config import get_config, ConfigurationError


# Global in-memory token storage
# Structure: {session_id: {provider, access_token, refresh_token, expires_at, scope, created_at}}
token_storage: Dict[str, Dict[str, Any]] = {}
storage_lock = threading.Lock()


class TokenStorage:
    """
    In-memory token storage system for OAuth tokens.
    
    This class provides secure, temporary storage for OAuth access and refresh tokens
    with session-based isolation and automatic cleanup of expired sessions.
    """
    
    @staticmethod
    def generate_session_id() -> str:
        """
        Generate a unique session ID for token storage.
        
        Returns:
            Cryptographically secure UUID4 string
        """
        return str(uuid.uuid4())
    
    @staticmethod
    def store_tokens(provider: str, access_token: str, refresh_token: str, 
                    expires_in: int, scope: str) -> str:
        """
        Store OAuth tokens with a unique session ID.
        
        Args:
            provider: OAuth provider name ('google' or 'microsoft')
            access_token: OAuth access token
            refresh_token: OAuth refresh token
            expires_in: Token expiration time in seconds
            scope: OAuth scope string
            
        Returns:
            Generated session ID for token retrieval
            
        Raises:
            ValueError: If required parameters are invalid
        """
        # Validate input parameters
        if not provider or provider not in ['google', 'microsoft']:
            raise ValueError(f"Invalid provider: {provider}")
        
        if not access_token or not isinstance(access_token, str):
            raise ValueError("Access token is required and must be a string")
        
        if not isinstance(expires_in, int) or expires_in <= 0:
            raise ValueError("expires_in must be a positive integer")
        
        try:
            session_id = TokenStorage.generate_session_id()
            current_time = time.time()
            expires_at = current_time + expires_in
            
            token_data = {
                'provider': provider,
                'access_token': access_token,
                'refresh_token': refresh_token or '',  # Ensure it's never None
                'expires_at': expires_at,
                'scope': scope or '',  # Ensure it's never None
                'created_at': current_time
            }
            
            with storage_lock:
                # Check storage limits (prevent memory exhaustion)
                if len(token_storage) >= 1000:  # Reasonable limit for demo
                    logging.warning("Token storage limit reached, cleaning up expired sessions")
                    TokenStorage.cleanup_expired_sessions()
                    
                    # If still at limit after cleanup, remove oldest sessions
                    if len(token_storage) >= 1000:
                        oldest_sessions = sorted(
                            token_storage.items(),
                            key=lambda x: x[1]['created_at']
                        )[:100]  # Remove oldest 100 sessions
                        
                        for old_session_id, _ in oldest_sessions:
                            del token_storage[old_session_id]
                        
                        logging.warning(f"Removed {len(oldest_sessions)} oldest sessions due to storage limit")
                
                token_storage[session_id] = token_data
                
            logging.info(f"Stored tokens for provider '{provider}' with session ID: {session_id}")
            return session_id
            
        except Exception as e:
            logging.error(f"Error storing tokens for provider '{provider}': {e}", exc_info=True)
            raise
    
    @staticmethod
    def retrieve_tokens(session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve stored tokens by session ID.
        
        Args:
            session_id: Session ID for token lookup
            
        Returns:
            Token data dictionary if found and valid, None otherwise
        """
        if not TokenStorage.validate_session_id(session_id):
            logging.warning(f"Invalid session ID format: {session_id}")
            return None
            
        with storage_lock:
            token_data = token_storage.get(session_id)
            
        if not token_data:
            logging.warning(f"Session ID not found: {session_id}")
            return None
            
        # Check if token has expired
        if time.time() > token_data['expires_at']:
            logging.info(f"Token expired for session ID: {session_id}")
            TokenStorage.remove_session(session_id)
            return None
            
        logging.info(f"Retrieved tokens for session ID: {session_id}")
        return token_data
    
    @staticmethod
    def validate_session_id(session_id: str) -> bool:
        """
        Validate session ID format.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            True if session ID format is valid, False otherwise
        """
        if not session_id or not isinstance(session_id, str):
            return False
            
        try:
            # Validate UUID4 format
            uuid.UUID(session_id, version=4)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def remove_session(session_id: str) -> bool:
        """
        Remove a session from storage.
        
        Args:
            session_id: Session ID to remove
            
        Returns:
            True if session was removed, False if not found
        """
        with storage_lock:
            if session_id in token_storage:
                del token_storage[session_id]
                logging.info(f"Removed session: {session_id}")
                return True
            return False
    
    @staticmethod
    def cleanup_expired_sessions() -> int:
        """
        Remove expired sessions from storage.
        
        Returns:
            Number of sessions cleaned up
        """
        current_time = time.time()
        expired_sessions = []
        
        with storage_lock:
            for session_id, token_data in token_storage.items():
                if current_time > token_data['expires_at']:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del token_storage[session_id]
        
        if expired_sessions:
            logging.info(f"Cleaned up {len(expired_sessions)} expired sessions")
            
        return len(expired_sessions)
    
    @staticmethod
    def get_storage_stats() -> Dict[str, Any]:
        """
        Get statistics about current token storage.
        
        Returns:
            Dictionary with storage statistics
        """
        with storage_lock:
            total_sessions = len(token_storage)
            providers = {}
            
            for token_data in token_storage.values():
                provider = token_data['provider']
                providers[provider] = providers.get(provider, 0) + 1
        
        return {
            'total_sessions': total_sessions,
            'providers': providers,
            'storage_size_bytes': sys.getsizeof(token_storage)
        }


def start_cleanup_scheduler():
    """
    Start background thread for periodic cleanup of expired tokens.
    
    This function starts a daemon thread that runs cleanup every 5 minutes
    to remove expired sessions from memory.
    """
    def cleanup_worker():
        while True:
            try:
                time.sleep(300)  # Sleep for 5 minutes
                TokenStorage.cleanup_expired_sessions()
            except Exception as e:
                logging.error(f"Error in cleanup worker: {e}")
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    logging.info("Started token cleanup scheduler")


def create_app() -> Flask:
    """
    Create and configure the Flask application.
    
    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)
    
    try:
        # Load configuration
        config = get_config()
        flask_config = config.get_flask_config()
        
        # Configure Flask application
        app.config.update(flask_config)
        
        # Set up comprehensive logging for OAuth debugging
        log_level = logging.DEBUG if flask_config.get('DEBUG', False) else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Set specific log levels for OAuth-related libraries
        logging.getLogger('authlib').setLevel(logging.DEBUG if flask_config.get('DEBUG', False) else logging.WARNING)
        logging.getLogger('requests').setLevel(logging.DEBUG if flask_config.get('DEBUG', False) else logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)  # Reduce noise from urllib3
        
        # Initialize OAuth
        oauth = OAuth(app)
        
        # Configure Google OAuth client
        google_config = config.get_oauth_config('google')
        google = oauth.register(
            name='google',
            client_id=google_config['client_id'],
            client_secret=google_config['client_secret'],
            server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
            client_kwargs={
                'scope': ' '.join(google_config['scopes'])
            }
        )
        
        # Configure Microsoft OAuth client
        microsoft_config = config.get_oauth_config('microsoft')
        microsoft = oauth.register(
            name='microsoft',
            client_id=microsoft_config['client_id'],
            client_secret=microsoft_config['client_secret'],
            authorize_url=microsoft_config['authorize_url'],
            access_token_url=microsoft_config['token_url'],
            client_kwargs={
                'scope': ' '.join(microsoft_config['scopes'])
            }
        )
        
        # Store OAuth clients in app context for route access
        app.oauth = oauth
        app.google_client = google
        app.microsoft_client = microsoft
        
        # Register error handlers
        register_error_handlers(app)
        
        # Register routes
        register_routes(app)
        
        # Start token cleanup scheduler
        start_cleanup_scheduler()
        
        app.logger.info("Flask application initialized successfully")
        return app
        
    except ConfigurationError as e:
        print(f"Failed to initialize Flask application: {e}", file=sys.stderr)
        sys.exit(1)


def register_error_handlers(app: Flask) -> None:
    """
    Register comprehensive error handling middleware for the Flask application.
    
    Args:
        app: Flask application instance
    """
    
    @app.errorhandler(404)
    def not_found_error(error) -> Tuple[str, int]:
        """Handle 404 Not Found errors."""
        app.logger.warning(f"404 error: {request.url} - User Agent: {request.headers.get('User-Agent', 'Unknown')}")
        return render_template('error.html', 
                             error_code=404,
                             error_message="The requested page was not found"), 404
    
    @app.errorhandler(500)
    def internal_error(error) -> Tuple[str, int]:
        """Handle 500 Internal Server errors."""
        app.logger.error(f"500 error: {error} - URL: {request.url}", exc_info=True)
        return render_template('error.html',
                             error_code=500, 
                             error_message="An internal server error occurred. Please try again later."), 500
    
    @app.errorhandler(400)
    def bad_request_error(error) -> Tuple[str, int]:
        """Handle 400 Bad Request errors."""
        app.logger.warning(f"400 error: {error} - URL: {request.url}")
        return render_template('error.html',
                             error_code=400,
                             error_message="The request was invalid. Please check your input and try again."), 400
    
    @app.errorhandler(403)
    def forbidden_error(error) -> Tuple[str, int]:
        """Handle 403 Forbidden errors."""
        app.logger.warning(f"403 error: {error} - URL: {request.url}")
        return render_template('error.html',
                             error_code=403,
                             error_message="Access forbidden. You don't have permission to access this resource."), 403
    
    @app.errorhandler(AuthlibBaseError)
    def handle_authlib_error(error) -> Tuple[str, int]:
        """Handle Authlib OAuth errors."""
        app.logger.error(f"Authlib OAuth error: {error} - URL: {request.url}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': {
                    'code': 'OAUTH_ERROR',
                    'message': 'OAuth authentication error occurred'
                }
            }), 500
        
        return render_template('error.html',
                             error_code=500,
                             error_message="OAuth authentication error. Please try again."), 500
    
    @app.errorhandler(ConnectionError)
    def handle_connection_error(error) -> Tuple[str, int]:
        """Handle network connection errors."""
        app.logger.error(f"Connection error: {error} - URL: {request.url}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': {
                    'code': 'NETWORK_ERROR',
                    'message': 'Network connection failed'
                }
            }), 503
        
        return render_template('error.html',
                             error_code=503,
                             error_message="Network connection failed. Please check your internet connection and try again."), 503
    
    @app.errorhandler(Timeout)
    def handle_timeout_error(error) -> Tuple[str, int]:
        """Handle request timeout errors."""
        app.logger.error(f"Timeout error: {error} - URL: {request.url}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': {
                    'code': 'TIMEOUT_ERROR',
                    'message': 'Request timed out'
                }
            }), 504
        
        return render_template('error.html',
                             error_code=504,
                             error_message="Request timed out. Please try again."), 504
    
    @app.errorhandler(RequestException)
    def handle_request_error(error) -> Tuple[str, int]:
        """Handle general request errors."""
        app.logger.error(f"Request error: {error} - URL: {request.url}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': {
                    'code': 'REQUEST_ERROR',
                    'message': 'Network request failed'
                }
            }), 502
        
        return render_template('error.html',
                             error_code=502,
                             error_message="Network request failed. Please try again."), 502
    
    @app.errorhandler(Exception)
    def handle_exception(error) -> Tuple[str, int]:
        """Handle unexpected exceptions with comprehensive logging."""
        app.logger.error(f"Unexpected error: {error} - URL: {request.url} - Method: {request.method} - IP: {request.remote_addr}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred'
                }
            }), 500
        
        return render_template('error.html',
                             error_code=500,
                             error_message="An unexpected error occurred. Please try again later."), 500


def register_routes(app: Flask) -> None:
    """
    Register application routes.
    
    Args:
        app: Flask application instance
    """
    
    @app.route('/')
    def index() -> str:
        """
        Serve the web UI at the root path.
        
        This route serves the main user interface with connection buttons
        for Google and Microsoft OAuth flows. It handles URL parameters
        for displaying connection status and error messages.
        
        Returns:
            Rendered HTML template for the web UI
        """
        # Get URL parameters for status display
        session_id = request.args.get('session_id')
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        
        # Prepare context for template
        context = {
            'session_id': session_id,
            'error': error,
            'error_description': error_description,
            'success': bool(session_id and not error)
        }
        
        app.logger.info(f"Serving web UI - session_id: {session_id}, error: {error}")
        
        return render_template('index.html', **context)
    
    @app.route('/api/tokens/<session_id>')
    def get_tokens(session_id: str) -> Tuple[Dict[str, Any], int]:
        """
        Token retrieval endpoint for AI agents and external systems.
        
        This endpoint allows retrieval of stored OAuth tokens using a session ID.
        It validates the session ID format and existence, returning appropriate
        error responses for invalid requests.
        
        Args:
            session_id: Session ID for token lookup
            
        Returns:
            JSON response with token data or error message
        """
        app.logger.info(f"Token retrieval request for session ID: {session_id}")
        
        try:
            # Validate session ID format first
            if not TokenStorage.validate_session_id(session_id):
                app.logger.warning(f"Invalid session ID format: {session_id}")
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'INVALID_SESSION_ID_FORMAT',
                        'message': 'Session ID format is invalid'
                    }
                }), 400
            
            # Retrieve tokens from storage
            token_data = TokenStorage.retrieve_tokens(session_id)
            
            if not token_data:
                app.logger.warning(f"Token retrieval failed for session ID: {session_id}")
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'SESSION_NOT_FOUND',
                        'message': 'Session ID not found or expired'
                    }
                }), 404
            
            # Format response according to API specification
            response_data = {
                'success': True,
                'data': {
                    'access_token': token_data['access_token'],
                    'refresh_token': token_data['refresh_token'],
                    'expires_at': datetime.fromtimestamp(token_data['expires_at']).isoformat(),
                    'scope': token_data['scope'],
                    'provider': token_data['provider']
                }
            }
            
            app.logger.info(f"Token retrieval successful for session ID: {session_id}")
            return jsonify(response_data), 200
            
        except ValueError as e:
            app.logger.error(f"Value error during token retrieval: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': {
                    'code': 'TOKEN_PROCESSING_ERROR',
                    'message': 'Error processing token data'
                }
            }), 500
        except Exception as e:
            app.logger.error(f"Unexpected error during token retrieval: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred'
                }
            }), 500
    
    @app.route('/api/storage/stats')
    def get_storage_stats() -> Dict[str, Any]:
        """
        Get token storage statistics (for debugging/monitoring).
        
        Returns:
            JSON response with storage statistics
        """
        stats = TokenStorage.get_storage_stats()
        return jsonify({
            'success': True,
            'data': stats
        })
    
    @app.route('/oauth/google/authorize')
    def google_authorize():
        """
        Google OAuth authorization endpoint.
        
        This route initiates the Google OAuth 2.0 flow by generating a secure
        state parameter for CSRF protection and redirecting the user to Google's
        OAuth consent screen with the required scopes.
        
        Returns:
            Redirect response to Google OAuth consent screen
        """
        app.logger.info("Initiating Google OAuth authorization flow")
        
        try:
            # Generate secure state parameter for CSRF protection
            state = secrets.token_urlsafe(32)
            session['oauth_state'] = state
            
            # Get redirect URI for callback
            redirect_uri = url_for('google_callback', _external=True)
            app.logger.debug(f"Google OAuth redirect URI: {redirect_uri}")
            
            # Redirect to Google OAuth consent screen
            return app.google_client.authorize_redirect(redirect_uri, state=state)
            
        except AuthlibBaseError as e:
            app.logger.error(f"Authlib error during Google OAuth authorization: {e}", exc_info=True)
            return redirect(url_for('index', error='oauth_config_error',
                                  error_description='OAuth configuration error. Please contact support.'))
        except Exception as e:
            app.logger.error(f"Unexpected error during Google OAuth authorization: {e}", exc_info=True)
            return redirect(url_for('index', error='authorization_error',
                                  error_description='Failed to initiate Google authorization. Please try again.'))
    
    @app.route('/oauth/google/callback')
    def google_callback():
        """
        Google OAuth callback handler.
        
        This route handles the callback from Google OAuth, validates the state
        parameter, exchanges the authorization code for tokens, stores them
        with a unique session ID, and redirects to the UI.
        
        Returns:
            Redirect response to UI with session ID or error parameters
        """
        app.logger.info("Handling Google OAuth callback")
        
        # Check for OAuth errors (user denial, etc.)
        error = request.args.get('error')
        if error:
            error_description = request.args.get('error_description', 'OAuth authorization failed')
            
            # Handle specific OAuth error types
            if error == 'access_denied':
                app.logger.info(f"User denied Google OAuth consent: {error_description}")
                return redirect(url_for('index', error='access_denied', 
                                      error_description='You cancelled the authorization. Please try again if you want to connect your Google account.'))
            elif error == 'invalid_request':
                app.logger.error(f"Invalid OAuth request to Google: {error_description}")
                return redirect(url_for('index', error='invalid_request',
                                      error_description='Invalid authorization request. Please try again.'))
            elif error == 'unauthorized_client':
                app.logger.error(f"Unauthorized OAuth client for Google: {error_description}")
                return redirect(url_for('index', error='unauthorized_client',
                                      error_description='Application not authorized. Please contact support.'))
            elif error == 'unsupported_response_type':
                app.logger.error(f"Unsupported response type for Google OAuth: {error_description}")
                return redirect(url_for('index', error='unsupported_response_type',
                                      error_description='Configuration error. Please contact support.'))
            elif error == 'invalid_scope':
                app.logger.error(f"Invalid scope for Google OAuth: {error_description}")
                return redirect(url_for('index', error='invalid_scope',
                                      error_description='Invalid permissions requested. Please contact support.'))
            else:
                app.logger.warning(f"Google OAuth error: {error} - {error_description}")
                return redirect(url_for('index', error=error, error_description=error_description))
        
        # Validate state parameter to prevent CSRF attacks
        received_state = request.args.get('state')
        stored_state = session.get('oauth_state')
        
        if not received_state:
            app.logger.error("OAuth state parameter missing from Google callback")
            return redirect(url_for('index', error='missing_state', 
                                  error_description='Security parameter missing. Please try again.'))
        
        if not stored_state:
            app.logger.error("OAuth state not found in session - possible session timeout")
            return redirect(url_for('index', error='session_expired', 
                                  error_description='Session expired. Please try again.'))
        
        if received_state != stored_state:
            app.logger.error(f"OAuth state validation failed - received: {received_state[:10]}..., expected: {stored_state[:10]}...")
            return redirect(url_for('index', error='state_mismatch', 
                                  error_description='Security validation failed. This may indicate a security issue. Please try again.'))
        
        # Clear the state from session
        session.pop('oauth_state', None)
        
        try:
            # Exchange authorization code for tokens
            app.logger.debug("Attempting to exchange authorization code for Google tokens")
            token = app.google_client.authorize_access_token()
            
            if not token:
                app.logger.error("Failed to obtain access token from Google - empty response")
                return redirect(url_for('index', error='token_exchange_failed',
                                      error_description='Failed to obtain access token from Google. Please try again.'))
            
            # Extract token information
            access_token = token.get('access_token')
            refresh_token = token.get('refresh_token')
            expires_in = token.get('expires_in', 3600)  # Default to 1 hour
            scope = token.get('scope', '')
            
            if not access_token:
                app.logger.error("Access token missing from Google response")
                return redirect(url_for('index', error='invalid_token',
                                      error_description='Invalid token response from Google. Please try again.'))
            
            app.logger.debug(f"Successfully obtained Google tokens - expires_in: {expires_in}, scope: {scope}")
            
            # Store tokens with unique session ID
            session_id = TokenStorage.store_tokens(
                provider='google',
                access_token=access_token,
                refresh_token=refresh_token or '',  # Refresh token might be None
                expires_in=expires_in,
                scope=scope
            )
            
            app.logger.info(f"Google OAuth flow completed successfully, session ID: {session_id}")
            
            # Redirect to UI with session ID
            return redirect(url_for('index', session_id=session_id))
            
        except AuthlibBaseError as e:
            app.logger.error(f"Authlib error during Google OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='oauth_library_error',
                                  error_description='OAuth library error occurred. Please try again.'))
        except ConnectionError as e:
            app.logger.error(f"Network connection error during Google OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='network_error',
                                  error_description='Network connection failed. Please check your internet connection and try again.'))
        except Timeout as e:
            app.logger.error(f"Timeout error during Google OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='timeout_error',
                                  error_description='Request timed out. Please try again.'))
        except RequestException as e:
            app.logger.error(f"Request error during Google OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='request_error',
                                  error_description='Network request failed. Please try again.'))
        except ValueError as e:
            app.logger.error(f"Value error during Google OAuth token processing: {e}", exc_info=True)
            return redirect(url_for('index', error='token_processing_error',
                                  error_description='Error processing token response. Please try again.'))
        except Exception as e:
            app.logger.error(f"Unexpected error during Google OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='unexpected_error',
                                  error_description='An unexpected error occurred during authentication. Please try again.'))
    
    @app.route('/oauth/microsoft/authorize')
    def microsoft_authorize():
        """
        Microsoft OAuth authorization endpoint.
        
        This route initiates the Microsoft OAuth 2.0 flow by generating a secure
        state parameter for CSRF protection and redirecting the user to Microsoft's
        OAuth consent screen with the required scopes (User.Read, Mail.Read, Calendars.Read).
        
        Returns:
            Redirect response to Microsoft OAuth consent screen
        """
        app.logger.info("Initiating Microsoft OAuth authorization flow")
        
        try:
            # Generate secure state parameter for CSRF protection
            state = secrets.token_urlsafe(32)
            session['oauth_state'] = state
            
            # Get redirect URI for callback
            redirect_uri = url_for('microsoft_callback', _external=True)
            app.logger.debug(f"Microsoft OAuth redirect URI: {redirect_uri}")
            
            # Redirect to Microsoft OAuth consent screen
            return app.microsoft_client.authorize_redirect(redirect_uri, state=state)
            
        except AuthlibBaseError as e:
            app.logger.error(f"Authlib error during Microsoft OAuth authorization: {e}", exc_info=True)
            return redirect(url_for('index', error='oauth_config_error',
                                  error_description='OAuth configuration error. Please contact support.'))
        except Exception as e:
            app.logger.error(f"Unexpected error during Microsoft OAuth authorization: {e}", exc_info=True)
            return redirect(url_for('index', error='authorization_error',
                                  error_description='Failed to initiate Microsoft authorization. Please try again.'))
    
    @app.route('/oauth/microsoft/callback')
    def microsoft_callback():
        """
        Microsoft OAuth callback handler.
        
        This route handles the callback from Microsoft OAuth, validates the state
        parameter, exchanges the authorization code for tokens, stores them
        with a unique session ID, and redirects to the UI.
        
        Returns:
            Redirect response to UI with session ID or error parameters
        """
        app.logger.info("Handling Microsoft OAuth callback")
        
        # Check for OAuth errors (user denial, etc.)
        error = request.args.get('error')
        if error:
            error_description = request.args.get('error_description', 'OAuth authorization failed')
            
            # Handle specific OAuth error types
            if error == 'access_denied':
                app.logger.info(f"User denied Microsoft OAuth consent: {error_description}")
                return redirect(url_for('index', error='access_denied', 
                                      error_description='You cancelled the authorization. Please try again if you want to connect your Microsoft account.'))
            elif error == 'invalid_request':
                app.logger.error(f"Invalid OAuth request to Microsoft: {error_description}")
                return redirect(url_for('index', error='invalid_request',
                                      error_description='Invalid authorization request. Please try again.'))
            elif error == 'unauthorized_client':
                app.logger.error(f"Unauthorized OAuth client for Microsoft: {error_description}")
                return redirect(url_for('index', error='unauthorized_client',
                                      error_description='Application not authorized. Please contact support.'))
            elif error == 'unsupported_response_type':
                app.logger.error(f"Unsupported response type for Microsoft OAuth: {error_description}")
                return redirect(url_for('index', error='unsupported_response_type',
                                      error_description='Configuration error. Please contact support.'))
            elif error == 'invalid_scope':
                app.logger.error(f"Invalid scope for Microsoft OAuth: {error_description}")
                return redirect(url_for('index', error='invalid_scope',
                                      error_description='Invalid permissions requested. Please contact support.'))
            elif error == 'server_error':
                app.logger.error(f"Microsoft server error during OAuth: {error_description}")
                return redirect(url_for('index', error='server_error',
                                      error_description='Microsoft server error. Please try again later.'))
            elif error == 'temporarily_unavailable':
                app.logger.warning(f"Microsoft OAuth temporarily unavailable: {error_description}")
                return redirect(url_for('index', error='temporarily_unavailable',
                                      error_description='Microsoft OAuth service is temporarily unavailable. Please try again later.'))
            else:
                app.logger.warning(f"Microsoft OAuth error: {error} - {error_description}")
                return redirect(url_for('index', error=error, error_description=error_description))
        
        # Validate state parameter to prevent CSRF attacks
        received_state = request.args.get('state')
        stored_state = session.get('oauth_state')
        
        if not received_state:
            app.logger.error("OAuth state parameter missing from Microsoft callback")
            return redirect(url_for('index', error='missing_state', 
                                  error_description='Security parameter missing. Please try again.'))
        
        if not stored_state:
            app.logger.error("OAuth state not found in session - possible session timeout")
            return redirect(url_for('index', error='session_expired', 
                                  error_description='Session expired. Please try again.'))
        
        if received_state != stored_state:
            app.logger.error(f"OAuth state validation failed - received: {received_state[:10]}..., expected: {stored_state[:10]}...")
            return redirect(url_for('index', error='state_mismatch', 
                                  error_description='Security validation failed. This may indicate a security issue. Please try again.'))
        
        # Clear the state from session
        session.pop('oauth_state', None)
        
        try:
            # Exchange authorization code for tokens
            app.logger.debug("Attempting to exchange authorization code for Microsoft tokens")
            token = app.microsoft_client.authorize_access_token()
            
            if not token:
                app.logger.error("Failed to obtain access token from Microsoft - empty response")
                return redirect(url_for('index', error='token_exchange_failed',
                                      error_description='Failed to obtain access token from Microsoft. Please try again.'))
            
            # Extract token information
            access_token = token.get('access_token')
            refresh_token = token.get('refresh_token')
            expires_in = token.get('expires_in', 3600)  # Default to 1 hour
            scope = token.get('scope', '')
            
            if not access_token:
                app.logger.error("Access token missing from Microsoft response")
                return redirect(url_for('index', error='invalid_token',
                                      error_description='Invalid token response from Microsoft. Please try again.'))
            
            app.logger.debug(f"Successfully obtained Microsoft tokens - expires_in: {expires_in}, scope: {scope}")
            
            # Store tokens with unique session ID
            session_id = TokenStorage.store_tokens(
                provider='microsoft',
                access_token=access_token,
                refresh_token=refresh_token or '',  # Refresh token might be None
                expires_in=expires_in,
                scope=scope
            )
            
            app.logger.info(f"Microsoft OAuth flow completed successfully, session ID: {session_id}")
            
            # Redirect to UI with session ID
            return redirect(url_for('index', session_id=session_id))
            
        except AuthlibBaseError as e:
            app.logger.error(f"Authlib error during Microsoft OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='oauth_library_error',
                                  error_description='OAuth library error occurred. Please try again.'))
        except ConnectionError as e:
            app.logger.error(f"Network connection error during Microsoft OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='network_error',
                                  error_description='Network connection failed. Please check your internet connection and try again.'))
        except Timeout as e:
            app.logger.error(f"Timeout error during Microsoft OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='timeout_error',
                                  error_description='Request timed out. Please try again.'))
        except RequestException as e:
            app.logger.error(f"Request error during Microsoft OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='request_error',
                                  error_description='Network request failed. Please try again.'))
        except ValueError as e:
            app.logger.error(f"Value error during Microsoft OAuth token processing: {e}", exc_info=True)
            return redirect(url_for('index', error='token_processing_error',
                                  error_description='Error processing token response. Please try again.'))
        except Exception as e:
            app.logger.error(f"Unexpected error during Microsoft OAuth token exchange: {e}", exc_info=True)
            return redirect(url_for('index', error='unexpected_error',
                                  error_description='An unexpected error occurred during authentication. Please try again.'))
    
    @app.route('/health')
    def health_check() -> Dict[str, Any]:
        """
        Health check endpoint for monitoring.
        
        Returns:
            JSON response indicating application health
        """
        return jsonify({
            'status': 'healthy',
            'service': 'SecureContext Protocol Authentication Proxy'
        })


# Create the Flask application instance
app = create_app()


if __name__ == '__main__':
    """Run the Flask application in development mode."""
    try:
        config = get_config()
        flask_config = config.get_flask_config()
        
        print("Starting SecureContext Protocol Authentication Proxy...")
        print(f"Server will run on http://{flask_config['HOST']}:{flask_config['PORT']}")
        
        app.run(
            host=flask_config['HOST'],
            port=flask_config['PORT'],
            debug=flask_config['DEBUG']
        )
        
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Failed to start application: {e}", file=sys.stderr)
        sys.exit(1)