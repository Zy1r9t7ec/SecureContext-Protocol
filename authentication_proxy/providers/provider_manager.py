"""
Provider manager system for dynamic OAuth provider registration and management.

This module implements the provider manager that handles dynamic provider registration,
route generation, and provider lifecycle management for the SecureContext Protocol.
"""

from typing import Dict, Any, List, Optional, Type, Callable
import logging
import importlib
from flask import Flask, url_for, redirect, request, session
import secrets

from .base_provider import BaseProvider, ProviderConfigurationError, OAuthFlowError


class ProviderManagerError(Exception):
    """Raised when provider manager encounters an error."""
    pass


class ProviderManager:
    """
    Manager for OAuth provider registration and dynamic route generation.
    
    This class handles the registration of OAuth providers, dynamic route creation,
    and provider lifecycle management. It provides a centralized way to manage
    multiple OAuth providers and their configurations.
    """
    
    def __init__(self, app: Optional[Flask] = None, config=None):
        """
        Initialize the provider manager.
        
        Args:
            app: Optional Flask application instance
            config: Optional configuration instance
        """
        self.providers: Dict[str, BaseProvider] = {}
        self.provider_classes: Dict[str, Type[BaseProvider]] = {}
        self.logger = logging.getLogger(__name__)
        self.app = None
        self.config = config
        
        # Register built-in provider classes
        self._register_builtin_providers()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask, config=None) -> None:
        """
        Initialize the provider manager with a Flask application.
        
        Args:
            app: Flask application instance
            config: Optional configuration instance
        """
        self.app = app
        if config:
            self.config = config
        
        # Store provider manager in app context
        app.provider_manager = self
        
        # Auto-register providers from configuration if enabled
        if self.config and self.config.get_provider_settings().get('auto_register_providers', True):
            self.register_providers_from_config()
        
        self.logger.info("Provider manager initialized with Flask app")
    
    def _register_builtin_providers(self) -> None:
        """Register built-in provider classes."""
        try:
            # Import and register Google provider
            from .google_provider import GoogleProvider
            self.provider_classes['google'] = GoogleProvider
            
            # Import and register Microsoft provider
            from .microsoft_provider import MicrosoftProvider
            self.provider_classes['microsoft'] = MicrosoftProvider
            
            self.logger.info("Registered built-in provider classes: google, microsoft")
            
        except ImportError as e:
            self.logger.error(f"Failed to import built-in providers: {e}")
            raise ProviderManagerError(f"Failed to register built-in providers: {e}")
    
    def register_provider_class(self, name: str, provider_class: Type[BaseProvider]) -> None:
        """
        Register a provider class for dynamic instantiation.
        
        Args:
            name: Provider name
            provider_class: Provider class that inherits from BaseProvider
            
        Raises:
            ProviderManagerError: If provider class is invalid
        """
        if not issubclass(provider_class, BaseProvider):
            raise ProviderManagerError(f"Provider class {provider_class.__name__} must inherit from BaseProvider")
        
        self.provider_classes[name] = provider_class
        self.logger.info(f"Registered provider class: {name} -> {provider_class.__name__}")
    
    def register_provider(self, name: str, config: Dict[str, Any]) -> BaseProvider:
        """
        Register and instantiate an OAuth provider.
        
        Args:
            name: Provider name
            config: Provider configuration dictionary
            
        Returns:
            Instantiated provider instance
            
        Raises:
            ProviderManagerError: If provider registration fails
        """
        try:
            # Get provider class
            provider_class_name = config.get('provider_class', name.title() + 'Provider')
            
            if name in self.provider_classes:
                provider_class = self.provider_classes[name]
            else:
                # Try to dynamically import provider class
                try:
                    module_name = f".{name}_provider"
                    module = importlib.import_module(module_name, package=__package__)
                    provider_class = getattr(module, provider_class_name)
                    self.provider_classes[name] = provider_class
                except (ImportError, AttributeError) as e:
                    raise ProviderManagerError(f"Failed to import provider class {provider_class_name}: {e}")
            
            # Instantiate provider
            provider = provider_class(config)
            
            # Store provider instance
            self.providers[name] = provider
            
            self.logger.info(f"Registered provider: {name} ({provider.__class__.__name__})")
            
            return provider
            
        except ProviderConfigurationError as e:
            self.logger.error(f"Provider configuration error for {name}: {e}")
            raise ProviderManagerError(f"Failed to register provider {name}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error registering provider {name}: {e}", exc_info=True)
            raise ProviderManagerError(f"Failed to register provider {name}: {e}")
    
    def get_provider(self, name: str) -> Optional[BaseProvider]:
        """
        Get a registered provider by name.
        
        Args:
            name: Provider name
            
        Returns:
            Provider instance or None if not found
        """
        return self.providers.get(name)
    
    def get_all_providers(self) -> Dict[str, BaseProvider]:
        """
        Get all registered providers.
        
        Returns:
            Dictionary of provider name to provider instance
        """
        return self.providers.copy()
    
    def get_provider_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all registered providers for API responses.
        
        Returns:
            List of provider information dictionaries
        """
        return [provider.get_provider_info() for provider in self.providers.values()]
    
    def register_routes(self, app: Flask) -> None:
        """
        Register dynamic OAuth routes for all providers.
        
        Args:
            app: Flask application instance
        """
        if not self.providers:
            self.logger.warning("No providers registered, skipping route registration")
            return
        
        # Register routes for each provider
        for provider_name, provider in self.providers.items():
            self._register_provider_routes(app, provider_name, provider)
        
        # Register provider list API endpoint
        self._register_provider_api_routes(app)
        
        # Register additional API endpoints
        self._register_versioning_api_routes(app)
        
        self.logger.info(f"Registered OAuth routes for {len(self.providers)} providers")
    
    def _register_provider_routes(self, app: Flask, provider_name: str, provider: BaseProvider) -> None:
        """
        Register OAuth routes for a specific provider.
        
        Args:
            app: Flask application instance
            provider_name: Provider name
            provider: Provider instance
        """
        # Authorization route
        authorize_endpoint = f'/oauth/{provider_name}/authorize'
        authorize_route_name = f'{provider_name}_authorize'
        
        def create_authorize_handler(p_name: str, p_instance: BaseProvider):
            def authorize_handler():
                return self._handle_authorization(p_name, p_instance)
            return authorize_handler
        
        app.add_url_rule(
            authorize_endpoint,
            authorize_route_name,
            create_authorize_handler(provider_name, provider),
            methods=['GET']
        )
        
        # Callback route
        callback_endpoint = f'/oauth/{provider_name}/callback'
        callback_route_name = f'{provider_name}_callback'
        
        def create_callback_handler(p_name: str, p_instance: BaseProvider):
            def callback_handler():
                return self._handle_callback(p_name, p_instance)
            return callback_handler
        
        app.add_url_rule(
            callback_endpoint,
            callback_route_name,
            create_callback_handler(provider_name, provider),
            methods=['GET']
        )
        
        self.logger.debug(f"Registered routes for {provider_name}: {authorize_endpoint}, {callback_endpoint}")
    
    def _register_provider_api_routes(self, app: Flask) -> None:
        """
        Register API routes for provider management.
        
        Args:
            app: Flask application instance
        """
        @app.route('/api/providers')
        def list_providers():
            """List all available providers with standardized response format."""
            try:
                from ..api_responses import ProviderResponseBuilder, log_api_request
                import time
                
                start_time = time.time()
                providers_info = self.get_provider_info()
                
                response_data = ProviderResponseBuilder.list_response(
                    providers_info,
                    f"Retrieved {len(providers_info)} available providers"
                )
                
                log_api_request('/api/providers', 'GET', 200,
                              (time.time() - start_time) * 1000)
                
                from ..api_responses import create_flask_response
                return create_flask_response(response_data, 200)
                
            except ImportError:
                # Fallback for import issues
                from flask import jsonify
                return jsonify({
                    'success': True,
                    'data': {
                        'providers': self.get_provider_info(),
                        'count': len(self.providers)
                    }
                })
            except Exception as e:
                self.logger.error(f"Error listing providers: {e}", exc_info=True)
                try:
                    from ..api_responses import APIResponse, ErrorCodes, create_flask_response
                    response_data = APIResponse.error(
                        ErrorCodes.INTERNAL_ERROR,
                        'Failed to retrieve provider list',
                        status_code=500
                    )
                    return create_flask_response(response_data, 500)
                except ImportError:
                    from flask import jsonify
                    return jsonify({
                        'success': False,
                        'error': {
                            'code': 'INTERNAL_ERROR',
                            'message': 'Failed to retrieve provider list'
                        }
                    }), 500
    
    def _register_versioning_api_routes(self, app: Flask) -> None:
        """
        Register API versioning and documentation routes.
        
        Args:
            app: Flask application instance
        """
        @app.route('/api/version')
        def api_version():
            """Get API version information."""
            try:
                from ..api_responses import APIResponse, create_flask_response, log_api_request
                import time
                
                start_time = time.time()
                
                version_info = {
                    "version": "1.0",
                    "release_date": "2024-01-01",
                    "supported_oauth_version": "2.0",
                    "supported_providers": list(self.providers.keys()),
                    "features": [
                        "oauth2_flows",
                        "token_management", 
                        "provider_extensibility",
                        "standardized_responses",
                        "api_versioning"
                    ],
                    "endpoints": {
                        "tokens": "/api/tokens/<session_id>",
                        "providers": "/api/providers",
                        "version": "/api/version",
                        "health": "/api/health",
                        "storage_stats": "/api/storage/stats"
                    }
                }
                
                response_data = APIResponse.success(
                    data=version_info,
                    message="API version information retrieved successfully"
                )
                
                log_api_request('/api/version', 'GET', 200,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 200)
                
            except ImportError:
                from flask import jsonify
                return jsonify({
                    "version": "1.0",
                    "supported_providers": list(self.providers.keys())
                })
            except Exception as e:
                self.logger.error(f"Error retrieving API version: {e}", exc_info=True)
                try:
                    from ..api_responses import APIResponse, ErrorCodes, create_flask_response
                    response_data = APIResponse.error(
                        ErrorCodes.INTERNAL_ERROR,
                        'Failed to retrieve API version information',
                        status_code=500
                    )
                    return create_flask_response(response_data, 500)
                except ImportError:
                    from flask import jsonify
                    return jsonify({
                        'error': 'Failed to retrieve API version information'
                    }), 500
        
        @app.route('/api/health')
        def health_check():
            """Health check endpoint for monitoring."""
            try:
                from ..api_responses import APIResponse, create_flask_response, log_api_request
                import time
                
                start_time = time.time()
                
                # Check system health
                health_status = {
                    "status": "healthy",
                    "timestamp": time.time(),
                    "providers": {
                        "total": len(self.providers),
                        "active": len([p for p in self.providers.values() if p]),
                        "names": list(self.providers.keys())
                    },
                    "storage": {
                        "type": "in_memory",
                        "status": "operational"
                    }
                }
                
                # Add storage stats if available
                try:
                    from ..app import TokenStorage
                    storage_stats = TokenStorage.get_storage_stats()
                    health_status["storage"]["sessions"] = storage_stats.get("total_sessions", 0)
                except:
                    pass
                
                response_data = APIResponse.success(
                    data=health_status,
                    message="System health check completed successfully"
                )
                
                log_api_request('/api/health', 'GET', 200,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 200)
                
            except ImportError:
                from flask import jsonify
                return jsonify({
                    "status": "healthy",
                    "providers": len(self.providers)
                })
            except Exception as e:
                self.logger.error(f"Error in health check: {e}", exc_info=True)
                try:
                    from ..api_responses import APIResponse, ErrorCodes, create_flask_response
                    response_data = APIResponse.error(
                        ErrorCodes.INTERNAL_ERROR,
                        'Health check failed',
                        status_code=500
                    )
                    return create_flask_response(response_data, 500)
                except ImportError:
                    from flask import jsonify
                    return jsonify({
                        'status': 'unhealthy',
                        'error': 'Health check failed'
                    }), 500
        
        @app.route('/api/docs')
        def api_documentation():
            """Comprehensive API documentation endpoint."""
            try:
                from ..api_responses import APIResponse, create_flask_response, log_api_request
                import time
                
                start_time = time.time()
                
                api_docs = {
                    "title": "SecureContext Protocol API",
                    "version": "1.0",
                    "description": "OAuth 2.0 mediation system with standardized API responses",
                    "base_url": request.host_url.rstrip('/'),
                    "authentication": {
                        "type": "session_based",
                        "description": "Uses session IDs obtained through OAuth flows"
                    },
                    "response_format": {
                        "success": {
                            "success": True,
                            "version": "1.0",
                            "timestamp": "ISO8601 timestamp",
                            "data": "Response payload",
                            "message": "Optional success message",
                            "metadata": "Optional response metadata"
                        },
                        "error": {
                            "success": False,
                            "version": "1.0", 
                            "timestamp": "ISO8601 timestamp",
                            "error": {
                                "code": "ERROR_CODE",
                                "message": "Human readable error message",
                                "status_code": "HTTP status code",
                                "details": "Optional error details"
                            }
                        }
                    },
                    "endpoints": {
                        "/api/tokens/<session_id>": {
                            "method": "GET",
                            "description": "Retrieve OAuth tokens by session ID",
                            "parameters": {
                                "session_id": {
                                    "type": "string",
                                    "format": "UUID v4",
                                    "description": "Session ID obtained from OAuth flow"
                                }
                            },
                            "responses": {
                                "200": {
                                    "description": "Token retrieved successfully",
                                    "data_format": {
                                        "access_token": "OAuth access token",
                                        "refresh_token": "OAuth refresh token",
                                        "token_type": "Bearer",
                                        "expires_at": "ISO8601 timestamp",
                                        "scope": "OAuth scopes",
                                        "provider": {
                                            "name": "Provider name",
                                            "display_name": "Human readable name",
                                            "type": "oauth2"
                                        },
                                        "metadata": {
                                            "created_at": "ISO8601 timestamp",
                                            "session_id": "Session ID",
                                            "expires_in_seconds": "Seconds until expiration"
                                        }
                                    }
                                },
                                "400": "Invalid session ID format",
                                "404": "Session not found or expired"
                            }
                        },
                        "/api/providers": {
                            "method": "GET",
                            "description": "List all available OAuth providers",
                            "responses": {
                                "200": {
                                    "description": "Providers retrieved successfully",
                                    "data_format": {
                                        "providers": [
                                            {
                                                "name": "Provider name",
                                                "display_name": "Human readable name",
                                                "type": "oauth2",
                                                "status": "active",
                                                "scopes": ["list", "of", "scopes"],
                                                "authorization_url": "/oauth/{provider}/authorize",
                                                "metadata": {
                                                    "icon_url": "Provider icon URL",
                                                    "documentation_url": "Provider docs URL"
                                                }
                                            }
                                        ],
                                        "count": "Number of providers"
                                    }
                                }
                            }
                        },
                        "/api/version": {
                            "method": "GET",
                            "description": "Get API version and feature information",
                            "responses": {
                                "200": {
                                    "description": "Version information retrieved",
                                    "data_format": {
                                        "version": "API version",
                                        "supported_oauth_version": "2.0",
                                        "supported_providers": ["list", "of", "providers"],
                                        "features": ["list", "of", "features"],
                                        "endpoints": "Available endpoints"
                                    }
                                }
                            }
                        },
                        "/api/health": {
                            "method": "GET", 
                            "description": "System health check for monitoring",
                            "responses": {
                                "200": {
                                    "description": "System is healthy",
                                    "data_format": {
                                        "status": "healthy",
                                        "providers": "Provider status",
                                        "storage": "Storage status"
                                    }
                                }
                            }
                        },
                        "/api/storage/stats": {
                            "method": "GET",
                            "description": "Get token storage statistics",
                            "responses": {
                                "200": {
                                    "description": "Storage statistics retrieved",
                                    "data_format": {
                                        "total_sessions": "Number of active sessions",
                                        "providers": "Sessions by provider",
                                        "storage_size_bytes": "Memory usage"
                                    }
                                }
                            }
                        }
                    },
                    "oauth_flows": {
                        "authorization_code": {
                            "description": "Standard OAuth 2.0 authorization code flow",
                            "steps": [
                                "1. User clicks provider connection button",
                                "2. System redirects to /oauth/{provider}/authorize",
                                "3. User grants consent on provider's site",
                                "4. Provider redirects to /oauth/{provider}/callback",
                                "5. System exchanges code for tokens",
                                "6. System stores tokens and returns session ID",
                                "7. Client uses session ID to retrieve tokens via API"
                            ]
                        }
                    },
                    "error_codes": {
                        "INVALID_SESSION_ID": "Session ID format is invalid",
                        "SESSION_NOT_FOUND": "Session ID not found or expired",
                        "OAUTH_ERROR": "OAuth authentication error",
                        "NETWORK_ERROR": "Network connection failed",
                        "INTERNAL_ERROR": "Internal server error",
                        "PROVIDER_NOT_FOUND": "OAuth provider not found",
                        "STORAGE_ERROR": "Token storage error"
                    }
                }
                
                response_data = APIResponse.success(
                    data=api_docs,
                    message="API documentation retrieved successfully"
                )
                
                log_api_request('/api/docs', 'GET', 200,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 200)
                
            except ImportError:
                from flask import jsonify
                return jsonify({
                    "title": "SecureContext Protocol API",
                    "version": "1.0",
                    "endpoints": ["/api/tokens/<session_id>", "/api/providers"]
                })
            except Exception as e:
                self.logger.error(f"Error retrieving API documentation: {e}", exc_info=True)
                try:
                    from ..api_responses import APIResponse, ErrorCodes, create_flask_response
                    response_data = APIResponse.error(
                        ErrorCodes.INTERNAL_ERROR,
                        'Failed to retrieve API documentation',
                        status_code=500
                    )
                    return create_flask_response(response_data, 500)
                except ImportError:
                    from flask import jsonify
                    return jsonify({
                        'error': 'Failed to retrieve API documentation'
                    }), 500
    
    def _handle_authorization(self, provider_name: str, provider: BaseProvider):
        """
        Handle OAuth authorization request for a provider.
        
        Args:
            provider_name: Provider name
            provider: Provider instance
            
        Returns:
            Flask redirect response to OAuth consent screen
        """
        try:
            self.logger.info(f"Initiating {provider.display_name} OAuth authorization flow")
            
            # Log audit event for OAuth initiation
            try:
                from ..audit_logger import get_audit_logger, AuditEventType
                audit_logger = get_audit_logger()
                audit_logger.log_event(
                    event_type=AuditEventType.OAUTH_INITIATED,
                    provider=provider_name,
                    user_ip=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=True,
                    details={
                        'flow_type': 'web_ui',
                        'provider_display_name': provider.display_name
                    }
                )
            except ImportError:
                pass  # Audit logging not available
            
            # Generate secure state parameter
            state = provider.generate_state()
            session['oauth_state'] = state
            session['oauth_provider'] = provider_name
            
            # Get redirect URI for callback (support enterprise callback URL override)
            if self.config:
                redirect_uri = self.config.get_callback_url(provider_name)
            else:
                redirect_uri = url_for(f'{provider_name}_callback', _external=True)
            self.logger.debug(f"{provider.display_name} OAuth redirect URI: {redirect_uri}")
            
            # Get authorization URL from provider
            auth_url = provider.get_authorization_url(redirect_uri, state)
            
            # Redirect to OAuth consent screen
            return redirect(auth_url)
            
        except OAuthFlowError as e:
            self.logger.error(f"OAuth flow error during {provider_name} authorization: {e}")
            return redirect(url_for('index', error='oauth_flow_error',
                                  error_description=str(e)))
        except Exception as e:
            self.logger.error(f"Unexpected error during {provider_name} authorization: {e}", exc_info=True)
            return redirect(url_for('index', error='authorization_error',
                                  error_description=f'Failed to initiate {provider.display_name} authorization. Please try again.'))
    
    def _handle_callback(self, provider_name: str, provider: BaseProvider):
        """
        Handle OAuth callback for a provider.
        
        Args:
            provider_name: Provider name
            provider: Provider instance
            
        Returns:
            Flask redirect response to UI with session ID or error
        """
        try:
            self.logger.info(f"Handling {provider.display_name} OAuth callback")
            
            # Check for OAuth errors
            error = request.args.get('error')
            if error:
                error_description = request.args.get('error_description', 'OAuth authorization failed')
                error_code, user_message = provider.parse_oauth_error(error, error_description)
                return redirect(url_for('index', error=error_code, error_description=user_message))
            
            # Validate state parameter
            received_state = request.args.get('state')
            stored_state = session.get('oauth_state')
            stored_provider = session.get('oauth_provider')
            
            if not received_state:
                self.logger.error(f"OAuth state parameter missing from {provider_name} callback")
                return redirect(url_for('index', error='missing_state',
                                      error_description='Security parameter missing. Please try again.'))
            
            if not stored_state:
                self.logger.error(f"OAuth state not found in session for {provider_name}")
                return redirect(url_for('index', error='session_expired',
                                      error_description='Session expired. Please try again.'))
            
            if stored_provider != provider_name:
                self.logger.error(f"Provider mismatch in session - expected: {provider_name}, got: {stored_provider}")
                return redirect(url_for('index', error='provider_mismatch',
                                      error_description='Provider mismatch. Please try again.'))
            
            if not provider.validate_state(received_state, stored_state):
                return redirect(url_for('index', error='state_mismatch',
                                      error_description='Security validation failed. Please try again.'))
            
            # Clear OAuth session data
            session.pop('oauth_state', None)
            session.pop('oauth_provider', None)
            
            # Get authorization code
            code = request.args.get('code')
            if not code:
                self.logger.error(f"Authorization code missing from {provider_name} callback")
                return redirect(url_for('index', error='missing_code',
                                      error_description='Authorization code missing. Please try again.'))
            
            # Exchange code for tokens (use same callback URL as authorization)
            if self.config:
                redirect_uri = self.config.get_callback_url(provider_name)
            else:
                redirect_uri = url_for(f'{provider_name}_callback', _external=True)
            token_data = provider.exchange_code_for_tokens(code, redirect_uri)
            
            # Store tokens using TokenStorage
            from ..app import TokenStorage
            
            # Extract agent context from session state if available
            agent_id = None
            workflow_id = None
            
            # Check if this was an agent-initiated OAuth flow
            state_key = f'oauth_state_{received_state}'
            if state_key in session:
                state_data = session.get(state_key)
                if isinstance(state_data, dict):
                    agent_id = state_data.get('agent_id')
                    workflow_id = state_data.get('workflow_id')
                # Clean up the state data
                session.pop(state_key, None)
            
            session_id = TokenStorage.store_tokens(
                provider=provider_name,
                access_token=token_data['access_token'],
                refresh_token=token_data['refresh_token'],
                expires_in=token_data['expires_in'],
                scope=token_data['scope'],
                webhook_manager=getattr(self.app, 'webhook_manager', None),
                agent_id=agent_id,
                workflow_id=workflow_id
            )
            
            # Log audit event for OAuth completion
            try:
                from ..audit_logger import get_audit_logger, AuditEventType
                audit_logger = get_audit_logger()
                audit_logger.log_event(
                    event_type=AuditEventType.OAUTH_COMPLETED,
                    session_id=session_id,
                    provider=provider_name,
                    agent_id=agent_id,
                    workflow_id=workflow_id,
                    user_ip=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    scopes=token_data.get('scope', '').split() if token_data.get('scope') else [],
                    success=True,
                    details={
                        'redirect_uri': redirect_uri,
                        'has_refresh_token': bool(token_data.get('refresh_token'))
                    }
                )
            except ImportError:
                pass  # Audit logging not available
            
            self.logger.info(f"{provider.display_name} OAuth flow completed successfully, session ID: {session_id}")
            
            # Redirect to UI with session ID
            return redirect(url_for('index', session_id=session_id))
            
        except OAuthFlowError as e:
            self.logger.error(f"OAuth flow error during {provider_name} callback: {e}")
            
            # Log audit event for OAuth failure
            try:
                from ..audit_logger import get_audit_logger, AuditEventType
                audit_logger = get_audit_logger()
                audit_logger.log_event(
                    event_type=AuditEventType.OAUTH_FAILED,
                    provider=provider_name,
                    user_ip=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=False,
                    details={
                        'error_type': 'oauth_flow_error',
                        'error_message': str(e)
                    }
                )
            except ImportError:
                pass  # Audit logging not available
            
            return redirect(url_for('index', error='oauth_flow_error',
                                  error_description=str(e)))
        except Exception as e:
            self.logger.error(f"Unexpected error during {provider_name} callback: {e}", exc_info=True)
            
            # Log audit event for OAuth failure
            try:
                from ..audit_logger import get_audit_logger, AuditEventType
                audit_logger = get_audit_logger()
                audit_logger.log_event(
                    event_type=AuditEventType.OAUTH_FAILED,
                    provider=provider_name,
                    user_ip=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=False,
                    details={
                        'error_type': 'unexpected_error',
                        'error_message': str(e)
                    }
                )
            except ImportError:
                pass  # Audit logging not available
            
            return redirect(url_for('index', error='callback_error',
                                  error_description=f'An error occurred during {provider.display_name} authentication. Please try again.'))
    
    def validate_provider_config(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Validate provider configuration without registering the provider.
        
        Args:
            name: Provider name
            config: Provider configuration dictionary
            
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Get provider class
            if name not in self.provider_classes:
                self.logger.error(f"Unknown provider class: {name}")
                return False
            
            provider_class = self.provider_classes[name]
            
            # Try to instantiate provider (this will validate config)
            test_provider = provider_class(config)
            
            return True
            
        except ProviderConfigurationError as e:
            self.logger.error(f"Provider configuration validation failed for {name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error validating provider config for {name}: {e}")
            return False
    
    def unregister_provider(self, name: str) -> bool:
        """
        Unregister a provider.
        
        Args:
            name: Provider name to unregister
            
        Returns:
            True if provider was unregistered, False if not found
        """
        if name in self.providers:
            del self.providers[name]
            self.logger.info(f"Unregistered provider: {name}")
            return True
        
        return False
    
    def reload_provider(self, name: str, config: Dict[str, Any]) -> BaseProvider:
        """
        Reload a provider with new configuration.
        
        Args:
            name: Provider name
            config: New provider configuration
            
        Returns:
            Reloaded provider instance
            
        Raises:
            ProviderManagerError: If reload fails
        """
        # Unregister existing provider
        self.unregister_provider(name)
        
        # Register with new config
        return self.register_provider(name, config)
    
    def register_providers_from_config(self) -> None:
        """
        Register all enabled providers from configuration.
        
        Raises:
            ProviderManagerError: If provider registration fails
        """
        if not self.config:
            raise ProviderManagerError("No configuration available for provider registration")
        
        enabled_providers = self.config.get_enabled_providers()
        registered_count = 0
        
        for provider_name in enabled_providers:
            try:
                provider_config = self.config.get_oauth_config(provider_name)
                self.register_provider(provider_name, provider_config)
                registered_count += 1
            except Exception as e:
                self.logger.error(f"Failed to register provider {provider_name} from config: {e}")
                # Continue with other providers instead of failing completely
                continue
        
        self.logger.info(f"Registered {registered_count} providers from configuration")
    
    def reload_providers_from_config(self) -> None:
        """
        Reload all providers from updated configuration.
        
        Raises:
            ProviderManagerError: If configuration reload fails
        """
        if not self.config:
            raise ProviderManagerError("No configuration available for provider reload")
        
        # Clear existing providers
        self.providers.clear()
        
        # Reload configuration
        self.config.reload_provider_configurations()
        
        # Re-register providers
        self.register_providers_from_config()
        
        self.logger.info("Reloaded all providers from configuration")
    
    def get_provider_stats(self) -> Dict[str, Any]:
        """
        Get statistics about registered providers.
        
        Returns:
            Provider statistics dictionary
        """
        return {
            'total_providers': len(self.providers),
            'provider_names': list(self.providers.keys()),
            'provider_classes': list(self.provider_classes.keys()),
            'providers_info': self.get_provider_info()
        }