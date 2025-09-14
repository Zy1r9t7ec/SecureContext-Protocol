"""
Flask application for the SecureContext Protocol Authentication Proxy.

This module implements the core Flask application with session management,
error handling, OAuth flows, and the web UI serving route.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO
import logging
import sys
import uuid
import time
import threading
import secrets
import redis
from typing import Tuple, Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
from authlib.common.errors import AuthlibBaseError
from requests.exceptions import RequestException, ConnectionError, Timeout

try:
    from .config import get_config, ConfigurationError
    from .api_responses import (
        APIResponse, TokenResponseBuilder, ProviderResponseBuilder, 
        ErrorCodes, create_flask_response, log_api_request
    )
    from .webhooks import WebhookManager
    from .audit_logger import get_audit_logger, AuditEventType
    from .session_pool import get_session_pool, SessionContext, SessionState
    from .streaming import init_streaming, get_streaming_manager
    from .data_streaming import get_data_streamer, DataStreamer, StreamConfig, DataStreamType
    from .marketplace import (
        get_agent_registry, get_agent_tester, AgentMetadata, AgentCapability,
        AgentCapabilityType, AgentStatus
    )
except ImportError:
    from config import get_config, ConfigurationError
    from api_responses import (
        APIResponse, TokenResponseBuilder, ProviderResponseBuilder, 
        ErrorCodes, create_flask_response, log_api_request
    )
    from webhooks import WebhookManager
    from audit_logger import get_audit_logger, AuditEventType
    from session_pool import get_session_pool, SessionContext, SessionState
    from streaming import init_streaming, get_streaming_manager
    from data_streaming import get_data_streamer, DataStreamer, StreamConfig, DataStreamType
    from marketplace import (
        get_agent_registry, get_agent_tester, AgentMetadata, AgentCapability,
        AgentCapabilityType, AgentStatus
    )


# Global in-memory token storage
# Structure: {session_id: {provider, access_token, refresh_token, expires_at, scope, created_at}}
token_storage: Dict[str, Dict[str, Any]] = {}
storage_lock = threading.Lock()

# Global webhook manager instance
webhook_manager = None


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
                    expires_in: int, scope: str, webhook_manager=None,
                    agent_id: Optional[str] = None, workflow_id: Optional[str] = None) -> str:
        """
        Store OAuth tokens with a unique session ID.
        
        Args:
            provider: OAuth provider name ('google' or 'microsoft')
            access_token: OAuth access token
            refresh_token: OAuth refresh token
            expires_in: Token expiration time in seconds
            scope: OAuth scope string
            webhook_manager: Optional webhook manager for notifications
            agent_id: Optional agent identifier for session tracking
            workflow_id: Optional workflow identifier for session tracking
            
        Returns:
            Generated session ID for token retrieval
            
        Raises:
            ValueError: If required parameters are invalid
        """
        # Validate input parameters
        if not provider or not isinstance(provider, str):
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
                'created_at': current_time,
                'agent_id': agent_id,
                'workflow_id': workflow_id
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
                
            # Send webhook notification for token creation
            if webhook_manager:
                webhook_manager.notify_token_created(session_id, provider, scope, expires_in)
            
            # Log audit event for token creation
            audit_logger = get_audit_logger()
            audit_logger.log_event(
                event_type=AuditEventType.TOKEN_CREATED,
                session_id=session_id,
                provider=provider,
                agent_id=agent_id,
                workflow_id=workflow_id,
                scopes=scope.split() if scope else [],
                success=True,
                details={
                    'expires_in': expires_in,
                    'has_refresh_token': bool(refresh_token)
                }
            )
                
            logging.info(f"Stored tokens for provider '{provider}' with session ID: {session_id}")
            return session_id
            
        except Exception as e:
            logging.error(f"Error storing tokens for provider '{provider}': {e}", exc_info=True)
            raise
    
    @staticmethod
    def retrieve_tokens(session_id: str, webhook_manager=None, client_info: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
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
            
            # Log audit event for token expiration
            audit_logger = get_audit_logger()
            audit_logger.log_event(
                event_type=AuditEventType.TOKEN_EXPIRED,
                session_id=session_id,
                provider=token_data['provider'],
                agent_id=token_data.get('agent_id'),
                workflow_id=token_data.get('workflow_id'),
                scopes=token_data.get('scope', '').split() if token_data.get('scope') else [],
                success=True,
                details={'expired_at': token_data['expires_at']}
            )
            
            # Send webhook notification for token expiration
            if webhook_manager:
                webhook_manager.notify_token_expired(session_id, token_data['provider'])
            TokenStorage.remove_session(session_id)
            return None
        
        # Send webhook notification for token retrieval
        if webhook_manager:
            webhook_manager.notify_token_retrieved(session_id, token_data['provider'], client_info)
        
        # Log audit event for token retrieval
        audit_logger = get_audit_logger()
        audit_logger.log_event(
            event_type=AuditEventType.TOKEN_RETRIEVED,
            session_id=session_id,
            provider=token_data['provider'],
            agent_id=token_data.get('agent_id'),
            workflow_id=token_data.get('workflow_id'),
            user_ip=client_info.get('ip_address') if client_info else None,
            user_agent=client_info.get('user_agent') if client_info else None,
            data_type=client_info.get('data_type') if client_info else None,
            scopes=token_data.get('scope', '').split() if token_data.get('scope') else [],
            success=True,
            details=client_info or {}
        )
            
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
            # Parse UUID and validate it's version 4
            parsed_uuid = uuid.UUID(session_id)
            return parsed_uuid.version == 4
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
            agents = {}
            workflows = {}
            
            for token_data in token_storage.values():
                provider = token_data['provider']
                providers[provider] = providers.get(provider, 0) + 1
                
                agent_id = token_data.get('agent_id')
                if agent_id:
                    agents[agent_id] = agents.get(agent_id, 0) + 1
                
                workflow_id = token_data.get('workflow_id')
                if workflow_id:
                    workflows[workflow_id] = workflows.get(workflow_id, 0) + 1
        
        return {
            'total_sessions': total_sessions,
            'providers': providers,
            'agents': agents,
            'workflows': workflows,
            'storage_size_bytes': sys.getsizeof(token_storage)
        }
    
    @staticmethod
    def extend_session_lifetime(session_id: str, additional_seconds: int = 3600) -> bool:
        """
        Extend the lifetime of a session for long-running workflows.
        
        Args:
            session_id: Session ID to extend
            additional_seconds: Additional seconds to add to expiration (default: 1 hour)
            
        Returns:
            True if session was extended, False if not found
        """
        if not TokenStorage.validate_session_id(session_id):
            return False
        
        with storage_lock:
            token_data = token_storage.get(session_id)
            if not token_data:
                return False
            
            # Extend expiration time
            token_data['expires_at'] += additional_seconds
            logging.info(f"Extended session {session_id} by {additional_seconds} seconds")
            return True
    
    @staticmethod
    def get_sessions_by_agent(agent_id: str) -> List[Dict[str, Any]]:
        """
        Get all sessions for a specific agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of session data dictionaries
        """
        sessions = []
        current_time = time.time()
        
        with storage_lock:
            for session_id, token_data in token_storage.items():
                if token_data.get('agent_id') == agent_id:
                    session_info = token_data.copy()
                    session_info['session_id'] = session_id
                    session_info['is_expired'] = current_time > token_data.get('expires_at', 0)
                    sessions.append(session_info)
        
        return sessions
    
    @staticmethod
    def get_sessions_by_workflow(workflow_id: str) -> List[Dict[str, Any]]:
        """
        Get all sessions for a specific workflow.
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            List of session data dictionaries
        """
        sessions = []
        current_time = time.time()
        
        with storage_lock:
            for session_id, token_data in token_storage.items():
                if token_data.get('workflow_id') == workflow_id:
                    session_info = token_data.copy()
                    session_info['session_id'] = session_id
                    session_info['is_expired'] = current_time > token_data.get('expires_at', 0)
                    sessions.append(session_info)
        
        return sessions
    
    @staticmethod
    def cleanup_agent_sessions(agent_id: str) -> int:
        """
        Clean up all sessions for a specific agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Number of sessions cleaned up
        """
        cleaned_count = 0
        sessions_to_remove = []
        
        with storage_lock:
            for session_id, token_data in token_storage.items():
                if token_data.get('agent_id') == agent_id:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del token_storage[session_id]
                cleaned_count += 1
        
        if cleaned_count > 0:
            logging.info(f"Cleaned up {cleaned_count} sessions for agent {agent_id}")
        
        return cleaned_count
    
    @staticmethod
    def cleanup_workflow_sessions(workflow_id: str) -> int:
        """
        Clean up all sessions for a specific workflow.
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            Number of sessions cleaned up
        """
        cleaned_count = 0
        sessions_to_remove = []
        
        with storage_lock:
            for session_id, token_data in token_storage.items():
                if token_data.get('workflow_id') == workflow_id:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del token_storage[session_id]
                cleaned_count += 1
        
        if cleaned_count > 0:
            logging.info(f"Cleaned up {cleaned_count} sessions for workflow {workflow_id}")
        
        return cleaned_count


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
                
                # Also cleanup streaming data
                data_streamer = get_data_streamer()
                data_streamer.cleanup_completed_streams()
                
            except Exception as e:
                logging.error(f"Error in cleanup worker: {e}")
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    logging.info("Started token cleanup scheduler")


def register_streaming_routes(app: Flask) -> None:
    """
    Register streaming and real-time data access routes.
    
    Args:
        app: Flask application instance
    """
    
    @app.route('/api/stream/start', methods=['POST'])
    def start_data_stream():
        """
        Start a data stream for large dataset processing.
        
        Request body:
        {
            "session_id": "string",
            "stream_type": "gmail_messages|calendar_events|outlook_messages|outlook_events",
            "batch_size": 100,
            "max_results": 1000,
            "filters": {...},
            "real_time": false
        }
        
        Returns:
            JSON response with stream ID and configuration
        """
        start_time = time.time()
        
        try:
            data = request.get_json()
            if not data:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    'Request body is required',
                    status_code=400
                )
                return create_flask_response(response_data, 400)
            
            session_id = data.get('session_id')
            stream_type_str = data.get('stream_type')
            
            if not session_id or not stream_type_str:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    'session_id and stream_type are required',
                    status_code=400
                )
                return create_flask_response(response_data, 400)
            
            # Validate session and get token data
            token_data = TokenStorage.retrieve_tokens(session_id)
            if not token_data:
                response_data = APIResponse.error(
                    ErrorCodes.SESSION_NOT_FOUND,
                    'Invalid or expired session ID',
                    status_code=404
                )
                return create_flask_response(response_data, 404)
            
            # Parse stream type
            try:
                stream_type = DataStreamType(stream_type_str)
            except ValueError:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    f'Invalid stream_type: {stream_type_str}',
                    status_code=400
                )
                return create_flask_response(response_data, 400)
            
            # Create stream configuration
            config = StreamConfig(
                stream_type=stream_type,
                session_id=session_id,
                provider=token_data['provider'],
                access_token=token_data['access_token'],
                batch_size=data.get('batch_size', 100),
                max_results=data.get('max_results'),
                filters=data.get('filters'),
                real_time=data.get('real_time', False),
                rate_limit_per_minute=data.get('rate_limit_per_minute', 60)
            )
            
            # Start the stream
            data_streamer = get_data_streamer()
            stream_id = data_streamer.start_stream(config)
            
            response_data = APIResponse.success({
                'stream_id': stream_id,
                'session_id': session_id,
                'stream_type': stream_type_str,
                'provider': token_data['provider'],
                'configuration': {
                    'batch_size': config.batch_size,
                    'max_results': config.max_results,
                    'real_time': config.real_time,
                    'rate_limit_per_minute': config.rate_limit_per_minute
                }
            })
            
            log_api_request('/api/stream/start', 'POST', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error starting data stream: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to start data stream',
                status_code=500
            )
            log_api_request('/api/stream/start', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/stream/<stream_id>/stop', methods=['POST'])
    def stop_data_stream(stream_id: str):
        """Stop a data stream."""
        start_time = time.time()
        
        try:
            data_streamer = get_data_streamer()
            success = data_streamer.stop_stream(stream_id)
            
            if success:
                response_data = APIResponse.success({
                    'stream_id': stream_id,
                    'status': 'stopped'
                })
                status_code = 200
            else:
                response_data = APIResponse.error(
                    ErrorCodes.STREAM_NOT_FOUND,
                    'Stream not found',
                    status_code=404
                )
                status_code = 404
            
            log_api_request(f'/api/stream/{stream_id}/stop', 'POST', status_code,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, status_code)
            
        except Exception as e:
            app.logger.error(f"Error stopping data stream: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to stop data stream',
                status_code=500
            )
            log_api_request(f'/api/stream/{stream_id}/stop', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/stream/<stream_id>/status', methods=['GET'])
    def get_stream_status(stream_id: str):
        """Get status of a data stream."""
        start_time = time.time()
        
        try:
            data_streamer = get_data_streamer()
            status = data_streamer.get_stream_status(stream_id)
            
            if status:
                response_data = APIResponse.success({
                    'stream_id': stream_id,
                    'status': status['status'],
                    'items_streamed': status['items_streamed'],
                    'started_at': status['started_at'],
                    'last_activity': status['last_activity'],
                    'configuration': {
                        'stream_type': status['config'].stream_type.value,
                        'session_id': status['config'].session_id,
                        'provider': status['config'].provider,
                        'batch_size': status['config'].batch_size,
                        'max_results': status['config'].max_results
                    }
                })
                status_code = 200
            else:
                response_data = APIResponse.error(
                    ErrorCodes.STREAM_NOT_FOUND,
                    'Stream not found',
                    status_code=404
                )
                status_code = 404
            
            log_api_request(f'/api/stream/{stream_id}/status', 'GET', status_code,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, status_code)
            
        except Exception as e:
            app.logger.error(f"Error getting stream status: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to get stream status',
                status_code=500
            )
            log_api_request(f'/api/stream/{stream_id}/status', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/streams', methods=['GET'])
    def get_active_streams():
        """Get all active data streams."""
        start_time = time.time()
        
        try:
            data_streamer = get_data_streamer()
            streams = data_streamer.get_active_streams()
            
            # Get streaming manager statistics
            streaming_manager = get_streaming_manager()
            websocket_stats = {
                'active_connections': streaming_manager.get_active_streams_count() if streaming_manager else 0
            }
            
            response_data = APIResponse.success({
                'streams': streams,
                'total_count': len(streams),
                'websocket_statistics': websocket_stats
            })
            
            log_api_request('/api/streams', 'GET', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error getting active streams: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to get active streams',
                status_code=500
            )
            log_api_request('/api/streams', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)


def register_marketplace_routes(app: Flask) -> None:
    """
    Register agent marketplace integration routes.
    
    Args:
        app: Flask application instance
    """
    
    @app.route('/api/marketplace/agents', methods=['POST'])
    def register_agent():
        """
        Register an agent in the marketplace.
        
        Request body should contain agent metadata in standardized format.
        """
        start_time = time.time()
        
        try:
            data = request.get_json()
            if not data:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    'Request body is required',
                    status_code=400
                )
                return create_flask_response(response_data, 400)
            
            # Parse agent metadata
            try:
                # Parse capabilities
                capabilities = []
                for cap_data in data.get('capabilities', []):
                    capability = AgentCapability(
                        capability_type=AgentCapabilityType(cap_data['capability_type']),
                        name=cap_data['name'],
                        description=cap_data['description'],
                        required_scopes=cap_data.get('required_scopes', []),
                        supported_providers=cap_data.get('supported_providers', []),
                        data_types=cap_data.get('data_types', []),
                        rate_limits=cap_data.get('rate_limits', {}),
                        security_level=cap_data.get('security_level', 'standard')
                    )
                    capabilities.append(capability)
                
                # Create agent metadata
                metadata = AgentMetadata(
                    agent_id=data['agent_id'],
                    name=data['name'],
                    version=data['version'],
                    description=data['description'],
                    author=data['author'],
                    license=data['license'],
                    homepage=data.get('homepage'),
                    repository=data.get('repository'),
                    documentation=data.get('documentation'),
                    capabilities=capabilities,
                    supported_frameworks=data.get('supported_frameworks', []),
                    minimum_scp_version=data.get('minimum_scp_version', '1.0'),
                    tags=data.get('tags', []),
                    category=data.get('category', 'general'),
                    created_at=datetime.now(timezone.utc).isoformat(),
                    updated_at=datetime.now(timezone.utc).isoformat(),
                    status=AgentStatus.PENDING
                )
                
            except (KeyError, ValueError, TypeError) as e:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    f'Invalid agent metadata: {e}',
                    status_code=400
                )
                return create_flask_response(response_data, 400)
            
            # Register agent
            registry = get_agent_registry()
            success = registry.register_agent(metadata)
            
            if success:
                response_data = APIResponse.success({
                    'agent_id': metadata.agent_id,
                    'status': metadata.status.value,
                    'message': 'Agent registered successfully'
                })
                status_code = 201
            else:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    'Failed to register agent (validation failed)',
                    status_code=400
                )
                status_code = 400
            
            log_api_request('/api/marketplace/agents', 'POST', status_code,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, status_code)
            
        except Exception as e:
            app.logger.error(f"Error registering agent: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to register agent',
                status_code=500
            )
            log_api_request('/api/marketplace/agents', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/marketplace/agents', methods=['GET'])
    def list_agents():
        """
        List agents with optional filtering.
        
        Query parameters:
        - capability: Filter by capability type
        - provider: Filter by supported provider
        - framework: Filter by supported framework
        - status: Filter by agent status
        - category: Filter by category
        - tags: Filter by tags (comma-separated)
        - search: Search in name, description, tags
        """
        start_time = time.time()
        
        try:
            registry = get_agent_registry()
            
            # Get query parameters
            search_query = request.args.get('search')
            
            if search_query:
                # Search agents
                agents = registry.search_agents(search_query)
            else:
                # List with filters
                filters = {}
                for param in ['capability', 'provider', 'framework', 'status', 'category']:
                    value = request.args.get(param)
                    if value:
                        filters[param] = value
                
                # Handle tags (comma-separated)
                tags_param = request.args.get('tags')
                if tags_param:
                    filters['tags'] = [tag.strip() for tag in tags_param.split(',')]
                
                agents = registry.list_agents(filters if filters else None)
            
            # Convert to dict format
            agents_data = []
            for agent in agents:
                agent_dict = agent.to_dict()
                
                # Add test score if available
                score = registry.get_agent_score(agent.agent_id)
                if score is not None:
                    agent_dict['test_score'] = round(score, 2)
                
                agents_data.append(agent_dict)
            
            response_data = APIResponse.success({
                'agents': agents_data,
                'total_count': len(agents_data),
                'filters_applied': dict(request.args)
            })
            
            log_api_request('/api/marketplace/agents', 'GET', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error listing agents: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to list agents',
                status_code=500
            )
            log_api_request('/api/marketplace/agents', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/marketplace/agents/<agent_id>', methods=['GET'])
    def get_agent(agent_id: str):
        """Get detailed agent information."""
        start_time = time.time()
        
        try:
            registry = get_agent_registry()
            agent = registry.get_agent(agent_id)
            
            if not agent:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    'Agent not found',
                    status_code=404
                )
                status_code = 404
            else:
                agent_dict = agent.to_dict()
                
                # Add test results
                test_results = registry.get_test_results(agent_id)
                agent_dict['test_results'] = [result.to_dict() for result in test_results[-10:]]  # Last 10 results
                
                # Add test score
                score = registry.get_agent_score(agent_id)
                if score is not None:
                    agent_dict['test_score'] = round(score, 2)
                
                response_data = APIResponse.success(agent_dict)
                status_code = 200
            
            log_api_request(f'/api/marketplace/agents/{agent_id}', 'GET', status_code,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, status_code)
            
        except Exception as e:
            app.logger.error(f"Error getting agent {agent_id}: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to get agent',
                status_code=500
            )
            log_api_request(f'/api/marketplace/agents/{agent_id}', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/marketplace/agents/<agent_id>', methods=['DELETE'])
    def unregister_agent(agent_id: str):
        """Unregister an agent from the marketplace."""
        start_time = time.time()
        
        try:
            registry = get_agent_registry()
            success = registry.unregister_agent(agent_id)
            
            if success:
                response_data = APIResponse.success({
                    'agent_id': agent_id,
                    'message': 'Agent unregistered successfully'
                })
                status_code = 200
            else:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    'Agent not found',
                    status_code=404
                )
                status_code = 404
            
            log_api_request(f'/api/marketplace/agents/{agent_id}', 'DELETE', status_code,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, status_code)
            
        except Exception as e:
            app.logger.error(f"Error unregistering agent {agent_id}: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to unregister agent',
                status_code=500
            )
            log_api_request(f'/api/marketplace/agents/{agent_id}', 'DELETE', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/marketplace/capabilities', methods=['GET'])
    def get_capabilities():
        """Get all available capabilities and their supporting agents."""
        start_time = time.time()
        
        try:
            registry = get_agent_registry()
            capabilities = registry.get_capabilities()
            
            response_data = APIResponse.success({
                'capabilities': capabilities,
                'total_capabilities': len(capabilities)
            })
            
            log_api_request('/api/marketplace/capabilities', 'GET', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error getting capabilities: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to get capabilities',
                status_code=500
            )
            log_api_request('/api/marketplace/capabilities', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/marketplace/test/<agent_id>', methods=['POST'])
    def test_agent(agent_id: str):
        """
        Run tests for an agent.
        
        Request body:
        {
            "test_types": ["metadata_validation", "capability_verification"]
        }
        """
        start_time = time.time()
        
        try:
            data = request.get_json() or {}
            test_types = data.get('test_types')
            
            registry = get_agent_registry()
            agent = registry.get_agent(agent_id)
            
            if not agent:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    'Agent not found',
                    status_code=404
                )
                return create_flask_response(response_data, 404)
            
            # Run tests
            tester = get_agent_tester()
            results = tester.run_tests(agent_id, test_types)
            
            response_data = APIResponse.success({
                'agent_id': agent_id,
                'test_results': [result.to_dict() for result in results],
                'total_tests': len(results)
            })
            
            log_api_request(f'/api/marketplace/test/{agent_id}', 'POST', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error testing agent {agent_id}: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to test agent',
                status_code=500
            )
            log_api_request(f'/api/marketplace/test/{agent_id}', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/marketplace/stats', methods=['GET'])
    def get_marketplace_stats():
        """Get marketplace statistics."""
        start_time = time.time()
        
        try:
            registry = get_agent_registry()
            
            # Get basic stats
            all_agents = registry.list_agents()
            total_agents = len(all_agents)
            
            # Count by status
            status_counts = {}
            for agent in all_agents:
                status = agent.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
            
            # Count by category
            category_counts = {}
            for agent in all_agents:
                category = agent.category
                category_counts[category] = category_counts.get(category, 0) + 1
            
            # Get capabilities and providers
            capabilities = registry.get_capabilities()
            providers = registry.get_providers()
            frameworks = registry.get_frameworks()
            
            response_data = APIResponse.success({
                'total_agents': total_agents,
                'status_distribution': status_counts,
                'category_distribution': category_counts,
                'total_capabilities': len(capabilities),
                'total_providers': len(providers),
                'total_frameworks': len(frameworks),
                'top_capabilities': sorted(
                    [(cap, len(agents)) for cap, agents in capabilities.items()],
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            })
            
            log_api_request('/api/marketplace/stats', 'GET', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error getting marketplace stats: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to get marketplace stats',
                status_code=500
            )
            log_api_request('/api/marketplace/stats', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)


def create_app() -> Tuple[Flask, SocketIO]:
    """
    Create and configure the Flask application with WebSocket support.
    
    Returns:
        Tuple of (Flask application instance, SocketIO instance)
    """
    app = Flask(__name__)
    
    try:
        # Load configuration
        config = get_config()
        flask_config = config.get_flask_config()
        
        # Configure Flask application
        app.config.update(flask_config)
        
        # Initialize SocketIO with CORS support
        socketio = SocketIO(
            app,
            cors_allowed_origins="*",
            async_mode='eventlet',
            logger=flask_config.get('DEBUG', False),
            engineio_logger=flask_config.get('DEBUG', False)
        )
        
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
        
        # Initialize Redis client for distributed features (optional)
        redis_client = None
        redis_url = flask_config.get('REDIS_URL')
        if redis_url:
            try:
                redis_client = redis.from_url(redis_url)
                redis_client.ping()  # Test connection
                app.logger.info("Redis connection established")
            except Exception as e:
                app.logger.warning(f"Redis connection failed, using local storage: {e}")
                redis_client = None
        
        # Initialize streaming manager
        streaming_manager = init_streaming(socketio, redis_client)
        app.streaming_manager = streaming_manager
        
        # Initialize webhook manager
        global webhook_manager
        webhook_manager = WebhookManager(config)
        app.webhook_manager = webhook_manager
        
        # Initialize provider manager with configuration
        try:
            from .providers.provider_manager import ProviderManager
        except ImportError:
            from authentication_proxy.providers.provider_manager import ProviderManager
        provider_manager = ProviderManager(config=config)
        provider_manager.init_app(app, config)
        
        # Register error handlers
        register_error_handlers(app)
        
        # Register core application routes (non-OAuth routes)
        register_core_routes(app)
        
        # Register streaming routes
        register_streaming_routes(app)
        
        # Register marketplace routes
        register_marketplace_routes(app)
        
        # Register dynamic routes for all providers
        provider_manager.register_routes(app)
        
        # Store provider manager in app context
        app.provider_manager = provider_manager
        
        # Start token cleanup scheduler
        start_cleanup_scheduler()
        
        app.logger.info("Flask application with WebSocket support initialized successfully")
        return app, socketio
        
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
            response_data = APIResponse.error(
                ErrorCodes.OAUTH_ERROR,
                'OAuth authentication error occurred',
                status_code=500
            )
            return create_flask_response(response_data, 500)
        
        return render_template('error.html',
                             error_code=500,
                             error_message="OAuth authentication error. Please try again."), 500
    
    @app.errorhandler(ConnectionError)
    def handle_connection_error(error) -> Tuple[str, int]:
        """Handle network connection errors."""
        app.logger.error(f"Connection error: {error} - URL: {request.url}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            response_data = APIResponse.error(
                ErrorCodes.NETWORK_ERROR,
                'Network connection failed',
                status_code=503
            )
            return create_flask_response(response_data, 503)
        
        return render_template('error.html',
                             error_code=503,
                             error_message="Network connection failed. Please check your internet connection and try again."), 503
    
    @app.errorhandler(Timeout)
    def handle_timeout_error(error) -> Tuple[str, int]:
        """Handle request timeout errors."""
        app.logger.error(f"Timeout error: {error} - URL: {request.url}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            response_data = APIResponse.error(
                ErrorCodes.TIMEOUT_ERROR,
                'Request timed out',
                status_code=504
            )
            return create_flask_response(response_data, 504)
        
        return render_template('error.html',
                             error_code=504,
                             error_message="Request timed out. Please try again."), 504
    
    @app.errorhandler(RequestException)
    def handle_request_error(error) -> Tuple[str, int]:
        """Handle general request errors."""
        app.logger.error(f"Request error: {error} - URL: {request.url}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            response_data = APIResponse.error(
                ErrorCodes.NETWORK_ERROR,
                'Network request failed',
                status_code=502
            )
            return create_flask_response(response_data, 502)
        
        return render_template('error.html',
                             error_code=502,
                             error_message="Network request failed. Please try again."), 502
    
    @app.errorhandler(Exception)
    def handle_exception(error) -> Tuple[str, int]:
        """Handle unexpected exceptions with comprehensive logging."""
        app.logger.error(f"Unexpected error: {error} - URL: {request.url} - Method: {request.method} - IP: {request.remote_addr}", exc_info=True)
        
        # Check if this is an API request
        if request.path.startswith('/api/'):
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'An unexpected error occurred',
                status_code=500
            )
            return create_flask_response(response_data, 500)
        
        return render_template('error.html',
                             error_code=500,
                             error_message="An unexpected error occurred. Please try again later."), 500


def register_core_routes(app: Flask) -> None:
    """
    Register core application routes (non-OAuth routes).
    
    Args:
        app: Flask application instance
    """
    
    @app.route('/')
    def index() -> str:
        """
        Serve the web UI at the root path.
        
        This route serves the main user interface with connection buttons
        for all configured OAuth providers. It handles URL parameters
        for displaying connection status and error messages.
        
        Returns:
            Rendered HTML template for the web UI
        """
        # Get URL parameters for status display
        session_id = request.args.get('session_id')
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        
        # Get available providers from provider manager
        providers = []
        if hasattr(app, 'provider_manager'):
            providers = app.provider_manager.get_provider_info()
        
        # Prepare context for template
        context = {
            'session_id': session_id,
            'error': error,
            'error_description': error_description,
            'success': bool(session_id and not error),
            'providers': providers
        }
        
        app.logger.info(f"Serving web UI - session_id: {session_id}, error: {error}")
        
        return render_template('index.html', **context)
    
    @app.route('/api/sessions', methods=['GET'])
    def get_sessions():
        """
        Get session information and statistics.
        
        Query parameters:
        - user_id: Filter by user ID
        - agent_id: Filter by agent ID
        - workflow_id: Filter by workflow ID
        - provider: Filter by provider
        - state: Filter by session state
        
        Returns:
            JSON response with session information
        """
        start_time = time.time()
        
        try:
            session_pool = get_session_pool()
            
            # Get query parameters
            user_id = request.args.get('user_id')
            agent_id = request.args.get('agent_id')
            workflow_id = request.args.get('workflow_id')
            provider = request.args.get('provider')
            state = request.args.get('state')
            
            sessions = []
            
            if user_id:
                user_sessions = session_pool.get_user_sessions(user_id)
                sessions.extend([s.to_dict() for s in user_sessions])
            elif agent_id:
                agent_sessions = session_pool.get_agent_sessions(agent_id)
                sessions.extend([s.to_dict() for s in agent_sessions])
            elif workflow_id:
                workflow_sessions = session_pool.get_workflow_sessions(workflow_id)
                sessions.extend([s.to_dict() for s in workflow_sessions])
            else:
                # Get all active sessions
                all_sessions = session_pool.get_active_sessions()
                sessions.extend([s.to_dict() for s in all_sessions])
            
            # Apply filters
            if provider:
                sessions = [s for s in sessions if s.get('provider') == provider]
            
            if state:
                sessions = [s for s in sessions if s.get('state') == state]
            
            # Get statistics
            stats = session_pool.get_statistics()
            
            response_data = APIResponse.success({
                'sessions': sessions,
                'statistics': stats,
                'total_count': len(sessions)
            })
            
            log_api_request('/api/sessions', 'GET', 200, 
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error retrieving sessions: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve sessions',
                status_code=500
            )
            log_api_request('/api/sessions', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/sessions/<session_id>', methods=['GET'])
    def get_session_info(session_id: str):
        """
        Get detailed information about a specific session.
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            JSON response with session information
        """
        start_time = time.time()
        
        try:
            session_pool = get_session_pool()
            session = session_pool.get_session(session_id)
            
            if not session:
                response_data = APIResponse.error(
                    ErrorCodes.SESSION_NOT_FOUND,
                    'Session not found',
                    status_code=404
                )
                log_api_request('/api/sessions/<session_id>', 'GET', 404,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 404)
            
            response_data = APIResponse.success({
                'session': session.to_dict()
            })
            
            log_api_request('/api/sessions/<session_id>', 'GET', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error retrieving session {session_id}: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve session',
                status_code=500
            )
            log_api_request('/api/sessions/<session_id>', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/sessions/<session_id>/extend', methods=['POST'])
    def extend_session(session_id: str):
        """
        Extend session lifetime for long-running workflows.
        
        Args:
            session_id: Session ID to extend
            
        Request body:
            {
                "additional_seconds": 3600  // Optional, defaults to 1 hour
            }
            
        Returns:
            JSON response with updated session information
        """
        start_time = time.time()
        
        try:
            data = request.get_json() or {}
            additional_seconds = data.get('additional_seconds', 3600)
            
            if not isinstance(additional_seconds, int) or additional_seconds <= 0:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    'additional_seconds must be a positive integer',
                    status_code=400
                )
                log_api_request('/api/sessions/<session_id>/extend', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            session_pool = get_session_pool()
            success = session_pool.extend_session(session_id, additional_seconds)
            
            if not success:
                response_data = APIResponse.error(
                    ErrorCodes.SESSION_NOT_FOUND,
                    'Session not found or cannot be extended',
                    status_code=404
                )
                log_api_request('/api/sessions/<session_id>/extend', 'POST', 404,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 404)
            
            # Get updated session info
            session = session_pool.get_session(session_id)
            
            response_data = APIResponse.success({
                'session': session.to_dict() if session else None,
                'extended_by_seconds': additional_seconds
            })
            
            log_api_request('/api/sessions/<session_id>/extend', 'POST', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error extending session {session_id}: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to extend session',
                status_code=500
            )
            log_api_request('/api/sessions/<session_id>/extend', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/workflows/templates', methods=['GET'])
    def get_workflow_templates():
        """
        Get workflow templates with optional filtering.
        
        Query parameters:
        - category: Filter by category
        - provider: Filter by provider support
        - tags: Comma-separated list of tags
        - query: Text search in name/description
        
        Returns:
            JSON response with workflow templates
        """
        start_time = time.time()
        
        try:
            from .workflow_templates import get_template_manager
            
            template_manager = get_template_manager()
            
            # Get query parameters
            category = request.args.get('category')
            provider = request.args.get('provider')
            tags_param = request.args.get('tags')
            query = request.args.get('query')
            
            # Parse tags
            tags = None
            if tags_param:
                tags = [tag.strip() for tag in tags_param.split(',')]
            
            # Search templates
            templates = template_manager.search_templates(
                query=query,
                category=category,
                provider=provider,
                tags=tags
            )
            
            # Convert to dict representation
            template_data = [template.to_dict() for template in templates]
            
            response_data = APIResponse.success({
                'templates': template_data,
                'total_count': len(template_data),
                'categories': template_manager.get_categories(),
                'supported_providers': template_manager.get_supported_providers()
            })
            
            log_api_request('/api/workflows/templates', 'GET', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error retrieving workflow templates: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve workflow templates',
                status_code=500
            )
            log_api_request('/api/workflows/templates', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/workflows/templates/<template_id>', methods=['GET'])
    def get_workflow_template(template_id: str):
        """
        Get specific workflow template by ID.
        
        Args:
            template_id: Template ID to retrieve
            
        Returns:
            JSON response with template details
        """
        start_time = time.time()
        
        try:
            from .workflow_templates import get_template_manager
            
            template_manager = get_template_manager()
            template = template_manager.get_template(template_id)
            
            if not template:
                response_data = APIResponse.error(
                    ErrorCodes.NOT_FOUND,
                    f'Template {template_id} not found',
                    status_code=404
                )
                log_api_request('/api/workflows/templates/<template_id>', 'GET', 404,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 404)
            
            response_data = APIResponse.success({
                'template': template.to_dict()
            })
            
            log_api_request('/api/workflows/templates/<template_id>', 'GET', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error retrieving template {template_id}: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve template',
                status_code=500
            )
            log_api_request('/api/workflows/templates/<template_id>', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/workflows/templates/<template_id>/validate', methods=['POST'])
    def validate_template_permissions(template_id: str):
        """
        Validate template permissions against available scopes.
        
        Args:
            template_id: Template ID to validate
            
        Request body:
            {
                "available_scopes": {
                    "google": ["scope1", "scope2"],
                    "microsoft": ["scope3", "scope4"]
                }
            }
            
        Returns:
            JSON response with validation results
        """
        start_time = time.time()
        
        try:
            from .workflow_templates import get_template_manager
            
            data = request.get_json()
            if not data or 'available_scopes' not in data:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    'available_scopes is required',
                    status_code=400
                )
                log_api_request('/api/workflows/templates/<template_id>/validate', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            template_manager = get_template_manager()
            validation_result = template_manager.validate_template_permissions(
                template_id,
                data['available_scopes']
            )
            
            response_data = APIResponse.success({
                'validation': validation_result
            })
            
            status_code = 200 if validation_result['valid'] else 422
            
            log_api_request('/api/workflows/templates/<template_id>/validate', 'POST', status_code,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, status_code)
            
        except Exception as e:
            app.logger.error(f"Error validating template {template_id}: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to validate template',
                status_code=500
            )
            log_api_request('/api/workflows/templates/<template_id>/validate', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/workflows/templates/<template_id>/config', methods=['POST'])
    def create_session_config(template_id: str):
        """
        Create session configuration from template.
        
        Args:
            template_id: Template ID to use
            
        Request body:
            {
                "provider": "google",
                "user_preferences": {
                    "include_optional_scopes": true,
                    "session_duration": 7200,
                    "auto_renewal": true,
                    "metadata": {"key": "value"}
                }
            }
            
        Returns:
            JSON response with session configuration
        """
        start_time = time.time()
        
        try:
            from .workflow_templates import get_template_manager
            
            data = request.get_json()
            if not data or 'provider' not in data:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    'provider is required',
                    status_code=400
                )
                log_api_request('/api/workflows/templates/<template_id>/config', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            template_manager = get_template_manager()
            
            try:
                session_config = template_manager.create_session_config(
                    template_id,
                    data['provider'],
                    data.get('user_preferences')
                )
                
                response_data = APIResponse.success({
                    'session_config': session_config
                })
                
                log_api_request('/api/workflows/templates/<template_id>/config', 'POST', 200,
                              (time.time() - start_time) * 1000)
                
                return create_flask_response(response_data, 200)
                
            except ValueError as e:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    str(e),
                    status_code=400
                )
                log_api_request('/api/workflows/templates/<template_id>/config', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
        except Exception as e:
            app.logger.error(f"Error creating session config for template {template_id}: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to create session configuration',
                status_code=500
            )
            log_api_request('/api/workflows/templates/<template_id>/config', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)

    @app.route('/api/sessions/cleanup', methods=['POST'])
    def cleanup_sessions():
        """
        Clean up sessions based on criteria.
        
        Request body:
            {
                "user_id": "user123",      // Optional: clean user sessions
                "agent_id": "agent456",    // Optional: clean agent sessions
                "workflow_id": "wf789",    // Optional: clean workflow sessions
                "expired_only": true       // Optional: clean only expired sessions
            }
            
        Returns:
            JSON response with cleanup results
        """
        start_time = time.time()
        
        try:
            data = request.get_json() or {}
            
            user_id = data.get('user_id')
            agent_id = data.get('agent_id')
            workflow_id = data.get('workflow_id')
            expired_only = data.get('expired_only', False)
            
            session_pool = get_session_pool()
            cleaned_count = 0
            
            if user_id:
                cleaned_count = session_pool.cleanup_user_sessions(user_id)
            elif agent_id:
                cleaned_count = session_pool.cleanup_agent_sessions(agent_id)
            elif workflow_id:
                cleaned_count = session_pool.cleanup_workflow_sessions(workflow_id)
            elif expired_only:
                cleaned_count = session_pool._cleanup_expired_sessions()
            else:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    'Must specify cleanup criteria',
                    status_code=400
                )
                log_api_request('/api/sessions/cleanup', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            response_data = APIResponse.success({
                'cleaned_sessions': cleaned_count,
                'criteria': {
                    'user_id': user_id,
                    'agent_id': agent_id,
                    'workflow_id': workflow_id,
                    'expired_only': expired_only
                }
            })
            
            log_api_request('/api/sessions/cleanup', 'POST', 200,
                          (time.time() - start_time) * 1000)
            
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error cleaning up sessions: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to clean up sessions',
                status_code=500
            )
            log_api_request('/api/sessions/cleanup', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)

    @app.route('/api/tokens/<session_id>')
    def get_tokens(session_id: str):
        """
        Token retrieval endpoint for AI agents and external systems.
        
        This endpoint allows retrieval of stored OAuth tokens using a session ID.
        It validates the session ID format and existence, returning appropriate
        error responses for invalid requests.
        
        Args:
            session_id: Session ID for token lookup
            
        Returns:
            Standardized JSON response with token data or error message
        """
        start_time = time.time()
        app.logger.info(f"Token retrieval request for session ID: {session_id}")
        
        try:
            # Validate session ID format first
            if not TokenStorage.validate_session_id(session_id):
                app.logger.warning(f"Invalid session ID format: {session_id}")
                response_data = TokenResponseBuilder.error_response(
                    ErrorCodes.INVALID_SESSION_ID,
                    'Session ID format is invalid',
                    session_id=session_id,
                    status_code=400
                )
                log_api_request('/api/tokens/<session_id>', 'GET', 400, 
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            # Prepare client info for webhook notification
            client_info = {
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'ip_address': request.remote_addr,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            # Retrieve tokens from storage
            token_data = TokenStorage.retrieve_tokens(session_id, app.webhook_manager, client_info)
            
            if not token_data:
                app.logger.warning(f"Token retrieval failed for session ID: {session_id}")
                response_data = TokenResponseBuilder.error_response(
                    ErrorCodes.SESSION_NOT_FOUND,
                    'Session ID not found or expired',
                    session_id=session_id,
                    status_code=404
                )
                log_api_request('/api/tokens/<session_id>', 'GET', 404,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 404)
            
            # Get provider information for metadata
            provider_info = None
            if hasattr(app, 'provider_manager'):
                provider = app.provider_manager.get_provider(token_data['provider'])
                if provider:
                    provider_info = provider.get_provider_info()
            
            # Add session_id to token_data for response formatting
            token_data['session_id'] = session_id
            
            # Create standardized success response
            response_data = TokenResponseBuilder.success_response(
                token_data, 
                provider_info,
                "Token retrieved successfully"
            )
            
            app.logger.info(f"Token retrieval successful for session ID: {session_id}")
            log_api_request('/api/tokens/<session_id>', 'GET', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
            
        except ValueError as e:
            app.logger.error(f"Value error during token retrieval: {e}", exc_info=True)
            response_data = TokenResponseBuilder.error_response(
                ErrorCodes.INVALID_TOKEN,
                'Error processing token data',
                session_id=session_id,
                status_code=500
            )
            log_api_request('/api/tokens/<session_id>', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
        except Exception as e:
            app.logger.error(f"Unexpected error during token retrieval: {e}", exc_info=True)
            response_data = TokenResponseBuilder.error_response(
                ErrorCodes.INTERNAL_ERROR,
                'An unexpected error occurred',
                session_id=session_id,
                status_code=500
            )
            log_api_request('/api/tokens/<session_id>', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/storage/stats')
    def get_storage_stats():
        """
        Get token storage statistics (for debugging/monitoring).
        
        Returns:
            Standardized JSON response with storage statistics
        """
        start_time = time.time()
        try:
            stats = TokenStorage.get_storage_stats()
            response_data = APIResponse.success(
                data=stats,
                message="Storage statistics retrieved successfully",
                metadata={
                    "storage_type": "in_memory",
                    "cleanup_enabled": True
                }
            )
            log_api_request('/api/storage/stats', 'GET', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
        except Exception as e:
            app.logger.error(f"Error retrieving storage stats: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.STORAGE_ERROR,
                'Failed to retrieve storage statistics',
                status_code=500
            )
            log_api_request('/api/storage/stats', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/enterprise/config')
    def get_enterprise_config():
        """
        Get enterprise configuration information.
        
        Returns:
            Standardized JSON response with enterprise configuration
        """
        start_time = time.time()
        try:
            config = get_config()
            enterprise_config = config.get_enterprise_config()
            
            # Sanitize sensitive information
            safe_config = {
                'base_url': enterprise_config['BASE_URL'],
                'environment': enterprise_config['ENVIRONMENT'],
                'webhook_enabled': config.is_webhook_enabled(),
                'webhook_events': enterprise_config['WEBHOOK_EVENTS'] if config.is_webhook_enabled() else [],
                'callback_url_override': bool(enterprise_config['CALLBACK_URL_OVERRIDE'])
            }
            
            response_data = APIResponse.success(
                data=safe_config,
                message="Enterprise configuration retrieved successfully"
            )
            log_api_request('/api/enterprise/config', 'GET', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
        except Exception as e:
            app.logger.error(f"Error retrieving enterprise config: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve enterprise configuration',
                status_code=500
            )
            log_api_request('/api/enterprise/config', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/enterprise/webhooks/info')
    def get_webhook_info():
        """
        Get webhook configuration information.
        
        Returns:
            Standardized JSON response with webhook information
        """
        start_time = time.time()
        try:
            webhook_info = app.webhook_manager.get_webhook_info()
            response_data = APIResponse.success(
                data=webhook_info,
                message="Webhook information retrieved successfully"
            )
            log_api_request('/api/enterprise/webhooks/info', 'GET', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
        except Exception as e:
            app.logger.error(f"Error retrieving webhook info: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve webhook information',
                status_code=500
            )
            log_api_request('/api/enterprise/webhooks/info', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/enterprise/webhooks/test', methods=['POST'])
    def test_webhook():
        """
        Test webhook configuration by sending a test notification.
        
        Returns:
            Standardized JSON response with test result
        """
        start_time = time.time()
        try:
            if not app.webhook_manager.is_enabled():
                response_data = APIResponse.error(
                    ErrorCodes.WEBHOOK_DISABLED,
                    'Webhook notifications are not enabled',
                    status_code=400
                )
                log_api_request('/api/enterprise/webhooks/test', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            success = app.webhook_manager.test_webhook()
            
            if success:
                response_data = APIResponse.success(
                    data={'test_sent': True},
                    message="Test webhook sent successfully"
                )
                status_code = 200
            else:
                response_data = APIResponse.error(
                    ErrorCodes.WEBHOOK_ERROR,
                    'Failed to send test webhook',
                    status_code=500
                )
                status_code = 500
            
            log_api_request('/api/enterprise/webhooks/test', 'POST', status_code,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, status_code)
            
        except Exception as e:
            app.logger.error(f"Error testing webhook: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'An unexpected error occurred while testing webhook',
                status_code=500
            )
            log_api_request('/api/enterprise/webhooks/test', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/agent/auth', methods=['POST'])
    def agent_auth():
        """
        Programmatic OAuth initiation for AI agents.
        
        This endpoint allows agents to initiate OAuth flows programmatically
        without requiring direct user interaction with the web UI.
        
        Expected JSON payload:
        {
            "provider": "google|microsoft",
            "callback_url": "optional_custom_callback",
            "scopes": ["optional", "custom", "scopes"],
            "agent_id": "optional_agent_identifier",
            "workflow_id": "optional_workflow_identifier"
        }
        
        Returns:
            Standardized JSON response with authorization URL and state
        """
        start_time = time.time()
        app.logger.info("Agent OAuth initiation request received")
        
        try:
            # Parse JSON request
            if not request.is_json:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    'Request must be JSON',
                    status_code=400
                )
                log_api_request('/api/agent/auth', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            data = request.get_json()
            provider_name = data.get('provider')
            
            # Validate required parameters
            if not provider_name:
                response_data = APIResponse.error(
                    ErrorCodes.MISSING_PARAMETER,
                    'Provider parameter is required',
                    status_code=400
                )
                log_api_request('/api/agent/auth', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            # Get provider instance
            if not hasattr(app, 'provider_manager'):
                response_data = APIResponse.error(
                    ErrorCodes.INTERNAL_ERROR,
                    'Provider manager not initialized',
                    status_code=500
                )
                log_api_request('/api/agent/auth', 'POST', 500,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 500)
            
            provider = app.provider_manager.get_provider(provider_name)
            if not provider:
                response_data = APIResponse.error(
                    ErrorCodes.PROVIDER_NOT_FOUND,
                    f'Provider "{provider_name}" not found or not configured',
                    status_code=404
                )
                log_api_request('/api/agent/auth', 'POST', 404,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 404)
            
            # Generate secure state parameter with agent context
            state_data = {
                'provider': provider_name,
                'agent_id': data.get('agent_id'),
                'workflow_id': data.get('workflow_id'),
                'timestamp': time.time(),
                'nonce': secrets.token_urlsafe(16)
            }
            
            # Store state in session for validation
            session_state = secrets.token_urlsafe(32)
            session[f'oauth_state_{session_state}'] = state_data
            
            # Build callback URL
            callback_url = data.get('callback_url')
            if not callback_url:
                callback_url = url_for('oauth_callback', provider=provider_name, _external=True)
            
            # Get authorization URL from provider
            try:
                auth_url = provider.get_authorization_url(session_state, callback_url)
                
                response_data = APIResponse.success(
                    data={
                        'authorization_url': auth_url,
                        'state': session_state,
                        'provider': provider_name,
                        'callback_url': callback_url,
                        'expires_at': datetime.fromtimestamp(
                            state_data['timestamp'] + 600  # 10 minutes
                        ).isoformat() + 'Z'
                    },
                    message="OAuth authorization URL generated successfully"
                )
                
                # Log audit event for agent OAuth initiation
                audit_logger = get_audit_logger()
                audit_logger.log_event(
                    event_type=AuditEventType.AGENT_AUTH,
                    provider=provider_name,
                    agent_id=data.get('agent_id'),
                    workflow_id=data.get('workflow_id'),
                    user_ip=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=True,
                    details={
                        'callback_url': callback_url,
                        'state': session_state,
                        'custom_scopes': data.get('scopes')
                    }
                )
                
                app.logger.info(f"Generated OAuth URL for agent - provider: {provider_name}, agent_id: {data.get('agent_id')}")
                log_api_request('/api/agent/auth', 'POST', 200,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 200)
                
            except Exception as e:
                app.logger.error(f"Error generating authorization URL: {e}", exc_info=True)
                response_data = APIResponse.error(
                    ErrorCodes.OAUTH_ERROR,
                    'Failed to generate authorization URL',
                    status_code=500
                )
                log_api_request('/api/agent/auth', 'POST', 500,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 500)
                
        except Exception as e:
            app.logger.error(f"Unexpected error in agent auth: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'An unexpected error occurred',
                status_code=500
            )
            log_api_request('/api/agent/auth', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/agent/sessions')
    def agent_sessions():
        """
        Session management endpoint for AI agents.
        
        This endpoint allows agents to list and manage their active sessions,
        supporting long-running workflows that need to persist across tasks.
        
        Query parameters:
        - agent_id: Filter sessions by agent ID
        - workflow_id: Filter sessions by workflow ID
        - provider: Filter sessions by provider
        - status: Filter by session status (active, expired)
        
        Returns:
            Standardized JSON response with session list
        """
        start_time = time.time()
        app.logger.info("Agent sessions request received")
        
        try:
            # Get query parameters
            agent_id = request.args.get('agent_id')
            workflow_id = request.args.get('workflow_id')
            provider_filter = request.args.get('provider')
            status_filter = request.args.get('status', 'active')
            
            # Get all sessions from storage
            sessions = []
            current_time = time.time()
            
            with storage_lock:
                for session_id, token_data in token_storage.items():
                    # Check if session matches filters
                    if provider_filter and token_data.get('provider') != provider_filter:
                        continue
                    
                    # Check session status
                    is_expired = current_time > token_data.get('expires_at', 0)
                    if status_filter == 'active' and is_expired:
                        continue
                    elif status_filter == 'expired' and not is_expired:
                        continue
                    
                    # Build session info
                    session_info = {
                        'session_id': session_id,
                        'provider': token_data.get('provider'),
                        'created_at': datetime.fromtimestamp(
                            token_data.get('created_at', 0)
                        ).isoformat() + 'Z',
                        'expires_at': datetime.fromtimestamp(
                            token_data.get('expires_at', 0)
                        ).isoformat() + 'Z',
                        'scope': token_data.get('scope', ''),
                        'status': 'expired' if is_expired else 'active',
                        'agent_id': token_data.get('agent_id'),
                        'workflow_id': token_data.get('workflow_id')
                    }
                    
                    # Apply agent/workflow filters
                    if agent_id and session_info.get('agent_id') != agent_id:
                        continue
                    if workflow_id and session_info.get('workflow_id') != workflow_id:
                        continue
                    
                    sessions.append(session_info)
            
            # Sort sessions by creation time (newest first)
            sessions.sort(key=lambda x: x['created_at'], reverse=True)
            
            response_data = APIResponse.success(
                data={
                    'sessions': sessions,
                    'count': len(sessions),
                    'filters': {
                        'agent_id': agent_id,
                        'workflow_id': workflow_id,
                        'provider': provider_filter,
                        'status': status_filter
                    }
                },
                message=f"Retrieved {len(sessions)} sessions"
            )
            
            app.logger.info(f"Retrieved {len(sessions)} sessions for agent")
            log_api_request('/api/agent/sessions', 'GET', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error retrieving agent sessions: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve sessions',
                status_code=500
            )
            log_api_request('/api/agent/sessions', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/agent/data/<provider>/<session_id>')
    def agent_data_access(provider: str, session_id: str):
        """
        Standardized data access endpoint for AI agents.
        
        This endpoint provides a unified interface for agents to access user data
        across different OAuth providers with consistent response formatting.
        
        Args:
            provider: OAuth provider name (google, microsoft, etc.)
            session_id: Session ID for token lookup
            
        Query parameters:
        - data_type: Type of data to retrieve (profile, emails, calendar, etc.)
        - limit: Maximum number of items to return
        - offset: Pagination offset
        
        Returns:
            Standardized JSON response with user data
        """
        start_time = time.time()
        app.logger.info(f"Agent data access request - provider: {provider}, session: {session_id}")
        
        try:
            # Validate session ID format
            if not TokenStorage.validate_session_id(session_id):
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_SESSION_ID,
                    'Session ID format is invalid',
                    status_code=400
                )
                log_api_request('/api/agent/data/<provider>/<session_id>', 'GET', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            # Retrieve token data
            client_info = {
                'user_agent': request.headers.get('User-Agent', 'Agent'),
                'ip_address': request.remote_addr,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'data_type': request.args.get('data_type', 'unknown')
            }
            
            token_data = TokenStorage.retrieve_tokens(session_id, app.webhook_manager, client_info)
            
            if not token_data:
                response_data = APIResponse.error(
                    ErrorCodes.SESSION_NOT_FOUND,
                    'Session ID not found or expired',
                    status_code=404
                )
                log_api_request('/api/agent/data/<provider>/<session_id>', 'GET', 404,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 404)
            
            # Validate provider matches token
            if token_data.get('provider') != provider:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    f'Provider mismatch: session is for {token_data.get("provider")}, not {provider}',
                    status_code=400
                )
                log_api_request('/api/agent/data/<provider>/<session_id>', 'GET', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            # Get query parameters
            data_type = request.args.get('data_type', 'profile')
            limit = min(int(request.args.get('limit', 50)), 100)  # Cap at 100
            offset = int(request.args.get('offset', 0))
            
            # Get provider instance for data access
            if not hasattr(app, 'provider_manager'):
                response_data = APIResponse.error(
                    ErrorCodes.INTERNAL_ERROR,
                    'Provider manager not initialized',
                    status_code=500
                )
                log_api_request('/api/agent/data/<provider>/<session_id>', 'GET', 500,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 500)
            
            provider_instance = app.provider_manager.get_provider(provider)
            if not provider_instance:
                response_data = APIResponse.error(
                    ErrorCodes.PROVIDER_NOT_FOUND,
                    f'Provider "{provider}" not found',
                    status_code=404
                )
                log_api_request('/api/agent/data/<provider>/<session_id>', 'GET', 404,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 404)
            
            # For now, return standardized token information
            # In a full implementation, this would make actual API calls to the provider
            response_data = APIResponse.success(
                data={
                    'provider': provider,
                    'session_id': session_id,
                    'data_type': data_type,
                    'access_token': token_data.get('access_token'),
                    'scope': token_data.get('scope', ''),
                    'expires_at': datetime.fromtimestamp(
                        token_data.get('expires_at', 0)
                    ).isoformat() + 'Z',
                    'pagination': {
                        'limit': limit,
                        'offset': offset,
                        'has_more': False  # Would be determined by actual API call
                    },
                    'note': 'This endpoint provides token access for agent data retrieval. Implement provider-specific data fetching as needed.'
                },
                message=f"Data access granted for {data_type} from {provider}",
                metadata={
                    'provider_info': provider_instance.get_provider_info() if hasattr(provider_instance, 'get_provider_info') else {},
                    'available_scopes': token_data.get('scope', '').split() if token_data.get('scope') else []
                }
            )
            
            # Log audit event for data access
            audit_logger = get_audit_logger()
            audit_logger.log_event(
                event_type=AuditEventType.DATA_ACCESS,
                session_id=session_id,
                provider=provider,
                agent_id=token_data.get('agent_id'),
                workflow_id=token_data.get('workflow_id'),
                user_ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                data_type=data_type,
                scopes=token_data.get('scope', '').split() if token_data.get('scope') else [],
                success=True,
                details={
                    'limit': limit,
                    'offset': offset,
                    'access_method': 'agent_api'
                }
            )
            
            app.logger.info(f"Agent data access granted - provider: {provider}, data_type: {data_type}")
            log_api_request('/api/agent/data/<provider>/<session_id>', 'GET', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
            
        except ValueError as e:
            app.logger.error(f"Value error in agent data access: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INVALID_PARAMETER,
                'Invalid parameter value',
                status_code=400
            )
            log_api_request('/api/agent/data/<provider>/<session_id>', 'GET', 400,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 400)
        except Exception as e:
            app.logger.error(f"Unexpected error in agent data access: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'An unexpected error occurred',
                status_code=500
            )
            log_api_request('/api/agent/data/<provider>/<session_id>', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/agent/sessions/<session_id>/extend', methods=['POST'])
    def extend_agent_session(session_id: str):
        """
        Extend the lifetime of an agent session for long-running workflows.
        
        Args:
            session_id: Session ID to extend
            
        Expected JSON payload:
        {
            "additional_seconds": 3600,  // Optional, defaults to 1 hour
            "reason": "Long-running workflow"  // Optional reason for extension
        }
        
        Returns:
            Standardized JSON response with extension result
        """
        start_time = time.time()
        app.logger.info(f"Session extension request for session: {session_id}")
        
        try:
            # Validate session ID format
            if not TokenStorage.validate_session_id(session_id):
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_SESSION_ID,
                    'Session ID format is invalid',
                    status_code=400
                )
                log_api_request('/api/agent/sessions/<session_id>/extend', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            # Parse request data
            additional_seconds = 3600  # Default to 1 hour
            reason = "Session extension requested"
            
            if request.is_json:
                data = request.get_json()
                additional_seconds = data.get('additional_seconds', 3600)
                reason = data.get('reason', reason)
                
                # Validate additional_seconds
                if not isinstance(additional_seconds, int) or additional_seconds <= 0:
                    response_data = APIResponse.error(
                        ErrorCodes.INVALID_PARAMETER,
                        'additional_seconds must be a positive integer',
                        status_code=400
                    )
                    log_api_request('/api/agent/sessions/<session_id>/extend', 'POST', 400,
                                  (time.time() - start_time) * 1000)
                    return create_flask_response(response_data, 400)
                
                # Cap extension to 24 hours for security
                if additional_seconds > 86400:
                    additional_seconds = 86400
            
            # Attempt to extend session
            success = TokenStorage.extend_session_lifetime(session_id, additional_seconds)
            
            if not success:
                response_data = APIResponse.error(
                    ErrorCodes.SESSION_NOT_FOUND,
                    'Session ID not found',
                    status_code=404
                )
                log_api_request('/api/agent/sessions/<session_id>/extend', 'POST', 404,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 404)
            
            # Get updated session info
            token_data = TokenStorage.retrieve_tokens(session_id)
            new_expires_at = datetime.fromtimestamp(
                token_data.get('expires_at', 0)
            ).isoformat() + 'Z' if token_data else None
            
            response_data = APIResponse.success(
                data={
                    'session_id': session_id,
                    'extended_by_seconds': additional_seconds,
                    'new_expires_at': new_expires_at,
                    'reason': reason
                },
                message=f"Session extended by {additional_seconds} seconds"
            )
            
            # Log audit event for session extension
            audit_logger = get_audit_logger()
            if token_data:
                audit_logger.log_event(
                    event_type=AuditEventType.SESSION_EXTENDED,
                    session_id=session_id,
                    provider=token_data.get('provider'),
                    agent_id=token_data.get('agent_id'),
                    workflow_id=token_data.get('workflow_id'),
                    user_ip=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=True,
                    details={
                        'additional_seconds': additional_seconds,
                        'reason': reason,
                        'new_expires_at': new_expires_at
                    }
                )
            
            app.logger.info(f"Session {session_id} extended by {additional_seconds} seconds")
            log_api_request('/api/agent/sessions/<session_id>/extend', 'POST', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error extending session: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to extend session',
                status_code=500
            )
            log_api_request('/api/agent/sessions/<session_id>/extend', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/agent/sessions/cleanup', methods=['POST'])
    def cleanup_agent_sessions():
        """
        Clean up sessions for specific agents or workflows.
        
        Expected JSON payload:
        {
            "agent_id": "optional_agent_id",
            "workflow_id": "optional_workflow_id",
            "cleanup_type": "agent|workflow|expired"  // Type of cleanup to perform
        }
        
        Returns:
            Standardized JSON response with cleanup results
        """
        start_time = time.time()
        app.logger.info("Agent session cleanup request received")
        
        try:
            if not request.is_json:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_REQUEST,
                    'Request must be JSON',
                    status_code=400
                )
                log_api_request('/api/agent/sessions/cleanup', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            data = request.get_json()
            cleanup_type = data.get('cleanup_type', 'expired')
            agent_id = data.get('agent_id')
            workflow_id = data.get('workflow_id')
            
            cleaned_count = 0
            cleanup_details = {}
            
            if cleanup_type == 'agent' and agent_id:
                cleaned_count = TokenStorage.cleanup_agent_sessions(agent_id)
                cleanup_details = {'agent_id': agent_id}
            elif cleanup_type == 'workflow' and workflow_id:
                cleaned_count = TokenStorage.cleanup_workflow_sessions(workflow_id)
                cleanup_details = {'workflow_id': workflow_id}
            elif cleanup_type == 'expired':
                cleaned_count = TokenStorage.cleanup_expired_sessions()
                cleanup_details = {'type': 'expired_sessions'}
            else:
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_PARAMETER,
                    'Invalid cleanup_type or missing required parameters',
                    status_code=400
                )
                log_api_request('/api/agent/sessions/cleanup', 'POST', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            response_data = APIResponse.success(
                data={
                    'cleanup_type': cleanup_type,
                    'sessions_cleaned': cleaned_count,
                    'details': cleanup_details
                },
                message=f"Cleaned up {cleaned_count} sessions"
            )
            
            # Log audit event for session cleanup
            audit_logger = get_audit_logger()
            audit_logger.log_event(
                event_type=AuditEventType.SESSION_CLEANUP,
                agent_id=agent_id,
                workflow_id=workflow_id,
                user_ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=True,
                details={
                    'cleanup_type': cleanup_type,
                    'sessions_cleaned': cleaned_count,
                    'details': cleanup_details
                }
            )
            
            app.logger.info(f"Cleaned up {cleaned_count} sessions - type: {cleanup_type}")
            log_api_request('/api/agent/sessions/cleanup', 'POST', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error during session cleanup: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to cleanup sessions',
                status_code=500
            )
            log_api_request('/api/agent/sessions/cleanup', 'POST', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/audit/<session_id>')
    def get_audit_log(session_id: str):
        """
        Get audit log for a specific session for transparency and compliance.
        
        This endpoint provides complete audit trail for all data access events
        related to a specific session, enabling transparency and compliance.
        
        Args:
            session_id: Session ID to get audit log for
            
        Returns:
            Standardized JSON response with audit log entries
        """
        start_time = time.time()
        app.logger.info(f"Audit log request for session: {session_id}")
        
        try:
            # Validate session ID format
            if not TokenStorage.validate_session_id(session_id):
                response_data = APIResponse.error(
                    ErrorCodes.INVALID_SESSION_ID,
                    'Session ID format is invalid',
                    status_code=400
                )
                log_api_request('/api/audit/<session_id>', 'GET', 400,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 400)
            
            # Get audit log from audit logger
            audit_logger = get_audit_logger()
            audit_events = audit_logger.get_session_audit_log(session_id)
            
            # Get session information if available
            token_data = TokenStorage.retrieve_tokens(session_id)
            session_info = None
            if token_data:
                session_info = {
                    'provider': token_data.get('provider'),
                    'agent_id': token_data.get('agent_id'),
                    'workflow_id': token_data.get('workflow_id'),
                    'created_at': datetime.fromtimestamp(
                        token_data.get('created_at', 0)
                    ).isoformat() + 'Z',
                    'expires_at': datetime.fromtimestamp(
                        token_data.get('expires_at', 0)
                    ).isoformat() + 'Z',
                    'scope': token_data.get('scope', '')
                }
            
            response_data = APIResponse.success(
                data={
                    'session_id': session_id,
                    'session_info': session_info,
                    'audit_events': audit_events,
                    'event_count': len(audit_events),
                    'audit_summary': {
                        'total_events': len(audit_events),
                        'event_types': list(set(event['event_type'] for event in audit_events)),
                        'data_access_count': len([e for e in audit_events if e['event_type'] == 'data_access']),
                        'token_retrievals': len([e for e in audit_events if e['event_type'] == 'token_retrieved']),
                        'first_event': audit_events[0]['timestamp'] if audit_events else None,
                        'last_event': audit_events[-1]['timestamp'] if audit_events else None
                    }
                },
                message=f"Retrieved audit log with {len(audit_events)} events"
            )
            
            app.logger.info(f"Retrieved {len(audit_events)} audit events for session {session_id}")
            log_api_request('/api/audit/<session_id>', 'GET', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
            
        except Exception as e:
            app.logger.error(f"Error retrieving audit log: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve audit log',
                status_code=500
            )
            log_api_request('/api/audit/<session_id>', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)
    
    @app.route('/api/audit/analytics')
    def get_audit_analytics():
        """
        Get audit analytics and reporting data.
        
        This endpoint provides system-wide audit analytics for monitoring,
        compliance reporting, and data access transparency.
        
        Query parameters:
        - agent_id: Filter analytics by agent ID
        - workflow_id: Filter analytics by workflow ID
        - provider: Filter analytics by provider
        - limit: Maximum number of events to analyze (default: 1000)
        
        Returns:
            Standardized JSON response with audit analytics
        """
        start_time = time.time()
        app.logger.info("Audit analytics request received")
        
        try:
            # Get query parameters
            agent_id = request.args.get('agent_id')
            workflow_id = request.args.get('workflow_id')
            provider = request.args.get('provider')
            limit = min(int(request.args.get('limit', 1000)), 5000)  # Cap at 5000
            
            audit_logger = get_audit_logger()
            
            # Get filtered audit data based on parameters
            if agent_id:
                events = audit_logger.get_agent_audit_log(agent_id, limit)
                filter_type = 'agent'
                filter_value = agent_id
            elif workflow_id:
                events = audit_logger.get_workflow_audit_log(workflow_id, limit)
                filter_type = 'workflow'
                filter_value = workflow_id
            elif provider:
                events = audit_logger.get_provider_audit_log(provider, limit)
                filter_type = 'provider'
                filter_value = provider
            else:
                # Get general statistics
                stats = audit_logger.get_audit_statistics()
                response_data = APIResponse.success(
                    data=stats,
                    message="Retrieved system-wide audit analytics"
                )
                log_api_request('/api/audit/analytics', 'GET', 200,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 200)
            
            # Analyze filtered events
            if not events:
                response_data = APIResponse.success(
                    data={
                        'filter': {filter_type: filter_value},
                        'events': [],
                        'analytics': {
                            'total_events': 0,
                            'event_types': {},
                            'success_rate': 0,
                            'time_range': None
                        }
                    },
                    message=f"No events found for {filter_type}: {filter_value}"
                )
                log_api_request('/api/audit/analytics', 'GET', 200,
                              (time.time() - start_time) * 1000)
                return create_flask_response(response_data, 200)
            
            # Calculate analytics
            event_types = {}
            success_count = 0
            data_access_count = 0
            unique_sessions = set()
            
            for event in events:
                event_type = event['event_type']
                event_types[event_type] = event_types.get(event_type, 0) + 1
                
                if event['success']:
                    success_count += 1
                
                if event_type == 'data_access':
                    data_access_count += 1
                
                if event['session_id']:
                    unique_sessions.add(event['session_id'])
            
            success_rate = (success_count / len(events) * 100) if events else 0
            
            analytics = {
                'total_events': len(events),
                'unique_sessions': len(unique_sessions),
                'event_types': event_types,
                'success_rate_percent': round(success_rate, 2),
                'data_access_events': data_access_count,
                'time_range': {
                    'first_event': events[0]['timestamp'] if events else None,
                    'last_event': events[-1]['timestamp'] if events else None
                }
            }
            
            response_data = APIResponse.success(
                data={
                    'filter': {filter_type: filter_value},
                    'events': events[:100],  # Return first 100 events for display
                    'analytics': analytics,
                    'note': f"Showing first 100 of {len(events)} events" if len(events) > 100 else None
                },
                message=f"Retrieved audit analytics for {filter_type}: {filter_value}"
            )
            
            app.logger.info(f"Retrieved audit analytics - {filter_type}: {filter_value}, events: {len(events)}")
            log_api_request('/api/audit/analytics', 'GET', 200,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 200)
            
        except ValueError as e:
            app.logger.error(f"Value error in audit analytics: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INVALID_PARAMETER,
                'Invalid parameter value',
                status_code=400
            )
            log_api_request('/api/audit/analytics', 'GET', 400,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 400)
        except Exception as e:
            app.logger.error(f"Error retrieving audit analytics: {e}", exc_info=True)
            response_data = APIResponse.error(
                ErrorCodes.INTERNAL_ERROR,
                'Failed to retrieve audit analytics',
                status_code=500
            )
            log_api_request('/api/audit/analytics', 'GET', 500,
                          (time.time() - start_time) * 1000)
            return create_flask_response(response_data, 500)


# Create the Flask application instance with WebSocket support
app, socketio = create_app()


if __name__ == '__main__':
    """Run the Flask application with WebSocket support in development mode."""
    try:
        config = get_config()
        flask_config = config.get_flask_config()
        
        print("Starting SecureContext Protocol Authentication Proxy with WebSocket support...")
        print(f"Server will run on http://{flask_config['HOST']}:{flask_config['PORT']}")
        
        socketio.run(
            app,
            host=flask_config['HOST'],
            port=flask_config['PORT'],
            debug=flask_config['DEBUG']
        )
        
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Failed to start application: {e}", file=sys.stderr)
        sys.exit(1)
