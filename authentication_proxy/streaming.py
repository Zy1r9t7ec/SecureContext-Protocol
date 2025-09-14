"""
Real-time data streaming module for SecureContext Protocol.

This module implements WebSocket endpoints for live data access,
event-driven notifications, and streaming APIs for large dataset processing.
"""

import time
import json
import logging
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from flask import request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
import redis
from requests.exceptions import RequestException

try:
    from .audit_logger import get_audit_logger, AuditEventType
    from .session_pool import get_session_pool
except ImportError:
    from audit_logger import get_audit_logger, AuditEventType
    from session_pool import get_session_pool


class StreamEventType(Enum):
    """Types of streaming events."""
    DATA_UPDATE = "data_update"
    TOKEN_REFRESH = "token_refresh"
    SESSION_EXPIRED = "session_expired"
    RATE_LIMIT_WARNING = "rate_limit_warning"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


@dataclass
class StreamEvent:
    """Represents a streaming event."""
    event_type: StreamEventType
    session_id: str
    provider: str
    timestamp: float
    data: Dict[str, Any]
    agent_id: Optional[str] = None
    workflow_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'event_type': self.event_type.value,
            'session_id': self.session_id,
            'provider': self.provider,
            'timestamp': self.timestamp,
            'data': self.data,
            'agent_id': self.agent_id,
            'workflow_id': self.workflow_id
        }


class RateLimiter:
    """Rate limiting for streaming operations."""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.local_limits = defaultdict(lambda: deque())
        self.lock = threading.Lock() 
   
    def is_rate_limited(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        """
        Check if a key is rate limited.
        
        Args:
            key: Rate limiting key (e.g., session_id, ip_address)
            limit: Maximum requests per window
            window_seconds: Time window in seconds
            
        Returns:
            True if rate limited, False otherwise
        """
        current_time = time.time()
        
        if self.redis_client:
            # Use Redis for distributed rate limiting
            try:
                pipe = self.redis_client.pipeline()
                pipe.zremrangebyscore(key, 0, current_time - window_seconds)
                pipe.zcard(key)
                pipe.zadd(key, {str(uuid.uuid4()): current_time})
                pipe.expire(key, window_seconds)
                results = pipe.execute()
                
                current_count = results[1]
                return current_count >= limit
                
            except Exception as e:
                logging.warning(f"Redis rate limiting failed, falling back to local: {e}")
        
        # Local rate limiting fallback
        with self.lock:
            requests = self.local_limits[key]
            
            # Remove old requests outside the window
            while requests and requests[0] < current_time - window_seconds:
                requests.popleft()
            
            # Check if limit exceeded
            if len(requests) >= limit:
                return True
            
            # Add current request
            requests.append(current_time)
            return False
    
    def get_remaining_quota(self, key: str, limit: int, window_seconds: int = 60) -> int:
        """Get remaining quota for a key."""
        current_time = time.time()
        
        if self.redis_client:
            try:
                count = self.redis_client.zcount(key, current_time - window_seconds, current_time)
                return max(0, limit - count)
            except Exception:
                pass
        
        # Local fallback
        with self.lock:
            requests = self.local_limits[key]
            while requests and requests[0] < current_time - window_seconds:
                requests.popleft()
            return max(0, limit - len(requests))


class StreamingManager:
    """Manages real-time data streaming and WebSocket connections."""
    
    def __init__(self, socketio: SocketIO, redis_client: Optional[redis.Redis] = None):
        self.socketio = socketio
        self.redis_client = redis_client
        self.rate_limiter = RateLimiter(redis_client)
        self.active_streams = defaultdict(set)  # session_id -> set of socket_ids
        self.stream_configs = {}  # session_id -> stream configuration
        self.event_handlers = defaultdict(list)  # event_type -> list of handlers
        self.lock = threading.Lock()
        
        # Default rate limits
        self.default_limits = {
            'connections_per_session': 5,
            'events_per_minute': 100,
            'data_requests_per_minute': 50
        }
        
        self._setup_event_handlers()
    
    def _setup_event_handlers(self):
        """Set up default event handlers."""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle WebSocket connection."""
            client_id = request.sid
            session_id = request.args.get('session_id')
            agent_id = request.args.get('agent_id')
            
            if not session_id:
                logging.warning(f"WebSocket connection without session_id: {client_id}")
                disconnect()
                return
            
            # Rate limit connections per session
            connection_key = f"connections:{session_id}"
            if self.rate_limiter.is_rate_limited(
                connection_key, 
                self.default_limits['connections_per_session'], 
                300  # 5 minute window
            ):
                logging.warning(f"Connection rate limited for session {session_id}")
                emit('error', {'message': 'Too many connections for this session'})
                disconnect()
                return
            
            # Join session room
            join_room(session_id)
            
            with self.lock:
                self.active_streams[session_id].add(client_id)
            
            # Log connection
            audit_logger = get_audit_logger()
            audit_logger.log_event(
                event_type=AuditEventType.STREAM_CONNECTED,
                session_id=session_id,
                agent_id=agent_id,
                user_ip=request.remote_addr,
                success=True,
                details={'client_id': client_id}
            )
            
            logging.info(f"WebSocket connected: {client_id} for session {session_id}")
            emit('connected', {'session_id': session_id, 'client_id': client_id})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle WebSocket disconnection."""
            client_id = request.sid
            
            # Find and remove from active streams
            session_to_remove = None
            with self.lock:
                for session_id, clients in self.active_streams.items():
                    if client_id in clients:
                        clients.remove(client_id)
                        session_to_remove = session_id
                        break
            
            if session_to_remove:
                leave_room(session_to_remove)
                logging.info(f"WebSocket disconnected: {client_id} from session {session_to_remove}")
        
        @self.socketio.on('subscribe_data')
        def handle_subscribe_data(data):
            """Handle data subscription requests."""
            client_id = request.sid
            session_id = data.get('session_id')
            data_types = data.get('data_types', [])
            
            if not session_id or not data_types:
                emit('error', {'message': 'Invalid subscription request'})
                return
            
            # Rate limit subscription requests
            rate_key = f"subscribe:{session_id}"
            if self.rate_limiter.is_rate_limited(rate_key, 10, 60):  # 10 per minute
                emit('error', {'message': 'Subscription rate limit exceeded'})
                return
            
            # Store subscription configuration
            with self.lock:
                if session_id not in self.stream_configs:
                    self.stream_configs[session_id] = {}
                self.stream_configs[session_id][client_id] = {
                    'data_types': data_types,
                    'subscribed_at': time.time()
                }
            
            emit('subscription_confirmed', {
                'session_id': session_id,
                'data_types': data_types
            })
            
            logging.info(f"Data subscription: {client_id} -> {data_types} for session {session_id}")
    
    def broadcast_event(self, event: StreamEvent):
        """Broadcast an event to all subscribers of a session."""
        session_id = event.session_id
        
        if session_id not in self.active_streams:
            return
        
        event_data = event.to_dict()
        
        # Broadcast to session room
        self.socketio.emit('stream_event', event_data, room=session_id)
        
        # Log the broadcast
        audit_logger = get_audit_logger()
        audit_logger.log_event(
            event_type=AuditEventType.DATA_STREAMED,
            session_id=session_id,
            provider=event.provider,
            agent_id=event.agent_id,
            workflow_id=event.workflow_id,
            data_type=event.event_type.value,
            success=True,
            details={'event_data_size': len(json.dumps(event_data))}
        )
    
    def stream_data_update(self, session_id: str, provider: str, data_type: str, 
                          data: Dict[str, Any], agent_id: Optional[str] = None,
                          workflow_id: Optional[str] = None):
        """Stream a data update event."""
        event = StreamEvent(
            event_type=StreamEventType.DATA_UPDATE,
            session_id=session_id,
            provider=provider,
            timestamp=time.time(),
            data={
                'data_type': data_type,
                'payload': data
            },
            agent_id=agent_id,
            workflow_id=workflow_id
        )
        
        self.broadcast_event(event)
    
    def stream_token_refresh(self, session_id: str, provider: str, 
                           new_expires_at: float, agent_id: Optional[str] = None):
        """Stream a token refresh event."""
        event = StreamEvent(
            event_type=StreamEventType.TOKEN_REFRESH,
            session_id=session_id,
            provider=provider,
            timestamp=time.time(),
            data={
                'new_expires_at': new_expires_at,
                'expires_in': new_expires_at - time.time()
            },
            agent_id=agent_id
        )
        
        self.broadcast_event(event)
    
    def stream_rate_limit_warning(self, session_id: str, provider: str, 
                                remaining_quota: int, reset_time: float):
        """Stream a rate limit warning."""
        event = StreamEvent(
            event_type=StreamEventType.RATE_LIMIT_WARNING,
            session_id=session_id,
            provider=provider,
            timestamp=time.time(),
            data={
                'remaining_quota': remaining_quota,
                'reset_time': reset_time,
                'warning_message': f'Rate limit approaching. {remaining_quota} requests remaining.'
            }
        )
        
        self.broadcast_event(event)
    
    def get_active_streams_count(self) -> int:
        """Get total number of active streams."""
        with self.lock:
            return sum(len(clients) for clients in self.active_streams.values())
    
    def get_session_streams(self, session_id: str) -> List[str]:
        """Get active stream client IDs for a session."""
        with self.lock:
            return list(self.active_streams.get(session_id, set()))
    
    def cleanup_inactive_streams(self):
        """Clean up inactive streams and configurations."""
        current_time = time.time()
        sessions_to_cleanup = []
        
        with self.lock:
            for session_id, config in self.stream_configs.items():
                active_clients = []
                for client_id, client_config in config.items():
                    # Remove clients inactive for more than 1 hour
                    if current_time - client_config.get('subscribed_at', 0) > 3600:
                        continue
                    active_clients.append(client_id)
                
                if not active_clients:
                    sessions_to_cleanup.append(session_id)
                else:
                    # Update with only active clients
                    self.stream_configs[session_id] = {
                        client_id: config[client_id] 
                        for client_id in active_clients
                    }
            
            # Remove inactive sessions
            for session_id in sessions_to_cleanup:
                if session_id in self.stream_configs:
                    del self.stream_configs[session_id]
                if session_id in self.active_streams:
                    del self.active_streams[session_id]
        
        if sessions_to_cleanup:
            logging.info(f"Cleaned up {len(sessions_to_cleanup)} inactive streaming sessions")


# Global streaming manager instance
_streaming_manager = None


def get_streaming_manager() -> Optional[StreamingManager]:
    """Get the global streaming manager instance."""
    return _streaming_manager


def init_streaming(socketio: SocketIO, redis_client: Optional[redis.Redis] = None) -> StreamingManager:
    """Initialize the streaming manager."""
    global _streaming_manager
    _streaming_manager = StreamingManager(socketio, redis_client)
    
    # Start cleanup scheduler
    def cleanup_worker():
        while True:
            try:
                time.sleep(300)  # 5 minutes
                if _streaming_manager:
                    _streaming_manager.cleanup_inactive_streams()
            except Exception as e:
                logging.error(f"Error in streaming cleanup worker: {e}")
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    
    logging.info("Streaming manager initialized")
    return _streaming_manager