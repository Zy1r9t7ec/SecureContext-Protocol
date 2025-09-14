"""
Session pool management for high-throughput concurrent operations.

This module provides advanced session management capabilities including
session pooling, multi-user isolation, and automatic session renewal
for workflow orchestration.
"""

import time
import threading
import uuid
import logging
from typing import Dict, Any, Optional, List, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import weakref

from .config import get_config


class SessionState(Enum):
    """Session state enumeration."""
    ACTIVE = "active"
    EXPIRED = "expired"
    RESERVED = "reserved"
    CLEANUP_PENDING = "cleanup_pending"


@dataclass
class SessionContext:
    """Enhanced session context with workflow support."""
    session_id: str
    provider: str
    user_id: str
    agent_id: Optional[str] = None
    workflow_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    state: SessionState = SessionState.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    workflow_step: Optional[str] = None
    parent_session_id: Optional[str] = None
    child_session_ids: Set[str] = field(default_factory=set)
    renewal_count: int = 0
    max_renewals: int = 5
    
    def __post_init__(self):
        """Initialize computed fields."""
        if self.expires_at == 0:
            # Default 1 hour expiration
            self.expires_at = self.created_at + 3600
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return time.time() > self.expires_at
    
    @property
    def expires_in_seconds(self) -> int:
        """Get seconds until expiration."""
        return max(0, int(self.expires_at - time.time()))
    
    @property
    def age_seconds(self) -> int:
        """Get session age in seconds."""
        return int(time.time() - self.created_at)
    
    def touch(self):
        """Update last accessed time and increment access count."""
        self.last_accessed = time.time()
        self.access_count += 1
    
    def can_renew(self) -> bool:
        """Check if session can be renewed."""
        return self.renewal_count < self.max_renewals
    
    def renew(self, additional_seconds: int = 3600) -> bool:
        """Renew session expiration."""
        if not self.can_renew():
            return False
        
        self.expires_at = time.time() + additional_seconds
        self.renewal_count += 1
        self.touch()
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'session_id': self.session_id,
            'provider': self.provider,
            'user_id': self.user_id,
            'agent_id': self.agent_id,
            'workflow_id': self.workflow_id,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'last_accessed': self.last_accessed,
            'access_count': self.access_count,
            'state': self.state.value,
            'metadata': self.metadata,
            'workflow_step': self.workflow_step,
            'parent_session_id': self.parent_session_id,
            'child_session_ids': list(self.child_session_ids),
            'renewal_count': self.renewal_count,
            'max_renewals': self.max_renewals,
            'is_expired': self.is_expired,
            'expires_in_seconds': self.expires_in_seconds,
            'age_seconds': self.age_seconds,
            'can_renew': self.can_renew()
        }


class SessionPool:
    """
    High-performance session pool for concurrent operations.
    
    Provides session pooling, multi-user isolation, automatic cleanup,
    and workflow context preservation.
    """
    
    def __init__(
        self,
        max_sessions: int = 1000,
        cleanup_interval: int = 300,
        auto_renewal: bool = True,
        renewal_threshold: int = 600  # Renew when < 10 minutes left
    ):
        """
        Initialize session pool.
        
        Args:
            max_sessions: Maximum number of concurrent sessions
            cleanup_interval: Cleanup interval in seconds
            auto_renewal: Enable automatic session renewal
            renewal_threshold: Seconds before expiry to trigger renewal
        """
        self.max_sessions = max_sessions
        self.cleanup_interval = cleanup_interval
        self.auto_renewal = auto_renewal
        self.renewal_threshold = renewal_threshold
        
        # Thread-safe session storage
        self._sessions: Dict[str, SessionContext] = {}
        self._user_sessions: Dict[str, Set[str]] = defaultdict(set)
        self._agent_sessions: Dict[str, Set[str]] = defaultdict(set)
        self._workflow_sessions: Dict[str, Set[str]] = defaultdict(set)
        self._provider_sessions: Dict[str, Set[str]] = defaultdict(set)
        
        # Session pools for reuse
        self._available_pools: Dict[str, deque] = defaultdict(deque)  # provider -> sessions
        self._reserved_sessions: Set[str] = set()
        
        # Thread synchronization
        self._lock = threading.RLock()
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        
        # Statistics
        self._stats = {
            'total_created': 0,
            'total_expired': 0,
            'total_renewed': 0,
            'total_pooled': 0,
            'pool_hits': 0,
            'pool_misses': 0
        }
        
        self.logger = logging.getLogger(__name__)
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def create_session(
        self,
        provider: str,
        user_id: str,
        expires_in: int = 3600,
        agent_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        workflow_step: Optional[str] = None,
        parent_session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        try_pool_reuse: bool = True
    ) -> SessionContext:
        """
        Create a new session or reuse from pool.
        
        Args:
            provider: OAuth provider name
            user_id: User identifier for isolation
            expires_in: Session expiration in seconds
            agent_id: Optional agent identifier
            workflow_id: Optional workflow identifier
            workflow_step: Optional workflow step identifier
            parent_session_id: Optional parent session for hierarchical workflows
            metadata: Optional session metadata
            try_pool_reuse: Whether to try reusing pooled sessions
            
        Returns:
            SessionContext object
            
        Raises:
            RuntimeError: If session limit exceeded
        """
        with self._lock:
            # Check session limits
            if len(self._sessions) >= self.max_sessions:
                # Try cleanup first
                self._cleanup_expired_sessions()
                
                if len(self._sessions) >= self.max_sessions:
                    raise RuntimeError(f"Session limit exceeded ({self.max_sessions})")
            
            # Try to reuse from pool if requested
            if try_pool_reuse:
                pool_key = f"{provider}:{user_id}"
                if pool_key in self._available_pools and self._available_pools[pool_key]:
                    session_id = self._available_pools[pool_key].popleft()
                    if session_id in self._sessions:
                        session = self._sessions[session_id]
                        if not session.is_expired and session.can_renew():
                            # Reuse existing session
                            session.renew(expires_in)
                            session.agent_id = agent_id
                            session.workflow_id = workflow_id
                            session.workflow_step = workflow_step
                            session.parent_session_id = parent_session_id
                            session.metadata.update(metadata or {})
                            session.state = SessionState.ACTIVE
                            
                            # Update indexes
                            self._update_session_indexes(session)
                            
                            self._stats['pool_hits'] += 1
                            self.logger.debug(f"Reused pooled session {session_id}")
                            return session
                
                self._stats['pool_misses'] += 1
            
            # Create new session
            session_id = str(uuid.uuid4())
            current_time = time.time()
            
            session = SessionContext(
                session_id=session_id,
                provider=provider,
                user_id=user_id,
                agent_id=agent_id,
                workflow_id=workflow_id,
                created_at=current_time,
                expires_at=current_time + expires_in,
                workflow_step=workflow_step,
                parent_session_id=parent_session_id,
                metadata=metadata or {}
            )
            
            # Store session
            self._sessions[session_id] = session
            
            # Update indexes
            self._update_session_indexes(session)
            
            # Handle parent-child relationships
            if parent_session_id and parent_session_id in self._sessions:
                self._sessions[parent_session_id].child_session_ids.add(session_id)
            
            self._stats['total_created'] += 1
            
            self.logger.info(
                f"Created session {session_id} for user {user_id}, "
                f"provider {provider}, workflow {workflow_id}"
            )
            
            return session
    
    def get_session(self, session_id: str) -> Optional[SessionContext]:
        """
        Get session by ID with automatic renewal if needed.
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            SessionContext or None if not found
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            
            # Check if expired
            if session.is_expired:
                self._expire_session(session_id)
                return None
            
            # Auto-renewal if enabled and close to expiry
            if (self.auto_renewal and 
                session.expires_in_seconds < self.renewal_threshold and
                session.can_renew()):
                session.renew()
                self._stats['total_renewed'] += 1
                self.logger.debug(f"Auto-renewed session {session_id}")
            
            session.touch()
            return session
    
    def reserve_session(self, session_id: str) -> bool:
        """
        Reserve a session for exclusive use.
        
        Args:
            session_id: Session ID to reserve
            
        Returns:
            True if successfully reserved
        """
        with self._lock:
            if session_id not in self._sessions:
                return False
            
            if session_id in self._reserved_sessions:
                return False
            
            session = self._sessions[session_id]
            if session.is_expired:
                return False
            
            session.state = SessionState.RESERVED
            self._reserved_sessions.add(session_id)
            return True
    
    def release_session(self, session_id: str, return_to_pool: bool = True) -> bool:
        """
        Release a reserved session.
        
        Args:
            session_id: Session ID to release
            return_to_pool: Whether to return to pool for reuse
            
        Returns:
            True if successfully released
        """
        with self._lock:
            if session_id not in self._reserved_sessions:
                return False
            
            self._reserved_sessions.discard(session_id)
            
            if session_id in self._sessions:
                session = self._sessions[session_id]
                session.state = SessionState.ACTIVE
                
                if return_to_pool and not session.is_expired:
                    pool_key = f"{session.provider}:{session.user_id}"
                    self._available_pools[pool_key].append(session_id)
                    self._stats['total_pooled'] += 1
                    self.logger.debug(f"Returned session {session_id} to pool")
            
            return True
    
    def extend_session(self, session_id: str, additional_seconds: int = 3600) -> bool:
        """
        Extend session lifetime.
        
        Args:
            session_id: Session ID to extend
            additional_seconds: Additional seconds to add
            
        Returns:
            True if successfully extended
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session or session.is_expired:
                return False
            
            return session.renew(additional_seconds)
    
    def get_user_sessions(self, user_id: str) -> List[SessionContext]:
        """
        Get all sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of SessionContext objects
        """
        with self._lock:
            session_ids = self._user_sessions.get(user_id, set())
            return [
                self._sessions[sid] for sid in session_ids
                if sid in self._sessions and not self._sessions[sid].is_expired
            ]
    
    def get_agent_sessions(self, agent_id: str) -> List[SessionContext]:
        """
        Get all sessions for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of SessionContext objects
        """
        with self._lock:
            session_ids = self._agent_sessions.get(agent_id, set())
            return [
                self._sessions[sid] for sid in session_ids
                if sid in self._sessions and not self._sessions[sid].is_expired
            ]
    
    def get_workflow_sessions(self, workflow_id: str) -> List[SessionContext]:
        """
        Get all sessions for a workflow.
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            List of SessionContext objects
        """
        with self._lock:
            session_ids = self._workflow_sessions.get(workflow_id, set())
            return [
                self._sessions[sid] for sid in session_ids
                if sid in self._sessions and not self._sessions[sid].is_expired
            ]
    
    def cleanup_user_sessions(self, user_id: str) -> int:
        """
        Clean up all sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            session_ids = self._user_sessions.get(user_id, set()).copy()
            cleaned_count = 0
            
            for session_id in session_ids:
                if self._remove_session(session_id):
                    cleaned_count += 1
            
            return cleaned_count
    
    def cleanup_agent_sessions(self, agent_id: str) -> int:
        """
        Clean up all sessions for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            session_ids = self._agent_sessions.get(agent_id, set()).copy()
            cleaned_count = 0
            
            for session_id in session_ids:
                if self._remove_session(session_id):
                    cleaned_count += 1
            
            return cleaned_count
    
    def cleanup_workflow_sessions(self, workflow_id: str) -> int:
        """
        Clean up all sessions for a workflow.
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            session_ids = self._workflow_sessions.get(workflow_id, set()).copy()
            cleaned_count = 0
            
            for session_id in session_ids:
                if self._remove_session(session_id):
                    cleaned_count += 1
            
            return cleaned_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get pool statistics.
        
        Returns:
            Dictionary with statistics
        """
        with self._lock:
            active_sessions = sum(
                1 for s in self._sessions.values()
                if not s.is_expired
            )
            
            expired_sessions = len(self._sessions) - active_sessions
            reserved_sessions = len(self._reserved_sessions)
            
            pool_sizes = {
                pool_key: len(sessions)
                for pool_key, sessions in self._available_pools.items()
            }
            
            return {
                'total_sessions': len(self._sessions),
                'active_sessions': active_sessions,
                'expired_sessions': expired_sessions,
                'reserved_sessions': reserved_sessions,
                'pool_sizes': pool_sizes,
                'user_count': len(self._user_sessions),
                'agent_count': len(self._agent_sessions),
                'workflow_count': len(self._workflow_sessions),
                'provider_count': len(self._provider_sessions),
                **self._stats
            }
    
    def _update_session_indexes(self, session: SessionContext):
        """Update session indexes for fast lookups."""
        session_id = session.session_id
        
        self._user_sessions[session.user_id].add(session_id)
        self._provider_sessions[session.provider].add(session_id)
        
        if session.agent_id:
            self._agent_sessions[session.agent_id].add(session_id)
        
        if session.workflow_id:
            self._workflow_sessions[session.workflow_id].add(session_id)
    
    def _remove_session_from_indexes(self, session: SessionContext):
        """Remove session from all indexes."""
        session_id = session.session_id
        
        self._user_sessions[session.user_id].discard(session_id)
        self._provider_sessions[session.provider].discard(session_id)
        
        if session.agent_id:
            self._agent_sessions[session.agent_id].discard(session_id)
        
        if session.workflow_id:
            self._workflow_sessions[session.workflow_id].discard(session_id)
        
        # Clean up empty sets
        if not self._user_sessions[session.user_id]:
            del self._user_sessions[session.user_id]
        
        if session.agent_id and not self._agent_sessions[session.agent_id]:
            del self._agent_sessions[session.agent_id]
        
        if session.workflow_id and not self._workflow_sessions[session.workflow_id]:
            del self._workflow_sessions[session.workflow_id]
    
    def _expire_session(self, session_id: str):
        """Mark session as expired and handle cleanup."""
        if session_id in self._sessions:
            session = self._sessions[session_id]
            session.state = SessionState.EXPIRED
            self._stats['total_expired'] += 1
            
            # Remove from pools
            pool_key = f"{session.provider}:{session.user_id}"
            if pool_key in self._available_pools:
                try:
                    self._available_pools[pool_key].remove(session_id)
                except ValueError:
                    pass
            
            self.logger.debug(f"Expired session {session_id}")
    
    def _remove_session(self, session_id: str) -> bool:
        """Remove session completely."""
        if session_id not in self._sessions:
            return False
        
        session = self._sessions[session_id]
        
        # Remove from indexes
        self._remove_session_from_indexes(session)
        
        # Remove from pools
        pool_key = f"{session.provider}:{session.user_id}"
        if pool_key in self._available_pools:
            try:
                self._available_pools[pool_key].remove(session_id)
            except ValueError:
                pass
        
        # Remove from reserved set
        self._reserved_sessions.discard(session_id)
        
        # Handle child sessions
        for child_id in session.child_session_ids:
            if child_id in self._sessions:
                self._sessions[child_id].parent_session_id = None
        
        # Remove from parent's children
        if session.parent_session_id and session.parent_session_id in self._sessions:
            self._sessions[session.parent_session_id].child_session_ids.discard(session_id)
        
        # Remove session
        del self._sessions[session_id]
        
        return True
    
    def _cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        expired_sessions = []
        
        for session_id, session in self._sessions.items():
            if session.is_expired:
                expired_sessions.append(session_id)
        
        cleaned_count = 0
        for session_id in expired_sessions:
            if self._remove_session(session_id):
                cleaned_count += 1
        
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} expired sessions")
        
        return cleaned_count
    
    def _start_cleanup_thread(self):
        """Start automatic cleanup thread."""
        def cleanup_worker():
            while not self._stop_cleanup.wait(self.cleanup_interval):
                try:
                    with self._lock:
                        self._cleanup_expired_sessions()
                except Exception as e:
                    self.logger.error(f"Error in cleanup thread: {e}", exc_info=True)
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
        self.logger.info("Started session pool cleanup thread")
    
    def stop_cleanup_thread(self):
        """Stop cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=5)
            self.logger.info("Stopped session pool cleanup thread")
    
    def close(self):
        """Clean up resources."""
        self.stop_cleanup_thread()
        with self._lock:
            self._sessions.clear()
            self._user_sessions.clear()
            self._agent_sessions.clear()
            self._workflow_sessions.clear()
            self._provider_sessions.clear()
            self._available_pools.clear()
            self._reserved_sessions.clear()
        
        self.logger.info("Session pool closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Global session pool instance
_session_pool = None
_pool_lock = threading.Lock()


def get_session_pool() -> SessionPool:
    """
    Get global session pool instance.
    
    Returns:
        SessionPool instance
    """
    global _session_pool
    
    if _session_pool is None:
        with _pool_lock:
            if _session_pool is None:
                config = get_config()
                settings = config.get_provider_settings()
                
                _session_pool = SessionPool(
                    max_sessions=settings.get('max_concurrent_sessions', 1000),
                    cleanup_interval=settings.get('cleanup_interval', 300),
                    auto_renewal=settings.get('auto_renewal', True),
                    renewal_threshold=settings.get('renewal_threshold', 600)
                )
    
    return _session_pool