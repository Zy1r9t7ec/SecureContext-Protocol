"""
Session management utilities for agent workflows.
"""

import time
import threading
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta
import logging

from .client import SCPClient
from .exceptions import SCPError, SCPSessionError, SCPValidationError


class SessionInfo:
    """Information about an active session."""
    
    def __init__(
        self,
        session_id: str,
        provider: str,
        created_at: float,
        expires_at: float,
        agent_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.session_id = session_id
        self.provider = provider
        self.created_at = created_at
        self.expires_at = expires_at
        self.agent_id = agent_id
        self.workflow_id = workflow_id
        self.metadata = metadata or {}
        self.last_accessed = time.time()
        self.access_count = 0
    
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
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'session_id': self.session_id,
            'provider': self.provider,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'agent_id': self.agent_id,
            'workflow_id': self.workflow_id,
            'metadata': self.metadata,
            'last_accessed': self.last_accessed,
            'access_count': self.access_count,
            'is_expired': self.is_expired,
            'expires_in_seconds': self.expires_in_seconds,
            'age_seconds': self.age_seconds
        }


class SessionManager:
    """
    Manager for handling multiple OAuth sessions in agent workflows.
    
    This class provides session lifecycle management, automatic cleanup,
    and utilities for managing sessions across different agents and workflows.
    """
    
    def __init__(
        self,
        scp_client: SCPClient,
        cleanup_interval: int = 300,  # 5 minutes
        auto_cleanup: bool = True
    ):
        """
        Initialize the session manager.
        
        Args:
            scp_client: SCP client instance for API communication
            cleanup_interval: Interval for automatic cleanup in seconds
            auto_cleanup: Whether to automatically clean up expired sessions
        """
        self.scp_client = scp_client
        self.cleanup_interval = cleanup_interval
        self.auto_cleanup = auto_cleanup
        
        # Thread-safe session storage
        self._sessions: Dict[str, SessionInfo] = {}
        self._lock = threading.RLock()
        
        # Cleanup thread
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        
        self.logger = logging.getLogger(__name__)
        
        if self.auto_cleanup:
            self._start_cleanup_thread()
    
    def add_session(
        self,
        session_id: str,
        provider: str,
        expires_in: int,
        agent_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SessionInfo:
        """
        Add a new session to the manager.
        
        Args:
            session_id: Session ID from OAuth flow
            provider: OAuth provider name
            expires_in: Token expiration time in seconds
            agent_id: Optional agent identifier
            workflow_id: Optional workflow identifier
            metadata: Optional session metadata
            
        Returns:
            SessionInfo object for the added session
            
        Raises:
            SCPValidationError: If session parameters are invalid
        """
        if not session_id or not provider:
            raise SCPValidationError("Session ID and provider are required")
        
        current_time = time.time()
        expires_at = current_time + expires_in
        
        session_info = SessionInfo(
            session_id=session_id,
            provider=provider,
            created_at=current_time,
            expires_at=expires_at,
            agent_id=agent_id,
            workflow_id=workflow_id,
            metadata=metadata
        )
        
        with self._lock:
            self._sessions[session_id] = session_info
        
        self.logger.info(
            f"Added session {session_id} for provider {provider} "
            f"(agent: {agent_id}, workflow: {workflow_id})"
        )
        
        return session_info
    
    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """
        Get session information by ID.
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            SessionInfo object or None if not found
        """
        with self._lock:
            session_info = self._sessions.get(session_id)
            if session_info:
                session_info.touch()
            return session_info
    
    def get_tokens(self, session_id: str) -> Dict[str, Any]:
        """
        Get OAuth tokens for a session with automatic session tracking.
        
        Args:
            session_id: Session ID to retrieve tokens for
            
        Returns:
            Token data dictionary
            
        Raises:
            SCPSessionError: If session not found or expired
        """
        session_info = self.get_session(session_id)
        if not session_info:
            raise SCPSessionError(f"Session {session_id} not found in manager")
        
        if session_info.is_expired:
            self.remove_session(session_id)
            raise SCPSessionError(f"Session {session_id} has expired")
        
        try:
            tokens = self.scp_client.get_tokens(session_id)
            session_info.touch()
            return tokens
        except SCPError as e:
            if e.error_code in ['SESSION_NOT_FOUND', 'INVALID_SESSION_ID']:
                # Remove from local cache if server doesn't have it
                self.remove_session(session_id)
            raise
    
    def remove_session(self, session_id: str) -> bool:
        """
        Remove a session from the manager.
        
        Args:
            session_id: Session ID to remove
            
        Returns:
            True if session was removed, False if not found
        """
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                self.logger.info(f"Removed session {session_id}")
                return True
            return False
    
    def get_sessions_by_agent(self, agent_id: str) -> List[SessionInfo]:
        """
        Get all sessions for a specific agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of SessionInfo objects for the agent
        """
        with self._lock:
            return [
                session for session in self._sessions.values()
                if session.agent_id == agent_id
            ]
    
    def get_sessions_by_workflow(self, workflow_id: str) -> List[SessionInfo]:
        """
        Get all sessions for a specific workflow.
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            List of SessionInfo objects for the workflow
        """
        with self._lock:
            return [
                session for session in self._sessions.values()
                if session.workflow_id == workflow_id
            ]
    
    def get_sessions_by_provider(self, provider: str) -> List[SessionInfo]:
        """
        Get all sessions for a specific provider.
        
        Args:
            provider: Provider name
            
        Returns:
            List of SessionInfo objects for the provider
        """
        with self._lock:
            return [
                session for session in self._sessions.values()
                if session.provider == provider
            ]
    
    def get_active_sessions(self) -> List[SessionInfo]:
        """
        Get all active (non-expired) sessions.
        
        Returns:
            List of active SessionInfo objects
        """
        current_time = time.time()
        with self._lock:
            return [
                session for session in self._sessions.values()
                if session.expires_at > current_time
            ]
    
    def get_expired_sessions(self) -> List[SessionInfo]:
        """
        Get all expired sessions.
        
        Returns:
            List of expired SessionInfo objects
        """
        current_time = time.time()
        with self._lock:
            return [
                session for session in self._sessions.values()
                if session.expires_at <= current_time
            ]
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove all expired sessions from the manager.
        
        Returns:
            Number of sessions cleaned up
        """
        expired_sessions = self.get_expired_sessions()
        
        with self._lock:
            for session in expired_sessions:
                del self._sessions[session.session_id]
        
        if expired_sessions:
            self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    def cleanup_agent_sessions(self, agent_id: str) -> int:
        """
        Remove all sessions for a specific agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Number of sessions cleaned up
        """
        agent_sessions = self.get_sessions_by_agent(agent_id)
        
        with self._lock:
            for session in agent_sessions:
                del self._sessions[session.session_id]
        
        if agent_sessions:
            self.logger.info(f"Cleaned up {len(agent_sessions)} sessions for agent {agent_id}")
        
        return len(agent_sessions)
    
    def cleanup_workflow_sessions(self, workflow_id: str) -> int:
        """
        Remove all sessions for a specific workflow.
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            Number of sessions cleaned up
        """
        workflow_sessions = self.get_sessions_by_workflow(workflow_id)
        
        with self._lock:
            for session in workflow_sessions:
                del self._sessions[session.session_id]
        
        if workflow_sessions:
            self.logger.info(f"Cleaned up {len(workflow_sessions)} sessions for workflow {workflow_id}")
        
        return len(workflow_sessions)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about managed sessions.
        
        Returns:
            Dictionary with session statistics
        """
        with self._lock:
            total_sessions = len(self._sessions)
            active_sessions = len(self.get_active_sessions())
            expired_sessions = total_sessions - active_sessions
            
            providers = {}
            agents = {}
            workflows = {}
            
            for session in self._sessions.values():
                # Provider stats
                providers[session.provider] = providers.get(session.provider, 0) + 1
                
                # Agent stats
                if session.agent_id:
                    agents[session.agent_id] = agents.get(session.agent_id, 0) + 1
                
                # Workflow stats
                if session.workflow_id:
                    workflows[session.workflow_id] = workflows.get(session.workflow_id, 0) + 1
        
        return {
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'providers': providers,
            'agents': agents,
            'workflows': workflows
        }
    
    def _start_cleanup_thread(self):
        """Start the automatic cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        def cleanup_worker():
            while not self._stop_cleanup.wait(self.cleanup_interval):
                try:
                    self.cleanup_expired_sessions()
                except Exception as e:
                    self.logger.error(f"Error in cleanup thread: {e}", exc_info=True)
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
        self.logger.info("Started automatic session cleanup thread")
    
    def stop_cleanup_thread(self):
        """Stop the automatic cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=5)
            self.logger.info("Stopped automatic session cleanup thread")
    
    def close(self):
        """Clean up resources."""
        self.stop_cleanup_thread()
        with self._lock:
            self._sessions.clear()
        self.logger.info("Session manager closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()