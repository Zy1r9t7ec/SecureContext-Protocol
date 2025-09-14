"""
Audit logging system for the SecureContext Protocol.

This module provides comprehensive audit logging for all data access events,
user consent tracking, and permission management for transparency and compliance.
"""

import logging
import time
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum


class AuditEventType(Enum):
    """Types of audit events that can be logged."""
    TOKEN_CREATED = "token_created"
    TOKEN_RETRIEVED = "token_retrieved"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"
    DATA_ACCESS = "data_access"
    SESSION_EXTENDED = "session_extended"
    SESSION_CLEANUP = "session_cleanup"
    OAUTH_INITIATED = "oauth_initiated"
    OAUTH_COMPLETED = "oauth_completed"
    OAUTH_FAILED = "oauth_failed"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_REVOKED = "consent_revoked"
    PERMISSION_CHECKED = "permission_checked"
    AGENT_AUTH = "agent_auth"
    WORKFLOW_STARTED = "workflow_started"
    WORKFLOW_COMPLETED = "workflow_completed"
    STREAM_CONNECTED = "stream_connected"
    STREAM_DISCONNECTED = "stream_disconnected"
    DATA_STREAMED = "data_streamed"
    STREAM_STARTED = "stream_started"
    STREAM_STOPPED = "stream_stopped"


@dataclass
class AuditEvent:
    """Represents a single audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: str
    session_id: Optional[str]
    provider: Optional[str]
    agent_id: Optional[str]
    workflow_id: Optional[str]
    user_ip: Optional[str]
    user_agent: Optional[str]
    data_type: Optional[str]
    scopes: List[str]
    success: bool
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        result = asdict(self)
        result['event_type'] = self.event_type.value
        return result


class AuditLogger:
    """
    Comprehensive audit logging system for SecureContext Protocol.
    
    This class provides audit logging for all data access events, user consent
    tracking, and permission management for transparency and compliance.
    """
    
    def __init__(self):
        """Initialize the audit logger."""
        self.logger = logging.getLogger(f"{__name__}.AuditLogger")
        self.audit_storage: Dict[str, List[AuditEvent]] = {}  # session_id -> events
        self.global_events: List[AuditEvent] = []  # All events for system-wide auditing
        self.storage_lock = threading.Lock()
        self.event_counter = 0
        
        # Set up audit-specific logging
        self._setup_audit_logging()
    
    def _setup_audit_logging(self):
        """Set up dedicated audit logging configuration."""
        # Create audit-specific logger
        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(logging.INFO)
        
        # Create audit log handler (could be file, database, etc.)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        if not audit_logger.handlers:
            audit_logger.addHandler(handler)
        
        self.audit_logger = audit_logger
    
    def _generate_event_id(self) -> str:
        """Generate a unique event ID."""
        with self.storage_lock:
            self.event_counter += 1
            return f"audit_{int(time.time())}_{self.event_counter}"
    
    def log_event(self, event_type: AuditEventType, session_id: Optional[str] = None,
                  provider: Optional[str] = None, agent_id: Optional[str] = None,
                  workflow_id: Optional[str] = None, user_ip: Optional[str] = None,
                  user_agent: Optional[str] = None, data_type: Optional[str] = None,
                  scopes: Optional[List[str]] = None, success: bool = True,
                  details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log an audit event.
        
        Args:
            event_type: Type of audit event
            session_id: Optional session ID
            provider: Optional OAuth provider name
            agent_id: Optional agent identifier
            workflow_id: Optional workflow identifier
            user_ip: Optional user IP address
            user_agent: Optional user agent string
            data_type: Optional type of data being accessed
            scopes: Optional list of OAuth scopes
            success: Whether the operation was successful
            details: Optional additional event details
            
        Returns:
            Generated event ID
        """
        event_id = self._generate_event_id()
        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            session_id=session_id,
            provider=provider,
            agent_id=agent_id,
            workflow_id=workflow_id,
            user_ip=user_ip,
            user_agent=user_agent,
            data_type=data_type,
            scopes=scopes or [],
            success=success,
            details=details or {}
        )
        
        with self.storage_lock:
            # Store event by session ID for easy retrieval
            if session_id:
                if session_id not in self.audit_storage:
                    self.audit_storage[session_id] = []
                self.audit_storage[session_id].append(event)
            
            # Store in global events list
            self.global_events.append(event)
            
            # Limit global events to prevent memory issues (keep last 10000)
            if len(self.global_events) > 10000:
                self.global_events = self.global_events[-10000:]
        
        # Log to audit logger
        self.audit_logger.info(
            f"Event: {event_type.value} | Session: {session_id} | "
            f"Provider: {provider} | Agent: {agent_id} | Success: {success}"
        )
        
        return event_id
    
    def get_session_audit_log(self, session_id: str) -> List[Dict[str, Any]]:
        """
        Get audit log for a specific session.
        
        Args:
            session_id: Session ID to get audit log for
            
        Returns:
            List of audit events for the session
        """
        with self.storage_lock:
            events = self.audit_storage.get(session_id, [])
            return [event.to_dict() for event in events]
    
    def get_agent_audit_log(self, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log for a specific agent.
        
        Args:
            agent_id: Agent ID to get audit log for
            limit: Maximum number of events to return
            
        Returns:
            List of audit events for the agent
        """
        agent_events = []
        
        with self.storage_lock:
            for event in reversed(self.global_events):  # Most recent first
                if event.agent_id == agent_id:
                    agent_events.append(event.to_dict())
                    if len(agent_events) >= limit:
                        break
        
        return agent_events
    
    def get_workflow_audit_log(self, workflow_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log for a specific workflow.
        
        Args:
            workflow_id: Workflow ID to get audit log for
            limit: Maximum number of events to return
            
        Returns:
            List of audit events for the workflow
        """
        workflow_events = []
        
        with self.storage_lock:
            for event in reversed(self.global_events):  # Most recent first
                if event.workflow_id == workflow_id:
                    workflow_events.append(event.to_dict())
                    if len(workflow_events) >= limit:
                        break
        
        return workflow_events
    
    def get_provider_audit_log(self, provider: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log for a specific provider.
        
        Args:
            provider: Provider name to get audit log for
            limit: Maximum number of events to return
            
        Returns:
            List of audit events for the provider
        """
        provider_events = []
        
        with self.storage_lock:
            for event in reversed(self.global_events):  # Most recent first
                if event.provider == provider:
                    provider_events.append(event.to_dict())
                    if len(provider_events) >= limit:
                        break
        
        return provider_events
    
    def get_audit_statistics(self) -> Dict[str, Any]:
        """
        Get audit statistics for analytics and reporting.
        
        Returns:
            Dictionary with audit statistics
        """
        with self.storage_lock:
            total_events = len(self.global_events)
            sessions_with_events = len(self.audit_storage)
            
            # Count events by type
            event_types = {}
            providers = {}
            agents = {}
            workflows = {}
            success_count = 0
            
            for event in self.global_events:
                # Event types
                event_type = event.event_type.value
                event_types[event_type] = event_types.get(event_type, 0) + 1
                
                # Providers
                if event.provider:
                    providers[event.provider] = providers.get(event.provider, 0) + 1
                
                # Agents
                if event.agent_id:
                    agents[event.agent_id] = agents.get(event.agent_id, 0) + 1
                
                # Workflows
                if event.workflow_id:
                    workflows[event.workflow_id] = workflows.get(event.workflow_id, 0) + 1
                
                # Success rate
                if event.success:
                    success_count += 1
        
        success_rate = (success_count / total_events * 100) if total_events > 0 else 0
        
        return {
            'total_events': total_events,
            'sessions_with_events': sessions_with_events,
            'success_rate_percent': round(success_rate, 2),
            'event_types': event_types,
            'providers': providers,
            'agents': agents,
            'workflows': workflows,
            'storage_info': {
                'in_memory': True,
                'max_global_events': 10000,
                'current_global_events': total_events
            }
        }
    
    def cleanup_session_audit_log(self, session_id: str) -> int:
        """
        Clean up audit log for a specific session.
        
        Args:
            session_id: Session ID to clean up
            
        Returns:
            Number of events cleaned up
        """
        with self.storage_lock:
            if session_id in self.audit_storage:
                event_count = len(self.audit_storage[session_id])
                del self.audit_storage[session_id]
                
                # Also remove from global events
                self.global_events = [
                    event for event in self.global_events 
                    if event.session_id != session_id
                ]
                
                self.logger.info(f"Cleaned up {event_count} audit events for session {session_id}")
                return event_count
        
        return 0
    
    def cleanup_expired_audit_logs(self, max_age_hours: int = 24) -> int:
        """
        Clean up audit logs older than specified age.
        
        Args:
            max_age_hours: Maximum age of audit logs in hours
            
        Returns:
            Number of events cleaned up
        """
        cutoff_time = time.time() - (max_age_hours * 3600)
        cleaned_count = 0
        
        with self.storage_lock:
            # Clean global events
            original_count = len(self.global_events)
            self.global_events = [
                event for event in self.global_events
                if datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')).timestamp() > cutoff_time
            ]
            cleaned_count = original_count - len(self.global_events)
            
            # Clean session-specific events
            sessions_to_clean = []
            for session_id, events in self.audit_storage.items():
                filtered_events = [
                    event for event in events
                    if datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')).timestamp() > cutoff_time
                ]
                
                if not filtered_events:
                    sessions_to_clean.append(session_id)
                else:
                    self.audit_storage[session_id] = filtered_events
            
            # Remove empty sessions
            for session_id in sessions_to_clean:
                del self.audit_storage[session_id]
        
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} expired audit events (older than {max_age_hours} hours)")
        
        return cleaned_count


# Global audit logger instance
audit_logger = AuditLogger()


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    return audit_logger