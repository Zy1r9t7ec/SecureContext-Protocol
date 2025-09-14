"""
Generic framework adapter for custom agent systems.
"""

from typing import Dict, Any, Optional, List, Callable, Protocol
import logging
from abc import ABC, abstractmethod

from ..client import SCPClient
from ..session_manager import SessionManager
from ..data_access import DataAccessClient
from ..exceptions import SCPError


class AgentInterface(Protocol):
    """Protocol defining the interface for agent frameworks."""
    
    def add_tool(self, name: str, func: Callable, description: str) -> None:
        """Add a tool/function to the agent."""
        ...
    
    def get_name(self) -> str:
        """Get the agent's name/identifier."""
        ...


class GenericAgentAdapter:
    """
    Generic adapter for integrating SCP with custom agent frameworks.
    
    This adapter provides a flexible interface that can be customized
    for any agent framework by implementing the required methods.
    """
    
    def __init__(
        self,
        scp_client: SCPClient,
        session_manager: Optional[SessionManager] = None,
        workflow_id: Optional[str] = None
    ):
        """
        Initialize the generic agent adapter.
        
        Args:
            scp_client: SCP client instance
            session_manager: Optional session manager for workflow support
            workflow_id: Optional workflow identifier for session tracking
        """
        self.scp_client = scp_client
        self.session_manager = session_manager
        self.workflow_id = workflow_id
        self.data_client = DataAccessClient(scp_client)
        self.logger = logging.getLogger(__name__)
        
        # Track registered agents and their sessions
        self.agent_sessions: Dict[str, str] = {}
        self.registered_tools: Dict[str, Callable] = {}
    
    def create_profile_tool(self, session_id: str, agent_id: Optional[str] = None) -> Callable:
        """
        Create a user profile access tool.
        
        Args:
            session_id: Session ID for token retrieval
            agent_id: Optional agent identifier
            
        Returns:
            Function that retrieves user profile data
        """
        def get_user_profile() -> Dict[str, Any]:
            """Get user profile information through SCP."""
            try:
                self.logger.info(f"Generic agent accessing profile for session {session_id}")
                
                # Update session context
                self._update_session_context(session_id, agent_id)
                
                data = self.data_client.get_user_profile(session_id)
                return {
                    'success': True,
                    'data': data,
                    'message': 'User profile retrieved successfully'
                }
            
            except SCPError as e:
                self.logger.error(f"SCP error retrieving profile: {e.message}")
                return {
                    'success': False,
                    'error': e.message,
                    'error_code': e.error_code
                }
            except Exception as e:
                self.logger.error(f"Unexpected error retrieving profile: {str(e)}", exc_info=True)
                return {
                    'success': False,
                    'error': str(e),
                    'error_code': 'UNEXPECTED_ERROR'
                }
        
        return get_user_profile
    
    def create_email_tool(
        self,
        session_id: str,
        agent_id: Optional[str] = None,
        default_max_results: int = 10
    ) -> Callable:
        """
        Create an email access tool.
        
        Args:
            session_id: Session ID for token retrieval
            agent_id: Optional agent identifier
            default_max_results: Default maximum number of results
            
        Returns:
            Function that retrieves email data
        """
        def get_emails(
            query: Optional[str] = None,
            max_results: int = default_max_results
        ) -> Dict[str, Any]:
            """Get email messages through SCP."""
            try:
                self.logger.info(f"Generic agent accessing emails for session {session_id}")
                
                # Update session context
                self._update_session_context(session_id, agent_id)
                
                data = self.data_client.get_emails(session_id, max_results, query)
                return {
                    'success': True,
                    'data': data,
                    'count': len(data),
                    'query': query,
                    'message': f'Retrieved {len(data)} emails successfully'
                }
            
            except SCPError as e:
                self.logger.error(f"SCP error retrieving emails: {e.message}")
                return {
                    'success': False,
                    'error': e.message,
                    'error_code': e.error_code
                }
            except Exception as e:
                self.logger.error(f"Unexpected error retrieving emails: {str(e)}", exc_info=True)
                return {
                    'success': False,
                    'error': str(e),
                    'error_code': 'UNEXPECTED_ERROR'
                }
        
        return get_emails
    
    def create_calendar_tool(
        self,
        session_id: str,
        agent_id: Optional[str] = None,
        default_max_results: int = 10
    ) -> Callable:
        """
        Create a calendar access tool.
        
        Args:
            session_id: Session ID for token retrieval
            agent_id: Optional agent identifier
            default_max_results: Default maximum number of results
            
        Returns:
            Function that retrieves calendar data
        """
        def get_calendar_events(
            max_results: int = default_max_results,
            time_min: Optional[str] = None,
            time_max: Optional[str] = None
        ) -> Dict[str, Any]:
            """Get calendar events through SCP."""
            try:
                self.logger.info(f"Generic agent accessing calendar for session {session_id}")
                
                # Update session context
                self._update_session_context(session_id, agent_id)
                
                data = self.data_client.get_calendar_events(session_id, max_results, time_min, time_max)
                return {
                    'success': True,
                    'data': data,
                    'count': len(data),
                    'time_range': {'min': time_min, 'max': time_max},
                    'message': f'Retrieved {len(data)} calendar events successfully'
                }
            
            except SCPError as e:
                self.logger.error(f"SCP error retrieving calendar: {e.message}")
                return {
                    'success': False,
                    'error': e.message,
                    'error_code': e.error_code
                }
            except Exception as e:
                self.logger.error(f"Unexpected error retrieving calendar: {str(e)}", exc_info=True)
                return {
                    'success': False,
                    'error': str(e),
                    'error_code': 'UNEXPECTED_ERROR'
                }
        
        return get_calendar_events
    
    def register_agent(
        self,
        agent: AgentInterface,
        session_id: str,
        tools: Optional[List[str]] = None
    ) -> None:
        """
        Register an agent with SCP capabilities.
        
        Args:
            agent: Agent instance implementing AgentInterface
            session_id: Session ID for the agent's data access
            tools: List of tools to register (default: all)
        """
        if tools is None:
            tools = ["profile", "emails", "calendar"]
        
        agent_name = agent.get_name()
        self.agent_sessions[agent_name] = session_id
        
        # Update session manager with workflow context
        if self.session_manager:
            session_info = self.session_manager.get_session(session_id)
            if session_info:
                session_info.workflow_id = self.workflow_id
                session_info.agent_id = agent_name
                session_info.touch()
        
        # Register requested tools
        tool_map = {
            "profile": (
                self.create_profile_tool(session_id, agent_name),
                "Get user profile information through SecureContext Protocol"
            ),
            "emails": (
                self.create_email_tool(session_id, agent_name),
                "Get email messages through SecureContext Protocol"
            ),
            "calendar": (
                self.create_calendar_tool(session_id, agent_name),
                "Get calendar events through SecureContext Protocol"
            )
        }
        
        registered_count = 0
        for tool_name in tools:
            if tool_name in tool_map:
                tool_func, description = tool_map[tool_name]
                tool_full_name = f"scp_{tool_name}"
                
                agent.add_tool(tool_full_name, tool_func, description)
                self.registered_tools[f"{agent_name}_{tool_full_name}"] = tool_func
                registered_count += 1
        
        self.logger.info(
            f"Registered {registered_count} SCP tools with agent {agent_name} "
            f"(session: {session_id}, workflow: {self.workflow_id})"
        )
    
    def create_simple_functions(self, session_id: str, agent_id: Optional[str] = None) -> Dict[str, Callable]:
        """
        Create simple functions for frameworks that don't use agent objects.
        
        Args:
            session_id: Session ID for token retrieval
            agent_id: Optional agent identifier
            
        Returns:
            Dictionary of function name to callable
        """
        return {
            'get_user_profile': self.create_profile_tool(session_id, agent_id),
            'get_emails': self.create_email_tool(session_id, agent_id),
            'get_calendar_events': self.create_calendar_tool(session_id, agent_id)
        }
    
    def _update_session_context(self, session_id: str, agent_id: Optional[str]) -> None:
        """Update session context with workflow and agent information."""
        if self.session_manager:
            session_info = self.session_manager.get_session(session_id)
            if session_info:
                if not session_info.workflow_id and self.workflow_id:
                    session_info.workflow_id = self.workflow_id
                if not session_info.agent_id and agent_id:
                    session_info.agent_id = agent_id
                session_info.touch()
    
    def get_workflow_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the workflow.
        
        Returns:
            Dictionary with workflow statistics
        """
        active_sessions = 0
        expired_sessions = 0
        
        if self.session_manager:
            for agent_name, session_id in self.agent_sessions.items():
                session_info = self.session_manager.get_session(session_id)
                if session_info:
                    if session_info.is_expired:
                        expired_sessions += 1
                    else:
                        active_sessions += 1
        
        return {
            'workflow_id': self.workflow_id,
            'total_agents': len(self.agent_sessions),
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'registered_tools': len(self.registered_tools),
            'agent_sessions': self.agent_sessions
        }
    
    def cleanup_workflow(self) -> int:
        """
        Clean up all sessions for this workflow.
        
        Returns:
            Number of sessions cleaned up
        """
        cleaned_count = 0
        
        if self.session_manager and self.workflow_id:
            cleaned_count = self.session_manager.cleanup_workflow_sessions(self.workflow_id)
        
        # Clear local tracking
        self.agent_sessions.clear()
        self.registered_tools.clear()
        
        self.logger.info(f"Cleaned up workflow {self.workflow_id}: {cleaned_count} sessions")
        return cleaned_count


# Example implementation for a custom agent framework
class ExampleCustomAgent:
    """Example implementation of a custom agent that works with the generic adapter."""
    
    def __init__(self, name: str):
        self.name = name
        self.tools: Dict[str, Callable] = {}
        self.tool_descriptions: Dict[str, str] = {}
    
    def add_tool(self, name: str, func: Callable, description: str) -> None:
        """Add a tool to the agent."""
        self.tools[name] = func
        self.tool_descriptions[name] = description
    
    def get_name(self) -> str:
        """Get the agent's name."""
        return self.name
    
    def execute_tool(self, tool_name: str, **kwargs) -> Any:
        """Execute a tool by name."""
        if tool_name in self.tools:
            return self.tools[tool_name](**kwargs)
        else:
            raise ValueError(f"Tool '{tool_name}' not found")
    
    def list_tools(self) -> Dict[str, str]:
        """List available tools and their descriptions."""
        return self.tool_descriptions.copy()