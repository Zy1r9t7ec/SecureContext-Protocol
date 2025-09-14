"""
CrewAI integration for the SCP SDK.
"""

from typing import Dict, Any, Optional, List
import logging

try:
    from crewai_tools import BaseTool
    CREWAI_AVAILABLE = True
except ImportError:
    # Create dummy base class if CrewAI is not available
    class BaseTool:
        pass
    CREWAI_AVAILABLE = False

from ..client import SCPClient
from ..session_manager import SessionManager
from ..data_access import DataAccessClient
from ..exceptions import SCPError


class SCPCrewTool(BaseTool):
    """
    CrewAI tool for accessing user data through SCP.
    
    This tool provides a CrewAI-compatible interface for accessing
    OAuth-protected user data in multi-agent workflows.
    """
    
    name: str = "SCP Data Access"
    description: str = "Access user data through SecureContext Protocol OAuth tokens"
    
    def __init__(
        self,
        scp_client: SCPClient,
        data_type: str = "profile",
        session_manager: Optional[SessionManager] = None,
        crew_id: Optional[str] = None
    ):
        """
        Initialize the SCP CrewAI tool.
        
        Args:
            scp_client: SCP client instance
            data_type: Type of data to access ('profile', 'emails', 'calendar')
            session_manager: Optional session manager for workflow support
            crew_id: Optional crew identifier for session tracking
        """
        if not CREWAI_AVAILABLE:
            raise ImportError("CrewAI is required for SCPCrewTool. Install with: pip install crewai")
        
        super().__init__()
        self.scp_client = scp_client
        self.data_type = data_type
        self.session_manager = session_manager
        self.crew_id = crew_id
        self.data_client = DataAccessClient(scp_client)
        self.logger = logging.getLogger(__name__)
        
        # Update tool name and description based on data type
        self.name = f"SCP {data_type.title()} Access"
        self.description = f"Access user {data_type} data through SecureContext Protocol for crew workflows"
    
    def _run(
        self,
        session_id: str,
        query: Optional[str] = None,
        max_results: int = 10,
        agent_id: Optional[str] = None
    ) -> str:
        """
        Execute the tool to retrieve user data for CrewAI workflows.
        
        Args:
            session_id: Session ID for token retrieval
            query: Optional query parameter
            max_results: Maximum number of results
            agent_id: Optional agent identifier within the crew
            
        Returns:
            Formatted string with user data for crew consumption
        """
        try:
            self.logger.info(
                f"CrewAI tool accessing {self.data_type} data for session {session_id} "
                f"(crew: {self.crew_id}, agent: {agent_id})"
            )
            
            # Update session manager with crew context
            if self.session_manager:
                session_info = self.session_manager.get_session(session_id)
                if session_info:
                    if not session_info.workflow_id and self.crew_id:
                        session_info.workflow_id = self.crew_id
                    if not session_info.agent_id and agent_id:
                        session_info.agent_id = agent_id
                    session_info.touch()
            
            # Retrieve data based on type
            if self.data_type == "profile":
                data = self.data_client.get_user_profile(session_id)
                return self._format_profile_for_crew(data)
            elif self.data_type == "emails":
                data = self.data_client.get_emails(session_id, max_results, query)
                return self._format_emails_for_crew(data, query)
            elif self.data_type == "calendar":
                data = self.data_client.get_calendar_events(session_id, max_results)
                return self._format_calendar_for_crew(data)
            else:
                return f"Error: Unsupported data type '{self.data_type}' for crew workflow"
        
        except SCPError as e:
            error_msg = f"SCP error in crew workflow: {e.message}"
            self.logger.error(error_msg)
            return f"Error accessing {self.data_type}: {error_msg}"
        except Exception as e:
            error_msg = f"Unexpected error in crew workflow: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return f"Error accessing {self.data_type}: {error_msg}"
    
    def _format_profile_for_crew(self, data: Dict[str, Any]) -> str:
        """Format user profile data for crew consumption."""
        name = data.get('name', data.get('displayName', 'Unknown User'))
        email = data.get('email', data.get('mail', data.get('userPrincipalName', 'Unknown Email')))
        
        # Provide structured data for crew agents
        return (
            f"USER PROFILE DATA:\n"
            f"Name: {name}\n"
            f"Email: {email}\n"
            f"Status: Profile data retrieved successfully\n"
            f"Available for crew workflow processing"
        )
    
    def _format_emails_for_crew(self, data: List[Dict[str, Any]], query: Optional[str]) -> str:
        """Format email data for crew consumption."""
        if not data:
            query_info = f" matching '{query}'" if query else ""
            return f"EMAIL DATA: No emails found{query_info}. Crew can proceed with alternative workflow."
        
        formatted = f"EMAIL DATA: Retrieved {len(data)} emails"
        if query:
            formatted += f" matching '{query}'"
        formatted += "\n\nEMAIL SUMMARY:\n"
        
        for i, email in enumerate(data[:3], 1):  # Show top 3 for crew processing
            subject = email.get('subject', 'No Subject')
            sender = email.get('from', {}).get('emailAddress', {}).get('address', 'Unknown Sender')
            formatted += f"{i}. Subject: {subject}\n   From: {sender}\n"
        
        if len(data) > 3:
            formatted += f"\nAdditional {len(data) - 3} emails available for detailed processing."
        
        formatted += "\n\nStatus: Email data ready for crew workflow analysis"
        return formatted
    
    def _format_calendar_for_crew(self, data: List[Dict[str, Any]]) -> str:
        """Format calendar data for crew consumption."""
        if not data:
            return "CALENDAR DATA: No upcoming events found. Crew can proceed with scheduling workflow."
        
        formatted = f"CALENDAR DATA: Retrieved {len(data)} upcoming events\n\nEVENT SUMMARY:\n"
        
        for i, event in enumerate(data[:3], 1):  # Show top 3 for crew processing
            summary = event.get('summary', event.get('subject', 'No Title'))
            start_time = event.get('start', {}).get('dateTime', 'Unknown Time')
            formatted += f"{i}. Event: {summary}\n   Start: {start_time}\n"
        
        if len(data) > 3:
            formatted += f"\nAdditional {len(data) - 3} events available for detailed scheduling analysis."
        
        formatted += "\n\nStatus: Calendar data ready for crew workflow scheduling"
        return formatted


class SCPCrewWorkflow:
    """
    Workflow orchestrator for CrewAI multi-agent SCP operations.
    
    This class helps coordinate multiple crew agents accessing user data
    through SCP with proper session management and context sharing.
    """
    
    def __init__(
        self,
        scp_client: SCPClient,
        session_manager: SessionManager,
        crew_id: str
    ):
        """
        Initialize the CrewAI workflow orchestrator.
        
        Args:
            scp_client: SCP client instance
            session_manager: Session manager for workflow support
            crew_id: Unique identifier for the crew workflow
        """
        self.scp_client = scp_client
        self.session_manager = session_manager
        self.crew_id = crew_id
        self.logger = logging.getLogger(__name__)
        
        # Track crew agents and their sessions
        self.agent_sessions: Dict[str, str] = {}
        self.workflow_context: Dict[str, Any] = {}
    
    def register_agent_session(self, agent_id: str, session_id: str) -> None:
        """
        Register a session for a specific crew agent.
        
        Args:
            agent_id: Unique identifier for the crew agent
            session_id: Session ID for the agent's data access
        """
        self.agent_sessions[agent_id] = session_id
        
        # Update session manager with crew context
        session_info = self.session_manager.get_session(session_id)
        if session_info:
            session_info.workflow_id = self.crew_id
            session_info.agent_id = agent_id
            session_info.touch()
        
        self.logger.info(f"Registered agent {agent_id} with session {session_id} for crew {self.crew_id}")
    
    def create_crew_tools(self, data_types: List[str]) -> List[SCPCrewTool]:
        """
        Create SCP tools for crew agents.
        
        Args:
            data_types: List of data types to create tools for
            
        Returns:
            List of configured SCPCrewTool instances
        """
        tools = []
        for data_type in data_types:
            tool = SCPCrewTool(
                scp_client=self.scp_client,
                data_type=data_type,
                session_manager=self.session_manager,
                crew_id=self.crew_id
            )
            tools.append(tool)
        
        self.logger.info(f"Created {len(tools)} SCP tools for crew {self.crew_id}")
        return tools
    
    def get_workflow_summary(self) -> Dict[str, Any]:
        """
        Get summary of the crew workflow state.
        
        Returns:
            Dictionary with workflow statistics and status
        """
        active_sessions = 0
        expired_sessions = 0
        
        for agent_id, session_id in self.agent_sessions.items():
            session_info = self.session_manager.get_session(session_id)
            if session_info:
                if session_info.is_expired:
                    expired_sessions += 1
                else:
                    active_sessions += 1
        
        return {
            'crew_id': self.crew_id,
            'total_agents': len(self.agent_sessions),
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'workflow_context': self.workflow_context
        }
    
    def cleanup_crew_sessions(self) -> int:
        """
        Clean up all sessions for this crew workflow.
        
        Returns:
            Number of sessions cleaned up
        """
        cleaned_count = 0
        for agent_id, session_id in self.agent_sessions.items():
            if self.session_manager.remove_session(session_id):
                cleaned_count += 1
        
        self.agent_sessions.clear()
        self.logger.info(f"Cleaned up {cleaned_count} sessions for crew {self.crew_id}")
        return cleaned_count