"""
AutoGen integration for the SCP SDK.
"""

from typing import Dict, Any, Optional, List, Callable
import logging

try:
    from autogen import ConversableAgent
    AUTOGEN_AVAILABLE = True
except ImportError:
    # Create dummy base class if AutoGen is not available
    class ConversableAgent:
        pass
    AUTOGEN_AVAILABLE = False

from ..client import SCPClient
from ..session_manager import SessionManager
from ..data_access import DataAccessClient
from ..exceptions import SCPError


class SCPAutoGenTool:
    """
    AutoGen tool for accessing user data through SCP.
    
    This tool provides AutoGen-compatible functions for accessing
    OAuth-protected user data in conversational agent workflows.
    """
    
    def __init__(
        self,
        scp_client: SCPClient,
        session_manager: Optional[SessionManager] = None,
        conversation_id: Optional[str] = None
    ):
        """
        Initialize the SCP AutoGen tool.
        
        Args:
            scp_client: SCP client instance
            session_manager: Optional session manager for workflow support
            conversation_id: Optional conversation identifier for session tracking
        """
        if not AUTOGEN_AVAILABLE:
            raise ImportError("AutoGen is required for SCPAutoGenTool. Install with: pip install pyautogen")
        
        self.scp_client = scp_client
        self.session_manager = session_manager
        self.conversation_id = conversation_id
        self.data_client = DataAccessClient(scp_client)
        self.logger = logging.getLogger(__name__)
    
    def get_user_profile_function(self) -> Callable:
        """
        Get AutoGen function for user profile access.
        
        Returns:
            Function that can be registered with AutoGen agents
        """
        def get_user_profile(session_id: str, agent_name: Optional[str] = None) -> str:
            """
            Get user profile information through SCP.
            
            Args:
                session_id: Session ID for token retrieval
                agent_name: Optional name of the calling agent
                
            Returns:
                Formatted user profile information
            """
            try:
                self.logger.info(
                    f"AutoGen agent '{agent_name}' accessing profile for session {session_id} "
                    f"(conversation: {self.conversation_id})"
                )
                
                # Update session context
                if self.session_manager:
                    session_info = self.session_manager.get_session(session_id)
                    if session_info:
                        if not session_info.workflow_id and self.conversation_id:
                            session_info.workflow_id = self.conversation_id
                        if not session_info.agent_id and agent_name:
                            session_info.agent_id = agent_name
                        session_info.touch()
                
                data = self.data_client.get_user_profile(session_id)
                name = data.get('name', data.get('displayName', 'Unknown User'))
                email = data.get('email', data.get('mail', data.get('userPrincipalName', 'Unknown Email')))
                
                return f"User Profile Retrieved:\nName: {name}\nEmail: {email}\n[Profile data available for conversation]"
            
            except SCPError as e:
                error_msg = f"Failed to retrieve user profile: {e.message}"
                self.logger.error(error_msg)
                return f"Error: {error_msg}"
            except Exception as e:
                error_msg = f"Unexpected error retrieving profile: {str(e)}"
                self.logger.error(error_msg, exc_info=True)
                return f"Error: {error_msg}"
        
        # Add function metadata for AutoGen
        get_user_profile.__name__ = "get_user_profile"
        get_user_profile.__doc__ = "Retrieve user profile information through SecureContext Protocol"
        
        return get_user_profile
    
    def get_emails_function(self) -> Callable:
        """
        Get AutoGen function for email access.
        
        Returns:
            Function that can be registered with AutoGen agents
        """
        def get_emails(
            session_id: str,
            query: Optional[str] = None,
            max_results: int = 5,
            agent_name: Optional[str] = None
        ) -> str:
            """
            Get email messages through SCP.
            
            Args:
                session_id: Session ID for token retrieval
                query: Optional search query for emails
                max_results: Maximum number of emails to retrieve
                agent_name: Optional name of the calling agent
                
            Returns:
                Formatted email information
            """
            try:
                self.logger.info(
                    f"AutoGen agent '{agent_name}' accessing emails for session {session_id} "
                    f"(conversation: {self.conversation_id}, query: {query})"
                )
                
                # Update session context
                if self.session_manager:
                    session_info = self.session_manager.get_session(session_id)
                    if session_info:
                        if not session_info.workflow_id and self.conversation_id:
                            session_info.workflow_id = self.conversation_id
                        if not session_info.agent_id and agent_name:
                            session_info.agent_id = agent_name
                        session_info.touch()
                
                data = self.data_client.get_emails(session_id, max_results, query)
                
                if not data:
                    query_info = f" matching '{query}'" if query else ""
                    return f"No emails found{query_info}. The user's mailbox may be empty or the query too specific."
                
                formatted = f"Retrieved {len(data)} emails"
                if query:
                    formatted += f" matching '{query}'"
                formatted += ":\n\n"
                
                for i, email in enumerate(data, 1):
                    subject = email.get('subject', 'No Subject')
                    sender = email.get('from', {}).get('emailAddress', {}).get('address', 'Unknown Sender')
                    formatted += f"{i}. {subject}\n   From: {sender}\n\n"
                
                formatted += "[Email data available for conversation analysis]"
                return formatted
            
            except SCPError as e:
                error_msg = f"Failed to retrieve emails: {e.message}"
                self.logger.error(error_msg)
                return f"Error: {error_msg}"
            except Exception as e:
                error_msg = f"Unexpected error retrieving emails: {str(e)}"
                self.logger.error(error_msg, exc_info=True)
                return f"Error: {error_msg}"
        
        # Add function metadata for AutoGen
        get_emails.__name__ = "get_emails"
        get_emails.__doc__ = "Retrieve email messages through SecureContext Protocol"
        
        return get_emails
    
    def get_calendar_function(self) -> Callable:
        """
        Get AutoGen function for calendar access.
        
        Returns:
            Function that can be registered with AutoGen agents
        """
        def get_calendar_events(
            session_id: str,
            max_results: int = 5,
            agent_name: Optional[str] = None
        ) -> str:
            """
            Get calendar events through SCP.
            
            Args:
                session_id: Session ID for token retrieval
                max_results: Maximum number of events to retrieve
                agent_name: Optional name of the calling agent
                
            Returns:
                Formatted calendar information
            """
            try:
                self.logger.info(
                    f"AutoGen agent '{agent_name}' accessing calendar for session {session_id} "
                    f"(conversation: {self.conversation_id})"
                )
                
                # Update session context
                if self.session_manager:
                    session_info = self.session_manager.get_session(session_id)
                    if session_info:
                        if not session_info.workflow_id and self.conversation_id:
                            session_info.workflow_id = self.conversation_id
                        if not session_info.agent_id and agent_name:
                            session_info.agent_id = agent_name
                        session_info.touch()
                
                data = self.data_client.get_calendar_events(session_id, max_results)
                
                if not data:
                    return "No upcoming calendar events found. The user's calendar may be empty or all events are in the past."
                
                formatted = f"Retrieved {len(data)} upcoming calendar events:\n\n"
                
                for i, event in enumerate(data, 1):
                    summary = event.get('summary', event.get('subject', 'No Title'))
                    start_time = event.get('start', {}).get('dateTime', 'Unknown Time')
                    location = event.get('location', 'No Location')
                    
                    formatted += f"{i}. {summary}\n"
                    formatted += f"   Start: {start_time}\n"
                    if location != 'No Location':
                        formatted += f"   Location: {location}\n"
                    formatted += "\n"
                
                formatted += "[Calendar data available for conversation scheduling]"
                return formatted
            
            except SCPError as e:
                error_msg = f"Failed to retrieve calendar events: {e.message}"
                self.logger.error(error_msg)
                return f"Error: {error_msg}"
            except Exception as e:
                error_msg = f"Unexpected error retrieving calendar: {str(e)}"
                self.logger.error(error_msg, exc_info=True)
                return f"Error: {error_msg}"
        
        # Add function metadata for AutoGen
        get_calendar_events.__name__ = "get_calendar_events"
        get_calendar_events.__doc__ = "Retrieve calendar events through SecureContext Protocol"
        
        return get_calendar_events
    
    def register_functions_with_agent(
        self,
        agent: ConversableAgent,
        functions: Optional[List[str]] = None
    ) -> None:
        """
        Register SCP functions with an AutoGen agent.
        
        Args:
            agent: AutoGen ConversableAgent instance
            functions: List of function names to register (default: all)
        """
        if functions is None:
            functions = ["profile", "emails", "calendar"]
        
        function_map = {
            "profile": self.get_user_profile_function(),
            "emails": self.get_emails_function(),
            "calendar": self.get_calendar_function()
        }
        
        registered_count = 0
        for func_name in functions:
            if func_name in function_map:
                func = function_map[func_name]
                agent.register_function(
                    function_map={func.__name__: func}
                )
                registered_count += 1
                self.logger.info(f"Registered {func.__name__} with agent {agent.name}")
        
        self.logger.info(f"Registered {registered_count} SCP functions with AutoGen agent {agent.name}")


class SCPConversationManager:
    """
    Manager for AutoGen conversations with SCP integration.
    
    This class helps coordinate AutoGen conversations that need access
    to user data through SCP with proper session management.
    """
    
    def __init__(
        self,
        scp_client: SCPClient,
        session_manager: SessionManager,
        conversation_id: str
    ):
        """
        Initialize the AutoGen conversation manager.
        
        Args:
            scp_client: SCP client instance
            session_manager: Session manager for workflow support
            conversation_id: Unique identifier for the conversation
        """
        self.scp_client = scp_client
        self.session_manager = session_manager
        self.conversation_id = conversation_id
        self.logger = logging.getLogger(__name__)
        
        # Track agents and their sessions
        self.agent_sessions: Dict[str, str] = {}
        self.scp_tool = SCPAutoGenTool(
            scp_client=scp_client,
            session_manager=session_manager,
            conversation_id=conversation_id
        )
    
    def setup_agent_with_scp(
        self,
        agent: ConversableAgent,
        session_id: str,
        functions: Optional[List[str]] = None
    ) -> None:
        """
        Set up an AutoGen agent with SCP capabilities.
        
        Args:
            agent: AutoGen ConversableAgent instance
            session_id: Session ID for the agent's data access
            functions: List of SCP functions to enable (default: all)
        """
        # Register session for the agent
        self.agent_sessions[agent.name] = session_id
        
        # Update session manager with conversation context
        session_info = self.session_manager.get_session(session_id)
        if session_info:
            session_info.workflow_id = self.conversation_id
            session_info.agent_id = agent.name
            session_info.touch()
        
        # Register SCP functions with the agent
        self.scp_tool.register_functions_with_agent(agent, functions)
        
        self.logger.info(
            f"Set up AutoGen agent {agent.name} with SCP capabilities "
            f"(session: {session_id}, conversation: {self.conversation_id})"
        )
    
    def get_conversation_summary(self) -> Dict[str, Any]:
        """
        Get summary of the conversation state.
        
        Returns:
            Dictionary with conversation statistics and status
        """
        active_sessions = 0
        expired_sessions = 0
        
        for agent_name, session_id in self.agent_sessions.items():
            session_info = self.session_manager.get_session(session_id)
            if session_info:
                if session_info.is_expired:
                    expired_sessions += 1
                else:
                    active_sessions += 1
        
        return {
            'conversation_id': self.conversation_id,
            'total_agents': len(self.agent_sessions),
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'agent_sessions': self.agent_sessions
        }