"""
LangChain integration for the SCP SDK.
"""

from typing import Dict, Any, Optional, List, Type
import logging

try:
    from langchain.tools import BaseTool
    from langchain.chains.base import Chain
    from langchain.schema import BaseMessage
    from pydantic import BaseModel, Field
    LANGCHAIN_AVAILABLE = True
except ImportError:
    # Create dummy base classes if LangChain is not available
    class BaseTool:
        pass
    class Chain:
        pass
    class BaseMessage:
        pass
    class BaseModel:
        pass
    def Field(**kwargs):
        return None
    LANGCHAIN_AVAILABLE = False

from ..client import SCPClient
from ..session_manager import SessionManager
from ..data_access import DataAccessClient
from ..exceptions import SCPError


class SCPToolInput(BaseModel):
    """Input schema for SCP tools."""
    session_id: str = Field(description="Session ID for OAuth token retrieval")
    query: Optional[str] = Field(default=None, description="Optional query parameter")
    max_results: Optional[int] = Field(default=10, description="Maximum number of results")


class SCPTool(BaseTool):
    """
    LangChain tool for accessing user data through SCP.
    
    This tool provides a LangChain-compatible interface for accessing
    OAuth-protected user data through the SecureContext Protocol.
    """
    
    name: str = "scp_data_access"
    description: str = "Access user data through SecureContext Protocol OAuth tokens"
    args_schema: Type[BaseModel] = SCPToolInput
    
    def __init__(
        self,
        scp_client: SCPClient,
        data_type: str = "profile",
        session_manager: Optional[SessionManager] = None,
        **kwargs
    ):
        """
        Initialize the SCP tool.
        
        Args:
            scp_client: SCP client instance
            data_type: Type of data to access ('profile', 'emails', 'calendar')
            session_manager: Optional session manager for workflow support
            **kwargs: Additional arguments for BaseTool
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain is required for SCPTool. Install with: pip install langchain")
        
        super().__init__(**kwargs)
        self.scp_client = scp_client
        self.data_type = data_type
        self.session_manager = session_manager
        self.data_client = DataAccessClient(scp_client)
        self.logger = logging.getLogger(__name__)
        
        # Update tool name and description based on data type
        self.name = f"scp_{data_type}_access"
        self.description = f"Access user {data_type} data through SecureContext Protocol"
    
    def _run(
        self,
        session_id: str,
        query: Optional[str] = None,
        max_results: Optional[int] = 10,
        **kwargs
    ) -> str:
        """
        Execute the tool to retrieve user data.
        
        Args:
            session_id: Session ID for token retrieval
            query: Optional query parameter
            max_results: Maximum number of results
            
        Returns:
            Formatted string with user data
        """
        try:
            self.logger.info(f"Accessing {self.data_type} data for session {session_id}")
            
            # Update session manager if available
            if self.session_manager:
                session_info = self.session_manager.get_session(session_id)
                if session_info:
                    session_info.touch()
            
            # Retrieve data based on type
            if self.data_type == "profile":
                data = self.data_client.get_user_profile(session_id)
                return self._format_profile_data(data)
            elif self.data_type == "emails":
                data = self.data_client.get_emails(session_id, max_results, query)
                return self._format_email_data(data)
            elif self.data_type == "calendar":
                data = self.data_client.get_calendar_events(session_id, max_results)
                return self._format_calendar_data(data)
            else:
                return f"Unsupported data type: {self.data_type}"
        
        except SCPError as e:
            error_msg = f"SCP error accessing {self.data_type}: {e.message}"
            self.logger.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Unexpected error accessing {self.data_type}: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return error_msg
    
    async def _arun(self, *args, **kwargs) -> str:
        """Async version of _run (not implemented)."""
        raise NotImplementedError("SCPTool does not support async execution")
    
    def _format_profile_data(self, data: Dict[str, Any]) -> str:
        """Format user profile data for display."""
        name = data.get('name', data.get('displayName', 'Unknown'))
        email = data.get('email', data.get('mail', data.get('userPrincipalName', 'Unknown')))
        return f"User Profile:\nName: {name}\nEmail: {email}"
    
    def _format_email_data(self, data: List[Dict[str, Any]]) -> str:
        """Format email data for display."""
        if not data:
            return "No emails found"
        
        formatted = f"Found {len(data)} emails:\n"
        for i, email in enumerate(data[:5], 1):  # Show first 5
            subject = email.get('subject', 'No Subject')
            sender = email.get('from', {}).get('emailAddress', {}).get('address', 'Unknown')
            formatted += f"{i}. {subject} (from: {sender})\n"
        
        if len(data) > 5:
            formatted += f"... and {len(data) - 5} more emails"
        
        return formatted
    
    def _format_calendar_data(self, data: List[Dict[str, Any]]) -> str:
        """Format calendar data for display."""
        if not data:
            return "No calendar events found"
        
        formatted = f"Found {len(data)} calendar events:\n"
        for i, event in enumerate(data[:5], 1):  # Show first 5
            summary = event.get('summary', event.get('subject', 'No Title'))
            start_time = event.get('start', {}).get('dateTime', 'Unknown time')
            formatted += f"{i}. {summary} (starts: {start_time})\n"
        
        if len(data) > 5:
            formatted += f"... and {len(data) - 5} more events"
        
        return formatted


class SCPChain(Chain):
    """
    LangChain chain for multi-step SCP operations.
    
    This chain orchestrates multiple SCP operations in sequence,
    maintaining session context across steps.
    """
    
    def __init__(
        self,
        scp_client: SCPClient,
        session_manager: SessionManager,
        operations: List[str],
        **kwargs
    ):
        """
        Initialize the SCP chain.
        
        Args:
            scp_client: SCP client instance
            session_manager: Session manager for workflow support
            operations: List of operations to perform in sequence
            **kwargs: Additional arguments for Chain
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain is required for SCPChain. Install with: pip install langchain")
        
        super().__init__(**kwargs)
        self.scp_client = scp_client
        self.session_manager = session_manager
        self.operations = operations
        self.data_client = DataAccessClient(scp_client)
        self.logger = logging.getLogger(__name__)
    
    @property
    def input_keys(self) -> List[str]:
        """Input keys for the chain."""
        return ["session_id", "workflow_id"]
    
    @property
    def output_keys(self) -> List[str]:
        """Output keys for the chain."""
        return ["results", "summary"]
    
    def _call(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the chain operations.
        
        Args:
            inputs: Input dictionary with session_id and workflow_id
            
        Returns:
            Dictionary with operation results and summary
        """
        session_id = inputs.get("session_id")
        workflow_id = inputs.get("workflow_id")
        
        if not session_id:
            return {"results": [], "summary": "Error: session_id is required"}
        
        results = []
        
        try:
            # Update session with workflow context
            if workflow_id and self.session_manager:
                session_info = self.session_manager.get_session(session_id)
                if session_info:
                    session_info.workflow_id = workflow_id
                    session_info.touch()
            
            # Execute operations in sequence
            for operation in self.operations:
                self.logger.info(f"Executing operation: {operation}")
                
                if operation == "profile":
                    data = self.data_client.get_user_profile(session_id)
                    results.append({"operation": operation, "data": data, "success": True})
                elif operation == "emails":
                    data = self.data_client.get_emails(session_id, max_results=5)
                    results.append({"operation": operation, "data": data, "success": True})
                elif operation == "calendar":
                    data = self.data_client.get_calendar_events(session_id, max_results=5)
                    results.append({"operation": operation, "data": data, "success": True})
                else:
                    results.append({
                        "operation": operation,
                        "error": f"Unknown operation: {operation}",
                        "success": False
                    })
            
            # Generate summary
            successful_ops = [r for r in results if r.get("success")]
            failed_ops = [r for r in results if not r.get("success")]
            
            summary = f"Completed {len(successful_ops)}/{len(self.operations)} operations successfully"
            if failed_ops:
                summary += f". {len(failed_ops)} operations failed."
            
            return {"results": results, "summary": summary}
        
        except SCPError as e:
            error_msg = f"SCP error in chain execution: {e.message}"
            self.logger.error(error_msg)
            return {"results": results, "summary": error_msg}
        except Exception as e:
            error_msg = f"Unexpected error in chain execution: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return {"results": results, "summary": error_msg}