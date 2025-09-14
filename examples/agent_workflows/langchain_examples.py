"""
LangChain Agent Workflow Examples for SecureContext Protocol (SCP)

This module demonstrates various agent workflows using LangChain with SCP integration.
Examples include email management, calendar scheduling, and multi-provider data analysis.
"""

import os
from typing import List, Dict, Any
from langchain.agents import initialize_agent, AgentType
from langchain.llms import OpenAI
from langchain.tools import BaseTool
from langchain.schema import AgentAction, AgentFinish
from langchain.callbacks.base import BaseCallbackHandler

from scp_sdk import SCPClient
from scp_sdk.integrations.langchain import SCPTool, SCPChain


class SCPCallbackHandler(BaseCallbackHandler):
    """Custom callback handler for SCP audit logging."""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.scp_client = SCPClient()
    
    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs) -> None:
        """Log when SCP tools are used."""
        if serialized.get("name", "").startswith("scp_"):
            print(f"[SCP AUDIT] Tool {serialized['name']} started for session {self.session_id}")
    
    def on_tool_end(self, output: str, **kwargs) -> None:
        """Log when SCP tools complete."""
        print(f"[SCP AUDIT] Tool completed for session {self.session_id}")


def create_email_management_agent(session_id: str) -> Any:
    """
    Create a LangChain agent for email management tasks.
    
    Args:
        session_id: SCP session ID for authenticated user
        
    Returns:
        Initialized LangChain agent with email management tools
    """
    # Initialize LLM
    llm = OpenAI(temperature=0)
    
    # Create SCP-enabled email tools
    gmail_reader = SCPTool(
        name="scp_gmail_reader",
        description="Read and search Gmail messages. Input should be search query or 'recent' for latest emails.",
        session_id=session_id,
        provider="google",
        data_type="emails"
    )
    
    outlook_reader = SCPTool(
        name="scp_outlook_reader", 
        description="Read and search Outlook emails. Input should be search query or 'recent' for latest emails.",
        session_id=session_id,
        provider="microsoft",
        data_type="emails"
    )
    
    email_sender = SCPTool(
        name="scp_email_sender",
        description="Send emails via Gmail or Outlook. Input should be JSON with 'to', 'subject', 'body', 'provider'.",
        session_id=session_id,
        provider="auto",  # Auto-select based on available tokens
        data_type="send_email"
    )
    
    tools = [gmail_reader, outlook_reader, email_sender]
    
    # Create agent with SCP callback handler
    callback_handler = SCPCallbackHandler(session_id)
    
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        callbacks=[callback_handler],
        verbose=True
    )
    
    return agent


def create_calendar_scheduling_agent(session_id: str) -> Any:
    """
    Create a LangChain agent for calendar management and scheduling.
    
    Args:
        session_id: SCP session ID for authenticated user
        
    Returns:
        Initialized LangChain agent with calendar management tools
    """
    llm = OpenAI(temperature=0)
    
    # Create calendar management tools
    google_calendar = SCPTool(
        name="scp_google_calendar",
        description="Access Google Calendar events. Input: 'list' for upcoming events, 'create' for new events.",
        session_id=session_id,
        provider="google",
        data_type="calendar"
    )
    
    outlook_calendar = SCPTool(
        name="scp_outlook_calendar",
        description="Access Outlook Calendar events. Input: 'list' for upcoming events, 'create' for new events.",
        session_id=session_id,
        provider="microsoft", 
        data_type="calendar"
    )
    
    meeting_scheduler = SCPTool(
        name="scp_meeting_scheduler",
        description="Schedule meetings across providers. Input: JSON with meeting details.",
        session_id=session_id,
        provider="auto",
        data_type="schedule_meeting"
    )
    
    tools = [google_calendar, outlook_calendar, meeting_scheduler]
    
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )
    
    return agent


def create_multi_provider_analysis_agent(session_id: str) -> Any:
    """
    Create an agent that analyzes data across multiple providers.
    
    Args:
        session_id: SCP session ID for authenticated user
        
    Returns:
        Agent capable of cross-provider data analysis
    """
    llm = OpenAI(temperature=0)
    
    # Multi-provider analysis tools
    data_aggregator = SCPTool(
        name="scp_data_aggregator",
        description="Aggregate data from multiple providers. Input: JSON with providers and data types.",
        session_id=session_id,
        provider="multi",
        data_type="aggregate"
    )
    
    cross_platform_search = SCPTool(
        name="scp_cross_search",
        description="Search across Gmail, Outlook, Google Drive, OneDrive. Input: search query.",
        session_id=session_id,
        provider="multi",
        data_type="search"
    )
    
    productivity_analyzer = SCPTool(
        name="scp_productivity_analyzer",
        description="Analyze productivity patterns from emails, calendar, and documents.",
        session_id=session_id,
        provider="multi",
        data_type="analytics"
    )
    
    tools = [data_aggregator, cross_platform_search, productivity_analyzer]
    
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )
    
    return agent


# Example usage and workflow demonstrations
def demo_email_workflow():
    """Demonstrate email management workflow."""
    print("=== Email Management Workflow Demo ===")
    
    # Assume user has completed OAuth and we have session_id
    session_id = "demo_session_123"
    
    # Create email management agent
    agent = create_email_management_agent(session_id)
    
    # Example tasks
    tasks = [
        "Read my 5 most recent emails and summarize them",
        "Search for emails about 'project deadline' from the last week",
        "Send a follow-up email to john@example.com about the meeting tomorrow"
    ]
    
    for task in tasks:
        print(f"\nExecuting task: {task}")
        try:
            result = agent.run(task)
            print(f"Result: {result}")
        except Exception as e:
            print(f"Error: {e}")


def demo_calendar_workflow():
    """Demonstrate calendar scheduling workflow."""
    print("=== Calendar Scheduling Workflow Demo ===")
    
    session_id = "demo_session_456"
    agent = create_calendar_scheduling_agent(session_id)
    
    tasks = [
        "Show me my calendar for today",
        "Find a free 1-hour slot next week for a team meeting",
        "Schedule a meeting with the development team for Friday at 2 PM"
    ]
    
    for task in tasks:
        print(f"\nExecuting task: {task}")
        try:
            result = agent.run(task)
            print(f"Result: {result}")
        except Exception as e:
            print(f"Error: {e}")


def demo_multi_provider_analysis():
    """Demonstrate cross-provider data analysis."""
    print("=== Multi-Provider Analysis Workflow Demo ===")
    
    session_id = "demo_session_789"
    agent = create_multi_provider_analysis_agent(session_id)
    
    tasks = [
        "Analyze my communication patterns across Gmail and Outlook",
        "Find all documents and emails related to 'quarterly review'",
        "Generate a productivity report based on my calendar and email activity"
    ]
    
    for task in tasks:
        print(f"\nExecuting task: {task}")
        try:
            result = agent.run(task)
            print(f"Result: {result}")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    # Run demonstrations
    demo_email_workflow()
    demo_calendar_workflow()
    demo_multi_provider_analysis()