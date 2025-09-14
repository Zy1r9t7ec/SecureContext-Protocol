"""
AutoGen Agent Workflow Examples for SecureContext Protocol (SCP)

This module demonstrates conversational multi-agent workflows using Microsoft AutoGen
with SCP integration for secure data access across OAuth providers.
"""

import asyncio
from typing import List, Dict, Any, Optional
import autogen
from autogen import AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager

from scp_sdk import SCPClient
from scp_sdk.integrations.autogen import SCPAutoGenTool, SCPFunctionCall


class SCPAssistantAgent(AssistantAgent):
    """Enhanced AssistantAgent with SCP integration capabilities."""
    
    def __init__(self, name: str, session_id: str, providers: List[str], **kwargs):
        super().__init__(name=name, **kwargs)
        self.session_id = session_id
        self.providers = providers
        self.scp_client = SCPClient()
        
        # Register SCP function calls
        self._register_scp_functions()
    
    def _register_scp_functions(self):
        """Register SCP-enabled function calls for this agent."""
        scp_functions = [
            {
                "name": "read_emails",
                "description": "Read emails from connected providers",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": self.providers},
                        "query": {"type": "string", "description": "Search query or 'recent'"},
                        "limit": {"type": "integer", "default": 10}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "read_calendar",
                "description": "Read calendar events from connected providers",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": self.providers},
                        "days_ahead": {"type": "integer", "default": 7}
                    }
                }
            },
            {
                "name": "send_email",
                "description": "Send email via connected providers",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": self.providers},
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"}
                    },
                    "required": ["to", "subject", "body"]
                }
            },
            {
                "name": "schedule_meeting",
                "description": "Schedule a meeting via connected calendar providers",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": self.providers},
                        "title": {"type": "string"},
                        "start_time": {"type": "string"},
                        "duration_minutes": {"type": "integer", "default": 60},
                        "attendees": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["title", "start_time"]
                }
            }
        ]
        
        # Register functions with AutoGen
        for func in scp_functions:
            self.register_function(
                function_map={func["name"]: self._create_scp_function(func["name"])},
                function_schema=func
            )
    
    def _create_scp_function(self, function_name: str):
        """Create SCP function wrapper for AutoGen."""
        def scp_function(**kwargs):
            try:
                return SCPFunctionCall.execute(
                    function_name=function_name,
                    session_id=self.session_id,
                    **kwargs
                )
            except Exception as e:
                return f"Error executing {function_name}: {str(e)}"
        
        return scp_function


def create_email_management_agents(session_id: str) -> tuple:
    """
    Create AutoGen agents for email management workflow.
    
    Args:
        session_id: SCP session ID for authenticated user
        
    Returns:
        Tuple of (user_proxy, email_assistant, email_analyzer)
    """
    # Configuration for LLM
    llm_config = {
        "config_list": [
            {
                "model": "gpt-4",
                "api_key": "your-openai-api-key"
            }
        ],
        "temperature": 0.1
    }
    
    # User proxy agent
    user_proxy = UserProxyAgent(
        name="User",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=3,
        is_termination_msg=lambda x: x.get("content", "").rstrip().endswith("TERMINATE"),
        code_execution_config={"work_dir": "autogen_workspace"},
        llm_config=llm_config
    )
    
    # Email assistant agent with SCP integration
    email_assistant = SCPAssistantAgent(
        name="EmailAssistant",
        session_id=session_id,
        providers=["google", "microsoft"],
        system_message="""You are an email management assistant with access to Gmail and Outlook accounts.
        You can read emails, categorize them, and send responses. Always use the available SCP functions
        to access email data securely. When asked to process emails, first read them, then provide
        analysis and suggestions.""",
        llm_config=llm_config
    )
    
    # Email analyzer agent
    email_analyzer = SCPAssistantAgent(
        name="EmailAnalyzer",
        session_id=session_id,
        providers=["google", "microsoft"],
        system_message="""You are an email analysis specialist. You excel at categorizing emails,
        identifying important patterns, and extracting actionable insights. Use SCP functions to
        access email data and provide detailed analysis reports.""",
        llm_config=llm_config
    )
    
    return user_proxy, email_assistant, email_analyzer


def create_calendar_coordination_agents(session_id: str) -> tuple:
    """
    Create AutoGen agents for calendar coordination workflow.
    
    Args:
        session_id: SCP session ID for authenticated user
        
    Returns:
        Tuple of (user_proxy, calendar_manager, meeting_coordinator)
    """
    llm_config = {
        "config_list": [
            {
                "model": "gpt-4",
                "api_key": "your-openai-api-key"
            }
        ],
        "temperature": 0.1
    }
    
    user_proxy = UserProxyAgent(
        name="User",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=3,
        is_termination_msg=lambda x: x.get("content", "").rstrip().endswith("TERMINATE"),
        llm_config=llm_config
    )
    
    calendar_manager = SCPAssistantAgent(
        name="CalendarManager",
        session_id=session_id,
        providers=["google", "microsoft"],
        system_message="""You are a calendar management expert with access to Google Calendar and Outlook.
        You can read calendar events, find available time slots, and schedule meetings. Always use SCP
        functions to access calendar data securely.""",
        llm_config=llm_config
    )
    
    meeting_coordinator = SCPAssistantAgent(
        name="MeetingCoordinator",
        session_id=session_id,
        providers=["google", "microsoft"],
        system_message="""You are a meeting coordination specialist. You excel at scheduling complex
        meetings, managing attendee availability, and sending appropriate invitations. Work with the
        CalendarManager to optimize meeting scheduling.""",
        llm_config=llm_config
    )
    
    return user_proxy, calendar_manager, meeting_coordinator


def demo_email_processing_conversation():
    """Demonstrate email processing through conversational agents."""
    print("=== AutoGen Email Processing Conversation Demo ===")
    
    session_id = "autogen_demo_123"
    user_proxy, email_assistant, email_analyzer = create_email_management_agents(session_id)
    
    # Create group chat for collaborative email processing
    groupchat = GroupChat(
        agents=[user_proxy, email_assistant, email_analyzer],
        messages=[],
        max_round=10
    )
    
    manager = GroupChatManager(groupchat=groupchat, llm_config={
        "config_list": [{"model": "gpt-4", "api_key": "your-openai-api-key"}],
        "temperature": 0.1
    })
    
    # Start conversation
    initial_message = """
    I need help managing my emails. Please:
    1. Read my recent emails from both Gmail and Outlook
    2. Categorize them by importance and topic
    3. Draft responses for the most important ones
    4. Provide a summary of action items
    """
    
    try:
        user_proxy.initiate_chat(manager, message=initial_message)
    except Exception as e:
        print(f"Error in email processing conversation: {e}")


def demo_calendar_coordination_conversation():
    """Demonstrate calendar coordination through conversational agents."""
    print("=== AutoGen Calendar Coordination Conversation Demo ===")
    
    session_id = "autogen_demo_456"
    user_proxy, calendar_manager, meeting_coordinator = create_calendar_coordination_agents(session_id)
    
    # Create group chat for calendar coordination
    groupchat = GroupChat(
        agents=[user_proxy, calendar_manager, meeting_coordinator],
        messages=[],
        max_round=8
    )
    
    manager = GroupChatManager(groupchat=groupchat, llm_config={
        "config_list": [{"model": "gpt-4", "api_key": "your-openai-api-key"}],
        "temperature": 0.1
    })
    
    # Start conversation
    initial_message = """
    I need to coordinate several meetings next week. Please:
    1. Check my availability across Google Calendar and Outlook
    2. Find optimal time slots for a 2-hour team meeting with 5 people
    3. Schedule a 1-hour client call for Thursday afternoon
    4. Send appropriate invitations to all participants
    """
    
    try:
        user_proxy.initiate_chat(manager, message=initial_message)
    except Exception as e:
        print(f"Error in calendar coordination conversation: {e}")


def demo_multi_agent_research_workflow():
    """Demonstrate complex research workflow with multiple specialized agents."""
    print("=== AutoGen Multi-Agent Research Workflow Demo ===")
    
    session_id = "autogen_research_789"
    
    # Configuration
    llm_config = {
        "config_list": [
            {
                "model": "gpt-4",
                "api_key": "your-openai-api-key"
            }
        ],
        "temperature": 0.1
    }
    
    # Create specialized research agents
    user_proxy = UserProxyAgent(
        name="ResearchCoordinator",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=2,
        is_termination_msg=lambda x: x.get("content", "").rstrip().endswith("TERMINATE"),
        llm_config=llm_config
    )
    
    data_collector = SCPAssistantAgent(
        name="DataCollector",
        session_id=session_id,
        providers=["google", "microsoft"],
        system_message="""You are a data collection specialist. Your job is to gather relevant
        information from emails, calendar events, and documents. You excel at finding patterns
        and extracting key data points from various sources.""",
        llm_config=llm_config
    )
    
    pattern_analyzer = SCPAssistantAgent(
        name="PatternAnalyzer",
        session_id=session_id,
        providers=["google", "microsoft"],
        system_message="""You are a pattern analysis expert. You analyze data collected by the
        DataCollector to identify trends, correlations, and insights. You provide structured
        analysis and recommendations based on the data.""",
        llm_config=llm_config
    )
    
    report_writer = SCPAssistantAgent(
        name="ReportWriter",
        session_id=session_id,
        providers=["google", "microsoft"],
        system_message="""You are a report writing specialist. You take analysis from the
        PatternAnalyzer and create comprehensive, well-structured reports. You can also
        send these reports via email to relevant stakeholders.""",
        llm_config=llm_config
    )
    
    # Create group chat for research workflow
    groupchat = GroupChat(
        agents=[user_proxy, data_collector, pattern_analyzer, report_writer],
        messages=[],
        max_round=12
    )
    
    manager = GroupChatManager(groupchat=groupchat, llm_config=llm_config)
    
    # Start research workflow
    research_request = """
    I need a comprehensive analysis of my work patterns and productivity. Please:
    1. Collect data from my emails and calendar for the past month
    2. Analyze communication patterns, meeting frequency, and time allocation
    3. Identify productivity trends and potential improvements
    4. Create a detailed report with recommendations
    5. Email the report to my manager at manager@company.com
    """
    
    try:
        user_proxy.initiate_chat(manager, message=research_request)
    except Exception as e:
        print(f"Error in research workflow: {e}")


async def demo_async_multi_user_processing():
    """Demonstrate asynchronous processing for multiple users."""
    print("=== AutoGen Async Multi-User Processing Demo ===")
    
    session_ids = ["user1_session", "user2_session", "user3_session"]
    
    async def process_user_emails(session_id: str):
        """Process emails for a single user asynchronously."""
        user_proxy, email_assistant, _ = create_email_management_agents(session_id)
        
        try:
            # Simulate async email processing
            result = await asyncio.to_thread(
                user_proxy.initiate_chat,
                email_assistant,
                message="Please read and summarize my recent emails."
            )
            return f"Processed emails for {session_id}: {result}"
        except Exception as e:
            return f"Error processing {session_id}: {e}"
    
    # Process multiple users concurrently
    tasks = [process_user_emails(session_id) for session_id in session_ids]
    results = await asyncio.gather(*tasks)
    
    for result in results:
        print(result)


# Performance optimization examples
def create_optimized_agent_config():
    """Create optimized configuration for high-throughput scenarios."""
    return {
        "config_list": [
            {
                "model": "gpt-3.5-turbo",  # Faster model for high throughput
                "api_key": "your-openai-api-key"
            }
        ],
        "temperature": 0,  # Deterministic responses
        "timeout": 30,  # Shorter timeout for faster processing
        "max_tokens": 1000,  # Limit response length
        "cache_seed": 42  # Enable caching for repeated queries
    }


if __name__ == "__main__":
    # Run demonstrations
    demo_email_processing_conversation()
    demo_calendar_coordination_conversation()
    demo_multi_agent_research_workflow()
    
    # Run async demo
    print("Running async multi-user processing...")
    asyncio.run(demo_async_multi_user_processing())