"""
CrewAI Agent Workflow Examples for SecureContext Protocol (SCP)

This module demonstrates multi-agent workflows using CrewAI with SCP integration.
Examples include collaborative email processing, meeting coordination, and research tasks.
"""

from typing import List, Dict, Any, Optional
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool

from scp_sdk import SCPClient
from scp_sdk.integrations.crewai import SCPCrewTool, SCPAgent


class EmailAnalystAgent(SCPAgent):
    """Specialized agent for email analysis and processing."""
    
    def __init__(self, session_id: str):
        super().__init__(
            role="Email Analyst",
            goal="Analyze and categorize emails to extract actionable insights",
            backstory="You are an expert at processing large volumes of email data and identifying important patterns, trends, and action items.",
            session_id=session_id,
            providers=["google", "microsoft"]
        )
        
        # Add SCP-enabled tools
        self.tools = [
            SCPCrewTool(
                name="email_reader",
                description="Read emails from Gmail or Outlook",
                session_id=session_id,
                provider="auto",
                data_type="emails"
            ),
            SCPCrewTool(
                name="email_categorizer",
                description="Categorize emails by importance and topic",
                session_id=session_id,
                provider="auto",
                data_type="categorize_emails"
            )
        ]


class CalendarManagerAgent(SCPAgent):
    """Specialized agent for calendar management and scheduling."""
    
    def __init__(self, session_id: str):
        super().__init__(
            role="Calendar Manager",
            goal="Optimize calendar scheduling and manage meeting coordination",
            backstory="You are a scheduling expert who can efficiently manage calendars across multiple platforms and coordinate complex meeting arrangements.",
            session_id=session_id,
            providers=["google", "microsoft"]
        )
        
        self.tools = [
            SCPCrewTool(
                name="calendar_reader",
                description="Read calendar events from Google Calendar or Outlook",
                session_id=session_id,
                provider="auto",
                data_type="calendar"
            ),
            SCPCrewTool(
                name="meeting_scheduler",
                description="Schedule new meetings and send invitations",
                session_id=session_id,
                provider="auto",
                data_type="schedule_meeting"
            ),
            SCPCrewTool(
                name="availability_checker",
                description="Check availability across multiple calendars",
                session_id=session_id,
                provider="multi",
                data_type="check_availability"
            )
        ]


class CommunicationCoordinatorAgent(SCPAgent):
    """Agent responsible for coordinating communications across platforms."""
    
    def __init__(self, session_id: str):
        super().__init__(
            role="Communication Coordinator",
            goal="Coordinate and manage communications across email and calendar platforms",
            backstory="You excel at managing complex communication workflows and ensuring all stakeholders are properly informed and coordinated.",
            session_id=session_id,
            providers=["google", "microsoft"]
        )
        
        self.tools = [
            SCPCrewTool(
                name="email_sender",
                description="Send emails via Gmail or Outlook",
                session_id=session_id,
                provider="auto",
                data_type="send_email"
            ),
            SCPCrewTool(
                name="meeting_inviter",
                description="Send meeting invitations and updates",
                session_id=session_id,
                provider="auto",
                data_type="send_invitation"
            ),
            SCPCrewTool(
                name="follow_up_tracker",
                description="Track and manage follow-up communications",
                session_id=session_id,
                provider="multi",
                data_type="track_followups"
            )
        ]


def create_email_processing_crew(session_id: str) -> Crew:
    """
    Create a crew for collaborative email processing and management.
    
    Args:
        session_id: SCP session ID for authenticated user
        
    Returns:
        Configured CrewAI crew for email processing
    """
    # Initialize agents
    email_analyst = EmailAnalystAgent(session_id)
    communication_coordinator = CommunicationCoordinatorAgent(session_id)
    
    # Define tasks
    email_analysis_task = Task(
        description="Analyze the user's inbox across all connected email providers. Categorize emails by importance (high, medium, low) and topic. Identify emails requiring immediate action.",
        agent=email_analyst,
        expected_output="A structured report of email categories with action items and priority levels."
    )
    
    response_coordination_task = Task(
        description="Based on the email analysis, draft appropriate responses for high-priority emails and schedule follow-up actions for medium-priority items.",
        agent=communication_coordinator,
        expected_output="Draft responses for urgent emails and a follow-up schedule for other important communications."
    )
    
    # Create crew
    crew = Crew(
        agents=[email_analyst, communication_coordinator],
        tasks=[email_analysis_task, response_coordination_task],
        process=Process.sequential,
        verbose=True
    )
    
    return crew


def create_meeting_coordination_crew(session_id: str) -> Crew:
    """
    Create a crew for complex meeting coordination across multiple calendars.
    
    Args:
        session_id: SCP session ID for authenticated user
        
    Returns:
        Configured CrewAI crew for meeting coordination
    """
    # Initialize agents
    calendar_manager = CalendarManagerAgent(session_id)
    communication_coordinator = CommunicationCoordinatorAgent(session_id)
    
    # Define tasks
    availability_analysis_task = Task(
        description="Analyze calendar availability across all connected calendar providers. Identify optimal meeting times for the next two weeks considering existing commitments.",
        agent=calendar_manager,
        expected_output="A comprehensive availability report with recommended meeting slots."
    )
    
    meeting_scheduling_task = Task(
        description="Schedule meetings based on availability analysis. Send appropriate invitations and confirmations to all participants.",
        agent=communication_coordinator,
        expected_output="Scheduled meetings with sent invitations and confirmation tracking."
    )
    
    # Create crew
    crew = Crew(
        agents=[calendar_manager, communication_coordinator],
        tasks=[availability_analysis_task, meeting_scheduling_task],
        process=Process.sequential,
        verbose=True
    )
    
    return crew


def create_research_and_communication_crew(session_id: str) -> Crew:
    """
    Create a crew for research tasks that involve data gathering and communication.
    
    Args:
        session_id: SCP session ID for authenticated user
        
    Returns:
        Configured CrewAI crew for research and communication
    """
    # Initialize agents with expanded capabilities
    email_analyst = EmailAnalystAgent(session_id)
    calendar_manager = CalendarManagerAgent(session_id)
    communication_coordinator = CommunicationCoordinatorAgent(session_id)
    
    # Define collaborative tasks
    data_gathering_task = Task(
        description="Gather relevant information from emails, calendar events, and documents related to the specified research topic. Extract key insights and data points.",
        agent=email_analyst,
        expected_output="Comprehensive data collection with key insights and relevant information."
    )
    
    timeline_analysis_task = Task(
        description="Analyze the timeline of events and meetings related to the research topic. Identify patterns and important milestones.",
        agent=calendar_manager,
        expected_output="Timeline analysis with identified patterns and key milestones."
    )
    
    report_and_communication_task = Task(
        description="Compile research findings into a comprehensive report and communicate results to relevant stakeholders via email.",
        agent=communication_coordinator,
        expected_output="Final research report with stakeholder communications sent."
    )
    
    # Create crew with hierarchical process
    crew = Crew(
        agents=[email_analyst, calendar_manager, communication_coordinator],
        tasks=[data_gathering_task, timeline_analysis_task, report_and_communication_task],
        process=Process.hierarchical,
        manager_llm="gpt-4",  # Use GPT-4 for crew management
        verbose=True
    )
    
    return crew


# Workflow execution examples
def demo_email_processing_workflow():
    """Demonstrate collaborative email processing workflow."""
    print("=== CrewAI Email Processing Workflow Demo ===")
    
    session_id = "crewai_demo_123"
    crew = create_email_processing_crew(session_id)
    
    try:
        result = crew.kickoff()
        print(f"Email processing completed: {result}")
    except Exception as e:
        print(f"Error in email processing workflow: {e}")


def demo_meeting_coordination_workflow():
    """Demonstrate meeting coordination workflow."""
    print("=== CrewAI Meeting Coordination Workflow Demo ===")
    
    session_id = "crewai_demo_456"
    crew = create_meeting_coordination_crew(session_id)
    
    try:
        result = crew.kickoff()
        print(f"Meeting coordination completed: {result}")
    except Exception as e:
        print(f"Error in meeting coordination workflow: {e}")


def demo_research_workflow():
    """Demonstrate research and communication workflow."""
    print("=== CrewAI Research Workflow Demo ===")
    
    session_id = "crewai_demo_789"
    crew = create_research_and_communication_crew(session_id)
    
    # Set research topic
    research_topic = "quarterly performance review preparation"
    
    try:
        result = crew.kickoff(inputs={"research_topic": research_topic})
        print(f"Research workflow completed: {result}")
    except Exception as e:
        print(f"Error in research workflow: {e}")


# Advanced crew configurations
def create_high_throughput_crew(session_ids: List[str]) -> Crew:
    """
    Create a crew optimized for high-throughput operations across multiple users.
    
    Args:
        session_ids: List of SCP session IDs for multiple users
        
    Returns:
        Configured crew for high-throughput processing
    """
    agents = []
    tasks = []
    
    # Create specialized agents for each user session
    for i, session_id in enumerate(session_ids):
        agent = EmailAnalystAgent(session_id)
        agent.role = f"Email Analyst {i+1}"
        agents.append(agent)
        
        task = Task(
            description=f"Process emails for user session {session_id}",
            agent=agent,
            expected_output=f"Email processing results for session {session_id}"
        )
        tasks.append(task)
    
    # Create crew with parallel processing
    crew = Crew(
        agents=agents,
        tasks=tasks,
        process=Process.parallel,
        verbose=True
    )
    
    return crew


if __name__ == "__main__":
    # Run demonstrations
    demo_email_processing_workflow()
    demo_meeting_coordination_workflow()
    demo_research_workflow()
    
    # Demo high-throughput processing
    print("=== High-Throughput Multi-User Processing Demo ===")
    session_ids = ["user1_session", "user2_session", "user3_session"]
    high_throughput_crew = create_high_throughput_crew(session_ids)
    
    try:
        result = high_throughput_crew.kickoff()
        print(f"High-throughput processing completed: {result}")
    except Exception as e:
        print(f"Error in high-throughput processing: {e}")