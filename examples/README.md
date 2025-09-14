# SCP Agent Workflow Examples

This directory contains comprehensive examples demonstrating how to integrate AI agents with the SecureContext Protocol (SCP) using popular agent frameworks.

## Overview

The SecureContext Protocol (SCP) enables AI agents to securely access user data across multiple OAuth providers (Google, Microsoft, etc.) with proper user consent and audit logging. These examples show how to build powerful agent workflows that can:

- Access user emails, calendars, and documents
- Perform cross-provider data analysis
- Maintain user privacy and security
- Scale to handle multiple users concurrently
- Provide audit trails for transparency

## Quick Start

### Prerequisites

1. **SCP Server Running**: Ensure the SCP authentication proxy is running
2. **OAuth Credentials**: Configure Google and Microsoft OAuth applications
3. **Python Dependencies**: Install required packages for your chosen framework

```bash
# Install SCP SDK
pip install -e ../scp_sdk

# Install framework-specific dependencies
pip install langchain openai  # For LangChain examples
pip install crewai            # For CrewAI examples  
pip install pyautogen         # For AutoGen examples
```

### Basic Usage Pattern

All examples follow this basic pattern:

1. **User Authentication**: User completes OAuth flow and gets session ID
2. **Agent Initialization**: Create agent with SCP integration and session ID
3. **Task Execution**: Agent uses SCP tools to access user data securely
4. **Result Processing**: Agent processes data and provides insights

```python
# Basic pattern example
from scp_sdk import SCPClient

# Initialize SCP client with user session
session_id = "user_session_from_oauth_flow"
scp_client = SCPClient()

# Access user data through SCP
emails = scp_client.get_data(
    session_id=session_id,
    provider="google",
    data_type="emails",
    query="recent"
)

# Process data with your agent framework
# ... agent processing logic ...
```

## Framework Examples

### 1. LangChain Integration (`langchain_examples.py`)

**Best for**: Tool-based agents, chain compositions, and single-agent workflows

**Key Features**:
- SCP-enabled tools for LangChain agents
- Custom chains for email and calendar processing
- Automatic error handling and retries
- Audit logging integration

**Example Workflows**:
- **Email Management**: Analyze, categorize, and respond to emails
- **Calendar Scheduling**: Find availability and schedule meetings
- **Multi-Provider Analysis**: Aggregate data across Google and Microsoft

```python
# Quick example
from examples.agent_workflows.langchain_examples import create_email_management_agent

session_id = "your_session_id"
agent = create_email_management_agent(session_id)

# Agent can now access user's Gmail and Outlook data
result = agent.run("Summarize my emails from this week and draft responses for urgent ones")
```

### 2. CrewAI Integration (`crewai_examples.py`)

**Best for**: Multi-agent collaboration, complex workflows, and specialized agent roles

**Key Features**:
- Specialized agents with SCP access (Email Analyst, Calendar Manager, etc.)
- Collaborative workflows with data sharing
- Hierarchical and sequential processing
- High-throughput multi-user support

**Example Workflows**:
- **Email Processing Crew**: Collaborative email analysis and response generation
- **Meeting Coordination Crew**: Complex scheduling across multiple calendars
- **Research Crew**: Multi-agent research with data gathering and reporting

```python
# Quick example
from examples.agent_workflows.crewai_examples import create_email_processing_crew

session_id = "your_session_id"
crew = create_email_processing_crew(session_id)

# Crew of agents collaboratively processes emails
result = crew.kickoff()
```

### 3. AutoGen Integration (`autogen_examples.py`)

**Best for**: Conversational agents, group chats, and dynamic agent interactions

**Key Features**:
- SCP function calling for conversational agents
- Group chat scenarios with multiple agents
- Async processing for multiple users
- Dynamic agent creation and management

**Example Workflows**:
- **Email Conversation**: Agents discuss and process emails conversationally
- **Calendar Coordination**: Multi-agent meeting scheduling discussions
- **Research Workflow**: Collaborative research with specialized agents

```python
# Quick example
from examples.agent_workflows.autogen_examples import create_email_management_agents

session_id = "your_session_id"
user_proxy, email_assistant, email_analyzer = create_email_management_agents(session_id)

# Start conversational workflow
user_proxy.initiate_chat(
    email_assistant, 
    message="Please analyze my recent emails and provide insights"
)
```

## Common Use Cases

### 1. Personal Productivity Assistant

Combine email analysis, calendar management, and task prioritization:

```python
# Multi-framework productivity assistant
class ProductivityAssistant:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.email_agent = create_email_management_agent(session_id)
        self.calendar_crew = create_meeting_coordination_crew(session_id)
    
    def daily_briefing(self):
        # Get email summary
        email_summary = self.email_agent.run("Summarize today's important emails")
        
        # Get calendar overview
        calendar_summary = self.calendar_crew.kickoff()
        
        return {
            'emails': email_summary,
            'calendar': calendar_summary,
            'recommendations': self.generate_recommendations()
        }
```

### 2. Customer Support Automation

Process customer emails and schedule follow-ups:

```python
# Customer support workflow
def customer_support_workflow(session_id: str):
    # Analyze customer emails
    support_agent = create_email_management_agent(session_id)
    
    # Categorize and prioritize
    analysis = support_agent.run("""
        Analyze customer support emails and:
        1. Categorize by urgency (high, medium, low)
        2. Identify common issues
        3. Draft appropriate responses
        4. Schedule follow-up meetings for complex issues
    """)
    
    return analysis
```

### 3. Sales Pipeline Management

Track communications and schedule meetings:

```python
# Sales pipeline workflow
def sales_pipeline_workflow(session_id: str):
    # Multi-agent sales crew
    crew = create_research_and_communication_crew(session_id)
    
    # Analyze sales communications
    result = crew.kickoff(inputs={
        "research_topic": "sales pipeline analysis and next steps"
    })
    
    return result
```

## Performance Considerations

### High-Throughput Scenarios

For processing multiple users or large datasets:

```python
# Concurrent processing example
import asyncio
from examples.agent_workflows.autogen_examples import demo_async_multi_user_processing

async def process_multiple_users(user_sessions: list):
    """Process multiple users concurrently."""
    
    # Limit concurrent operations
    semaphore = asyncio.Semaphore(10)
    
    async def process_user(session_id):
        async with semaphore:
            return await process_single_user(session_id)
    
    # Process all users
    tasks = [process_user(session_id) for session_id in user_sessions]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    return results

# Run concurrent processing
user_sessions = ["session_1", "session_2", "session_3"]
results = asyncio.run(process_multiple_users(user_sessions))
```

### Memory Optimization

For long-running agents:

```python
# Memory-efficient agent management
class ManagedAgent:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self._agent = None
    
    @property
    def agent(self):
        if self._agent is None:
            self._agent = create_email_management_agent(self.session_id)
        return self._agent
    
    def cleanup(self):
        """Clean up agent resources."""
        if self._agent:
            # Cleanup agent resources
            self._agent = None
```

## Error Handling

All examples include comprehensive error handling:

```python
# Error handling pattern
def robust_agent_execution(session_id: str, task: str):
    """Execute agent task with robust error handling."""
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            agent = create_email_management_agent(session_id)
            return agent.run(task)
            
        except Exception as e:
            if "401" in str(e) or "unauthorized" in str(e).lower():
                # Token expired, need re-authentication
                print(f"Authentication failed for session {session_id}")
                # Trigger re-authentication flow
                break
            elif attempt < max_retries - 1:
                # Retry on other errors
                print(f"Attempt {attempt + 1} failed: {e}")
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            else:
                raise e
    
    return None
```

## Security Best Practices

### 1. Session Validation

Always validate sessions before processing:

```python
def validate_session_before_processing(session_id: str):
    """Validate session before agent processing."""
    
    from scp_sdk import SCPClient
    client = SCPClient()
    
    try:
        session_info = client.get_session_info(session_id)
        if not session_info.get('valid', False):
            raise ValueError("Invalid session")
        
        # Check token expiry
        expires_at = session_info.get('expires_at')
        if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
            raise ValueError("Session expired")
        
        return True
        
    except Exception as e:
        print(f"Session validation failed: {e}")
        return False
```

### 2. Audit Logging

All examples include audit logging:

```python
# Audit logging example
from scp_sdk import AuditLogger

audit_logger = AuditLogger()

def logged_data_access(session_id: str, provider: str, data_type: str, purpose: str):
    """Access data with audit logging."""
    
    # Log access attempt
    audit_logger.log_access_attempt(
        session_id=session_id,
        provider=provider,
        data_type=data_type,
        purpose=purpose
    )
    
    try:
        # Access data
        data = scp_client.get_data(
            session_id=session_id,
            provider=provider,
            data_type=data_type
        )
        
        # Log successful access
        audit_logger.log_access_success(
            session_id=session_id,
            provider=provider,
            data_type=data_type,
            records_accessed=len(data)
        )
        
        return data
        
    except Exception as e:
        # Log access failure
        audit_logger.log_access_failure(
            session_id=session_id,
            provider=provider,
            data_type=data_type,
            error=str(e)
        )
        raise
```

## Testing

Each example includes testing utilities:

```bash
# Run example tests
python -m pytest examples/tests/

# Run specific framework tests
python examples/agent_workflows/langchain_examples.py
python examples/agent_workflows/crewai_examples.py
python examples/agent_workflows/autogen_examples.py
```

## Troubleshooting

Common issues and solutions:

### 1. Session Not Found
- **Cause**: Session expired or invalid session ID
- **Solution**: Check session validity, re-authenticate if needed

### 2. Rate Limiting
- **Cause**: Too many API requests to OAuth providers
- **Solution**: Implement exponential backoff, use request queuing

### 3. Framework Integration Issues
- **Cause**: Incorrect tool registration or configuration
- **Solution**: Check framework-specific setup, validate tool registration

### 4. Performance Issues
- **Cause**: Inefficient data access patterns
- **Solution**: Use caching, batch requests, implement connection pooling

For detailed troubleshooting, see `../docs/agent_integration_troubleshooting.md`.

## Contributing

To add new examples or improve existing ones:

1. Follow the established patterns in existing examples
2. Include comprehensive error handling
3. Add audit logging for data access
4. Include performance considerations
5. Add tests for your examples
6. Update this README with your additions

## Support

For questions or issues:

1. Check the troubleshooting guide
2. Review the integration patterns documentation
3. Examine the performance optimization guide
4. Open an issue in the project repository

## License

These examples are provided under the same license as the main SCP project.