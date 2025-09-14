# SecureContext Protocol (SCP) Python SDK

The SCP Python SDK provides a simple and powerful interface for AI agents and applications to securely access OAuth-protected user data through the SecureContext Protocol Authentication Proxy.

## Features

- **Simple Token Management**: Easy retrieval and management of OAuth tokens
- **Session Management**: Built-in session lifecycle management for agent workflows
- **Data Access Utilities**: High-level methods for common data operations
- **Framework Integrations**: Native support for LangChain, CrewAI, AutoGen, and custom frameworks
- **Error Handling**: Comprehensive error handling with retry mechanisms
- **Thread Safety**: Safe for use in multi-threaded applications

## Installation

### Basic Installation

```bash
pip install scp-sdk
```

### With Framework Support

```bash
# For LangChain integration
pip install scp-sdk[langchain]

# For CrewAI integration
pip install scp-sdk[crewai]

# For AutoGen integration
pip install scp-sdk[autogen]

# For all integrations
pip install scp-sdk[all]
```

## Quick Start

### Basic Usage

```python
from scp_sdk import SCPClient

# Initialize the client
client = SCPClient(base_url="http://localhost:5000")

# Get OAuth tokens
tokens = client.get_tokens("your-session-id")
print(f"Access token: {tokens['access_token']}")

# Get available providers
providers = client.get_providers()
print(f"Available providers: {[p['name'] for p in providers]}")
```

### With Session Management

```python
from scp_sdk import SCPClient, SessionManager

# Initialize client and session manager
client = SCPClient(base_url="http://localhost:5000")
session_manager = SessionManager(client)

# Add a session
session_info = session_manager.add_session(
    session_id="your-session-id",
    provider="google",
    expires_in=3600,
    agent_id="my-agent",
    workflow_id="email-workflow"
)

# Get tokens with automatic session tracking
tokens = session_manager.get_tokens("your-session-id")
```

### Data Access

```python
from scp_sdk import SCPClient, DataAccessClient

client = SCPClient(base_url="http://localhost:5000")
data_client = DataAccessClient(client)

# Get user profile
profile = data_client.get_user_profile("your-session-id")
print(f"User: {profile['name']} ({profile['email']})")

# Get emails
emails = data_client.get_emails("your-session-id", max_results=10)
print(f"Found {len(emails)} emails")

# Get calendar events
events = data_client.get_calendar_events("your-session-id", max_results=5)
print(f"Found {len(events)} upcoming events")
```

## Framework Integrations

### LangChain

```python
from scp_sdk import SCPClient
from scp_sdk.integrations import SCPTool
from langchain.agents import initialize_agent, AgentType

# Create SCP tool
client = SCPClient(base_url="http://localhost:5000")
scp_tool = SCPTool(client, data_type="emails")

# Use with LangChain agent
agent = initialize_agent([scp_tool], llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
result = agent.run("Get my recent emails")
```

### CrewAI

```python
from scp_sdk import SCPClient, SessionManager
from scp_sdk.integrations import SCPCrewTool, SCPCrewWorkflow

# Set up crew workflow
client = SCPClient(base_url="http://localhost:5000")
session_manager = SessionManager(client)
workflow = SCPCrewWorkflow(client, session_manager, crew_id="email-crew")

# Create tools for crew
tools = workflow.create_crew_tools(["profile", "emails", "calendar"])

# Register agent sessions
workflow.register_agent_session("email-agent", "session-id-1")
workflow.register_agent_session("calendar-agent", "session-id-2")
```

### AutoGen

```python
from scp_sdk import SCPClient, SessionManager
from scp_sdk.integrations import SCPConversationManager
from autogen import ConversableAgent

# Set up conversation
client = SCPClient(base_url="http://localhost:5000")
session_manager = SessionManager(client)
conv_manager = SCPConversationManager(client, session_manager, "conv-123")

# Create and set up agent
agent = ConversableAgent(name="assistant")
conv_manager.setup_agent_with_scp(agent, "your-session-id", ["profile", "emails"])
```

### Custom Frameworks

```python
from scp_sdk import SCPClient, SessionManager
from scp_sdk.integrations import GenericAgentAdapter

# Set up generic adapter
client = SCPClient(base_url="http://localhost:5000")
session_manager = SessionManager(client)
adapter = GenericAgentAdapter(client, session_manager, workflow_id="custom-workflow")

# Create simple functions
functions = adapter.create_simple_functions("your-session-id", "my-agent")

# Use the functions
profile = functions['get_user_profile']()
emails = functions['get_emails'](query="important", max_results=5)
```

## Configuration

### Retry Configuration

```python
from scp_sdk import SCPClient, RetryConfig

# Custom retry configuration
retry_config = RetryConfig(
    max_attempts=5,
    base_delay=2.0,
    max_delay=120.0,
    exponential_base=2.0,
    jitter=True
)

client = SCPClient(
    base_url="http://localhost:5000",
    timeout=30.0,
    retry_config=retry_config
)
```

### Session Manager Configuration

```python
from scp_sdk import SessionManager

session_manager = SessionManager(
    scp_client=client,
    cleanup_interval=300,  # 5 minutes
    auto_cleanup=True
)
```

## Error Handling

The SDK provides comprehensive error handling:

```python
from scp_sdk import SCPClient
from scp_sdk.exceptions import (
    SCPError,
    SCPConnectionError,
    SCPAuthenticationError,
    SCPSessionError,
    SCPTimeoutError
)

client = SCPClient(base_url="http://localhost:5000")

try:
    tokens = client.get_tokens("invalid-session-id")
except SCPSessionError as e:
    print(f"Session error: {e.message} (code: {e.error_code})")
except SCPConnectionError as e:
    print(f"Connection error: {e.message}")
except SCPError as e:
    print(f"General SCP error: {e.message}")
```

## API Reference

### SCPClient

Main client for interacting with the SCP Authentication Proxy.

**Methods:**
- `get_tokens(session_id)`: Retrieve OAuth tokens
- `get_providers()`: Get available OAuth providers
- `get_api_version()`: Get API version information
- `health_check()`: Perform health check
- `get_authorization_url(provider)`: Get OAuth authorization URL

### SessionManager

Manager for handling multiple OAuth sessions.

**Methods:**
- `add_session(session_id, provider, expires_in, ...)`: Add new session
- `get_session(session_id)`: Get session information
- `get_tokens(session_id)`: Get tokens with session tracking
- `cleanup_expired_sessions()`: Remove expired sessions
- `get_statistics()`: Get session statistics

### DataAccessClient

High-level client for accessing user data.

**Methods:**
- `get_user_profile(session_id)`: Get user profile
- `get_emails(session_id, max_results, query)`: Get email messages
- `get_calendar_events(session_id, max_results, time_min, time_max)`: Get calendar events

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- Documentation: https://docs.securecontext.dev/sdk
- Issues: https://github.com/securecontext/scp-sdk/issues
- Discussions: https://github.com/securecontext/scp-sdk/discussions