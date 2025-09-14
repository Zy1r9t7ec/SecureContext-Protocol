# Agent Marketplace Integration Guide

This guide covers the agent marketplace integration features of the SecureContext Protocol, including agent registration, capability discovery, standardized metadata formats, and testing frameworks.

## Overview

The SCP marketplace system provides:

- **Agent Registration** - Register agents with standardized metadata
- **Capability Discovery** - Find agents by capabilities and providers
- **Testing Framework** - Automated testing and validation
- **Standardized Metadata** - Consistent agent documentation format

## Agent Metadata Format

### Basic Structure

```json
{
  "agent_id": "unique-agent-identifier",
  "name": "Human Readable Agent Name",
  "version": "1.0.0",
  "description": "Detailed description of what the agent does",
  "author": "Agent Author or Organization",
  "license": "MIT",
  "homepage": "https://example.com/agent",
  "repository": "https://github.com/example/agent",
  "documentation": "https://docs.example.com/agent",
  "capabilities": [...],
  "supported_frameworks": ["langchain", "crewai", "autogen"],
  "minimum_scp_version": "1.0",
  "tags": ["email", "productivity", "automation"],
  "category": "productivity"
}
```

### Capability Definition

```json
{
  "capability_type": "email_management",
  "name": "Email Reading",
  "description": "Read and parse emails from Gmail and Outlook",
  "required_scopes": [
    "https://www.googleapis.com/auth/gmail.readonly",
    "Mail.Read"
  ],
  "supported_providers": ["google", "microsoft"],
  "data_types": ["messages", "threads", "labels"],
  "rate_limits": {
    "requests_per_minute": 100,
    "messages_per_hour": 1000
  },
  "security_level": "high"
}
```

### Capability Types

Available capability types:

- `data_access` - Basic data access
- `email_management` - Email operations
- `calendar_management` - Calendar operations
- `file_management` - File operations
- `contact_management` - Contact operations
- `workflow_automation` - Workflow automation
- `data_analysis` - Data analysis and insights
- `content_generation` - Content creation
- `integration` - System integrations
- `custom` - Custom capabilities

### Security Levels

- `standard` - Basic security requirements
- `high` - Enhanced security requirements
- `enterprise` - Enterprise-grade security

## API Endpoints

### Register Agent

Register a new agent in the marketplace.

**Endpoint:** `POST /api/marketplace/agents`

**Request Body:**
```json
{
  "agent_id": "email-assistant-v1",
  "name": "Email Assistant",
  "version": "1.2.0",
  "description": "An intelligent email management agent",
  "author": "SecureContext Team",
  "license": "MIT",
  "capabilities": [
    {
      "capability_type": "email_management",
      "name": "Email Reading",
      "description": "Read and parse emails",
      "required_scopes": ["gmail.readonly"],
      "supported_providers": ["google"],
      "data_types": ["messages"],
      "rate_limits": {"requests_per_minute": 100},
      "security_level": "high"
    }
  ],
  "supported_frameworks": ["langchain"],
  "minimum_scp_version": "1.0",
  "tags": ["email", "productivity"],
  "category": "productivity"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "agent_id": "email-assistant-v1",
    "status": "pending",
    "message": "Agent registered successfully"
  }
}
```

### List Agents

List agents with optional filtering.

**Endpoint:** `GET /api/marketplace/agents`

**Query Parameters:**
- `capability` - Filter by capability type
- `provider` - Filter by supported provider
- `framework` - Filter by supported framework
- `status` - Filter by agent status
- `category` - Filter by category
- `tags` - Filter by tags (comma-separated)
- `search` - Search in name, description, tags

**Examples:**
```bash
# List all agents
GET /api/marketplace/agents

# Filter by capability
GET /api/marketplace/agents?capability=email_management

# Filter by provider
GET /api/marketplace/agents?provider=google

# Search agents
GET /api/marketplace/agents?search=email

# Multiple filters
GET /api/marketplace/agents?capability=email_management&provider=google&status=approved
```

**Response:**
```json
{
  "success": true,
  "data": {
    "agents": [
      {
        "agent_id": "email-assistant-v1",
        "name": "Email Assistant",
        "version": "1.2.0",
        "description": "An intelligent email management agent",
        "author": "SecureContext Team",
        "status": "approved",
        "test_score": 0.85,
        "capabilities": [...],
        "tags": ["email", "productivity"]
      }
    ],
    "total_count": 1,
    "filters_applied": {
      "capability": "email_management"
    }
  }
}
```

### Get Agent Details

Get detailed information about a specific agent.

**Endpoint:** `GET /api/marketplace/agents/{agent_id}`

**Response:**
```json
{
  "success": true,
  "data": {
    "agent_id": "email-assistant-v1",
    "name": "Email Assistant",
    "version": "1.2.0",
    "description": "An intelligent email management agent",
    "author": "SecureContext Team",
    "license": "MIT",
    "homepage": "https://github.com/securecontext/email-assistant",
    "repository": "https://github.com/securecontext/email-assistant",
    "documentation": "https://docs.securecontext.com/agents/email-assistant",
    "capabilities": [...],
    "supported_frameworks": ["langchain", "crewai"],
    "minimum_scp_version": "1.0",
    "tags": ["email", "productivity"],
    "category": "productivity",
    "status": "approved",
    "test_score": 0.85,
    "test_results": [
      {
        "test_id": "test-123",
        "test_type": "metadata_validation",
        "status": "passed",
        "score": 0.9,
        "timestamp": "2024-01-01T12:00:00Z",
        "duration_seconds": 1.5
      }
    ]
  }
}
```

### Unregister Agent

Remove an agent from the marketplace.

**Endpoint:** `DELETE /api/marketplace/agents/{agent_id}`

**Response:**
```json
{
  "success": true,
  "data": {
    "agent_id": "email-assistant-v1",
    "message": "Agent unregistered successfully"
  }
}
```

### Get Capabilities

Get all available capabilities and their supporting agents.

**Endpoint:** `GET /api/marketplace/capabilities`

**Response:**
```json
{
  "success": true,
  "data": {
    "capabilities": {
      "email_management": ["email-assistant-v1", "mail-bot-v2"],
      "calendar_management": ["calendar-agent-v1"],
      "data_analysis": ["analytics-agent-v1", "email-assistant-v1"]
    },
    "total_capabilities": 3
  }
}
```

### Test Agent

Run tests for an agent to validate its implementation.

**Endpoint:** `POST /api/marketplace/test/{agent_id}`

**Request Body:**
```json
{
  "test_types": ["metadata_validation", "capability_verification"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "agent_id": "email-assistant-v1",
    "test_results": [
      {
        "test_id": "test-456",
        "agent_id": "email-assistant-v1",
        "test_type": "metadata_validation",
        "status": "passed",
        "score": 0.9,
        "details": {
          "checks": [
            "✓ agent_id: email-assistant-v1",
            "✓ name: Email Assistant",
            "✓ version: 1.2.0"
          ]
        },
        "timestamp": "2024-01-01T12:00:00Z",
        "duration_seconds": 1.2
      }
    ],
    "total_tests": 1
  }
}
```

### Get Marketplace Statistics

Get overall marketplace statistics.

**Endpoint:** `GET /api/marketplace/stats`

**Response:**
```json
{
  "success": true,
  "data": {
    "total_agents": 15,
    "status_distribution": {
      "approved": 12,
      "pending": 2,
      "rejected": 1
    },
    "category_distribution": {
      "productivity": 8,
      "analytics": 4,
      "integration": 3
    },
    "total_capabilities": 10,
    "total_providers": 5,
    "total_frameworks": 4,
    "top_capabilities": [
      ["email_management", 6],
      ["data_analysis", 4],
      ["calendar_management", 3]
    ]
  }
}
```

## Testing Framework

### Test Types

The marketplace includes several automated test types:

#### Metadata Validation
- Validates required fields
- Checks field formats and constraints
- Verifies capability definitions

#### Capability Verification
- Validates capability definitions
- Checks required scopes and providers
- Verifies data type specifications

#### Security Compliance
- Checks security level configurations
- Validates rate limiting settings
- Reviews license and documentation

#### Performance Benchmark
- Measures response times
- Tests throughput capabilities
- Evaluates resource usage

### Test Scoring

Tests are scored from 0.0 to 1.0:
- **0.9-1.0:** Excellent
- **0.8-0.9:** Good
- **0.7-0.8:** Acceptable
- **0.6-0.7:** Needs improvement
- **Below 0.6:** Failed

### Running Tests

```bash
# Run all tests for an agent
curl -X POST http://localhost:5000/api/marketplace/test/email-assistant-v1 \
  -H "Content-Type: application/json" \
  -d '{}'

# Run specific tests
curl -X POST http://localhost:5000/api/marketplace/test/email-assistant-v1 \
  -H "Content-Type: application/json" \
  -d '{"test_types": ["metadata_validation", "security_compliance"]}'
```

## Python SDK Usage

### Register Agent

```python
import requests
import json

# Load agent metadata
with open('agent_metadata.json', 'r') as f:
    agent_data = json.load(f)

# Register agent
response = requests.post(
    'http://localhost:5000/api/marketplace/agents',
    json=agent_data,
    headers={'Content-Type': 'application/json'}
)

if response.status_code == 201:
    result = response.json()
    print(f"Agent registered: {result['data']['agent_id']}")
else:
    print(f"Registration failed: {response.text}")
```

### Search Agents

```python
import requests

# Search for email agents
response = requests.get(
    'http://localhost:5000/api/marketplace/agents',
    params={'search': 'email', 'capability': 'email_management'}
)

if response.status_code == 200:
    data = response.json()
    agents = data['data']['agents']
    
    for agent in agents:
        print(f"Agent: {agent['name']} v{agent['version']}")
        print(f"  Description: {agent['description']}")
        print(f"  Score: {agent.get('test_score', 'N/A')}")
        print()
```

### Test Agent

```python
import requests

agent_id = 'email-assistant-v1'

# Run tests
response = requests.post(
    f'http://localhost:5000/api/marketplace/test/{agent_id}',
    json={'test_types': ['metadata_validation', 'capability_verification']},
    headers={'Content-Type': 'application/json'}
)

if response.status_code == 200:
    data = response.json()
    results = data['data']['test_results']
    
    for result in results:
        print(f"Test: {result['test_type']}")
        print(f"  Status: {result['status']}")
        print(f"  Score: {result.get('score', 'N/A')}")
        print(f"  Duration: {result['duration_seconds']:.2f}s")
```

## Agent Development Guidelines

### Metadata Best Practices

1. **Use descriptive names and descriptions**
2. **Specify accurate capability requirements**
3. **Include comprehensive documentation links**
4. **Use semantic versioning**
5. **Add relevant tags for discoverability**

### Capability Definition

1. **Be specific about required scopes**
2. **List all supported providers**
3. **Define appropriate rate limits**
4. **Choose correct security level**
5. **Document data types clearly**

### Testing Preparation

1. **Ensure all required fields are present**
2. **Validate capability definitions**
3. **Include proper documentation**
4. **Set appropriate rate limits**
5. **Choose suitable security level**

## Integration Examples

### LangChain Agent

```python
from langchain.agents import Tool
from scp_sdk import SCPClient

class EmailAgent:
    def __init__(self, scp_client: SCPClient):
        self.scp_client = scp_client
    
    def read_emails(self, session_id: str, query: str = ""):
        """Read emails using SCP."""
        return self.scp_client.get_data(
            session_id=session_id,
            provider='google',
            data_type='messages',
            filters={'query': query}
        )
    
    def get_langchain_tools(self):
        """Get LangChain tools for this agent."""
        return [
            Tool(
                name="read_emails",
                description="Read emails from user's Gmail account",
                func=self.read_emails
            )
        ]
```

### CrewAI Agent

```python
from crewai import Agent, Task, Crew
from scp_sdk import SCPClient

class EmailAnalysisAgent(Agent):
    def __init__(self, scp_client: SCPClient, session_id: str):
        self.scp_client = scp_client
        self.session_id = session_id
        
        super().__init__(
            role='Email Analyst',
            goal='Analyze email patterns and provide insights',
            backstory='Expert in email analysis and productivity optimization'
        )
    
    def analyze_emails(self):
        """Analyze user's emails."""
        emails = self.scp_client.get_data(
            session_id=self.session_id,
            provider='google',
            data_type='messages'
        )
        
        # Perform analysis
        return self.process_email_data(emails)
```

## Error Handling

### Common Error Codes

- `INVALID_PARAMETER` - Invalid agent metadata or parameters
- `AGENT_NOT_FOUND` - Agent ID not found
- `VALIDATION_FAILED` - Agent validation failed
- `TEST_FAILED` - Agent testing failed

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "INVALID_PARAMETER",
    "message": "Invalid agent metadata",
    "details": {
      "field": "capabilities",
      "issue": "At least one capability is required"
    }
  }
}
```

## Security Considerations

### Agent Validation

- All agents undergo metadata validation
- Capability definitions are verified
- Security levels are enforced
- Rate limits are validated

### Data Privacy

- Agent metadata is stored securely
- Test results are anonymized
- No sensitive data is exposed
- Audit logs track all operations

### Access Control

- Agent registration requires validation
- Testing is rate-limited
- Marketplace access is controlled
- Sensitive operations are logged

## Troubleshooting

### Common Issues

1. **Registration fails with validation error**
   - Check required fields are present
   - Verify capability definitions
   - Ensure version format is correct

2. **Tests fail with low scores**
   - Review test details for specific issues
   - Update metadata based on feedback
   - Ensure documentation is complete

3. **Agent not found in search**
   - Check agent status (must be approved)
   - Verify tags and category are set
   - Ensure capabilities are defined

### Debug Mode

Enable debug logging for detailed information:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Testing

Use the provided test script:

```bash
python test_marketplace.py --url http://localhost:5000
```

## Examples

See the `examples/` directory for complete examples:

- `sample_agent_metadata.json` - Complete agent metadata example
- `marketplace_client_example.py` - Python client usage
- `agent_registration_example.py` - Registration workflow
- `capability_discovery_example.py` - Finding agents by capability

## API Reference

For complete API documentation, see:
- [API Endpoints](api_reference.md)
- [Error Codes](error_codes.md)
- [Agent Metadata Schema](agent_metadata_schema.md)