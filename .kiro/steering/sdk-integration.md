---
inclusion: fileMatch
fileMatchPattern: "scp_sdk/**/*.py"
---

# SDK Integration Guidelines

This steering document provides guidance for implementing and extending the SCP SDK.

## SDK Architecture Principles

### Client Design
- Single entry point through SCPClient class
- Consistent method naming across all operations
- Automatic session management and token refresh
- Comprehensive error handling with specific exception types

### Integration Patterns
- Framework-specific integration classes
- Generic integration base for custom frameworks
- Consistent authentication flow across all integrations
- Minimal configuration required from users

## Implementation Standards

### Session Management
```python
# Always use session manager for token operations
session_manager = SessionManager(base_url=self.base_url)
session = session_manager.create_session(provider="google")

# Handle session errors gracefully
try:
    data = session_manager.get_data(session_id, endpoint)
except SessionExpiredError:
    # Automatic refresh or re-authentication
    session = session_manager.refresh_session(session_id)
    data = session_manager.get_data(session_id, endpoint)
```

### Error Handling
- Use specific exception types (SessionError, AuthenticationError, etc.)
- Provide actionable error messages
- Include context information in exceptions
- Log errors appropriately without exposing sensitive data

### Framework Integration Standards

### LangChain Integration
- Extend LangChain's base tool classes
- Implement proper async support
- Handle LangChain's callback system
- Provide chain-compatible interfaces

### CrewAI Integration
- Implement CrewAI tool interface
- Support agent role-based access
- Handle CrewAI's task execution model
- Provide crew-compatible data structures

### AutoGen Integration
- Support AutoGen's conversable agent pattern
- Implement proper message handling
- Support multi-agent scenarios
- Handle AutoGen's execution context

## Data Access Patterns

### API Calls
```python
# Standardized data access pattern
def get_external_data(self, session_id: str, endpoint: str, **kwargs) -> Dict[str, Any]:
    """Get data from external service via authenticated session."""
    try:
        response = self._make_authenticated_request(session_id, endpoint, **kwargs)
        return self._parse_response(response)
    except AuthenticationError:
        # Handle re-authentication
        self._refresh_session(session_id)
        response = self._make_authenticated_request(session_id, endpoint, **kwargs)
        return self._parse_response(response)
```

### Response Handling
- Standardize response formats across all methods
- Include metadata (timestamps, request IDs, etc.)
- Handle pagination consistently
- Provide both sync and async interfaces where applicable

## Testing Guidelines

### Unit Testing
- Mock all external API calls
- Test error conditions thoroughly
- Validate session management logic
- Test framework-specific integrations

### Integration Testing
- Test with real authentication flows
- Validate framework compatibility
- Test concurrent usage scenarios
- Verify data access patterns

## Documentation Requirements

### Code Documentation
- Comprehensive docstrings with examples
- Type hints for all parameters and return values
- Usage examples for complex operations
- Security considerations for each method

### Integration Examples
- Complete working examples for each framework
- Step-by-step setup instructions
- Common use case demonstrations
- Troubleshooting guides

## Reference Files
- `scp_sdk/client.py` - Main SDK client implementation
- `scp_sdk/session_manager.py` - Session management utilities
- `scp_sdk/integrations/` - Framework-specific integrations