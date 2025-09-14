# Project Standards and Guidelines

This steering document provides context and standards for the Secure Context Protocol project.

## Code Standards

### Python Code Style
- Follow PEP 8 guidelines
- Use type hints for all function parameters and return values
- Maximum line length: 88 characters (Black formatter standard)
- Use descriptive variable and function names

### Error Handling
- Always use specific exception types
- Provide meaningful error messages
- Log errors with appropriate severity levels
- Include context information in error responses

### Security Requirements
- Never log sensitive information (tokens, secrets, passwords)
- Validate all input parameters
- Use secure random generation for session IDs
- Implement proper CSRF protection for OAuth flows

## OAuth Implementation Standards

### Provider Implementation
- All providers must inherit from BaseProvider
- Implement all required abstract methods
- Follow OAuth 2.0 specification strictly
- Support PKCE when available
- Handle token refresh automatically

### Session Management
- Use UUID4 for session IDs
- Implement session expiration
- Support concurrent sessions per user
- Clean up expired sessions automatically

## API Design Principles

### Response Format
- Use standardized APIResponse class
- Include success/error status
- Provide meaningful error codes
- Include request timestamps

### Endpoint Naming
- Use RESTful conventions
- Version APIs appropriately (/api/v1/)
- Use plural nouns for collections
- Keep URLs lowercase with hyphens

## Testing Requirements

### Test Coverage
- Minimum 80% code coverage
- Test all OAuth flows end-to-end
- Include error condition testing
- Test concurrent access scenarios

### Test Organization
- Unit tests in tests/ directory
- Integration tests in dev/tests/
- Performance tests separate from functional tests
- Mock external API calls in unit tests

## Documentation Standards

### Code Documentation
- Docstrings for all public functions and classes
- Include parameter types and descriptions
- Provide usage examples for complex functions
- Document security considerations

### API Documentation
- OpenAPI/Swagger specifications
- Include request/response examples
- Document error conditions
- Provide integration guides