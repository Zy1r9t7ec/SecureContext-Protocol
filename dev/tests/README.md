# Development Test Files

This directory contains standalone test files for specific features and comprehensive testing suites.

## Test Categories

### Core Functionality Tests
- `core_functionality_test.py` - OAuth flows, token management, API endpoints
- `security_test.py` - Security vulnerabilities, authentication, CSRF protection
- `config_environment_test.py` - Configuration validation, environment setup

### Feature-Specific Tests
- `ui_comprehensive_test.py` - User interface, accessibility, cross-browser testing
- `api_integration_test.py` - API endpoint integration and response validation
- `provider_extensibility_test.py` - Provider system extensibility and configuration
- `test_agent_integration.py` - Agent framework integration (LangChain, CrewAI, AutoGen)
- `test_marketplace.py` - Agent marketplace functionality
- `test_streaming.py` - Real-time data streaming capabilities
- `test_live_provider_extensibility.py` - Live provider testing with real OAuth

### Performance Tests
- `performance_scalability_test_comprehensive.py` - Comprehensive performance and scalability testing
- `performance_test_simple_app.py` - Simplified Flask app for isolated performance testing

### Master Test Runner
- `comprehensive_test.py` - Runs all test suites with comprehensive reporting

## Running Tests

### Individual Tests
```bash
python dev/tests/core_functionality_test.py
python dev/tests/security_test.py
python dev/tests/performance_scalability_test_comprehensive.py
```

### All Tests
```bash
python dev/tests/comprehensive_test.py
```

## Test Requirements

Most tests can run independently, but some require:
- OAuth credentials in `.env` file
- Redis server (for performance tests)
- Internet connection (for live provider tests)

See individual test files for specific requirements.