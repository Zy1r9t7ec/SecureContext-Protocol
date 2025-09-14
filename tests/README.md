# SecureContext Protocol - Test Suite

This directory contains comprehensive unit tests for the SecureContext Protocol Authentication Proxy.

## Test Coverage

### 1. Token Storage System Tests (`test_token_storage.py`)
- **23 tests** covering the core token storage functionality
- Session ID generation and validation
- Token storage and retrieval operations
- Token cleanup mechanisms
- Session isolation and security
- Thread safety and concurrent access
- Storage limits and memory management

### 2. OAuth Flow Handler Tests (`test_oauth_flows.py`)
- **25 tests** covering OAuth 2.0 authentication flows
- Google and Microsoft OAuth authorization endpoints
- OAuth callback handling and token exchange
- Error scenarios (user denial, invalid codes, network errors)
- State parameter validation for CSRF protection
- Authorization flow isolation between providers

### 3. API Endpoint Tests (`test_api_endpoints.py`)
- **21 tests** covering REST API functionality
- Token retrieval endpoint with valid/invalid session IDs
- JSON response formatting and consistency
- API security and input validation
- Error handling and proper HTTP status codes
- Storage statistics endpoint
- Concurrent access and session isolation

## Test Requirements Mapping

The tests verify compliance with the following requirements from the specification:

### Token Storage System (Requirements 8.1, 8.3)
- ✅ In-memory token storage with session isolation
- ✅ Session ID generation and validation
- ✅ Token cleanup mechanisms
- ✅ Thread-safe concurrent access

### OAuth Flow Handlers (Requirements 1.1-1.6, 2.1-2.6, 7.1-7.4)
- ✅ Google OAuth 2.0 authorization flow
- ✅ Microsoft OAuth 2.0 authorization flow
- ✅ State parameter CSRF protection
- ✅ Error handling for user denial and invalid requests
- ✅ Token exchange and storage

### API Endpoints (Requirements 4.1-4.4)
- ✅ Token retrieval with session ID validation
- ✅ JSON response formatting
- ✅ Error responses for invalid session IDs
- ✅ API security and input validation

## Running Tests

### Run All Tests
```bash
python -m pytest tests/ -v
```

### Run Specific Test Modules
```bash
# Token storage tests
python -m pytest tests/test_token_storage.py -v

# OAuth flow tests
python -m pytest tests/test_oauth_flows.py -v

# API endpoint tests
python -m pytest tests/test_api_endpoints.py -v
```

### Run Tests with Coverage
```bash
pip install pytest-cov
python -m pytest tests/ --cov=authentication_proxy --cov-report=html
```

## Test Environment Setup

The tests require the following dependencies:
- Flask 2.3.3
- Authlib 1.2.1
- python-dotenv 1.0.0
- requests 2.31.0
- pytest

Environment variables are loaded from `.env` file for testing configuration.

## Test Architecture

### Mocking Strategy
- OAuth clients are mocked to simulate provider responses
- Network errors are simulated using mock exceptions
- Token storage operations use real implementation for integration testing

### Test Isolation
- Each test method clears token storage before and after execution
- Session IDs are generated uniquely for each test
- Flask test client provides isolated request contexts

### Security Testing
- Input validation with malicious payloads
- Session isolation verification
- Error message security (no information leakage)
- CSRF protection validation

## Test Results Summary

- **Total Tests**: 69
- **Passing**: 69 (100%)
- **Coverage**: Core functionality, error handling, security, and edge cases
- **Performance**: Concurrent access and thread safety verified

All tests pass successfully, providing confidence in the implementation's correctness, security, and reliability.