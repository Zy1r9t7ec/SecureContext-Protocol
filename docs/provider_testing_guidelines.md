# Provider Testing Guidelines

This document provides comprehensive guidelines for testing OAuth providers in the SecureContext Protocol. Following these guidelines ensures that your provider implementation is robust, secure, and reliable.

## Table of Contents

- [Testing Philosophy](#testing-philosophy)
- [Test Categories](#test-categories)
- [Unit Testing](#unit-testing)
- [Integration Testing](#integration-testing)
- [Security Testing](#security-testing)
- [Performance Testing](#performance-testing)
- [Error Handling Testing](#error-handling-testing)
- [Test Data Management](#test-data-management)
- [Mocking Strategies](#mocking-strategies)
- [Continuous Integration](#continuous-integration)

## Testing Philosophy

### Core Principles

1. **Comprehensive Coverage**: Test all code paths, including error scenarios
2. **Isolation**: Each test should be independent and not rely on external services
3. **Repeatability**: Tests should produce consistent results across environments
4. **Clarity**: Test names and assertions should clearly indicate what is being tested
5. **Maintainability**: Tests should be easy to update when requirements change

### Test Pyramid Structure

```
    /\
   /  \     E2E Tests (Few)
  /____\    Integration Tests (Some)
 /      \   Unit Tests (Many)
/__________\
```

- **Unit Tests (70%)**: Test individual methods and classes in isolation
- **Integration Tests (20%)**: Test component interactions and OAuth flows
- **End-to-End Tests (10%)**: Test complete user workflows

## Test Categories

### 1. Unit Tests
- Provider class initialization
- Method behavior with valid inputs
- Method behavior with invalid inputs
- Error handling and exception raising
- Utility method functionality

### 2. Integration Tests
- Complete OAuth flow testing
- Provider manager integration
- Flask route integration
- Token storage integration

### 3. Security Tests
- State parameter validation
- CSRF protection
- Token isolation
- Input sanitization

### 4. Performance Tests
- Response time benchmarks
- Concurrent request handling
- Memory usage validation
- Rate limiting behavior

### 5. Error Handling Tests
- Network failure scenarios
- OAuth provider errors
- Invalid response handling
- Timeout scenarios

## Unit Testing

### Test Structure

Use the standard Arrange-Act-Assert pattern:

```python
def test_method_name_scenario(self):
    """Test description explaining what is being tested."""
    # Arrange: Set up test data and mocks
    provider = YourProvider(valid_config)
    expected_result = "expected_value"
    
    # Act: Execute the method being tested
    result = provider.method_under_test(test_input)
    
    # Assert: Verify the result
    self.assertEqual(result, expected_result)
```

### Required Unit Tests

#### Provider Initialization Tests

```python
def test_initialization_success(self):
    """Test successful provider initialization with valid configuration."""
    config = {
        'client_id': 'test_client_id',
        'client_secret': 'test_client_secret',
        'scopes': ['scope1', 'scope2']
    }
    
    provider = YourProvider(config)
    
    self.assertEqual(provider.name, 'your_provider')
    self.assertEqual(provider.client_id, 'test_client_id')
    self.assertEqual(provider.client_secret, 'test_client_secret')
    self.assertEqual(provider.scopes, ['scope1', 'scope2'])

def test_initialization_missing_client_id(self):
    """Test provider initialization fails with missing client_id."""
    config = {'client_secret': 'test_client_secret'}
    
    with self.assertRaises(ProviderConfigurationError) as context:
        YourProvider(config)
    
    self.assertIn('client_id', str(context.exception))

def test_initialization_with_defaults(self):
    """Test provider initialization uses default values correctly."""
    minimal_config = {
        'client_id': 'test_client_id',
        'client_secret': 'test_client_secret'
    }
    
    provider = YourProvider(minimal_config)
    
    self.assertIsNotNone(provider.authorize_url)
    self.assertIsNotNone(provider.token_url)
    self.assertIsInstance(provider.scopes, list)
```

#### Authorization URL Tests

```python
def test_get_authorization_url_success(self):
    """Test successful authorization URL generation."""
    redirect_uri = 'http://localhost:5000/callback'
    state = 'test_state_123'
    
    auth_url = self.provider.get_authorization_url(redirect_uri, state)
    
    self.assertIsInstance(auth_url, str)
    self.assertTrue(auth_url.startswith(self.provider.authorize_url))
    self.assertIn('client_id=', auth_url)
    self.assertIn('redirect_uri=', auth_url)
    self.assertIn('state=test_state_123', auth_url)

def test_get_authorization_url_custom_scope(self):
    """Test authorization URL generation with custom scope."""
    custom_scope = 'custom_scope1 custom_scope2'
    
    auth_url = self.provider.get_authorization_url(
        'http://localhost:5000/callback', 
        'test_state', 
        scope=custom_scope
    )
    
    self.assertIn('scope=custom_scope1', auth_url)

def test_get_authorization_url_error_handling(self):
    """Test authorization URL generation error handling."""
    with patch.object(self.provider, 'authorize_url', None):
        with self.assertRaises(OAuthFlowError):
            self.provider.get_authorization_url('http://localhost:5000/callback', 'state')
```

#### Token Exchange Tests

```python
@patch('requests.post')
def test_exchange_code_for_tokens_success(self, mock_post):
    """Test successful authorization code to token exchange."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'access_token': 'test_access_token',
        'refresh_token': 'test_refresh_token',
        'expires_in': 3600,
        'scope': 'scope1 scope2'
    }
    mock_response.headers = {'content-type': 'application/json'}
    mock_post.return_value = mock_response
    
    result = self.provider.exchange_code_for_tokens('test_code', 'http://localhost:5000/callback')
    
    # Verify request was made correctly
    mock_post.assert_called_once()
    call_args = mock_post.call_args
    self.assertEqual(call_args[1]['data']['code'], 'test_code')
    self.assertEqual(call_args[1]['data']['grant_type'], 'authorization_code')
    
    # Verify response format
    self.assertEqual(result['access_token'], 'test_access_token')
    self.assertEqual(result['refresh_token'], 'test_refresh_token')
    self.assertEqual(result['expires_in'], 3600)

@patch('requests.post')
def test_exchange_code_for_tokens_http_error(self, mock_post):
    """Test token exchange with HTTP error response."""
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {
        'error': 'invalid_grant',
        'error_description': 'Invalid authorization code'
    }
    mock_response.headers = {'content-type': 'application/json'}
    mock_post.return_value = mock_response
    
    with self.assertRaises(OAuthFlowError) as context:
        self.provider.exchange_code_for_tokens('invalid_code', 'http://localhost:5000/callback')
    
    self.assertIn('Token exchange failed', str(context.exception))

@patch('requests.post')
def test_exchange_code_for_tokens_network_error(self, mock_post):
    """Test token exchange with network error."""
    mock_post.side_effect = ConnectionError('Network connection failed')
    
    with self.assertRaises(OAuthFlowError) as context:
        self.provider.exchange_code_for_tokens('test_code', 'http://localhost:5000/callback')
    
    self.assertIn('Network connection failed', str(context.exception))
```

#### Scope Validation Tests

```python
def test_validate_scopes_valid(self):
    """Test scope validation with valid scopes."""
    valid_scopes = ['scope1', 'scope2']
    result = self.provider.validate_scopes(valid_scopes)
    self.assertTrue(result)

def test_validate_scopes_invalid(self):
    """Test scope validation with invalid scopes."""
    invalid_scopes = ['invalid_scope']
    result = self.provider.validate_scopes(invalid_scopes)
    self.assertFalse(result)

def test_validate_scopes_empty(self):
    """Test scope validation with empty scope list."""
    empty_scopes = []
    result = self.provider.validate_scopes(empty_scopes)
    self.assertTrue(result)
```

### Test Coverage Requirements

Aim for at least 90% code coverage for provider implementations:

```bash
# Run tests with coverage
python -m pytest tests/test_your_provider.py --cov=authentication_proxy.providers.your_provider --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Integration Testing

### OAuth Flow Integration Tests

```python
def test_complete_oauth_flow(self):
    """Test complete OAuth flow from authorization to token retrieval."""
    # Test authorization endpoint
    response = self.client.get('/oauth/your_provider/authorize')
    self.assertEqual(response.status_code, 302)
    self.assertIn('your_provider_domain.com', response.location)
    
    # Verify state was stored in session
    with self.client.session_transaction() as sess:
        self.assertIsNotNone(sess.get('oauth_state'))
        self.assertEqual(sess.get('oauth_provider'), 'your_provider')
    
    # Test callback with mock token exchange
    with self.client.session_transaction() as sess:
        sess['oauth_state'] = 'test_state'
        sess['oauth_provider'] = 'your_provider'
    
    mock_token_response = {
        'access_token': 'test_token',
        'refresh_token': 'test_refresh',
        'expires_in': 3600,
        'scope': 'scope1 scope2'
    }
    
    with patch.object(self.app.provider_manager, 'get_provider') as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.validate_state.return_value = True
        mock_provider.exchange_code_for_tokens.return_value = mock_token_response
        mock_get_provider.return_value = mock_provider
        
        response = self.client.get('/oauth/your_provider/callback?code=test_code&state=test_state')
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('session_id=', response.location)
        
        # Verify token was stored
        session_id = self.extract_session_id(response.location)
        stored_token = TokenStorage.retrieve_tokens(session_id)
        self.assertIsNotNone(stored_token)
        self.assertEqual(stored_token['provider'], 'your_provider')
```

### Provider Manager Integration Tests

```python
def test_provider_registration(self):
    """Test provider registration with provider manager."""
    config = {
        'client_id': 'test_client_id',
        'client_secret': 'test_client_secret',
        'scopes': ['scope1', 'scope2']
    }
    
    provider = self.app.provider_manager.register_provider('your_provider', config)
    
    self.assertIsInstance(provider, YourProvider)
    self.assertEqual(provider.name, 'your_provider')
    
    # Verify provider is accessible
    retrieved_provider = self.app.provider_manager.get_provider('your_provider')
    self.assertEqual(provider, retrieved_provider)

def test_dynamic_route_generation(self):
    """Test that OAuth routes are generated for the provider."""
    # Test authorization route exists
    response = self.client.get('/oauth/your_provider/authorize')
    self.assertNotEqual(response.status_code, 404)
    
    # Test callback route exists
    response = self.client.get('/oauth/your_provider/callback')
    # Should redirect due to missing parameters, not 404
    self.assertIn(response.status_code, [302, 400])
```

## Security Testing

### State Parameter Security Tests

```python
def test_state_parameter_uniqueness(self):
    """Test that state parameters are unique across requests."""
    states = set()
    
    for _ in range(100):
        state = self.provider.generate_state()
        self.assertNotIn(state, states, "State parameter collision detected")
        states.add(state)

def test_state_parameter_length(self):
    """Test that state parameters have sufficient entropy."""
    state = self.provider.generate_state()
    
    # Should be at least 32 characters for security
    self.assertGreaterEqual(len(state), 32)
    
    # Should contain only URL-safe characters
    import string
    allowed_chars = string.ascii_letters + string.digits + '-_'
    self.assertTrue(all(c in allowed_chars for c in state))

def test_state_validation_prevents_csrf(self):
    """Test that state validation prevents CSRF attacks."""
    # Valid state validation
    self.assertTrue(self.provider.validate_state('same_state', 'same_state'))
    
    # Invalid state validation
    self.assertFalse(self.provider.validate_state('state1', 'state2'))
    self.assertFalse(self.provider.validate_state(None, 'state'))
    self.assertFalse(self.provider.validate_state('state', None))
```

### Input Sanitization Tests

```python
def test_authorization_url_parameter_sanitization(self):
    """Test that authorization URL parameters are properly sanitized."""
    malicious_redirect_uri = 'http://evil.com/callback"><script>alert("xss")</script>'
    malicious_state = '<script>alert("xss")</script>'
    
    # Should not crash and should properly encode parameters
    try:
        auth_url = self.provider.get_authorization_url(malicious_redirect_uri, malicious_state)
        self.assertIsInstance(auth_url, str)
        # Verify dangerous characters are encoded
        self.assertNotIn('<script>', auth_url)
        self.assertNotIn('alert(', auth_url)
    except Exception as e:
        # If provider rejects malicious input, that's also acceptable
        self.assertIsInstance(e, (OAuthFlowError, ValueError))

def test_token_response_validation(self):
    """Test that token responses are properly validated."""
    # Test with missing access_token
    invalid_response = {
        'refresh_token': 'test_refresh',
        'expires_in': 3600
    }
    
    self.assertFalse(self.provider.validate_token_response(invalid_response))
    
    # Test with invalid expires_in
    invalid_response = {
        'access_token': 'test_token',
        'expires_in': 'invalid'
    }
    
    self.assertFalse(self.provider.validate_token_response(invalid_response))
```

## Performance Testing

### Response Time Tests

```python
def test_authorization_url_generation_performance(self):
    """Test authorization URL generation performance."""
    import time
    
    start_time = time.time()
    
    for _ in range(1000):
        auth_url = self.provider.get_authorization_url(
            'http://localhost:5000/callback', 
            f'state_{_}'
        )
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Should complete 1000 URL generations in under 1 second
    self.assertLess(duration, 1.0, f"URL generation too slow: {duration:.3f}s")

def test_concurrent_state_generation(self):
    """Test concurrent state parameter generation."""
    import threading
    import time
    
    states = []
    
    def generate_states():
        for _ in range(100):
            states.append(self.provider.generate_state())
    
    start_time = time.time()
    
    threads = []
    for _ in range(10):
        thread = threading.Thread(target=generate_states)
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Should complete in reasonable time
    self.assertLess(duration, 2.0, f"Concurrent state generation too slow: {duration:.3f}s")
    
    # All states should be unique
    self.assertEqual(len(states), len(set(states)), "State collision in concurrent generation")
```

### Memory Usage Tests

```python
def test_memory_usage_token_storage(self):
    """Test memory usage doesn't grow excessively with token storage."""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss
    
    # Store many tokens
    session_ids = []
    for i in range(1000):
        session_id = TokenStorage.store_tokens(
            provider='your_provider',
            access_token=f'token_{i}',
            refresh_token=f'refresh_{i}',
            expires_in=3600,
            scope='scope1 scope2'
        )
        session_ids.append(session_id)
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Memory increase should be reasonable (less than 10MB for 1000 tokens)
    self.assertLess(memory_increase, 10 * 1024 * 1024, 
                   f"Excessive memory usage: {memory_increase / 1024 / 1024:.2f}MB")
    
    # Clean up
    for session_id in session_ids:
        TokenStorage.retrieve_tokens(session_id)
```

## Error Handling Testing

### Network Error Scenarios

```python
@patch('requests.post')
def test_connection_error_handling(self, mock_post):
    """Test handling of network connection errors."""
    mock_post.side_effect = ConnectionError('Connection failed')
    
    with self.assertRaises(OAuthFlowError) as context:
        self.provider.exchange_code_for_tokens('test_code', 'http://localhost:5000/callback')
    
    error_message = str(context.exception)
    self.assertIn('connection', error_message.lower())
    # Should provide user-friendly message
    self.assertNotIn('ConnectionError', error_message)

@patch('requests.post')
def test_timeout_error_handling(self, mock_post):
    """Test handling of request timeout errors."""
    from requests.exceptions import Timeout
    mock_post.side_effect = Timeout('Request timed out')
    
    with self.assertRaises(OAuthFlowError) as context:
        self.provider.exchange_code_for_tokens('test_code', 'http://localhost:5000/callback')
    
    error_message = str(context.exception)
    self.assertIn('timeout', error_message.lower())

@patch('requests.post')
def test_generic_request_error_handling(self, mock_post):
    """Test handling of generic request errors."""
    from requests.exceptions import RequestException
    mock_post.side_effect = RequestException('Generic request error')
    
    with self.assertRaises(OAuthFlowError) as context:
        self.provider.exchange_code_for_tokens('test_code', 'http://localhost:5000/callback')
    
    self.assertIsInstance(context.exception, OAuthFlowError)
```

### OAuth Provider Error Scenarios

```python
@patch('requests.post')
def test_oauth_error_responses(self, mock_post):
    """Test handling of various OAuth error responses."""
    error_scenarios = [
        ('invalid_grant', 'Invalid authorization code'),
        ('invalid_client', 'Invalid client credentials'),
        ('invalid_request', 'Malformed request'),
        ('unsupported_grant_type', 'Unsupported grant type')
    ]
    
    for error_code, error_description in error_scenarios:
        with self.subTest(error_code=error_code):
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.json.return_value = {
                'error': error_code,
                'error_description': error_description
            }
            mock_response.headers = {'content-type': 'application/json'}
            mock_post.return_value = mock_response
            
            with self.assertRaises(OAuthFlowError) as context:
                self.provider.exchange_code_for_tokens('test_code', 'http://localhost:5000/callback')
            
            self.assertIn(error_description, str(context.exception))
```

## Test Data Management

### Test Configuration

```python
class TestYourProvider(unittest.TestCase):
    """Test cases for Your Provider OAuth provider."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test class with shared test data."""
        cls.valid_config = {
            'client_id': 'test_client_id_123',
            'client_secret': 'test_client_secret_456',
            'scopes': ['scope1', 'scope2', 'scope3']
        }
        
        cls.test_urls = {
            'redirect_uri': 'http://localhost:5000/oauth/your_provider/callback',
            'authorize_url': 'https://provider.com/oauth/authorize',
            'token_url': 'https://provider.com/oauth/token'
        }
        
        cls.mock_responses = {
            'token_success': {
                'access_token': 'test_access_token_789',
                'refresh_token': 'test_refresh_token_012',
                'expires_in': 3600,
                'scope': 'scope1 scope2 scope3',
                'token_type': 'Bearer'
            },
            'user_info_success': {
                'id': 'test_user_id_345',
                'email': 'test@example.com',
                'name': 'Test User'
            }
        }
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.provider = YourProvider(self.valid_config)
        self.test_state = 'test_state_parameter_123'
        self.test_code = 'test_authorization_code_456'
```

### Test Data Factories

```python
class TestDataFactory:
    """Factory for generating test data."""
    
    @staticmethod
    def create_provider_config(**overrides):
        """Create a provider configuration with optional overrides."""
        default_config = {
            'client_id': 'test_client_id',
            'client_secret': 'test_client_secret',
            'scopes': ['scope1', 'scope2'],
            'display_name': 'Test Provider'
        }
        return {**default_config, **overrides}
    
    @staticmethod
    def create_token_response(**overrides):
        """Create a token response with optional overrides."""
        default_response = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'expires_in': 3600,
            'scope': 'scope1 scope2',
            'token_type': 'Bearer'
        }
        return {**default_response, **overrides}
    
    @staticmethod
    def create_user_info(**overrides):
        """Create user info response with optional overrides."""
        default_user_info = {
            'id': 'test_user_id',
            'email': 'test@example.com',
            'name': 'Test User'
        }
        return {**default_user_info, **overrides}
```

## Mocking Strategies

### HTTP Request Mocking

```python
# Use patch decorator for single method mocking
@patch('requests.post')
def test_method(self, mock_post):
    mock_post.return_value = mock_response

# Use context manager for multiple mocks
def test_method(self):
    with patch('requests.post') as mock_post, \
         patch('requests.get') as mock_get:
        # Configure mocks
        mock_post.return_value = mock_token_response
        mock_get.return_value = mock_user_response
        
        # Execute test
        result = self.provider.some_method()

# Use patch.object for mocking specific methods
@patch.object(YourProvider, 'validate_token_response')
def test_method(self, mock_validate):
    mock_validate.return_value = True
    # Test continues...
```

### Response Mocking Patterns

```python
def create_mock_response(status_code=200, json_data=None, headers=None):
    """Create a mock HTTP response."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = json_data or {}
    mock_response.headers = headers or {'content-type': 'application/json'}
    return mock_response

# Usage
mock_response = create_mock_response(
    status_code=200,
    json_data={'access_token': 'test_token'},
    headers={'content-type': 'application/json'}
)
```

## Continuous Integration

### GitHub Actions Configuration

Create `.github/workflows/test-providers.yml`:

```yaml
name: Provider Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, '3.10', 3.11]

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v3
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-cov
    
    - name: Run provider tests
      run: |
        python -m pytest tests/test_*_provider.py -v --cov=authentication_proxy.providers --cov-report=xml
    
    - name: Run integration tests
      run: |
        python -m pytest tests/test_integration.py -v
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: providers
        name: provider-tests
```

### Pre-commit Hooks

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 22.3.0
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/pycqa/flake8
    rev: 4.0.1
    hooks:
      - id: flake8
        args: [--max-line-length=88, --extend-ignore=E203]

  - repo: local
    hooks:
      - id: provider-tests
        name: Provider Tests
        entry: python -m pytest tests/test_*_provider.py
        language: system
        pass_filenames: false
        always_run: true
```

### Test Coverage Requirements

Set minimum coverage thresholds in `pytest.ini`:

```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    --cov=authentication_proxy.providers
    --cov-report=html
    --cov-report=term-missing
    --cov-fail-under=90
    --strict-markers
    --disable-warnings
markers =
    unit: Unit tests
    integration: Integration tests
    security: Security tests
    performance: Performance tests
```

## Best Practices Summary

### Do's ✅

- **Write tests first** (TDD approach)
- **Test both success and failure scenarios**
- **Use descriptive test names** that explain the scenario
- **Mock external dependencies** (HTTP requests, time, random)
- **Test edge cases** and boundary conditions
- **Verify error messages** are user-friendly
- **Test concurrent scenarios** where applicable
- **Use test data factories** for consistent test data
- **Measure and maintain high test coverage**
- **Run tests in CI/CD pipeline**

### Don'ts ❌

- **Don't test external services directly** in unit tests
- **Don't use real OAuth credentials** in tests
- **Don't write tests that depend on each other**
- **Don't ignore flaky tests** - fix them
- **Don't test implementation details** - test behavior
- **Don't use sleep()** in tests - use proper mocking
- **Don't commit failing tests**
- **Don't skip security tests**
- **Don't test only happy paths**
- **Don't use production data** in tests

Following these guidelines will ensure your OAuth provider implementation is robust, secure, and maintainable. Remember that good tests are an investment in the long-term health of your code.