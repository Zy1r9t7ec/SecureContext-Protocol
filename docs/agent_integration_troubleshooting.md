# Agent Integration Troubleshooting Guide

This comprehensive guide helps diagnose and resolve common issues when integrating AI agents with the SecureContext Protocol (SCP).

## Table of Contents

1. [Common Issues Overview](#common-issues-overview)
2. [Authentication and OAuth Issues](#authentication-and-oauth-issues)
3. [Session Management Issues](#session-management-issues)
4. [Data Access Issues](#data-access-issues)
5. [Performance Issues](#performance-issues)
6. [Framework-Specific Issues](#framework-specific-issues)
7. [Network and Connectivity Issues](#network-and-connectivity-issues)
8. [Configuration Issues](#configuration-issues)
9. [Debugging Tools and Techniques](#debugging-tools-and-techniques)
10. [Error Code Reference](#error-code-reference)

## Common Issues Overview

### Issue Categories by Frequency

| Issue Type | Frequency | Typical Cause | Resolution Time |
|------------|-----------|---------------|-----------------|
| OAuth Token Expired | Very High | Token lifecycle | < 5 minutes |
| Invalid Session ID | High | Session management | < 10 minutes |
| Rate Limiting | High | API usage patterns | 15-30 minutes |
| Network Timeouts | Medium | Infrastructure | 10-60 minutes |
| Configuration Errors | Medium | Setup issues | 30-120 minutes |
| Framework Integration | Low | Code issues | 1-4 hours |

### Quick Diagnostic Checklist

Before diving into specific issues, run through this quick checklist:

```python
# Quick SCP Health Check Script
import requests
import json
from datetime import datetime

def quick_health_check(base_url: str = "http://localhost:5000"):
    """Run a quick health check on SCP components."""
    
    print("=== SCP Quick Health Check ===")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Base URL: {base_url}")
    print()
    
    checks = {
        "Server Connectivity": check_server_connectivity,
        "Health Endpoint": check_health_endpoint,
        "Provider Configuration": check_provider_config,
        "Session Creation": check_session_creation,
        "Token Retrieval": check_token_retrieval
    }
    
    results = {}
    for check_name, check_func in checks.items():
        try:
            result = check_func(base_url)
            results[check_name] = {"status": "PASS", "details": result}
            print(f"✅ {check_name}: PASS")
        except Exception as e:
            results[check_name] = {"status": "FAIL", "error": str(e)}
            print(f"❌ {check_name}: FAIL - {e}")
    
    return results

def check_server_connectivity(base_url: str):
    response = requests.get(f"{base_url}/", timeout=5)
    return f"Status: {response.status_code}"

def check_health_endpoint(base_url: str):
    response = requests.get(f"{base_url}/health", timeout=5)
    data = response.json()
    return f"Status: {data.get('status', 'unknown')}"

def check_provider_config(base_url: str):
    response = requests.get(f"{base_url}/api/providers", timeout=5)
    data = response.json()
    return f"Providers: {len(data.get('providers', []))}"

def check_session_creation(base_url: str):
    # This would require a test OAuth flow
    return "Manual test required"

def check_token_retrieval(base_url: str):
    # Test with a known invalid session ID
    response = requests.get(f"{base_url}/api/tokens/invalid_session", timeout=5)
    return f"Expected 404, got: {response.status_code}"

# Run the health check
if __name__ == "__main__":
    results = quick_health_check()
    print(f"\nHealth check completed. Issues found: {sum(1 for r in results.values() if r['status'] == 'FAIL')}")
```

## Authentication and OAuth Issues

### Issue: OAuth Token Expired

**Symptoms:**
- API calls return 401 Unauthorized
- Error messages about invalid or expired tokens
- Agent workflows fail after working initially

**Diagnosis:**
```python
def diagnose_token_expiry(session_id: str, base_url: str = "http://localhost:5000"):
    """Diagnose token expiry issues."""
    
    try:
        response = requests.get(f"{base_url}/api/tokens/{session_id}")
        
        if response.status_code == 404:
            return "Session not found - may have expired or been cleaned up"
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                expires_at = data['data'].get('expires_at')
                if expires_at:
                    from datetime import datetime
                    expiry_time = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                    current_time = datetime.now()
                    
                    if current_time > expiry_time:
                        return f"Token expired at {expires_at}"
                    else:
                        time_remaining = expiry_time - current_time
                        return f"Token valid for {time_remaining}"
                
        return f"Unexpected response: {response.status_code}"
        
    except Exception as e:
        return f"Error checking token: {e}"

# Usage
print(diagnose_token_expiry("your_session_id"))
```

**Solutions:**

1. **Implement Token Refresh:**
```python
from scp_sdk import SCPClient
import time

class TokenRefreshHandler:
    def __init__(self, session_id: str):
        self.scp_client = SCPClient()
        self.session_id = session_id
        self.last_refresh = 0
        self.refresh_threshold = 300  # Refresh 5 minutes before expiry
    
    def get_valid_token(self):
        """Get a valid token, refreshing if necessary."""
        try:
            token_info = self.scp_client.get_tokens(self.session_id)
            
            if self.should_refresh_token(token_info):
                token_info = self.refresh_token()
            
            return token_info
            
        except Exception as e:
            print(f"Error getting valid token: {e}")
            raise
    
    def should_refresh_token(self, token_info):
        if not token_info or 'expires_at' not in token_info:
            return True
        
        from datetime import datetime
        expires_at = datetime.fromisoformat(token_info['expires_at'])
        current_time = datetime.now()
        
        # Refresh if token expires within threshold
        return (expires_at - current_time).total_seconds() < self.refresh_threshold
    
    def refresh_token(self):
        """Refresh the token using refresh token."""
        current_time = time.time()
        
        # Prevent too frequent refresh attempts
        if current_time - self.last_refresh < 60:
            raise Exception("Token refresh attempted too recently")
        
        try:
            refreshed_tokens = self.scp_client.refresh_tokens(self.session_id)
            self.last_refresh = current_time
            return refreshed_tokens
        except Exception as e:
            print(f"Token refresh failed: {e}")
            raise
```

2. **Automatic Re-authentication:**
```python
def with_auto_reauth(func):
    """Decorator to automatically handle re-authentication."""
    def wrapper(self, *args, **kwargs):
        max_retries = 2
        for attempt in range(max_retries):
            try:
                return func(self, *args, **kwargs)
            except Exception as e:
                if "401" in str(e) or "unauthorized" in str(e).lower():
                    if attempt < max_retries - 1:
                        print(f"Authentication failed, attempting re-auth (attempt {attempt + 1})")
                        self.reauthenticate()
                        continue
                raise e
    return wrapper

class ResilientSCPAgent:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.scp_client = SCPClient()
    
    def reauthenticate(self):
        """Trigger re-authentication flow."""
        # Implementation depends on your authentication strategy
        print(f"Re-authentication required for session {self.session_id}")
        # You might need to redirect user to OAuth flow again
    
    @with_auto_reauth
    def get_user_emails(self, provider: str = "google"):
        return self.scp_client.get_data(
            session_id=self.session_id,
            provider=provider,
            data_type="emails"
        )
```

### Issue: OAuth State Parameter Mismatch

**Symptoms:**
- OAuth callback fails with state validation error
- Security warnings in logs
- Users redirected to error page after OAuth consent

**Diagnosis:**
```python
def diagnose_oauth_state_issue():
    """Check for common OAuth state parameter issues."""
    
    issues = []
    
    # Check session configuration
    import os
    if not os.environ.get('FLASK_SECRET_KEY'):
        issues.append("FLASK_SECRET_KEY not set - required for secure sessions")
    
    # Check for session persistence
    try:
        from flask import session
        if not session.permanent:
            issues.append("Sessions not configured as permanent")
    except:
        issues.append("Flask session not available")
    
    # Check state parameter generation
    import secrets
    state = secrets.token_urlsafe(32)
    if len(state) < 20:
        issues.append("State parameter too short")
    
    return issues

# Check for issues
issues = diagnose_oauth_state_issue()
for issue in issues:
    print(f"⚠️  {issue}")
```

**Solutions:**

1. **Proper State Parameter Handling:**
```python
import secrets
from flask import session, request, redirect, url_for

def generate_oauth_state():
    """Generate secure state parameter."""
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session.permanent = True
    return state

def validate_oauth_state(received_state):
    """Validate OAuth state parameter."""
    stored_state = session.get('oauth_state')
    
    if not stored_state:
        raise ValueError("No stored state found in session")
    
    if not received_state:
        raise ValueError("No state parameter received")
    
    if stored_state != received_state:
        raise ValueError("State parameter mismatch - possible CSRF attack")
    
    # Clear used state
    session.pop('oauth_state', None)
    return True

@app.route('/oauth/<provider>/callback')
def oauth_callback(provider):
    try:
        state = request.args.get('state')
        validate_oauth_state(state)
        
        # Continue with OAuth flow
        code = request.args.get('code')
        # ... rest of callback handling
        
    except ValueError as e:
        return redirect(url_for('index', error=str(e)))
```

## Session Management Issues

### Issue: Session ID Not Found

**Symptoms:**
- 404 errors when retrieving tokens
- "Session not found" error messages
- Agent workflows fail to access user data

**Diagnosis:**
```python
def diagnose_session_issues(session_id: str, base_url: str = "http://localhost:5000"):
    """Comprehensive session diagnosis."""
    
    print(f"Diagnosing session: {session_id}")
    
    # Check session ID format
    if not session_id or len(session_id) < 10:
        return "Invalid session ID format"
    
    # Check if session exists
    try:
        response = requests.get(f"{base_url}/api/tokens/{session_id}")
        
        if response.status_code == 404:
            # Check if session was recently created
            return check_recent_sessions(base_url)
        elif response.status_code == 200:
            data = response.json()
            return f"Session found: {data.get('data', {}).get('provider', 'unknown provider')}"
        else:
            return f"Unexpected response: {response.status_code}"
            
    except Exception as e:
        return f"Error checking session: {e}"

def check_recent_sessions(base_url: str):
    """Check for recently created sessions."""
    try:
        # This would require an admin endpoint to list sessions
        response = requests.get(f"{base_url}/api/admin/sessions")
        if response.status_code == 200:
            sessions = response.json().get('sessions', [])
            return f"Found {len(sessions)} active sessions"
        else:
            return "Cannot check recent sessions - admin endpoint not available"
    except:
        return "Cannot check recent sessions"
```

**Solutions:**

1. **Session Persistence Check:**
```python
class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.session_timeout = 3600  # 1 hour
    
    def create_session(self, user_id: str, provider: str, tokens: dict) -> str:
        """Create a new session with proper tracking."""
        import uuid
        import time
        
        session_id = str(uuid.uuid4())
        
        self.sessions[session_id] = {
            'user_id': user_id,
            'provider': provider,
            'tokens': tokens,
            'created_at': time.time(),
            'last_accessed': time.time()
        }
        
        print(f"Created session {session_id} for user {user_id}")
        return session_id
    
    def get_session(self, session_id: str) -> dict:
        """Get session with automatic cleanup."""
        import time
        
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        current_time = time.time()
        
        # Check if session has expired
        if current_time - session['created_at'] > self.session_timeout:
            del self.sessions[session_id]
            raise ValueError(f"Session {session_id} has expired")
        
        # Update last accessed time
        session['last_accessed'] = current_time
        return session
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        import time
        
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if current_time - session['created_at'] > self.session_timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
            print(f"Cleaned up expired session {session_id}")
        
        return len(expired_sessions)
```

2. **Session Recovery Mechanism:**
```python
class SessionRecovery:
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.recovery_cache = {}
    
    def attempt_session_recovery(self, session_id: str, user_id: str = None):
        """Attempt to recover a lost session."""
        
        # Check if session exists in recovery cache
        if session_id in self.recovery_cache:
            cached_session = self.recovery_cache[session_id]
            
            # Validate cached session
            if self.validate_cached_session(cached_session):
                # Restore session
                self.session_manager.sessions[session_id] = cached_session
                del self.recovery_cache[session_id]
                return True
        
        # If user_id provided, check for alternative sessions
        if user_id:
            alternative_session = self.find_alternative_session(user_id)
            if alternative_session:
                return alternative_session
        
        return None
    
    def validate_cached_session(self, session: dict) -> bool:
        """Validate a cached session."""
        required_fields = ['user_id', 'provider', 'tokens', 'created_at']
        return all(field in session for field in required_fields)
    
    def find_alternative_session(self, user_id: str) -> str:
        """Find alternative session for the same user."""
        for session_id, session in self.session_manager.sessions.items():
            if session.get('user_id') == user_id:
                return session_id
        return None
```

### Issue: Concurrent Session Conflicts

**Symptoms:**
- Data access conflicts between multiple agents
- Session data corruption
- Inconsistent authentication state

**Solutions:**

1. **Thread-Safe Session Management:**
```python
import threading
from typing import Dict, Any

class ThreadSafeSessionManager:
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.locks: Dict[str, threading.RLock] = {}
        self.global_lock = threading.RLock()
    
    def get_session_lock(self, session_id: str) -> threading.RLock:
        """Get or create a lock for a specific session."""
        with self.global_lock:
            if session_id not in self.locks:
                self.locks[session_id] = threading.RLock()
            return self.locks[session_id]
    
    def access_session(self, session_id: str, operation: callable, *args, **kwargs):
        """Thread-safe session access."""
        session_lock = self.get_session_lock(session_id)
        
        with session_lock:
            if session_id not in self.sessions:
                raise ValueError(f"Session {session_id} not found")
            
            return operation(self.sessions[session_id], *args, **kwargs)
    
    def update_session_tokens(self, session_id: str, new_tokens: Dict[str, Any]):
        """Thread-safe token update."""
        def update_operation(session, tokens):
            session['tokens'].update(tokens)
            session['last_updated'] = time.time()
            return session['tokens']
        
        return self.access_session(session_id, update_operation, new_tokens)
```

## Data Access Issues

### Issue: API Rate Limiting

**Symptoms:**
- 429 Too Many Requests errors
- Temporary failures followed by success
- Degraded performance during high usage

**Diagnosis:**
```python
import time
from collections import defaultdict, deque

class RateLimitMonitor:
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.request_times = defaultdict(lambda: deque())
        self.rate_limits = {}
    
    def record_request(self, provider: str, endpoint: str):
        """Record a request for rate limit monitoring."""
        key = f"{provider}:{endpoint}"
        current_time = time.time()
        
        # Add current request
        self.request_times[key].append(current_time)
        
        # Remove old requests outside the window
        cutoff_time = current_time - self.window_size
        while (self.request_times[key] and 
               self.request_times[key][0] < cutoff_time):
            self.request_times[key].popleft()
    
    def get_current_rate(self, provider: str, endpoint: str) -> float:
        """Get current request rate for provider/endpoint."""
        key = f"{provider}:{endpoint}"
        return len(self.request_times[key]) / self.window_size
    
    def is_rate_limited(self, provider: str, endpoint: str, limit: float) -> bool:
        """Check if current rate exceeds limit."""
        current_rate = self.get_current_rate(provider, endpoint)
        return current_rate >= limit
    
    def time_until_available(self, provider: str, endpoint: str, limit: float) -> float:
        """Calculate time until rate limit allows next request."""
        key = f"{provider}:{endpoint}"
        
        if not self.is_rate_limited(provider, endpoint, limit):
            return 0
        
        # Find the oldest request that needs to expire
        if self.request_times[key]:
            oldest_request = self.request_times[key][0]
            return oldest_request + self.window_size - time.time()
        
        return 0

rate_monitor = RateLimitMonitor()
```

**Solutions:**

1. **Exponential Backoff with Jitter:**
```python
import random
import asyncio

class RateLimitHandler:
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.attempt_count = defaultdict(int)
    
    async def execute_with_backoff(self, func, *args, **kwargs):
        """Execute function with exponential backoff on rate limits."""
        key = f"{func.__name__}:{hash(str(args))}"
        
        while True:
            try:
                result = await func(*args, **kwargs)
                # Reset attempt count on success
                self.attempt_count[key] = 0
                return result
                
            except Exception as e:
                if "429" in str(e) or "rate limit" in str(e).lower():
                    self.attempt_count[key] += 1
                    delay = self.calculate_delay(self.attempt_count[key])
                    
                    print(f"Rate limited, waiting {delay:.2f} seconds (attempt {self.attempt_count[key]})")
                    await asyncio.sleep(delay)
                    continue
                else:
                    # Reset attempt count on non-rate-limit errors
                    self.attempt_count[key] = 0
                    raise
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff and jitter."""
        delay = min(self.base_delay * (2 ** attempt), self.max_delay)
        # Add jitter to prevent thundering herd
        jitter = random.uniform(0.1, 0.3) * delay
        return delay + jitter

# Usage
rate_handler = RateLimitHandler()

async def rate_limited_api_call(session_id: str, provider: str):
    async def api_call():
        # Your actual API call here
        return scp_client.get_data(session_id=session_id, provider=provider, data_type="emails")
    
    return await rate_handler.execute_with_backoff(api_call)
```

2. **Request Queue with Rate Limiting:**
```python
import asyncio
from asyncio import Queue
from dataclasses import dataclass
from typing import Callable, Any

@dataclass
class QueuedRequest:
    func: Callable
    args: tuple
    kwargs: dict
    future: asyncio.Future

class RateLimitedQueue:
    def __init__(self, requests_per_second: float = 10):
        self.requests_per_second = requests_per_second
        self.queue = Queue()
        self.running = False
        self.worker_task = None
    
    async def start(self):
        """Start the queue worker."""
        self.running = True
        self.worker_task = asyncio.create_task(self._worker())
    
    async def stop(self):
        """Stop the queue worker."""
        self.running = False
        if self.worker_task:
            await self.worker_task
    
    async def enqueue(self, func: Callable, *args, **kwargs) -> Any:
        """Enqueue a request and wait for result."""
        future = asyncio.Future()
        request = QueuedRequest(func, args, kwargs, future)
        await self.queue.put(request)
        return await future
    
    async def _worker(self):
        """Process queued requests with rate limiting."""
        interval = 1.0 / self.requests_per_second
        
        while self.running:
            try:
                # Wait for next request or timeout
                request = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                
                try:
                    # Execute the request
                    if asyncio.iscoroutinefunction(request.func):
                        result = await request.func(*request.args, **request.kwargs)
                    else:
                        result = request.func(*request.args, **request.kwargs)
                    
                    request.future.set_result(result)
                    
                except Exception as e:
                    request.future.set_exception(e)
                
                # Rate limiting delay
                await asyncio.sleep(interval)
                
            except asyncio.TimeoutError:
                # No requests in queue, continue
                continue
            except Exception as e:
                print(f"Queue worker error: {e}")

# Usage
rate_limited_queue = RateLimitedQueue(requests_per_second=5)

async def queued_api_call(session_id: str, provider: str):
    return await rate_limited_queue.enqueue(
        scp_client.get_data,
        session_id=session_id,
        provider=provider,
        data_type="emails"
    )
```

### Issue: Data Format Inconsistencies

**Symptoms:**
- Parsing errors when processing API responses
- Inconsistent data structures between providers
- Agent workflows fail on certain data types

**Solutions:**

1. **Data Normalization Layer:**
```python
from typing import Dict, Any, List
from datetime import datetime
import re

class DataNormalizer:
    def __init__(self):
        self.provider_schemas = {
            'google': {
                'email': self.normalize_gmail_message,
                'calendar': self.normalize_google_calendar_event
            },
            'microsoft': {
                'email': self.normalize_outlook_message,
                'calendar': self.normalize_outlook_calendar_event
            }
        }
    
    def normalize_data(self, provider: str, data_type: str, raw_data: Any) -> List[Dict[str, Any]]:
        """Normalize data from any provider to standard format."""
        
        if provider not in self.provider_schemas:
            raise ValueError(f"Unsupported provider: {provider}")
        
        if data_type not in self.provider_schemas[provider]:
            raise ValueError(f"Unsupported data type {data_type} for provider {provider}")
        
        normalizer = self.provider_schemas[provider][data_type]
        
        if isinstance(raw_data, list):
            return [normalizer(item) for item in raw_data]
        else:
            return [normalizer(raw_data)]
    
    def normalize_gmail_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Gmail message to standard format."""
        headers = {h['name'].lower(): h['value'] for h in message.get('payload', {}).get('headers', [])}
        
        return {
            'id': message.get('id'),
            'subject': headers.get('subject', ''),
            'from': headers.get('from', ''),
            'to': headers.get('to', ''),
            'date': self.parse_date(headers.get('date', '')),
            'body': self.extract_gmail_body(message.get('payload', {})),
            'provider': 'google',
            'raw_data': message
        }
    
    def normalize_outlook_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Outlook message to standard format."""
        return {
            'id': message.get('id'),
            'subject': message.get('subject', ''),
            'from': message.get('from', {}).get('emailAddress', {}).get('address', ''),
            'to': ', '.join([addr.get('emailAddress', {}).get('address', '') 
                           for addr in message.get('toRecipients', [])]),
            'date': self.parse_date(message.get('receivedDateTime', '')),
            'body': message.get('body', {}).get('content', ''),
            'provider': 'microsoft',
            'raw_data': message
        }
    
    def normalize_google_calendar_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Google Calendar event to standard format."""
        return {
            'id': event.get('id'),
            'title': event.get('summary', ''),
            'description': event.get('description', ''),
            'start_time': self.parse_date(event.get('start', {}).get('dateTime', '')),
            'end_time': self.parse_date(event.get('end', {}).get('dateTime', '')),
            'attendees': [a.get('email', '') for a in event.get('attendees', [])],
            'provider': 'google',
            'raw_data': event
        }
    
    def normalize_outlook_calendar_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Outlook Calendar event to standard format."""
        return {
            'id': event.get('id'),
            'title': event.get('subject', ''),
            'description': event.get('body', {}).get('content', ''),
            'start_time': self.parse_date(event.get('start', {}).get('dateTime', '')),
            'end_time': self.parse_date(event.get('end', {}).get('dateTime', '')),
            'attendees': [a.get('emailAddress', {}).get('address', '') 
                         for a in event.get('attendees', [])],
            'provider': 'microsoft',
            'raw_data': event
        }
    
    def parse_date(self, date_string: str) -> datetime:
        """Parse date string from various formats."""
        if not date_string:
            return None
        
        # Common date formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S',
            '%a, %d %b %Y %H:%M:%S %z',
            '%d %b %Y %H:%M:%S %z'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_string, fmt)
            except ValueError:
                continue
        
        # If all formats fail, return None
        print(f"Could not parse date: {date_string}")
        return None
    
    def extract_gmail_body(self, payload: Dict[str, Any]) -> str:
        """Extract body text from Gmail message payload."""
        if 'parts' in payload:
            # Multipart message
            for part in payload['parts']:
                if part.get('mimeType') == 'text/plain':
                    body_data = part.get('body', {}).get('data', '')
                    if body_data:
                        import base64
                        return base64.urlsafe_b64decode(body_data).decode('utf-8')
        else:
            # Single part message
            if payload.get('mimeType') == 'text/plain':
                body_data = payload.get('body', {}).get('data', '')
                if body_data:
                    import base64
                    return base64.urlsafe_b64decode(body_data).decode('utf-8')
        
        return ''

# Usage
normalizer = DataNormalizer()

def get_normalized_emails(session_id: str, provider: str):
    """Get emails in normalized format."""
    raw_emails = scp_client.get_data(
        session_id=session_id,
        provider=provider,
        data_type="emails"
    )
    
    return normalizer.normalize_data(provider, 'email', raw_emails)
```

## Framework-Specific Issues

### LangChain Integration Issues

**Issue: Tool Registration Failures**

**Symptoms:**
- Tools not available to agent
- "Tool not found" errors
- Agent unable to access SCP functions

**Solutions:**

```python
from langchain.tools import BaseTool
from langchain.agents import initialize_agent, AgentType
from scp_sdk import SCPClient

class DebugSCPTool(BaseTool):
    """SCP tool with enhanced debugging."""
    
    name = "scp_debug_tool"
    description = "SCP tool with debugging capabilities"
    
    def __init__(self, session_id: str, provider: str):
        super().__init__()
        self.session_id = session_id
        self.provider = provider
        self.scp_client = SCPClient()
        self.debug_mode = True
    
    def _run(self, query: str) -> str:
        if self.debug_mode:
            print(f"SCP Tool called with query: {query}")
            print(f"Session ID: {self.session_id}")
            print(f"Provider: {self.provider}")
        
        try:
            # Validate session before making request
            if not self.validate_session():
                return "Error: Invalid session ID"
            
            result = self.scp_client.get_data(
                session_id=self.session_id,
                provider=self.provider,
                data_type="emails",
                query=query
            )
            
            if self.debug_mode:
                print(f"SCP Tool result: {len(result) if isinstance(result, list) else 'single item'}")
            
            return self.format_result(result)
            
        except Exception as e:
            error_msg = f"SCP Tool error: {str(e)}"
            if self.debug_mode:
                print(error_msg)
            return error_msg
    
    def validate_session(self) -> bool:
        """Validate session before making requests."""
        try:
            session_info = self.scp_client.get_session_info(self.session_id)
            return session_info.get('valid', False)
        except:
            return False
    
    def format_result(self, result) -> str:
        """Format result for agent consumption."""
        if isinstance(result, list):
            return f"Found {len(result)} items: " + str(result[:3])  # Show first 3 items
        else:
            return str(result)

# Test tool registration
def test_tool_registration():
    """Test if tools are properly registered with agent."""
    
    session_id = "test_session_123"
    tool = DebugSCPTool(session_id=session_id, provider="google")
    
    # Test tool directly
    print("Testing tool directly:")
    result = tool._run("recent emails")
    print(f"Direct tool result: {result}")
    
    # Test with agent
    print("\nTesting with agent:")
    try:
        from langchain.llms import OpenAI
        llm = OpenAI(temperature=0)
        
        agent = initialize_agent(
            tools=[tool],
            llm=llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            verbose=True
        )
        
        agent_result = agent.run("Get my recent emails")
        print(f"Agent result: {agent_result}")
        
    except Exception as e:
        print(f"Agent test failed: {e}")

# Run the test
test_tool_registration()
```

### CrewAI Integration Issues

**Issue: Agent Communication Failures**

**Symptoms:**
- Agents not sharing data properly
- Workflow stalls or fails
- Inconsistent results between agents

**Solutions:**

```python
from crewai import Agent, Task, Crew
from scp_sdk import SCPClient

class DebuggableCrewAgent(Agent):
    """CrewAI agent with enhanced debugging and error handling."""
    
    def __init__(self, role: str, goal: str, backstory: str, session_id: str, **kwargs):
        super().__init__(role=role, goal=goal, backstory=backstory, **kwargs)
        self.session_id = session_id
        self.scp_client = SCPClient()
        self.debug_mode = True
        self.shared_context = {}
    
    def execute_task(self, task: Task) -> str:
        """Execute task with debugging and error handling."""
        
        if self.debug_mode:
            print(f"Agent {self.role} executing task: {task.description}")
        
        try:
            # Pre-task validation
            self.validate_prerequisites()
            
            # Execute the task
            result = super().execute_task(task)
            
            # Post-task validation
            self.validate_result(result)
            
            if self.debug_mode:
                print(f"Agent {self.role} completed task successfully")
            
            return result
            
        except Exception as e:
            error_msg = f"Agent {self.role} task failed: {str(e)}"
            if self.debug_mode:
                print(error_msg)
            
            # Attempt recovery
            recovery_result = self.attempt_recovery(task, e)
            if recovery_result:
                return recovery_result
            
            raise e
    
    def validate_prerequisites(self):
        """Validate that agent has necessary access and data."""
        
        # Check session validity
        if not self.scp_client.validate_session(self.session_id):
            raise ValueError(f"Invalid session for agent {self.role}")
        
        # Check required tools are available
        if not self.tools:
            print(f"Warning: Agent {self.role} has no tools configured")
    
    def validate_result(self, result: str):
        """Validate task result."""
        
        if not result or len(result.strip()) == 0:
            raise ValueError(f"Agent {self.role} produced empty result")
        
        # Check for error indicators in result
        error_indicators = ["error", "failed", "exception", "timeout"]
        if any(indicator in result.lower() for indicator in error_indicators):
            print(f"Warning: Agent {self.role} result may contain errors: {result[:100]}")
    
    def attempt_recovery(self, task: Task, error: Exception) -> str:
        """Attempt to recover from task failure."""
        
        if "session" in str(error).lower():
            # Try to refresh session
            try:
                self.scp_client.refresh_session(self.session_id)
                return super().execute_task(task)
            except:
                pass
        
        # Return partial result if available
        if hasattr(self, 'partial_result'):
            return f"Partial result due to error: {self.partial_result}"
        
        return None
    
    def share_context(self, key: str, value: any):
        """Share context with other agents."""
        self.shared_context[key] = value
        if self.debug_mode:
            print(f"Agent {self.role} shared context: {key}")
    
    def get_shared_context(self, key: str) -> any:
        """Get shared context from other agents."""
        return self.shared_context.get(key)

# Test crew communication
def test_crew_communication():
    """Test communication between crew agents."""
    
    session_id = "test_session_456"
    
    # Create agents with shared context
    email_agent = DebuggableCrewAgent(
        role="Email Analyst",
        goal="Analyze emails and extract insights",
        backstory="Expert at email analysis",
        session_id=session_id
    )
    
    calendar_agent = DebuggableCrewAgent(
        role="Calendar Manager",
        goal="Manage calendar and scheduling",
        backstory="Expert at calendar management",
        session_id=session_id
    )
    
    # Share context between agents
    email_agent.shared_context = calendar_agent.shared_context = {}
    
    # Create tasks that require communication
    email_task = Task(
        description="Analyze recent emails and identify meeting requests",
        agent=email_agent,
        expected_output="List of meeting requests found in emails"
    )
    
    calendar_task = Task(
        description="Schedule meetings based on email analysis results",
        agent=calendar_agent,
        expected_output="Scheduled meetings confirmation"
    )
    
    # Create crew
    crew = Crew(
        agents=[email_agent, calendar_agent],
        tasks=[email_task, calendar_task],
        verbose=True
    )
    
    try:
        result = crew.kickoff()
        print(f"Crew execution successful: {result}")
    except Exception as e:
        print(f"Crew execution failed: {e}")

# Run the test
test_crew_communication()
```

## Debugging Tools and Techniques

### Comprehensive Logging System

```python
import logging
import json
import time
from datetime import datetime
from typing import Dict, Any

class SCPLogger:
    def __init__(self, log_level: str = "INFO"):
        self.logger = logging.getLogger("SCP")
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler('scp_debug.log')
        file_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(file_handler)
    
    def log_api_call(self, session_id: str, provider: str, endpoint: str, 
                     request_data: Dict = None, response_data: Dict = None, 
                     error: Exception = None, duration: float = None):
        """Log API call details."""
        
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id,
            'provider': provider,
            'endpoint': endpoint,
            'duration_ms': duration * 1000 if duration else None,
            'request_size': len(json.dumps(request_data)) if request_data else 0,
            'response_size': len(json.dumps(response_data)) if response_data else 0,
            'success': error is None
        }
        
        if error:
            log_data['error'] = str(error)
            log_data['error_type'] = type(error).__name__
            self.logger.error(f"API call failed: {json.dumps(log_data, indent=2)}")
        else:
            self.logger.info(f"API call successful: {json.dumps(log_data, indent=2)}")
    
    def log_session_event(self, session_id: str, event_type: str, details: Dict = None):
        """Log session-related events."""
        
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id,
            'event_type': event_type,
            'details': details or {}
        }
        
        self.logger.info(f"Session event: {json.dumps(log_data, indent=2)}")
    
    def log_performance_metric(self, metric_name: str, value: float, tags: Dict = None):
        """Log performance metrics."""
        
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'metric_name': metric_name,
            'value': value,
            'tags': tags or {}
        }
        
        self.logger.info(f"Performance metric: {json.dumps(log_data, indent=2)}")

# Global logger instance
scp_logger = SCPLogger()

# Decorator for automatic API call logging
def log_api_calls(func):
    """Decorator to automatically log API calls."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        session_id = kwargs.get('session_id', 'unknown')
        provider = kwargs.get('provider', 'unknown')
        
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            scp_logger.log_api_call(
                session_id=session_id,
                provider=provider,
                endpoint=func.__name__,
                response_data={'result_count': len(result) if isinstance(result, list) else 1},
                duration=duration
            )
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            
            scp_logger.log_api_call(
                session_id=session_id,
                provider=provider,
                endpoint=func.__name__,
                error=e,
                duration=duration
            )
            
            raise
    
    return wrapper
```

### Interactive Debugging Console

```python
import cmd
import json
from scp_sdk import SCPClient

class SCPDebugConsole(cmd.Cmd):
    """Interactive debugging console for SCP."""
    
    intro = 'Welcome to SCP Debug Console. Type help or ? to list commands.\n'
    prompt = '(scp-debug) '
    
    def __init__(self):
        super().__init__()
        self.scp_client = SCPClient()
        self.current_session = None
    
    def do_session(self, session_id):
        """Set current session ID for debugging."""
        if not session_id:
            print(f"Current session: {self.current_session}")
            return
        
        self.current_session = session_id
        print(f"Session set to: {session_id}")
    
    def do_validate(self, args):
        """Validate current session."""
        if not self.current_session:
            print("No session set. Use 'session <session_id>' first.")
            return
        
        try:
            is_valid = self.scp_client.validate_session(self.current_session)
            print(f"Session {self.current_session} is {'valid' if is_valid else 'invalid'}")
        except Exception as e:
            print(f"Error validating session: {e}")
    
    def do_tokens(self, args):
        """Get tokens for current session."""
        if not self.current_session:
            print("No session set. Use 'session <session_id>' first.")
            return
        
        try:
            tokens = self.scp_client.get_tokens(self.current_session)
            print(json.dumps(tokens, indent=2))
        except Exception as e:
            print(f"Error getting tokens: {e}")
    
    def do_data(self, args):
        """Get data for current session. Usage: data <provider> <data_type> [query]"""
        if not self.current_session:
            print("No session set. Use 'session <session_id>' first.")
            return
        
        parts = args.split()
        if len(parts) < 2:
            print("Usage: data <provider> <data_type> [query]")
            return
        
        provider = parts[0]
        data_type = parts[1]
        query = parts[2] if len(parts) > 2 else None
        
        try:
            data = self.scp_client.get_data(
                session_id=self.current_session,
                provider=provider,
                data_type=data_type,
                query=query
            )
            print(json.dumps(data, indent=2))
        except Exception as e:
            print(f"Error getting data: {e}")
    
    def do_health(self, args):
        """Check SCP server health."""
        try:
            health = self.scp_client.get_health()
            print(json.dumps(health, indent=2))
        except Exception as e:
            print(f"Error checking health: {e}")
    
    def do_providers(self, args):
        """List available providers."""
        try:
            providers = self.scp_client.get_providers()
            print(json.dumps(providers, indent=2))
        except Exception as e:
            print(f"Error getting providers: {e}")
    
    def do_quit(self, args):
        """Exit the debug console."""
        print("Goodbye!")
        return True

# Start debug console
if __name__ == "__main__":
    SCPDebugConsole().cmdloop()
```

## Error Code Reference

### HTTP Status Codes

| Code | Meaning | Common Causes | Solutions |
|------|---------|---------------|-----------|
| 400 | Bad Request | Invalid parameters, malformed JSON | Validate input data |
| 401 | Unauthorized | Expired/invalid tokens | Refresh tokens or re-authenticate |
| 403 | Forbidden | Insufficient permissions | Check OAuth scopes |
| 404 | Not Found | Invalid session ID, missing resource | Verify session exists |
| 429 | Too Many Requests | Rate limiting | Implement backoff strategy |
| 500 | Internal Server Error | Server-side issues | Check server logs |
| 502 | Bad Gateway | Upstream service issues | Check provider status |
| 503 | Service Unavailable | Server overloaded | Retry with backoff |

### SCP-Specific Error Codes

| Code | Description | Troubleshooting |
|------|-------------|-----------------|
| SCP_001 | Invalid session format | Check session ID format |
| SCP_002 | Session expired | Create new session |
| SCP_003 | Provider not configured | Check provider configuration |
| SCP_004 | OAuth flow failed | Check OAuth credentials |
| SCP_005 | Token refresh failed | Re-authenticate user |
| SCP_006 | Rate limit exceeded | Implement rate limiting |
| SCP_007 | Data access denied | Check permissions |
| SCP_008 | Network timeout | Check connectivity |

This troubleshooting guide provides comprehensive solutions for the most common issues encountered when integrating AI agents with SCP. Use the diagnostic tools and solutions provided to quickly identify and resolve problems in your agent workflows.