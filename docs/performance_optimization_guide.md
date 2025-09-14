# Performance Optimization Guide for SCP Agent Integration

This guide provides comprehensive strategies for optimizing performance when integrating AI agents with the SecureContext Protocol (SCP) in high-throughput scenarios.

## Table of Contents

1. [Performance Overview](#performance-overview)
2. [Bottleneck Identification](#bottleneck-identification)
3. [Client-Side Optimizations](#client-side-optimizations)
4. [Server-Side Optimizations](#server-side-optimizations)
5. [Network Optimizations](#network-optimizations)
6. [Caching Strategies](#caching-strategies)
7. [Concurrent Processing](#concurrent-processing)
8. [Memory Management](#memory-management)
9. [Monitoring and Profiling](#monitoring-and-profiling)
10. [Scaling Strategies](#scaling-strategies)

## Performance Overview

### Key Performance Metrics

- **Throughput**: Requests per second (RPS) that the system can handle
- **Latency**: Time from request initiation to response completion
- **Concurrent Users**: Number of simultaneous user sessions supported
- **Memory Usage**: RAM consumption for token storage and processing
- **CPU Utilization**: Processing overhead for OAuth flows and data access
- **Network Bandwidth**: Data transfer requirements for API calls

### Performance Targets

| Scenario | Target Throughput | Target Latency | Concurrent Users |
|----------|------------------|----------------|------------------|
| Development | 10 RPS | < 500ms | 10 |
| Small Production | 100 RPS | < 200ms | 100 |
| Enterprise | 1000+ RPS | < 100ms | 1000+ |

## Bottleneck Identification

### Common Performance Bottlenecks

1. **OAuth Token Exchange**: Initial authentication flows
2. **API Rate Limits**: Provider-imposed request limits
3. **Network Latency**: Round-trip time to OAuth providers
4. **Memory Usage**: Token storage and session management
5. **Database Queries**: Session and audit log storage
6. **JSON Serialization**: Data format conversion overhead

### Performance Profiling Tools

```python
import time
import psutil
import threading
from functools import wraps
from typing import Dict, Any

class PerformanceProfiler:
    def __init__(self):
        self.metrics = {}
        self.lock = threading.Lock()
    
    def profile_function(self, func_name: str):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                start_memory = psutil.Process().memory_info().rss
                
                try:
                    result = func(*args, **kwargs)
                    success = True
                except Exception as e:
                    result = e
                    success = False
                
                end_time = time.time()
                end_memory = psutil.Process().memory_info().rss
                
                with self.lock:
                    if func_name not in self.metrics:
                        self.metrics[func_name] = {
                            'calls': 0,
                            'total_time': 0,
                            'total_memory': 0,
                            'errors': 0
                        }
                    
                    self.metrics[func_name]['calls'] += 1
                    self.metrics[func_name]['total_time'] += (end_time - start_time)
                    self.metrics[func_name]['total_memory'] += (end_memory - start_memory)
                    
                    if not success:
                        self.metrics[func_name]['errors'] += 1
                
                if not success:
                    raise result
                
                return result
            return wrapper
        return decorator
    
    def get_report(self) -> Dict[str, Any]:
        with self.lock:
            report = {}
            for func_name, metrics in self.metrics.items():
                calls = metrics['calls']
                if calls > 0:
                    report[func_name] = {
                        'calls': calls,
                        'avg_time': metrics['total_time'] / calls,
                        'avg_memory': metrics['total_memory'] / calls,
                        'error_rate': metrics['errors'] / calls,
                        'total_time': metrics['total_time']
                    }
            return report

# Usage example
profiler = PerformanceProfiler()

@profiler.profile_function('scp_data_access')
def get_user_data(session_id: str, provider: str):
    # Your SCP data access code here
    pass
```

## Client-Side Optimizations

### 1. Connection Pooling

```python
import threading
from queue import Queue
from scp_sdk import SCPClient

class SCPConnectionPool:
    def __init__(self, pool_size: int = 10):
        self.pool_size = pool_size
        self.pool = Queue(maxsize=pool_size)
        self.lock = threading.Lock()
        
        # Initialize pool with clients
        for _ in range(pool_size):
            client = SCPClient()
            self.pool.put(client)
    
    def get_client(self) -> SCPClient:
        return self.pool.get()
    
    def return_client(self, client: SCPClient):
        self.pool.put(client)
    
    def __enter__(self):
        self.client = self.get_client()
        return self.client
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.return_client(self.client)

# Usage
pool = SCPConnectionPool(pool_size=20)

def optimized_data_access(session_id: str, provider: str):
    with pool as client:
        return client.get_data(
            session_id=session_id,
            provider=provider,
            data_type="emails"
        )
```

### 2. Request Batching

```python
import asyncio
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class BatchRequest:
    session_id: str
    provider: str
    data_type: str
    query: str = None

class BatchProcessor:
    def __init__(self, batch_size: int = 10, batch_timeout: float = 0.1):
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.pending_requests = []
        self.lock = asyncio.Lock()
    
    async def add_request(self, request: BatchRequest) -> Any:
        async with self.lock:
            self.pending_requests.append(request)
            
            if len(self.pending_requests) >= self.batch_size:
                return await self._process_batch()
        
        # Wait for batch timeout
        await asyncio.sleep(self.batch_timeout)
        
        async with self.lock:
            if self.pending_requests:
                return await self._process_batch()
    
    async def _process_batch(self) -> List[Any]:
        if not self.pending_requests:
            return []
        
        batch = self.pending_requests.copy()
        self.pending_requests.clear()
        
        # Process batch concurrently
        tasks = [self._process_single_request(req) for req in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    async def _process_single_request(self, request: BatchRequest) -> Any:
        # Simulate async SCP client call
        return await asyncio.to_thread(
            self._sync_scp_call,
            request.session_id,
            request.provider,
            request.data_type,
            request.query
        )
    
    def _sync_scp_call(self, session_id: str, provider: str, data_type: str, query: str):
        with pool as client:
            return client.get_data(
                session_id=session_id,
                provider=provider,
                data_type=data_type,
                query=query
            )
```

### 3. Intelligent Caching

```python
import time
import hashlib
from typing import Any, Optional
from dataclasses import dataclass
from threading import RLock

@dataclass
class CacheEntry:
    data: Any
    timestamp: float
    access_count: int
    ttl: float

class IntelligentCache:
    def __init__(self, max_size: int = 1000, default_ttl: float = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = {}
        self.access_times = {}
        self.lock = RLock()
    
    def _generate_key(self, session_id: str, provider: str, data_type: str, query: str = None) -> str:
        key_string = f"{session_id}:{provider}:{data_type}:{query or ''}"
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, session_id: str, provider: str, data_type: str, query: str = None) -> Optional[Any]:
        key = self._generate_key(session_id, provider, data_type, query)
        
        with self.lock:
            if key not in self.cache:
                return None
            
            entry = self.cache[key]
            current_time = time.time()
            
            # Check if entry has expired
            if current_time - entry.timestamp > entry.ttl:
                del self.cache[key]
                return None
            
            # Update access statistics
            entry.access_count += 1
            self.access_times[key] = current_time
            
            return entry.data
    
    def set(self, session_id: str, provider: str, data_type: str, data: Any, 
            query: str = None, ttl: float = None) -> None:
        key = self._generate_key(session_id, provider, data_type, query)
        ttl = ttl or self.default_ttl
        
        with self.lock:
            # Evict old entries if cache is full
            if len(self.cache) >= self.max_size:
                self._evict_lru()
            
            current_time = time.time()
            self.cache[key] = CacheEntry(
                data=data,
                timestamp=current_time,
                access_count=1,
                ttl=ttl
            )
            self.access_times[key] = current_time
    
    def _evict_lru(self) -> None:
        # Remove least recently used entry
        if not self.access_times:
            return
        
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        del self.cache[lru_key]
        del self.access_times[lru_key]
    
    def clear_expired(self) -> int:
        current_time = time.time()
        expired_keys = []
        
        with self.lock:
            for key, entry in self.cache.items():
                if current_time - entry.timestamp > entry.ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]
        
        return len(expired_keys)

# Global cache instance
intelligent_cache = IntelligentCache(max_size=5000, default_ttl=300)

def cached_data_access(session_id: str, provider: str, data_type: str, query: str = None):
    # Try cache first
    cached_data = intelligent_cache.get(session_id, provider, data_type, query)
    if cached_data is not None:
        return cached_data
    
    # Fetch from SCP
    with pool as client:
        data = client.get_data(
            session_id=session_id,
            provider=provider,
            data_type=data_type,
            query=query
        )
    
    # Cache the result with adaptive TTL
    ttl = 600 if data_type == "emails" else 300  # Emails cached longer
    intelligent_cache.set(session_id, provider, data_type, data, query, ttl)
    
    return data
```

## Server-Side Optimizations

### 1. Async Request Handling

```python
import asyncio
import aiohttp
from typing import Dict, Any
from flask import Flask
from quart import Quart, request, jsonify

# Using Quart for async Flask-like API
app = Quart(__name__)

class AsyncSCPServer:
    def __init__(self):
        self.session = None
        self.token_cache = {}
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def exchange_code_for_tokens(self, provider: str, code: str, redirect_uri: str) -> Dict[str, Any]:
        # Async token exchange
        provider_config = self.get_provider_config(provider)
        
        async with self.session.post(
            provider_config['token_url'],
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
                'client_id': provider_config['client_id'],
                'client_secret': provider_config['client_secret']
            }
        ) as response:
            return await response.json()
    
    async def get_user_data(self, session_id: str, provider: str, data_type: str) -> Dict[str, Any]:
        # Async data retrieval
        tokens = await self.get_tokens_async(session_id)
        
        headers = {'Authorization': f"Bearer {tokens['access_token']}"}
        endpoint = self.get_data_endpoint(provider, data_type)
        
        async with self.session.get(endpoint, headers=headers) as response:
            return await response.json()

@app.route('/api/tokens/<session_id>', methods=['GET'])
async def get_tokens_async(session_id: str):
    async with AsyncSCPServer() as server:
        try:
            tokens = await server.get_tokens_async(session_id)
            return jsonify({'success': True, 'data': tokens})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
```

### 2. Database Connection Pooling

```python
import asyncpg
import asyncio
from typing import Optional, Dict, Any

class AsyncDatabasePool:
    def __init__(self, database_url: str, min_size: int = 10, max_size: int = 20):
        self.database_url = database_url
        self.min_size = min_size
        self.max_size = max_size
        self.pool: Optional[asyncpg.Pool] = None
    
    async def initialize(self):
        self.pool = await asyncpg.create_pool(
            self.database_url,
            min_size=self.min_size,
            max_size=self.max_size,
            command_timeout=60
        )
    
    async def close(self):
        if self.pool:
            await self.pool.close()
    
    async def store_tokens(self, session_id: str, tokens: Dict[str, Any]) -> None:
        async with self.pool.acquire() as connection:
            await connection.execute(
                """
                INSERT INTO tokens (session_id, access_token, refresh_token, expires_at, provider)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (session_id) DO UPDATE SET
                    access_token = EXCLUDED.access_token,
                    refresh_token = EXCLUDED.refresh_token,
                    expires_at = EXCLUDED.expires_at,
                    updated_at = NOW()
                """,
                session_id,
                tokens['access_token'],
                tokens.get('refresh_token'),
                tokens.get('expires_at'),
                tokens.get('provider')
            )
    
    async def get_tokens(self, session_id: str) -> Optional[Dict[str, Any]]:
        async with self.pool.acquire() as connection:
            row = await connection.fetchrow(
                "SELECT * FROM tokens WHERE session_id = $1 AND expires_at > NOW()",
                session_id
            )
            
            if row:
                return dict(row)
            return None

# Global database pool
db_pool = AsyncDatabasePool("postgresql://user:pass@localhost/scp_db")
```

### 3. Redis Caching

```python
import aioredis
import json
from typing import Optional, Any

class RedisCache:
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
    
    async def initialize(self):
        self.redis = aioredis.from_url(self.redis_url)
    
    async def close(self):
        if self.redis:
            await self.redis.close()
    
    async def get(self, key: str) -> Optional[Any]:
        if not self.redis:
            return None
        
        value = await self.redis.get(key)
        if value:
            return json.loads(value)
        return None
    
    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        if not self.redis:
            return
        
        await self.redis.setex(key, ttl, json.dumps(value))
    
    async def delete(self, key: str) -> None:
        if not self.redis:
            return
        
        await self.redis.delete(key)
    
    async def get_or_set(self, key: str, factory_func, ttl: int = 300) -> Any:
        # Try to get from cache first
        cached_value = await self.get(key)
        if cached_value is not None:
            return cached_value
        
        # Generate new value
        new_value = await factory_func()
        await self.set(key, new_value, ttl)
        return new_value

# Global Redis cache
redis_cache = RedisCache()
```

## Network Optimizations

### 1. HTTP/2 and Connection Reuse

```python
import httpx
import asyncio
from typing import Dict, Any

class OptimizedHTTPClient:
    def __init__(self):
        self.client = httpx.AsyncClient(
            http2=True,  # Enable HTTP/2
            limits=httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
                keepalive_expiry=30
            ),
            timeout=httpx.Timeout(30.0)
        )
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def make_oauth_request(self, url: str, data: Dict[str, Any]) -> Dict[str, Any]:
        response = await self.client.post(url, data=data)
        response.raise_for_status()
        return response.json()
    
    async def make_api_request(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        response = await self.client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

# Usage
async def optimized_token_exchange(provider: str, code: str):
    async with OptimizedHTTPClient() as client:
        return await client.make_oauth_request(
            url=f"https://oauth.{provider}.com/token",
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'client_id': 'your_client_id',
                'client_secret': 'your_client_secret'
            }
        )
```

### 2. Request Compression

```python
import gzip
import json
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

def compress_response(data: dict) -> Response:
    """Compress JSON response using gzip."""
    json_data = json.dumps(data)
    
    # Check if client accepts gzip
    if 'gzip' in request.headers.get('Accept-Encoding', ''):
        compressed_data = gzip.compress(json_data.encode('utf-8'))
        response = Response(
            compressed_data,
            mimetype='application/json',
            headers={'Content-Encoding': 'gzip'}
        )
    else:
        response = jsonify(data)
    
    return response

@app.route('/api/tokens/<session_id>')
def get_tokens_compressed(session_id: str):
    tokens = get_user_tokens(session_id)  # Your token retrieval logic
    return compress_response({'success': True, 'data': tokens})
```

## Concurrent Processing

### 1. Thread Pool Optimization

```python
import concurrent.futures
import threading
from typing import List, Callable, Any

class OptimizedThreadPool:
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        self.local = threading.local()
    
    def submit_task(self, func: Callable, *args, **kwargs) -> concurrent.futures.Future:
        return self.executor.submit(func, *args, **kwargs)
    
    def map_tasks(self, func: Callable, iterable: List[Any]) -> List[Any]:
        return list(self.executor.map(func, iterable))
    
    def shutdown(self, wait: bool = True):
        self.executor.shutdown(wait=wait)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

# Usage for concurrent SCP operations
def process_multiple_users_concurrent(user_sessions: List[str]):
    with OptimizedThreadPool(max_workers=20) as pool:
        futures = []
        
        for session_id in user_sessions:
            future = pool.submit_task(process_user_data, session_id)
            futures.append(future)
        
        results = []
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=30)
                results.append(result)
            except Exception as e:
                print(f"Error processing user: {e}")
                results.append(None)
        
        return results

def process_user_data(session_id: str):
    # Your SCP data processing logic
    with pool as client:
        return client.get_data(session_id=session_id, provider="google", data_type="emails")
```

### 2. Async/Await Patterns

```python
import asyncio
import aiohttp
from typing import List, Dict, Any

class AsyncSCPProcessor:
    def __init__(self, max_concurrent: int = 50):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_user_data_async(self, session_id: str, provider: str) -> Dict[str, Any]:
        async with self.semaphore:
            # Simulate async data processing
            await asyncio.sleep(0.1)  # Simulate I/O delay
            
            # Your actual SCP async processing here
            return {
                'session_id': session_id,
                'provider': provider,
                'data': f'processed_data_for_{session_id}'
            }
    
    async def process_multiple_users(self, user_sessions: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        tasks = []
        
        for session_info in user_sessions:
            task = self.process_user_data_async(
                session_info['session_id'],
                session_info['provider']
            )
            tasks.append(task)
        
        # Process all users concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        successful_results = [r for r in results if not isinstance(r, Exception)]
        return successful_results

# Usage
async def main():
    processor = AsyncSCPProcessor(max_concurrent=100)
    
    user_sessions = [
        {'session_id': f'user_{i}', 'provider': 'google'}
        for i in range(1000)
    ]
    
    results = await processor.process_multiple_users(user_sessions)
    print(f"Processed {len(results)} users successfully")

# Run the async processing
asyncio.run(main())
```

## Memory Management

### 1. Memory-Efficient Token Storage

```python
import weakref
import gc
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class CompactToken:
    """Memory-efficient token storage."""
    access_token: str
    refresh_token: Optional[str]
    expires_at: datetime
    provider: str
    
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_at': self.expires_at.isoformat(),
            'provider': self.provider
        }

class MemoryEfficientTokenStore:
    def __init__(self, cleanup_interval: int = 300):
        self.tokens: Dict[str, CompactToken] = {}
        self.weak_refs: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = datetime.now()
    
    def store_token(self, session_id: str, token_data: Dict[str, Any]) -> None:
        token = CompactToken(
            access_token=token_data['access_token'],
            refresh_token=token_data.get('refresh_token'),
            expires_at=datetime.fromisoformat(token_data['expires_at']),
            provider=token_data['provider']
        )
        
        self.tokens[session_id] = token
        self._maybe_cleanup()
    
    def get_token(self, session_id: str) -> Optional[Dict[str, Any]]:
        token = self.tokens.get(session_id)
        if token and not token.is_expired():
            return token.to_dict()
        elif token and token.is_expired():
            # Remove expired token
            del self.tokens[session_id]
        return None
    
    def _maybe_cleanup(self) -> None:
        now = datetime.now()
        if now - self.last_cleanup > timedelta(seconds=self.cleanup_interval):
            self._cleanup_expired_tokens()
            self.last_cleanup = now
    
    def _cleanup_expired_tokens(self) -> int:
        expired_sessions = []
        for session_id, token in self.tokens.items():
            if token.is_expired():
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.tokens[session_id]
        
        # Force garbage collection
        gc.collect()
        
        return len(expired_sessions)
    
    def get_memory_usage(self) -> Dict[str, Any]:
        import sys
        
        total_size = sys.getsizeof(self.tokens)
        for session_id, token in self.tokens.items():
            total_size += sys.getsizeof(session_id)
            total_size += sys.getsizeof(token)
            total_size += sys.getsizeof(token.access_token)
            if token.refresh_token:
                total_size += sys.getsizeof(token.refresh_token)
        
        return {
            'total_tokens': len(self.tokens),
            'memory_bytes': total_size,
            'memory_mb': total_size / (1024 * 1024)
        }

# Global memory-efficient token store
efficient_token_store = MemoryEfficientTokenStore()
```

### 2. Object Pooling

```python
from queue import Queue
import threading
from typing import Generic, TypeVar, Callable

T = TypeVar('T')

class ObjectPool(Generic[T]):
    def __init__(self, factory: Callable[[], T], max_size: int = 50):
        self.factory = factory
        self.max_size = max_size
        self.pool = Queue(maxsize=max_size)
        self.lock = threading.Lock()
        
        # Pre-populate pool
        for _ in range(min(10, max_size)):
            self.pool.put(self.factory())
    
    def acquire(self) -> T:
        try:
            return self.pool.get_nowait()
        except:
            return self.factory()
    
    def release(self, obj: T) -> None:
        try:
            self.pool.put_nowait(obj)
        except:
            # Pool is full, let object be garbage collected
            pass
    
    def __enter__(self) -> T:
        self.obj = self.acquire()
        return self.obj
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release(self.obj)

# Example: Pool for HTTP sessions
def create_http_session():
    import requests
    session = requests.Session()
    session.headers.update({'User-Agent': 'SCP-Agent/1.0'})
    return session

http_session_pool = ObjectPool(create_http_session, max_size=20)

def make_api_call(url: str, headers: Dict[str, str]):
    with http_session_pool as session:
        response = session.get(url, headers=headers)
        return response.json()
```

## Monitoring and Profiling

### 1. Performance Monitoring

```python
import time
import psutil
import threading
from collections import defaultdict, deque
from typing import Dict, Any, Deque
from dataclasses import dataclass
from datetime import datetime

@dataclass
class PerformanceMetric:
    timestamp: datetime
    value: float
    tags: Dict[str, str]

class PerformanceMonitor:
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.metrics: Dict[str, Deque[PerformanceMetric]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self.lock = threading.RLock()
    
    def record_metric(self, name: str, value: float, tags: Dict[str, str] = None):
        with self.lock:
            metric = PerformanceMetric(
                timestamp=datetime.now(),
                value=value,
                tags=tags or {}
            )
            self.metrics[name].append(metric)
    
    def record_timing(self, name: str, duration: float, tags: Dict[str, str] = None):
        self.record_metric(f"{name}_duration", duration, tags)
    
    def record_counter(self, name: str, tags: Dict[str, str] = None):
        self.record_metric(f"{name}_count", 1, tags)
    
    def get_stats(self, name: str) -> Dict[str, float]:
        with self.lock:
            if name not in self.metrics:
                return {}
            
            values = [m.value for m in self.metrics[name]]
            if not values:
                return {}
            
            return {
                'count': len(values),
                'min': min(values),
                'max': max(values),
                'avg': sum(values) / len(values),
                'recent': values[-1] if values else 0
            }
    
    def get_system_metrics(self) -> Dict[str, float]:
        process = psutil.Process()
        
        return {
            'cpu_percent': process.cpu_percent(),
            'memory_mb': process.memory_info().rss / (1024 * 1024),
            'memory_percent': process.memory_percent(),
            'threads': process.num_threads(),
            'open_files': len(process.open_files()),
            'connections': len(process.connections())
        }

# Global performance monitor
perf_monitor = PerformanceMonitor()

# Decorator for automatic timing
def monitor_performance(metric_name: str, tags: Dict[str, str] = None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                perf_monitor.record_counter(f"{metric_name}_success", tags)
                return result
            except Exception as e:
                perf_monitor.record_counter(f"{metric_name}_error", tags)
                raise
            finally:
                duration = time.time() - start_time
                perf_monitor.record_timing(metric_name, duration, tags)
        return wrapper
    return decorator

# Usage
@monitor_performance("scp_token_exchange", {"provider": "google"})
def exchange_tokens(code: str, provider: str):
    # Your token exchange logic
    pass
```

### 2. Health Check Endpoints

```python
from flask import Flask, jsonify
import time
from datetime import datetime, timedelta

app = Flask(__name__)

class HealthChecker:
    def __init__(self):
        self.start_time = datetime.now()
        self.last_health_check = datetime.now()
        self.health_status = "healthy"
    
    def check_database_health(self) -> bool:
        try:
            # Check database connectivity
            # Your database health check logic
            return True
        except Exception:
            return False
    
    def check_redis_health(self) -> bool:
        try:
            # Check Redis connectivity
            # Your Redis health check logic
            return True
        except Exception:
            return False
    
    def check_oauth_providers(self) -> Dict[str, bool]:
        providers = {}
        for provider in ['google', 'microsoft']:
            try:
                # Check OAuth provider connectivity
                # Your provider health check logic
                providers[provider] = True
            except Exception:
                providers[provider] = False
        return providers
    
    def get_health_status(self) -> Dict[str, Any]:
        current_time = datetime.now()
        uptime = current_time - self.start_time
        
        # System metrics
        system_metrics = perf_monitor.get_system_metrics()
        
        # Component health
        db_healthy = self.check_database_health()
        redis_healthy = self.check_redis_health()
        oauth_providers = self.check_oauth_providers()
        
        # Overall health
        overall_healthy = (
            db_healthy and 
            redis_healthy and 
            all(oauth_providers.values()) and
            system_metrics['memory_percent'] < 90 and
            system_metrics['cpu_percent'] < 80
        )
        
        return {
            'status': 'healthy' if overall_healthy else 'unhealthy',
            'timestamp': current_time.isoformat(),
            'uptime_seconds': uptime.total_seconds(),
            'components': {
                'database': 'healthy' if db_healthy else 'unhealthy',
                'redis': 'healthy' if redis_healthy else 'unhealthy',
                'oauth_providers': oauth_providers
            },
            'metrics': system_metrics,
            'performance': {
                'token_exchange_avg': perf_monitor.get_stats('scp_token_exchange_duration').get('avg', 0),
                'api_requests_per_minute': self.get_requests_per_minute()
            }
        }
    
    def get_requests_per_minute(self) -> float:
        # Calculate requests per minute from performance metrics
        stats = perf_monitor.get_stats('api_request_count')
        return stats.get('count', 0) / max(1, stats.get('window_minutes', 1))

health_checker = HealthChecker()

@app.route('/health')
def health_check():
    health_status = health_checker.get_health_status()
    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code

@app.route('/metrics')
def metrics():
    return jsonify({
        'system': perf_monitor.get_system_metrics(),
        'performance': {
            'token_exchange': perf_monitor.get_stats('scp_token_exchange_duration'),
            'api_requests': perf_monitor.get_stats('api_request_count'),
            'cache_hits': perf_monitor.get_stats('cache_hit_count'),
            'cache_misses': perf_monitor.get_stats('cache_miss_count')
        }
    })
```

## Scaling Strategies

### 1. Horizontal Scaling with Load Balancing

```yaml
# docker-compose.yml for horizontal scaling
version: '3.8'
services:
  scp-app-1:
    build: .
    environment:
      - INSTANCE_ID=1
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://user:pass@postgres:5432/scp
    depends_on:
      - redis
      - postgres
  
  scp-app-2:
    build: .
    environment:
      - INSTANCE_ID=2
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://user:pass@postgres:5432/scp
    depends_on:
      - redis
      - postgres
  
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - scp-app-1
      - scp-app-2
  
  redis:
    image: redis:alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
  
  postgres:
    image: postgres:13
    environment:
      - POSTGRES_DB=scp
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### 2. Auto-scaling Configuration

```python
import psutil
import threading
import time
from typing import Dict, Any

class AutoScaler:
    def __init__(self, min_instances: int = 2, max_instances: int = 10):
        self.min_instances = min_instances
        self.max_instances = max_instances
        self.current_instances = min_instances
        self.monitoring = True
        self.scale_up_threshold = 80  # CPU percentage
        self.scale_down_threshold = 30
        self.scale_cooldown = 300  # 5 minutes
        self.last_scale_action = 0
    
    def start_monitoring(self):
        def monitor():
            while self.monitoring:
                try:
                    self.check_scaling_conditions()
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    print(f"Auto-scaling error: {e}")
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def check_scaling_conditions(self):
        current_time = time.time()
        
        # Check cooldown period
        if current_time - self.last_scale_action < self.scale_cooldown:
            return
        
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        
        # Get application metrics
        app_metrics = perf_monitor.get_system_metrics()
        
        # Scale up conditions
        if (cpu_percent > self.scale_up_threshold or 
            memory_percent > 85 or
            app_metrics.get('connections', 0) > 100):
            
            if self.current_instances < self.max_instances:
                self.scale_up()
                self.last_scale_action = current_time
        
        # Scale down conditions
        elif (cpu_percent < self.scale_down_threshold and 
              memory_percent < 50 and
              app_metrics.get('connections', 0) < 20):
            
            if self.current_instances > self.min_instances:
                self.scale_down()
                self.last_scale_action = current_time
    
    def scale_up(self):
        print(f"Scaling up from {self.current_instances} to {self.current_instances + 1} instances")
        # Your scaling up logic (e.g., Docker Swarm, Kubernetes API calls)
        self.current_instances += 1
    
    def scale_down(self):
        print(f"Scaling down from {self.current_instances} to {self.current_instances - 1} instances")
        # Your scaling down logic
        self.current_instances -= 1
    
    def stop_monitoring(self):
        self.monitoring = False

# Initialize auto-scaler
auto_scaler = AutoScaler(min_instances=2, max_instances=20)
auto_scaler.start_monitoring()
```

## Performance Testing

### 1. Load Testing Script

```python
import asyncio
import aiohttp
import time
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class LoadTestResult:
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    requests_per_second: float

class LoadTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def make_request(self, endpoint: str, method: str = 'GET', data: Dict = None) -> Dict[str, Any]:
        start_time = time.time()
        
        try:
            if method == 'GET':
                async with self.session.get(f"{self.base_url}{endpoint}") as response:
                    result = await response.json()
            else:
                async with self.session.post(f"{self.base_url}{endpoint}", json=data) as response:
                    result = await response.json()
            
            end_time = time.time()
            return {
                'success': True,
                'response_time': end_time - start_time,
                'status_code': response.status,
                'data': result
            }
        except Exception as e:
            end_time = time.time()
            return {
                'success': False,
                'response_time': end_time - start_time,
                'error': str(e)
            }
    
    async def run_load_test(self, endpoint: str, concurrent_users: int, 
                           requests_per_user: int) -> LoadTestResult:
        print(f"Starting load test: {concurrent_users} users, {requests_per_user} requests each")
        
        async def user_simulation():
            results = []
            for _ in range(requests_per_user):
                result = await self.make_request(endpoint)
                results.append(result)
                await asyncio.sleep(0.1)  # Small delay between requests
            return results
        
        start_time = time.time()
        
        # Run concurrent user simulations
        tasks = [user_simulation() for _ in range(concurrent_users)]
        all_results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Flatten results
        flat_results = [result for user_results in all_results for result in user_results]
        
        # Calculate statistics
        successful_requests = sum(1 for r in flat_results if r['success'])
        failed_requests = len(flat_results) - successful_requests
        response_times = [r['response_time'] for r in flat_results]
        
        return LoadTestResult(
            total_requests=len(flat_results),
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            avg_response_time=sum(response_times) / len(response_times) if response_times else 0,
            min_response_time=min(response_times) if response_times else 0,
            max_response_time=max(response_times) if response_times else 0,
            requests_per_second=len(flat_results) / total_duration
        )

# Usage
async def run_performance_tests():
    async with LoadTester("http://localhost:5000") as tester:
        # Test token retrieval endpoint
        result = await tester.run_load_test(
            endpoint="/api/tokens/test_session_123",
            concurrent_users=50,
            requests_per_user=20
        )
        
        print(f"Load Test Results:")
        print(f"Total Requests: {result.total_requests}")
        print(f"Successful: {result.successful_requests}")
        print(f"Failed: {result.failed_requests}")
        print(f"Average Response Time: {result.avg_response_time:.3f}s")
        print(f"Requests per Second: {result.requests_per_second:.2f}")

# Run the load test
asyncio.run(run_performance_tests())
```

This comprehensive performance optimization guide provides practical strategies and code examples for optimizing SCP agent integration performance across all layers of the system. Implement these optimizations based on your specific performance requirements and bottlenecks.