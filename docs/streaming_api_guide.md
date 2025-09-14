# Real-Time Data Streaming API Guide

This guide covers the real-time data streaming features of the SecureContext Protocol, including WebSocket connections, streaming APIs, and rate limiting.

## Overview

The SCP streaming system provides:

- **WebSocket connections** for real-time event notifications
- **Streaming APIs** for processing large datasets
- **Rate limiting** and throttling for API protection
- **Event-driven notifications** for data changes

## WebSocket Connection

### Connecting to WebSocket

```javascript
// Connect with session ID
const socket = io('http://localhost:5000', {
    query: {
        session_id: 'your-session-id',
        agent_id: 'optional-agent-id'
    }
});

socket.on('connect', () => {
    console.log('Connected to streaming');
});

socket.on('stream_event', (data) => {
    console.log('Stream event:', data);
});
```

### Event Types

The WebSocket connection receives various event types:

#### Data Update Events
```json
{
    "event_type": "data_update",
    "session_id": "session-123",
    "provider": "google",
    "timestamp": 1640995200.0,
    "data": {
        "data_type": "gmail_messages_message",
        "payload": {
            "id": "message-id",
            "subject": "Email subject",
            "from": "sender@example.com"
        }
    }
}
```

#### Token Refresh Events
```json
{
    "event_type": "token_refresh",
    "session_id": "session-123",
    "provider": "google",
    "timestamp": 1640995200.0,
    "data": {
        "new_expires_at": 1640998800.0,
        "expires_in": 3600
    }
}
```

#### Rate Limit Warnings
```json
{
    "event_type": "rate_limit_warning",
    "session_id": "session-123",
    "provider": "google",
    "timestamp": 1640995200.0,
    "data": {
        "remaining_quota": 10,
        "reset_time": 1640995260.0,
        "warning_message": "Rate limit approaching. 10 requests remaining."
    }
}
```

### Subscribing to Data Types

```javascript
// Subscribe to specific data types
socket.emit('subscribe_data', {
    session_id: 'your-session-id',
    data_types: ['gmail_messages', 'calendar_events']
});

socket.on('subscription_confirmed', (data) => {
    console.log('Subscribed to:', data.data_types);
});
```

## Streaming API Endpoints

### Start Data Stream

Start streaming large datasets with pagination and real-time updates.

**Endpoint:** `POST /api/stream/start`

**Request Body:**
```json
{
    "session_id": "your-session-id",
    "stream_type": "gmail_messages",
    "batch_size": 100,
    "max_results": 1000,
    "filters": {
        "query": "is:unread",
        "label_ids": ["INBOX"]
    },
    "real_time": true,
    "rate_limit_per_minute": 60
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "stream_id": "stream-abc123",
        "session_id": "your-session-id",
        "stream_type": "gmail_messages",
        "provider": "google",
        "configuration": {
            "batch_size": 100,
            "max_results": 1000,
            "real_time": true,
            "rate_limit_per_minute": 60
        }
    }
}
```

### Stream Types

Available stream types:

- `gmail_messages` - Gmail messages
- `gmail_threads` - Gmail conversation threads
- `calendar_events` - Google Calendar events
- `outlook_messages` - Outlook/Exchange messages
- `outlook_events` - Outlook/Exchange calendar events
- `contacts` - Contact information
- `files` - File metadata

### Stream Status

**Endpoint:** `GET /api/stream/{stream_id}/status`

**Response:**
```json
{
    "success": true,
    "data": {
        "stream_id": "stream-abc123",
        "status": "active",
        "items_streamed": 250,
        "started_at": 1640995200.0,
        "last_activity": 1640995800.0,
        "configuration": {
            "stream_type": "gmail_messages",
            "session_id": "your-session-id",
            "provider": "google",
            "batch_size": 100,
            "max_results": 1000
        }
    }
}
```

### Stop Stream

**Endpoint:** `POST /api/stream/{stream_id}/stop`

**Response:**
```json
{
    "success": true,
    "data": {
        "stream_id": "stream-abc123",
        "status": "stopped"
    }
}
```

### List Active Streams

**Endpoint:** `GET /api/streams`

**Response:**
```json
{
    "success": true,
    "data": {
        "streams": {
            "stream-abc123": {
                "stream_type": "gmail_messages",
                "session_id": "session-123",
                "provider": "google",
                "started_at": 1640995200.0,
                "items_streamed": 250,
                "status": "active",
                "last_activity": 1640995800.0
            }
        },
        "total_count": 1,
        "websocket_statistics": {
            "active_connections": 3
        }
    }
}
```

## Rate Limiting

### Default Limits

- **WebSocket connections per session:** 5 connections per 5 minutes
- **Stream events per minute:** 100 events per minute
- **Data requests per minute:** 50 requests per minute
- **Subscription requests:** 10 per minute

### Rate Limit Headers

API responses include rate limiting information:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1640995260
```

### Handling Rate Limits

When rate limited, you'll receive:

```json
{
    "success": false,
    "error": {
        "code": "RATE_LIMIT_EXCEEDED",
        "message": "Rate limit exceeded. Try again later.",
        "details": {
            "retry_after": 60,
            "limit": 60,
            "reset_time": 1640995260
        }
    }
}
```

## Filtering and Querying

### Gmail Message Filters

```json
{
    "filters": {
        "query": "is:unread from:important@example.com",
        "label_ids": ["INBOX", "IMPORTANT"],
        "include_spam_trash": false
    }
}
```

### Calendar Event Filters

```json
{
    "filters": {
        "time_min": "2024-01-01T00:00:00Z",
        "time_max": "2024-12-31T23:59:59Z",
        "query": "meeting"
    }
}
```

### Outlook Message Filters

```json
{
    "filters": {
        "filter": "isRead eq false",
        "search": "subject:important"
    }
}
```

## Error Handling

### Common Error Codes

- `STREAM_NOT_FOUND` - Stream ID not found
- `STREAM_ALREADY_ACTIVE` - Stream already running for session
- `STREAM_RATE_LIMITED` - Too many stream requests
- `STREAM_CONFIG_ERROR` - Invalid stream configuration
- `SESSION_NOT_FOUND` - Invalid session ID
- `TOKEN_EXPIRED` - OAuth token expired

### Error Response Format

```json
{
    "success": false,
    "error": {
        "code": "STREAM_CONFIG_ERROR",
        "message": "Invalid stream configuration",
        "details": {
            "field": "stream_type",
            "value": "invalid_type",
            "allowed_values": ["gmail_messages", "calendar_events"]
        }
    }
}
```

## Python SDK Usage

### Basic Streaming

```python
from scp_sdk import SCPClient

client = SCPClient(base_url='http://localhost:5000')

# Start a stream
stream_id = client.start_stream(
    session_id='your-session-id',
    stream_type='gmail_messages',
    batch_size=50,
    max_results=500
)

# Monitor stream status
status = client.get_stream_status(stream_id)
print(f"Stream status: {status['status']}")
print(f"Items streamed: {status['items_streamed']}")

# Stop stream when done
client.stop_stream(stream_id)
```

### WebSocket Integration

```python
import asyncio
import socketio

sio = socketio.AsyncClient()

@sio.event
async def stream_event(data):
    print(f"Received: {data['event_type']}")
    # Process streaming data
    if data['event_type'] == 'data_update':
        process_data_update(data['data'])

async def main():
    await sio.connect('http://localhost:5000', 
                     query={'session_id': 'your-session-id'})
    
    # Subscribe to data types
    await sio.emit('subscribe_data', {
        'session_id': 'your-session-id',
        'data_types': ['gmail_messages']
    })
    
    # Keep connection alive
    await sio.wait()

asyncio.run(main())
```

## Performance Considerations

### Batch Size Optimization

- **Small batches (10-50):** Better for real-time processing
- **Large batches (100-500):** Better for bulk processing
- **Very large batches (500+):** May cause memory issues

### Connection Management

- Limit WebSocket connections per session
- Use connection pooling for multiple streams
- Implement reconnection logic for reliability

### Memory Usage

- Streams automatically clean up after completion
- Inactive streams are cleaned up after 1 hour
- Monitor memory usage with large datasets

## Security Considerations

### Authentication

- All streaming requires valid session ID
- WebSocket connections are authenticated
- Rate limiting prevents abuse

### Data Privacy

- Stream data is not persisted on server
- All data flows through encrypted connections
- Audit logs track all data access

### Network Security

- Use HTTPS/WSS in production
- Implement proper CORS policies
- Monitor for suspicious activity

## Troubleshooting

### Common Issues

1. **WebSocket connection fails**
   - Check session ID validity
   - Verify network connectivity
   - Check for firewall blocking

2. **Stream not receiving data**
   - Verify OAuth token is valid
   - Check provider API limits
   - Ensure proper scopes granted

3. **Rate limiting errors**
   - Reduce request frequency
   - Implement exponential backoff
   - Check rate limit headers

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Testing

Use the provided test script:

```bash
python test_streaming.py --url http://localhost:5000
```

## Examples

See the `examples/` directory for complete working examples:

- `streaming_gmail_example.py` - Gmail message streaming
- `streaming_calendar_example.py` - Calendar event streaming
- `websocket_client_example.py` - WebSocket client implementation
- `rate_limiting_example.py` - Handling rate limits

## API Reference

For complete API documentation, see:
- [API Endpoints](api_reference.md)
- [WebSocket Events](websocket_reference.md)
- [Error Codes](error_codes.md)