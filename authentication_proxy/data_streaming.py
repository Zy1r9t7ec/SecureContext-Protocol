"""
Data streaming APIs for large dataset processing.

This module provides APIs for streaming large datasets from OAuth providers
with proper rate limiting, pagination, and real-time updates.
"""

import time
import json
import logging
import asyncio
import threading
from typing import Dict, Any, List, Optional, Generator, AsyncGenerator
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from .streaming import get_streaming_manager, StreamEventType
    from .audit_logger import get_audit_logger, AuditEventType
except ImportError:
    from streaming import get_streaming_manager, StreamEventType
    from audit_logger import get_audit_logger, AuditEventType


class DataStreamType(Enum):
    """Types of data streams."""
    GMAIL_MESSAGES = "gmail_messages"
    GMAIL_THREADS = "gmail_threads"
    CALENDAR_EVENTS = "calendar_events"
    OUTLOOK_MESSAGES = "outlook_messages"
    OUTLOOK_EVENTS = "outlook_events"
    CONTACTS = "contacts"
    FILES = "files"


@dataclass
class StreamConfig:
    """Configuration for data streaming."""
    stream_type: DataStreamType
    session_id: str
    provider: str
    access_token: str
    batch_size: int = 100
    max_results: Optional[int] = None
    filters: Optional[Dict[str, Any]] = None
    real_time: bool = False
    rate_limit_per_minute: int = 60


class DataStreamer:
    """Handles streaming of large datasets from OAuth providers."""
    
    def __init__(self):
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.active_streams = {}  # stream_id -> stream_info
        self.rate_limiters = {}  # provider -> rate_limiter_info
    
    def start_stream(self, config: StreamConfig) -> str:
        """
        Start a data stream.
        
        Args:
            config: Stream configuration
            
        Returns:
            Stream ID for tracking
        """
        stream_id = f"{config.session_id}_{config.stream_type.value}_{int(time.time())}"
        
        self.active_streams[stream_id] = {
            'config': config,
            'started_at': time.time(),
            'items_streamed': 0,
            'last_activity': time.time(),
            'status': 'active'
        }
        
        # Start streaming in background thread
        thread = threading.Thread(
            target=self._stream_worker,
            args=(stream_id, config),
            daemon=True
        )
        thread.start()
        
        logging.info(f"Started data stream {stream_id} for {config.stream_type.value}")
        return stream_id
    
    def stop_stream(self, stream_id: str) -> bool:
        """Stop a data stream."""
        if stream_id in self.active_streams:
            self.active_streams[stream_id]['status'] = 'stopped'
            logging.info(f"Stopped data stream {stream_id}")
            return True
        return False
    
    def get_stream_status(self, stream_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a data stream."""
        return self.active_streams.get(stream_id)
    
    def _stream_worker(self, stream_id: str, config: StreamConfig):
        """Worker thread for streaming data."""
        try:
            stream_info = self.active_streams[stream_id]
            
            if config.stream_type == DataStreamType.GMAIL_MESSAGES:
                self._stream_gmail_messages(stream_id, config, stream_info)
            elif config.stream_type == DataStreamType.CALENDAR_EVENTS:
                self._stream_calendar_events(stream_id, config, stream_info)
            elif config.stream_type == DataStreamType.OUTLOOK_MESSAGES:
                self._stream_outlook_messages(stream_id, config, stream_info)
            elif config.stream_type == DataStreamType.OUTLOOK_EVENTS:
                self._stream_outlook_events(stream_id, config, stream_info)
            else:
                logging.warning(f"Unsupported stream type: {config.stream_type}")
                
        except Exception as e:
            logging.error(f"Error in stream worker {stream_id}: {e}", exc_info=True)
            if stream_id in self.active_streams:
                self.active_streams[stream_id]['status'] = 'error'
                self.active_streams[stream_id]['error'] = str(e)
    
    def _stream_gmail_messages(self, stream_id: str, config: StreamConfig, stream_info: Dict):
        """Stream Gmail messages."""
        headers = {'Authorization': f'Bearer {config.access_token}'}
        base_url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages'
        
        # Build query parameters
        params = {
            'maxResults': config.batch_size,
            'includeSpamTrash': False
        }
        
        if config.filters:
            if 'query' in config.filters:
                params['q'] = config.filters['query']
            if 'label_ids' in config.filters:
                params['labelIds'] = config.filters['label_ids']
        
        next_page_token = None
        total_streamed = 0
        
        while (stream_info['status'] == 'active' and 
               (config.max_results is None or total_streamed < config.max_results)):
            
            # Rate limiting
            self._apply_rate_limit(config.provider, config.rate_limit_per_minute)
            
            if next_page_token:
                params['pageToken'] = next_page_token
            
            try:
                # Get message list
                response = self.session.get(base_url, headers=headers, params=params)
                response.raise_for_status()
                
                data = response.json()
                messages = data.get('messages', [])
                
                if not messages:
                    break
                
                # Stream each message with full details
                for message_ref in messages:
                    if stream_info['status'] != 'active':
                        break
                    
                    # Get full message details
                    msg_response = self.session.get(
                        f"{base_url}/{message_ref['id']}",
                        headers=headers,
                        params={'format': 'full'}
                    )
                    msg_response.raise_for_status()
                    
                    message_data = msg_response.json()
                    
                    # Stream the message
                    self._emit_stream_data(config, 'message', message_data)
                    
                    total_streamed += 1
                    stream_info['items_streamed'] = total_streamed
                    stream_info['last_activity'] = time.time()
                    
                    if config.max_results and total_streamed >= config.max_results:
                        break
                    
                    # Small delay to prevent overwhelming
                    time.sleep(0.1)
                
                next_page_token = data.get('nextPageToken')
                if not next_page_token:
                    break
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"Error streaming Gmail messages: {e}")
                if e.response and e.response.status_code == 429:
                    # Rate limited, wait longer
                    time.sleep(60)
                else:
                    break
        
        stream_info['status'] = 'completed'
        logging.info(f"Gmail message stream {stream_id} completed. Streamed {total_streamed} messages")
    
    def _stream_calendar_events(self, stream_id: str, config: StreamConfig, stream_info: Dict):
        """Stream Google Calendar events."""
        headers = {'Authorization': f'Bearer {config.access_token}'}
        base_url = 'https://www.googleapis.com/calendar/v3/calendars/primary/events'
        
        params = {
            'maxResults': config.batch_size,
            'singleEvents': True,
            'orderBy': 'startTime'
        }
        
        if config.filters:
            if 'time_min' in config.filters:
                params['timeMin'] = config.filters['time_min']
            if 'time_max' in config.filters:
                params['timeMax'] = config.filters['time_max']
            if 'query' in config.filters:
                params['q'] = config.filters['query']
        
        next_page_token = None
        total_streamed = 0
        
        while (stream_info['status'] == 'active' and 
               (config.max_results is None or total_streamed < config.max_results)):
            
            self._apply_rate_limit(config.provider, config.rate_limit_per_minute)
            
            if next_page_token:
                params['pageToken'] = next_page_token
            
            try:
                response = self.session.get(base_url, headers=headers, params=params)
                response.raise_for_status()
                
                data = response.json()
                events = data.get('items', [])
                
                if not events:
                    break
                
                for event in events:
                    if stream_info['status'] != 'active':
                        break
                    
                    self._emit_stream_data(config, 'event', event)
                    
                    total_streamed += 1
                    stream_info['items_streamed'] = total_streamed
                    stream_info['last_activity'] = time.time()
                    
                    if config.max_results and total_streamed >= config.max_results:
                        break
                    
                    time.sleep(0.05)
                
                next_page_token = data.get('nextPageToken')
                if not next_page_token:
                    break
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"Error streaming calendar events: {e}")
                if e.response and e.response.status_code == 429:
                    time.sleep(60)
                else:
                    break
        
        stream_info['status'] = 'completed'
        logging.info(f"Calendar events stream {stream_id} completed. Streamed {total_streamed} events")
    
    def _stream_outlook_messages(self, stream_id: str, config: StreamConfig, stream_info: Dict):
        """Stream Outlook messages."""
        headers = {'Authorization': f'Bearer {config.access_token}'}
        base_url = 'https://graph.microsoft.com/v1.0/me/messages'
        
        params = {
            '$top': config.batch_size,
            '$orderby': 'receivedDateTime desc'
        }
        
        if config.filters:
            if 'filter' in config.filters:
                params['$filter'] = config.filters['filter']
            if 'search' in config.filters:
                params['$search'] = config.filters['search']
        
        next_link = None
        total_streamed = 0
        
        while (stream_info['status'] == 'active' and 
               (config.max_results is None or total_streamed < config.max_results)):
            
            self._apply_rate_limit(config.provider, config.rate_limit_per_minute)
            
            url = next_link if next_link else base_url
            request_params = {} if next_link else params
            
            try:
                response = self.session.get(url, headers=headers, params=request_params)
                response.raise_for_status()
                
                data = response.json()
                messages = data.get('value', [])
                
                if not messages:
                    break
                
                for message in messages:
                    if stream_info['status'] != 'active':
                        break
                    
                    self._emit_stream_data(config, 'message', message)
                    
                    total_streamed += 1
                    stream_info['items_streamed'] = total_streamed
                    stream_info['last_activity'] = time.time()
                    
                    if config.max_results and total_streamed >= config.max_results:
                        break
                    
                    time.sleep(0.1)
                
                next_link = data.get('@odata.nextLink')
                if not next_link:
                    break
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"Error streaming Outlook messages: {e}")
                if e.response and e.response.status_code == 429:
                    time.sleep(60)
                else:
                    break
        
        stream_info['status'] = 'completed'
        logging.info(f"Outlook messages stream {stream_id} completed. Streamed {total_streamed} messages")
    
    def _stream_outlook_events(self, stream_id: str, config: StreamConfig, stream_info: Dict):
        """Stream Outlook calendar events."""
        headers = {'Authorization': f'Bearer {config.access_token}'}
        base_url = 'https://graph.microsoft.com/v1.0/me/events'
        
        params = {
            '$top': config.batch_size,
            '$orderby': 'start/dateTime'
        }
        
        if config.filters:
            if 'filter' in config.filters:
                params['$filter'] = config.filters['filter']
        
        next_link = None
        total_streamed = 0
        
        while (stream_info['status'] == 'active' and 
               (config.max_results is None or total_streamed < config.max_results)):
            
            self._apply_rate_limit(config.provider, config.rate_limit_per_minute)
            
            url = next_link if next_link else base_url
            request_params = {} if next_link else params
            
            try:
                response = self.session.get(url, headers=headers, params=request_params)
                response.raise_for_status()
                
                data = response.json()
                events = data.get('value', [])
                
                if not events:
                    break
                
                for event in events:
                    if stream_info['status'] != 'active':
                        break
                    
                    self._emit_stream_data(config, 'event', event)
                    
                    total_streamed += 1
                    stream_info['items_streamed'] = total_streamed
                    stream_info['last_activity'] = time.time()
                    
                    if config.max_results and total_streamed >= config.max_results:
                        break
                    
                    time.sleep(0.05)
                
                next_link = data.get('@odata.nextLink')
                if not next_link:
                    break
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"Error streaming Outlook events: {e}")
                if e.response and e.response.status_code == 429:
                    time.sleep(60)
                else:
                    break
        
        stream_info['status'] = 'completed'
        logging.info(f"Outlook events stream {stream_id} completed. Streamed {total_streamed} events")
    
    def _emit_stream_data(self, config: StreamConfig, data_type: str, data: Dict[str, Any]):
        """Emit streaming data to WebSocket clients."""
        streaming_manager = get_streaming_manager()
        if streaming_manager:
            streaming_manager.stream_data_update(
                session_id=config.session_id,
                provider=config.provider,
                data_type=f"{config.stream_type.value}_{data_type}",
                data=data
            )
        
        # Log audit event
        audit_logger = get_audit_logger()
        audit_logger.log_event(
            event_type=AuditEventType.DATA_STREAMED,
            session_id=config.session_id,
            provider=config.provider,
            data_type=data_type,
            success=True,
            details={
                'stream_type': config.stream_type.value,
                'data_size': len(json.dumps(data))
            }
        )
    
    def _apply_rate_limit(self, provider: str, requests_per_minute: int):
        """Apply rate limiting for API requests."""
        current_time = time.time()
        
        if provider not in self.rate_limiters:
            self.rate_limiters[provider] = {
                'requests': [],
                'last_reset': current_time
            }
        
        rate_info = self.rate_limiters[provider]
        
        # Clean old requests (older than 1 minute)
        rate_info['requests'] = [
            req_time for req_time in rate_info['requests']
            if current_time - req_time < 60
        ]
        
        # Check if we need to wait
        if len(rate_info['requests']) >= requests_per_minute:
            sleep_time = 60 - (current_time - rate_info['requests'][0])
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        # Add current request
        rate_info['requests'].append(current_time)
    
    def get_active_streams(self) -> Dict[str, Dict[str, Any]]:
        """Get all active streams."""
        return {
            stream_id: {
                'stream_type': info['config'].stream_type.value,
                'session_id': info['config'].session_id,
                'provider': info['config'].provider,
                'started_at': info['started_at'],
                'items_streamed': info['items_streamed'],
                'status': info['status'],
                'last_activity': info['last_activity']
            }
            for stream_id, info in self.active_streams.items()
        }
    
    def cleanup_completed_streams(self):
        """Clean up completed or stopped streams."""
        current_time = time.time()
        streams_to_remove = []
        
        for stream_id, info in self.active_streams.items():
            # Remove streams that have been inactive for more than 1 hour
            if (info['status'] in ['completed', 'stopped', 'error'] and 
                current_time - info['last_activity'] > 3600):
                streams_to_remove.append(stream_id)
        
        for stream_id in streams_to_remove:
            del self.active_streams[stream_id]
        
        if streams_to_remove:
            logging.info(f"Cleaned up {len(streams_to_remove)} completed streams")


# Global data streamer instance
_data_streamer = None


def get_data_streamer() -> DataStreamer:
    """Get the global data streamer instance."""
    global _data_streamer
    if _data_streamer is None:
        _data_streamer = DataStreamer()
    return _data_streamer