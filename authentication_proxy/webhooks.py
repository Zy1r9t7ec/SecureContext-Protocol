"""
Webhook notification system for SecureContext Protocol.

This module provides webhook functionality for notifying external systems
about token events such as creation, retrieval, and expiration.
"""

import json
import time
import hmac
import hashlib
import logging
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class WebhookEvent:
    """Represents a webhook event with standardized structure."""
    
    def __init__(self, event_type: str, session_id: str, provider: str, 
                 data: Optional[Dict[str, Any]] = None, metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a webhook event.
        
        Args:
            event_type: Type of event (token_created, token_retrieved, token_expired)
            session_id: Session ID associated with the event
            provider: OAuth provider name
            data: Event-specific data
            metadata: Additional metadata
        """
        self.event_type = event_type
        self.session_id = session_id
        self.provider = provider
        self.data = data or {}
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
        self.event_id = f"{event_type}_{session_id}_{int(time.time() * 1000)}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for JSON serialization."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'timestamp': self.timestamp,
            'session_id': self.session_id,
            'provider': self.provider,
            'data': self.data,
            'metadata': self.metadata
        }


class WebhookNotifier:
    """
    Webhook notification system for sending HTTP notifications about token events.
    
    This class handles webhook delivery with retry logic, signature verification,
    and asynchronous processing to avoid blocking the main application.
    """
    
    def __init__(self, webhook_url: str, webhook_secret: Optional[str] = None,
                 timeout: int = 30, retry_count: int = 3, retry_delay: int = 5,
                 enabled_events: Optional[List[str]] = None):
        """
        Initialize webhook notifier.
        
        Args:
            webhook_url: URL to send webhook notifications to
            webhook_secret: Secret for HMAC signature generation
            timeout: Request timeout in seconds
            retry_count: Number of retry attempts
            retry_delay: Delay between retries in seconds
            enabled_events: List of enabled event types
        """
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.enabled_events = enabled_events or ['token_created', 'token_retrieved', 'token_expired']
        
        # Configure HTTP session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retry_count,
            backoff_factor=retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.logger = logging.getLogger(__name__)
    
    def _generate_signature(self, payload: str) -> Optional[str]:
        """
        Generate HMAC-SHA256 signature for webhook payload.
        
        Args:
            payload: JSON payload string
            
        Returns:
            Hex-encoded signature or None if no secret configured
        """
        if not self.webhook_secret:
            return None
        
        signature = hmac.new(
            self.webhook_secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return f"sha256={signature}"
    
    def _send_webhook(self, event: WebhookEvent) -> bool:
        """
        Send webhook notification synchronously.
        
        Args:
            event: Webhook event to send
            
        Returns:
            True if webhook was sent successfully, False otherwise
        """
        try:
            payload = json.dumps(event.to_dict(), separators=(',', ':'))
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'SecureContext-Protocol-Webhook/1.0',
                'X-SCP-Event-Type': event.event_type,
                'X-SCP-Event-ID': event.event_id,
                'X-SCP-Timestamp': event.timestamp
            }
            
            # Add signature if secret is configured
            signature = self._generate_signature(payload)
            if signature:
                headers['X-SCP-Signature'] = signature
            
            response = self.session.post(
                self.webhook_url,
                data=payload,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                self.logger.info(f"Webhook sent successfully for event {event.event_id}")
                return True
            else:
                self.logger.warning(f"Webhook failed with status {response.status_code} for event {event.event_id}: {response.text}")
                return False
                
        except requests.exceptions.Timeout:
            self.logger.error(f"Webhook timeout for event {event.event_id}")
            return False
        except requests.exceptions.ConnectionError:
            self.logger.error(f"Webhook connection error for event {event.event_id}")
            return False
        except Exception as e:
            self.logger.error(f"Webhook error for event {event.event_id}: {e}", exc_info=True)
            return False
    
    def send_webhook_async(self, event: WebhookEvent) -> None:
        """
        Send webhook notification asynchronously.
        
        Args:
            event: Webhook event to send
        """
        if event.event_type not in self.enabled_events:
            self.logger.debug(f"Event type {event.event_type} not enabled for webhooks")
            return
        
        def webhook_worker():
            """Worker function for sending webhook in background thread."""
            try:
                success = self._send_webhook(event)
                if not success:
                    self.logger.warning(f"Failed to send webhook for event {event.event_id}")
            except Exception as e:
                self.logger.error(f"Error in webhook worker for event {event.event_id}: {e}", exc_info=True)
        
        # Send webhook in background thread to avoid blocking
        webhook_thread = threading.Thread(target=webhook_worker, daemon=True)
        webhook_thread.start()
    
    def notify_token_created(self, session_id: str, provider: str, scope: str, expires_in: int) -> None:
        """
        Send notification for token creation event.
        
        Args:
            session_id: Session ID for the created token
            provider: OAuth provider name
            scope: OAuth scope granted
            expires_in: Token expiration time in seconds
        """
        event = WebhookEvent(
            event_type='token_created',
            session_id=session_id,
            provider=provider,
            data={
                'scope': scope,
                'expires_in': expires_in
            },
            metadata={
                'created_at': datetime.utcnow().isoformat() + 'Z'
            }
        )
        self.send_webhook_async(event)
    
    def notify_token_retrieved(self, session_id: str, provider: str, client_info: Optional[Dict[str, Any]] = None) -> None:
        """
        Send notification for token retrieval event.
        
        Args:
            session_id: Session ID for the retrieved token
            provider: OAuth provider name
            client_info: Information about the client retrieving the token
        """
        event = WebhookEvent(
            event_type='token_retrieved',
            session_id=session_id,
            provider=provider,
            data={
                'client_info': client_info or {}
            },
            metadata={
                'retrieved_at': datetime.utcnow().isoformat() + 'Z'
            }
        )
        self.send_webhook_async(event)
    
    def notify_token_expired(self, session_id: str, provider: str) -> None:
        """
        Send notification for token expiration event.
        
        Args:
            session_id: Session ID for the expired token
            provider: OAuth provider name
        """
        event = WebhookEvent(
            event_type='token_expired',
            session_id=session_id,
            provider=provider,
            metadata={
                'expired_at': datetime.utcnow().isoformat() + 'Z'
            }
        )
        self.send_webhook_async(event)
    
    def test_webhook(self) -> bool:
        """
        Send a test webhook to verify configuration.
        
        Returns:
            True if test webhook was sent successfully, False otherwise
        """
        test_event = WebhookEvent(
            event_type='test',
            session_id='test-session-id',
            provider='test',
            data={'message': 'This is a test webhook from SecureContext Protocol'},
            metadata={'test': True}
        )
        
        return self._send_webhook(test_event)


class WebhookManager:
    """
    Manager class for webhook notifications with configuration support.
    
    This class integrates with the application configuration system and
    provides a centralized interface for webhook operations.
    """
    
    def __init__(self, config):
        """
        Initialize webhook manager with configuration.
        
        Args:
            config: Application configuration instance
        """
        self.config = config
        self.notifier = None
        self.logger = logging.getLogger(__name__)
        
        # Initialize webhook notifier if enabled
        if config.is_webhook_enabled():
            enterprise_config = config.get_enterprise_config()
            self.notifier = WebhookNotifier(
                webhook_url=enterprise_config['WEBHOOK_URL'],
                webhook_secret=enterprise_config['WEBHOOK_SECRET'],
                timeout=enterprise_config['WEBHOOK_TIMEOUT'],
                retry_count=enterprise_config['WEBHOOK_RETRY_COUNT'],
                retry_delay=enterprise_config['WEBHOOK_RETRY_DELAY'],
                enabled_events=enterprise_config['WEBHOOK_EVENTS']
            )
            self.logger.info("Webhook notifications enabled")
        else:
            self.logger.info("Webhook notifications disabled")
    
    def is_enabled(self) -> bool:
        """
        Check if webhook notifications are enabled.
        
        Returns:
            True if webhooks are enabled, False otherwise
        """
        return self.notifier is not None
    
    def notify_token_created(self, session_id: str, provider: str, scope: str, expires_in: int) -> None:
        """Send token creation notification if webhooks are enabled."""
        if self.notifier:
            self.notifier.notify_token_created(session_id, provider, scope, expires_in)
    
    def notify_token_retrieved(self, session_id: str, provider: str, client_info: Optional[Dict[str, Any]] = None) -> None:
        """Send token retrieval notification if webhooks are enabled."""
        if self.notifier:
            self.notifier.notify_token_retrieved(session_id, provider, client_info)
    
    def notify_token_expired(self, session_id: str, provider: str) -> None:
        """Send token expiration notification if webhooks are enabled."""
        if self.notifier:
            self.notifier.notify_token_expired(session_id, provider)
    
    def test_webhook(self) -> bool:
        """
        Test webhook configuration.
        
        Returns:
            True if test webhook was sent successfully, False otherwise
        """
        if self.notifier:
            return self.notifier.test_webhook()
        return False
    
    def get_webhook_info(self) -> Dict[str, Any]:
        """
        Get webhook configuration information.
        
        Returns:
            Dictionary with webhook configuration details
        """
        if not self.notifier:
            return {'enabled': False}
        
        enterprise_config = self.config.get_enterprise_config()
        return {
            'enabled': True,
            'webhook_url': enterprise_config['WEBHOOK_URL'],
            'enabled_events': enterprise_config['WEBHOOK_EVENTS'],
            'timeout': enterprise_config['WEBHOOK_TIMEOUT'],
            'retry_count': enterprise_config['WEBHOOK_RETRY_COUNT'],
            'has_secret': bool(enterprise_config['WEBHOOK_SECRET'])
        }