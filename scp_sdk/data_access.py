"""
Data access utilities for common operations with OAuth providers.
"""

import requests
from typing import Dict, Any, Optional, List
import logging

from .client import SCPClient
from .exceptions import SCPError, SCPConnectionError, SCPAuthenticationError
from .retry import with_retry


class DataAccessClient:
    """
    Client for accessing user data through OAuth providers.
    
    This client provides high-level methods for common data access operations
    across different OAuth providers with standardized interfaces.
    """
    
    def __init__(self, scp_client: SCPClient):
        """
        Initialize the data access client.
        
        Args:
            scp_client: SCP client instance for token management
        """
        self.scp_client = scp_client
        self.logger = logging.getLogger(__name__)
    
    @with_retry()
    def get_user_profile(self, session_id: str) -> Dict[str, Any]:
        """
        Get user profile information from the OAuth provider.
        
        Args:
            session_id: Session ID for token retrieval
            
        Returns:
            User profile information
            
        Raises:
            SCPError: If token retrieval or API call fails
        """
        tokens = self.scp_client.get_tokens(session_id)
        provider = tokens.get('provider', {}).get('name', '')
        access_token = tokens.get('access_token')
        
        if not access_token:
            raise SCPAuthenticationError("No access token available")
        
        headers = {'Authorization': f'Bearer {access_token}'}
        
        if provider == 'google':
            return self._get_google_profile(headers)
        elif provider == 'microsoft':
            return self._get_microsoft_profile(headers)
        else:
            raise SCPError(f"Unsupported provider for profile access: {provider}")
    
    def _get_google_profile(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Get Google user profile."""
        response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers=headers,
            timeout=self.scp_client.timeout
        )
        response.raise_for_status()
        return response.json()
    
    def _get_microsoft_profile(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Get Microsoft user profile."""
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers=headers,
            timeout=self.scp_client.timeout
        )
        response.raise_for_status()
        return response.json()
    
    @with_retry()
    def get_emails(
        self,
        session_id: str,
        max_results: int = 10,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get email messages from the user's mailbox.
        
        Args:
            session_id: Session ID for token retrieval
            max_results: Maximum number of emails to retrieve
            query: Optional search query
            
        Returns:
            List of email message objects
            
        Raises:
            SCPError: If token retrieval or API call fails
        """
        tokens = self.scp_client.get_tokens(session_id)
        provider = tokens.get('provider', {}).get('name', '')
        access_token = tokens.get('access_token')
        
        if not access_token:
            raise SCPAuthenticationError("No access token available")
        
        headers = {'Authorization': f'Bearer {access_token}'}
        
        if provider == 'google':
            return self._get_gmail_messages(headers, max_results, query)
        elif provider == 'microsoft':
            return self._get_outlook_messages(headers, max_results, query)
        else:
            raise SCPError(f"Unsupported provider for email access: {provider}")
    
    def _get_gmail_messages(
        self,
        headers: Dict[str, str],
        max_results: int,
        query: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Get Gmail messages."""
        params = {'maxResults': max_results}
        if query:
            params['q'] = query
        
        response = requests.get(
            'https://www.googleapis.com/gmail/v1/users/me/messages',
            headers=headers,
            params=params,
            timeout=self.scp_client.timeout
        )
        response.raise_for_status()
        return response.json().get('messages', [])
    
    def _get_outlook_messages(
        self,
        headers: Dict[str, str],
        max_results: int,
        query: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Get Outlook messages."""
        params = {'$top': max_results}
        if query:
            params['$search'] = f'"{query}"'
        
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me/messages',
            headers=headers,
            params=params,
            timeout=self.scp_client.timeout
        )
        response.raise_for_status()
        return response.json().get('value', [])
    
    @with_retry()
    def get_calendar_events(
        self,
        session_id: str,
        max_results: int = 10,
        time_min: Optional[str] = None,
        time_max: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get calendar events from the user's calendar.
        
        Args:
            session_id: Session ID for token retrieval
            max_results: Maximum number of events to retrieve
            time_min: Minimum time for events (ISO format)
            time_max: Maximum time for events (ISO format)
            
        Returns:
            List of calendar event objects
            
        Raises:
            SCPError: If token retrieval or API call fails
        """
        tokens = self.scp_client.get_tokens(session_id)
        provider = tokens.get('provider', {}).get('name', '')
        access_token = tokens.get('access_token')
        
        if not access_token:
            raise SCPAuthenticationError("No access token available")
        
        headers = {'Authorization': f'Bearer {access_token}'}
        
        if provider == 'google':
            return self._get_google_calendar_events(headers, max_results, time_min, time_max)
        elif provider == 'microsoft':
            return self._get_microsoft_calendar_events(headers, max_results, time_min, time_max)
        else:
            raise SCPError(f"Unsupported provider for calendar access: {provider}")
    
    def _get_google_calendar_events(
        self,
        headers: Dict[str, str],
        max_results: int,
        time_min: Optional[str],
        time_max: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Get Google Calendar events."""
        params = {'maxResults': max_results, 'singleEvents': True, 'orderBy': 'startTime'}
        if time_min:
            params['timeMin'] = time_min
        if time_max:
            params['timeMax'] = time_max
        
        response = requests.get(
            'https://www.googleapis.com/calendar/v3/calendars/primary/events',
            headers=headers,
            params=params,
            timeout=self.scp_client.timeout
        )
        response.raise_for_status()
        return response.json().get('items', [])
    
    def _get_microsoft_calendar_events(
        self,
        headers: Dict[str, str],
        max_results: int,
        time_min: Optional[str],
        time_max: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Get Microsoft Calendar events."""
        params = {'$top': max_results, '$orderby': 'start/dateTime'}
        
        filter_conditions = []
        if time_min:
            filter_conditions.append(f"start/dateTime ge '{time_min}'")
        if time_max:
            filter_conditions.append(f"end/dateTime le '{time_max}'")
        
        if filter_conditions:
            params['$filter'] = ' and '.join(filter_conditions)
        
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me/events',
            headers=headers,
            params=params,
            timeout=self.scp_client.timeout
        )
        response.raise_for_status()
        return response.json().get('value', [])