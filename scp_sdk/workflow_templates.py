"""
Client-side workflow templates functionality for the SCP SDK.

This module provides client-side access to workflow templates,
allowing agents to discover and use predefined authentication
configurations for common use cases.
"""

import logging
from typing import Dict, Any, List, Optional
import requests

from .client import SCPClient
from .exceptions import SCPError, SCPConnectionError, SCPValidationError


class WorkflowTemplateClient:
    """
    Client for accessing workflow templates from SCP server.
    
    Provides methods to discover, validate, and use workflow templates
    for agent authentication configurations.
    """
    
    def __init__(self, scp_client: Optional[SCPClient] = None):
        """
        Initialize workflow template client.
        
        Args:
            scp_client: SCP client instance
        """
        self.scp_client = scp_client or SCPClient()
        self.logger = logging.getLogger(__name__)
    
    def get_templates(
        self,
        category: Optional[str] = None,
        provider: Optional[str] = None,
        tags: Optional[List[str]] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get workflow templates with optional filtering.
        
        Args:
            category: Filter by category
            provider: Filter by provider support
            tags: Filter by tags
            query: Text search in name/description
            
        Returns:
            List of template dictionaries
            
        Raises:
            SCPConnectionError: If connection to server fails
            SCPError: If server returns an error
        """
        try:
            params = {}
            
            if category:
                params['category'] = category
            
            if provider:
                params['provider'] = provider
            
            if tags:
                params['tags'] = ','.join(tags)
            
            if query:
                params['query'] = query
            
            response = self.scp_client._make_request(
                'GET',
                '/api/workflows/templates',
                params=params
            )
            
            if response.get('success'):
                return response['data']['templates']
            else:
                raise SCPError(
                    response.get('error', {}).get('message', 'Failed to get templates'),
                    error_code=response.get('error', {}).get('code')
                )
                
        except requests.exceptions.RequestException as e:
            raise SCPConnectionError(f"Failed to connect to SCP server: {e}")
    
    def get_template(self, template_id: str) -> Dict[str, Any]:
        """
        Get specific template by ID.
        
        Args:
            template_id: Template ID
            
        Returns:
            Template dictionary
            
        Raises:
            SCPConnectionError: If connection to server fails
            SCPError: If template not found or server error
        """
        try:
            response = self.scp_client._make_request(
                'GET',
                f'/api/workflows/templates/{template_id}'
            )
            
            if response.get('success'):
                return response['data']['template']
            else:
                raise SCPError(
                    response.get('error', {}).get('message', f'Template {template_id} not found'),
                    error_code=response.get('error', {}).get('code')
                )
                
        except requests.exceptions.RequestException as e:
            raise SCPConnectionError(f"Failed to connect to SCP server: {e}")
    
    def validate_template(
        self,
        template_id: str,
        available_scopes: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """
        Validate template permissions against available scopes.
        
        Args:
            template_id: Template ID to validate
            available_scopes: Dict of provider -> available scopes
            
        Returns:
            Validation result dictionary
            
        Raises:
            SCPConnectionError: If connection to server fails
            SCPError: If server returns an error
        """
        try:
            data = {
                'available_scopes': available_scopes
            }
            
            response = self.scp_client._make_request(
                'POST',
                f'/api/workflows/templates/{template_id}/validate',
                json=data
            )
            
            if response.get('success'):
                return response['data']['validation']
            else:
                raise SCPError(
                    response.get('error', {}).get('message', 'Validation failed'),
                    error_code=response.get('error', {}).get('code')
                )
                
        except requests.exceptions.RequestException as e:
            raise SCPConnectionError(f"Failed to connect to SCP server: {e}")
    
    def create_session_config(
        self,
        template_id: str,
        provider: str,
        user_preferences: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create session configuration from template.
        
        Args:
            template_id: Template ID
            provider: OAuth provider
            user_preferences: Optional user preferences
            
        Returns:
            Session configuration dictionary
            
        Raises:
            SCPConnectionError: If connection to server fails
            SCPValidationError: If template or provider invalid
            SCPError: If server returns an error
        """
        try:
            data = {
                'provider': provider
            }
            
            if user_preferences:
                data['user_preferences'] = user_preferences
            
            response = self.scp_client._make_request(
                'POST',
                f'/api/workflows/templates/{template_id}/config',
                json=data
            )
            
            if response.get('success'):
                return response['data']['session_config']
            else:
                error_code = response.get('error', {}).get('code')
                error_message = response.get('error', {}).get('message', 'Failed to create session config')
                
                if error_code in ['INVALID_REQUEST', 'TEMPLATE_NOT_FOUND', 'PROVIDER_NOT_SUPPORTED']:
                    raise SCPValidationError(error_message, error_code=error_code)
                else:
                    raise SCPError(error_message, error_code=error_code)
                
        except requests.exceptions.RequestException as e:
            raise SCPConnectionError(f"Failed to connect to SCP server: {e}")
    
    def get_categories(self) -> List[str]:
        """
        Get all available template categories.
        
        Returns:
            List of category names
            
        Raises:
            SCPConnectionError: If connection to server fails
            SCPError: If server returns an error
        """
        try:
            response = self.scp_client._make_request(
                'GET',
                '/api/workflows/templates'
            )
            
            if response.get('success'):
                return response['data']['categories']
            else:
                raise SCPError(
                    response.get('error', {}).get('message', 'Failed to get categories'),
                    error_code=response.get('error', {}).get('code')
                )
                
        except requests.exceptions.RequestException as e:
            raise SCPConnectionError(f"Failed to connect to SCP server: {e}")
    
    def get_supported_providers(self) -> List[str]:
        """
        Get all supported providers across templates.
        
        Returns:
            List of provider names
            
        Raises:
            SCPConnectionError: If connection to server fails
            SCPError: If server returns an error
        """
        try:
            response = self.scp_client._make_request(
                'GET',
                '/api/workflows/templates'
            )
            
            if response.get('success'):
                return response['data']['supported_providers']
            else:
                raise SCPError(
                    response.get('error', {}).get('message', 'Failed to get supported providers'),
                    error_code=response.get('error', {}).get('code')
                )
                
        except requests.exceptions.RequestException as e:
            raise SCPConnectionError(f"Failed to connect to SCP server: {e}")
    
    def find_templates_for_use_case(
        self,
        use_case: str,
        provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Find templates suitable for a specific use case.
        
        Args:
            use_case: Use case description (e.g., "email management", "calendar")
            provider: Optional provider requirement
            
        Returns:
            List of suitable template dictionaries
        """
        # Search by query and provider
        templates = self.get_templates(query=use_case, provider=provider)
        
        # Also search by tags
        use_case_words = use_case.lower().split()
        tag_results = self.get_templates(tags=use_case_words, provider=provider)
        
        # Combine and deduplicate results
        all_templates = templates + tag_results
        seen_ids = set()
        unique_templates = []
        
        for template in all_templates:
            if template['template_id'] not in seen_ids:
                seen_ids.add(template['template_id'])
                unique_templates.append(template)
        
        return unique_templates
    
    def get_template_recommendations(
        self,
        required_permissions: List[str],
        preferred_provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get template recommendations based on required permissions.
        
        Args:
            required_permissions: List of required permission types
            preferred_provider: Optional preferred provider
            
        Returns:
            List of recommended template dictionaries
        """
        # Get all templates
        all_templates = self.get_templates(provider=preferred_provider)
        
        recommendations = []
        
        for template in all_templates:
            # Check if template covers required permissions
            template_permissions = {
                perm['data_type'] for perm in template.get('permissions', [])
                if perm.get('required', True)
            }
            
            required_set = set(required_permissions)
            
            # Calculate coverage
            coverage = len(required_set.intersection(template_permissions)) / len(required_set)
            
            if coverage > 0:
                template_copy = template.copy()
                template_copy['_recommendation_score'] = coverage
                recommendations.append(template_copy)
        
        # Sort by coverage score
        recommendations.sort(key=lambda t: t['_recommendation_score'], reverse=True)
        
        return recommendations
    
    def create_oauth_session_from_template(
        self,
        template_id: str,
        provider: str,
        user_preferences: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create OAuth session using template configuration.
        
        This is a convenience method that creates session config from template
        and initiates OAuth flow.
        
        Args:
            template_id: Template ID
            provider: OAuth provider
            user_preferences: Optional user preferences
            
        Returns:
            OAuth authorization URL
            
        Raises:
            SCPConnectionError: If connection to server fails
            SCPValidationError: If template or provider invalid
            SCPError: If server returns an error
        """
        # Get session config from template
        session_config = self.create_session_config(
            template_id,
            provider,
            user_preferences
        )
        
        # Use the scopes from template for OAuth flow
        scopes = session_config.get('scopes', [])
        
        # Initiate OAuth flow with template scopes
        # This would typically involve calling the provider's OAuth endpoint
        # For now, we'll return the authorization URL that would be used
        
        # Note: This is a simplified implementation
        # In practice, this would integrate with the OAuth flow endpoints
        
        return f"/oauth/{provider}/authorize?scopes={','.join(scopes)}&template_id={template_id}"


class TemplateBasedWorkflow:
    """
    Helper class for creating template-based workflows.
    
    Provides high-level methods for common workflow patterns
    using predefined templates.
    """
    
    def __init__(self, template_client: Optional[WorkflowTemplateClient] = None):
        """
        Initialize template-based workflow helper.
        
        Args:
            template_client: Template client instance
        """
        self.template_client = template_client or WorkflowTemplateClient()
        self.logger = logging.getLogger(__name__)
    
    def setup_email_workflow(
        self,
        provider: str,
        include_send_permissions: bool = False,
        session_duration: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Set up email management workflow.
        
        Args:
            provider: OAuth provider
            include_send_permissions: Whether to include email sending permissions
            session_duration: Optional custom session duration
            
        Returns:
            Session configuration for email workflow
        """
        # Find email management template
        templates = self.template_client.find_templates_for_use_case(
            "email management",
            provider=provider
        )
        
        if not templates:
            raise SCPValidationError(f"No email templates found for provider {provider}")
        
        # Use the first matching template
        template = templates[0]
        
        # Set up user preferences
        user_preferences = {
            'include_optional_scopes': include_send_permissions
        }
        
        if session_duration:
            user_preferences['session_duration'] = session_duration
        
        return self.template_client.create_session_config(
            template['template_id'],
            provider,
            user_preferences
        )
    
    def setup_calendar_workflow(
        self,
        provider: str,
        include_write_permissions: bool = False,
        session_duration: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Set up calendar management workflow.
        
        Args:
            provider: OAuth provider
            include_write_permissions: Whether to include calendar write permissions
            session_duration: Optional custom session duration
            
        Returns:
            Session configuration for calendar workflow
        """
        # Find calendar management template
        templates = self.template_client.find_templates_for_use_case(
            "calendar management",
            provider=provider
        )
        
        if not templates:
            raise SCPValidationError(f"No calendar templates found for provider {provider}")
        
        # Use the first matching template
        template = templates[0]
        
        # Set up user preferences
        user_preferences = {
            'include_optional_scopes': include_write_permissions
        }
        
        if session_duration:
            user_preferences['session_duration'] = session_duration
        
        return self.template_client.create_session_config(
            template['template_id'],
            provider,
            user_preferences
        )
    
    def setup_personal_assistant_workflow(
        self,
        provider: str,
        session_duration: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Set up comprehensive personal assistant workflow.
        
        Args:
            provider: OAuth provider
            session_duration: Optional custom session duration
            
        Returns:
            Session configuration for personal assistant workflow
        """
        # Find personal assistant template
        templates = self.template_client.find_templates_for_use_case(
            "personal assistant",
            provider=provider
        )
        
        if not templates:
            raise SCPValidationError(f"No personal assistant templates found for provider {provider}")
        
        # Use the first matching template
        template = templates[0]
        
        # Set up user preferences with all optional scopes
        user_preferences = {
            'include_optional_scopes': True
        }
        
        if session_duration:
            user_preferences['session_duration'] = session_duration
        
        return self.template_client.create_session_config(
            template['template_id'],
            provider,
            user_preferences
        )
    
    def setup_custom_workflow(
        self,
        required_permissions: List[str],
        provider: str,
        session_duration: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Set up custom workflow based on required permissions.
        
        Args:
            required_permissions: List of required permission types
            provider: OAuth provider
            session_duration: Optional custom session duration
            
        Returns:
            Session configuration for custom workflow
        """
        # Get template recommendations
        recommendations = self.template_client.get_template_recommendations(
            required_permissions,
            preferred_provider=provider
        )
        
        if not recommendations:
            raise SCPValidationError(
                f"No suitable templates found for permissions {required_permissions} "
                f"and provider {provider}"
            )
        
        # Use the best matching template
        template = recommendations[0]
        
        # Set up user preferences
        user_preferences = {}
        
        if session_duration:
            user_preferences['session_duration'] = session_duration
        
        return self.template_client.create_session_config(
            template['template_id'],
            provider,
            user_preferences
        )