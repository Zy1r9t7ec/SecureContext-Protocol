"""
Workflow templates system for predefined authentication configurations.

This module provides a template system for common agent use cases,
allowing predefined scope templates, permission validation, and
workflow-specific authentication configurations.
"""

import json
import os
import time
import logging
from typing import Dict, Any, List, Optional, Set, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid
from pathlib import Path

try:
    from .config import get_config
except ImportError:
    try:
        from config import get_config
    except ImportError:
        # Fallback for testing
        def get_config():
            return type('Config', (), {
                'get_provider_settings': lambda: {}
            })()


class PermissionLevel(Enum):
    """Permission levels for data access."""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class DataType(Enum):
    """Types of data that can be accessed."""
    EMAIL = "email"
    CALENDAR = "calendar"
    CONTACTS = "contacts"
    DOCUMENTS = "documents"
    PROFILE = "profile"
    FILES = "files"
    PHOTOS = "photos"
    TASKS = "tasks"
    NOTES = "notes"


@dataclass
class PermissionRequirement:
    """Represents a permission requirement for a data type."""
    data_type: DataType
    permission_level: PermissionLevel
    required: bool = True
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'data_type': self.data_type.value,
            'permission_level': self.permission_level.value,
            'required': self.required,
            'description': self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PermissionRequirement':
        """Create from dictionary representation."""
        return cls(
            data_type=DataType(data['data_type']),
            permission_level=PermissionLevel(data['permission_level']),
            required=data.get('required', True),
            description=data.get('description')
        )


@dataclass
class ProviderScope:
    """Represents OAuth scopes for a specific provider."""
    provider: str
    scopes: List[str]
    optional_scopes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'provider': self.provider,
            'scopes': self.scopes,
            'optional_scopes': self.optional_scopes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProviderScope':
        """Create from dictionary representation."""
        return cls(
            provider=data['provider'],
            scopes=data['scopes'],
            optional_scopes=data.get('optional_scopes', [])
        )


@dataclass
class WorkflowTemplate:
    """Represents a workflow template with authentication requirements."""
    template_id: str
    name: str
    description: str
    version: str
    category: str
    permissions: List[PermissionRequirement]
    provider_scopes: List[ProviderScope]
    supported_providers: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    author: Optional[str] = None
    min_session_duration: int = 3600  # 1 hour default
    max_session_duration: int = 86400  # 24 hours default
    auto_renewal: bool = True
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not self.template_id:
            self.template_id = str(uuid.uuid4())
        
        # Validate provider scopes match supported providers
        scope_providers = {scope.provider for scope in self.provider_scopes}
        supported_set = set(self.supported_providers)
        
        if not scope_providers.issubset(supported_set):
            missing = scope_providers - supported_set
            raise ValueError(f"Provider scopes defined for unsupported providers: {missing}")
    
    def get_scopes_for_provider(self, provider: str) -> Optional[ProviderScope]:
        """Get scopes for a specific provider."""
        for scope in self.provider_scopes:
            if scope.provider == provider:
                return scope
        return None
    
    def get_required_permissions(self) -> List[PermissionRequirement]:
        """Get only required permissions."""
        return [perm for perm in self.permissions if perm.required]
    
    def get_optional_permissions(self) -> List[PermissionRequirement]:
        """Get only optional permissions."""
        return [perm for perm in self.permissions if not perm.required]
    
    def validate_provider_support(self, provider: str) -> bool:
        """Check if provider is supported by this template."""
        return provider in self.supported_providers
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'template_id': self.template_id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'category': self.category,
            'permissions': [perm.to_dict() for perm in self.permissions],
            'provider_scopes': [scope.to_dict() for scope in self.provider_scopes],
            'supported_providers': self.supported_providers,
            'metadata': self.metadata,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'tags': self.tags,
            'author': self.author,
            'min_session_duration': self.min_session_duration,
            'max_session_duration': self.max_session_duration,
            'auto_renewal': self.auto_renewal
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WorkflowTemplate':
        """Create from dictionary representation."""
        return cls(
            template_id=data['template_id'],
            name=data['name'],
            description=data['description'],
            version=data['version'],
            category=data['category'],
            permissions=[
                PermissionRequirement.from_dict(perm) 
                for perm in data['permissions']
            ],
            provider_scopes=[
                ProviderScope.from_dict(scope) 
                for scope in data['provider_scopes']
            ],
            supported_providers=data['supported_providers'],
            metadata=data.get('metadata', {}),
            created_at=data.get('created_at', time.time()),
            updated_at=data.get('updated_at', time.time()),
            tags=data.get('tags', []),
            author=data.get('author'),
            min_session_duration=data.get('min_session_duration', 3600),
            max_session_duration=data.get('max_session_duration', 86400),
            auto_renewal=data.get('auto_renewal', True)
        )


class WorkflowTemplateManager:
    """
    Manager for workflow templates with versioning and validation.
    
    Provides template registration, validation, and retrieval functionality
    for agent workflow authentication configurations.
    """
    
    def __init__(self, templates_dir: Optional[str] = None):
        """
        Initialize template manager.
        
        Args:
            templates_dir: Directory containing template files
        """
        self.templates_dir = templates_dir or self._get_default_templates_dir()
        self.templates: Dict[str, WorkflowTemplate] = {}
        self.templates_by_category: Dict[str, List[str]] = {}
        self.templates_by_provider: Dict[str, List[str]] = {}
        
        self.logger = logging.getLogger(__name__)
        
        # Load templates
        self._load_templates()
    
    def _get_default_templates_dir(self) -> str:
        """Get default templates directory."""
        current_dir = Path(__file__).parent
        return str(current_dir / "templates" / "workflows")
    
    def _load_templates(self):
        """Load templates from directory."""
        templates_path = Path(self.templates_dir)
        
        if not templates_path.exists():
            self.logger.warning(f"Templates directory not found: {templates_path}")
            self._create_default_templates()
            return
        
        # Check if directory is empty
        template_files = list(templates_path.glob("*.json"))
        if not template_files:
            self.logger.info(f"Templates directory is empty, creating default templates")
            self._create_default_templates()
            return
        
        # Load template files
        for template_file in templates_path.glob("*.json"):
            try:
                with open(template_file, 'r') as f:
                    template_data = json.load(f)
                
                template = WorkflowTemplate.from_dict(template_data)
                self.register_template(template)
                
                self.logger.info(f"Loaded template: {template.name} ({template.template_id})")
                
            except Exception as e:
                self.logger.error(f"Error loading template {template_file}: {e}")
    
    def _create_default_templates(self):
        """Create default templates."""
        templates_path = Path(self.templates_dir)
        templates_path.mkdir(parents=True, exist_ok=True)
        
        # Create default templates
        default_templates = self._get_default_templates()
        
        for template in default_templates:
            self.register_template(template)
            
            # Save to file
            template_file = templates_path / f"{template.template_id}.json"
            with open(template_file, 'w') as f:
                json.dump(template.to_dict(), f, indent=2)
            
            self.logger.info(f"Created default template: {template.name}")
    
    def _get_default_templates(self) -> List[WorkflowTemplate]:
        """Get default workflow templates."""
        return [
            # Email Management Template
            WorkflowTemplate(
                template_id="email-management-v1",
                name="Email Management",
                description="Template for agents that need to read, send, and manage emails",
                version="1.0.0",
                category="email",
                permissions=[
                    PermissionRequirement(
                        data_type=DataType.EMAIL,
                        permission_level=PermissionLevel.READ,
                        required=True,
                        description="Read user emails"
                    ),
                    PermissionRequirement(
                        data_type=DataType.EMAIL,
                        permission_level=PermissionLevel.WRITE,
                        required=False,
                        description="Send emails on behalf of user"
                    )
                ],
                provider_scopes=[
                    ProviderScope(
                        provider="google",
                        scopes=[
                            "https://www.googleapis.com/auth/gmail.readonly",
                            "https://www.googleapis.com/auth/gmail.send"
                        ],
                        optional_scopes=[
                            "https://www.googleapis.com/auth/gmail.modify"
                        ]
                    ),
                    ProviderScope(
                        provider="microsoft",
                        scopes=[
                            "Mail.Read",
                            "Mail.Send"
                        ],
                        optional_scopes=[
                            "Mail.ReadWrite"
                        ]
                    )
                ],
                supported_providers=["google", "microsoft"],
                tags=["email", "communication", "productivity"],
                author="SCP Team",
                min_session_duration=1800,  # 30 minutes
                max_session_duration=14400  # 4 hours
            ),
            
            # Calendar Management Template
            WorkflowTemplate(
                template_id="calendar-management-v1",
                name="Calendar Management",
                description="Template for agents that need to read and manage calendar events",
                version="1.0.0",
                category="calendar",
                permissions=[
                    PermissionRequirement(
                        data_type=DataType.CALENDAR,
                        permission_level=PermissionLevel.READ,
                        required=True,
                        description="Read calendar events"
                    ),
                    PermissionRequirement(
                        data_type=DataType.CALENDAR,
                        permission_level=PermissionLevel.WRITE,
                        required=False,
                        description="Create and modify calendar events"
                    )
                ],
                provider_scopes=[
                    ProviderScope(
                        provider="google",
                        scopes=[
                            "https://www.googleapis.com/auth/calendar.readonly"
                        ],
                        optional_scopes=[
                            "https://www.googleapis.com/auth/calendar.events"
                        ]
                    ),
                    ProviderScope(
                        provider="microsoft",
                        scopes=[
                            "Calendars.Read"
                        ],
                        optional_scopes=[
                            "Calendars.ReadWrite"
                        ]
                    )
                ],
                supported_providers=["google", "microsoft"],
                tags=["calendar", "scheduling", "productivity"],
                author="SCP Team",
                min_session_duration=1800,  # 30 minutes
                max_session_duration=7200   # 2 hours
            ),
            
            # Document Processing Template
            WorkflowTemplate(
                template_id="document-processing-v1",
                name="Document Processing",
                description="Template for agents that need to access and process documents",
                version="1.0.0",
                category="documents",
                permissions=[
                    PermissionRequirement(
                        data_type=DataType.DOCUMENTS,
                        permission_level=PermissionLevel.READ,
                        required=True,
                        description="Read documents"
                    ),
                    PermissionRequirement(
                        data_type=DataType.FILES,
                        permission_level=PermissionLevel.READ,
                        required=True,
                        description="Access file storage"
                    )
                ],
                provider_scopes=[
                    ProviderScope(
                        provider="google",
                        scopes=[
                            "https://www.googleapis.com/auth/drive.readonly",
                            "https://www.googleapis.com/auth/documents.readonly"
                        ],
                        optional_scopes=[
                            "https://www.googleapis.com/auth/drive.file"
                        ]
                    ),
                    ProviderScope(
                        provider="microsoft",
                        scopes=[
                            "Files.Read.All"
                        ],
                        optional_scopes=[
                            "Files.ReadWrite.All"
                        ]
                    )
                ],
                supported_providers=["google", "microsoft"],
                tags=["documents", "files", "processing"],
                author="SCP Team",
                min_session_duration=3600,  # 1 hour
                max_session_duration=28800  # 8 hours
            ),
            
            # Personal Assistant Template
            WorkflowTemplate(
                template_id="personal-assistant-v1",
                name="Personal Assistant",
                description="Comprehensive template for personal assistant agents",
                version="1.0.0",
                category="assistant",
                permissions=[
                    PermissionRequirement(
                        data_type=DataType.EMAIL,
                        permission_level=PermissionLevel.READ,
                        required=True,
                        description="Read emails"
                    ),
                    PermissionRequirement(
                        data_type=DataType.CALENDAR,
                        permission_level=PermissionLevel.READ,
                        required=True,
                        description="Read calendar"
                    ),
                    PermissionRequirement(
                        data_type=DataType.CONTACTS,
                        permission_level=PermissionLevel.READ,
                        required=False,
                        description="Access contacts"
                    ),
                    PermissionRequirement(
                        data_type=DataType.TASKS,
                        permission_level=PermissionLevel.READ,
                        required=False,
                        description="Access tasks and reminders"
                    )
                ],
                provider_scopes=[
                    ProviderScope(
                        provider="google",
                        scopes=[
                            "https://www.googleapis.com/auth/gmail.readonly",
                            "https://www.googleapis.com/auth/calendar.readonly"
                        ],
                        optional_scopes=[
                            "https://www.googleapis.com/auth/contacts.readonly",
                            "https://www.googleapis.com/auth/tasks.readonly"
                        ]
                    ),
                    ProviderScope(
                        provider="microsoft",
                        scopes=[
                            "Mail.Read",
                            "Calendars.Read"
                        ],
                        optional_scopes=[
                            "Contacts.Read",
                            "Tasks.Read"
                        ]
                    )
                ],
                supported_providers=["google", "microsoft"],
                tags=["assistant", "comprehensive", "productivity"],
                author="SCP Team",
                min_session_duration=3600,  # 1 hour
                max_session_duration=43200  # 12 hours
            )
        ]
    
    def register_template(self, template: WorkflowTemplate):
        """
        Register a workflow template.
        
        Args:
            template: WorkflowTemplate to register
        """
        template.updated_at = time.time()
        
        # Store template
        self.templates[template.template_id] = template
        
        # Update category index
        if template.category not in self.templates_by_category:
            self.templates_by_category[template.category] = []
        
        if template.template_id not in self.templates_by_category[template.category]:
            self.templates_by_category[template.category].append(template.template_id)
        
        # Update provider index
        for provider in template.supported_providers:
            if provider not in self.templates_by_provider:
                self.templates_by_provider[provider] = []
            
            if template.template_id not in self.templates_by_provider[provider]:
                self.templates_by_provider[provider].append(template.template_id)
    
    def get_template(self, template_id: str) -> Optional[WorkflowTemplate]:
        """
        Get template by ID.
        
        Args:
            template_id: Template ID
            
        Returns:
            WorkflowTemplate or None if not found
        """
        return self.templates.get(template_id)
    
    def get_templates_by_category(self, category: str) -> List[WorkflowTemplate]:
        """
        Get templates by category.
        
        Args:
            category: Template category
            
        Returns:
            List of WorkflowTemplate objects
        """
        template_ids = self.templates_by_category.get(category, [])
        return [self.templates[tid] for tid in template_ids if tid in self.templates]
    
    def get_templates_by_provider(self, provider: str) -> List[WorkflowTemplate]:
        """
        Get templates that support a specific provider.
        
        Args:
            provider: Provider name
            
        Returns:
            List of WorkflowTemplate objects
        """
        template_ids = self.templates_by_provider.get(provider, [])
        return [self.templates[tid] for tid in template_ids if tid in self.templates]
    
    def search_templates(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        provider: Optional[str] = None,
        tags: Optional[List[str]] = None,
        permissions: Optional[List[DataType]] = None
    ) -> List[WorkflowTemplate]:
        """
        Search templates by various criteria.
        
        Args:
            query: Text query for name/description
            category: Template category
            provider: Required provider support
            tags: Required tags
            permissions: Required permission types
            
        Returns:
            List of matching WorkflowTemplate objects
        """
        results = list(self.templates.values())
        
        # Filter by category
        if category:
            results = [t for t in results if t.category == category]
        
        # Filter by provider
        if provider:
            results = [t for t in results if provider in t.supported_providers]
        
        # Filter by tags
        if tags:
            results = [
                t for t in results
                if any(tag in t.tags for tag in tags)
            ]
        
        # Filter by permissions
        if permissions:
            results = [
                t for t in results
                if any(
                    perm.data_type in permissions
                    for perm in t.permissions
                )
            ]
        
        # Filter by text query
        if query:
            query_lower = query.lower()
            results = [
                t for t in results
                if (query_lower in t.name.lower() or
                    query_lower in t.description.lower())
            ]
        
        return results
    
    def validate_template_permissions(
        self,
        template_id: str,
        available_scopes: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """
        Validate that available scopes meet template requirements.
        
        Args:
            template_id: Template ID to validate
            available_scopes: Dict of provider -> available scopes
            
        Returns:
            Validation result with details
        """
        template = self.get_template(template_id)
        if not template:
            return {
                'valid': False,
                'error': f'Template {template_id} not found'
            }
        
        validation_result = {
            'valid': True,
            'template_id': template_id,
            'template_name': template.name,
            'providers': {},
            'missing_permissions': [],
            'warnings': []
        }
        
        # Check each provider
        for provider_scope in template.provider_scopes:
            provider = provider_scope.provider
            required_scopes = set(provider_scope.scopes)
            optional_scopes = set(provider_scope.optional_scopes)
            available = set(available_scopes.get(provider, []))
            
            provider_result = {
                'provider': provider,
                'valid': True,
                'required_scopes': list(required_scopes),
                'optional_scopes': list(optional_scopes),
                'available_scopes': list(available),
                'missing_required': [],
                'missing_optional': []
            }
            
            # Check required scopes
            missing_required = required_scopes - available
            if missing_required:
                provider_result['valid'] = False
                provider_result['missing_required'] = list(missing_required)
                validation_result['valid'] = False
                validation_result['missing_permissions'].extend([
                    f"{provider}: {scope}" for scope in missing_required
                ])
            
            # Check optional scopes
            missing_optional = optional_scopes - available
            if missing_optional:
                provider_result['missing_optional'] = list(missing_optional)
                validation_result['warnings'].extend([
                    f"Optional scope missing for {provider}: {scope}"
                    for scope in missing_optional
                ])
            
            validation_result['providers'][provider] = provider_result
        
        return validation_result
    
    def create_session_config(
        self,
        template_id: str,
        provider: str,
        user_preferences: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create session configuration based on template.
        
        Args:
            template_id: Template ID
            provider: OAuth provider
            user_preferences: Optional user preferences
            
        Returns:
            Session configuration dictionary
        """
        template = self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")
        
        if not template.validate_provider_support(provider):
            raise ValueError(f"Provider {provider} not supported by template {template_id}")
        
        provider_scope = template.get_scopes_for_provider(provider)
        if not provider_scope:
            raise ValueError(f"No scopes defined for provider {provider} in template {template_id}")
        
        # Build session configuration
        config = {
            'template_id': template_id,
            'template_name': template.name,
            'provider': provider,
            'scopes': provider_scope.scopes.copy(),
            'session_duration': template.min_session_duration,
            'auto_renewal': template.auto_renewal,
            'permissions': [perm.to_dict() for perm in template.get_required_permissions()],
            'metadata': {
                'template_version': template.version,
                'template_category': template.category,
                'created_from_template': True
            }
        }
        
        # Apply user preferences
        if user_preferences:
            # Include optional scopes if requested
            if user_preferences.get('include_optional_scopes', False):
                config['scopes'].extend(provider_scope.optional_scopes)
            
            # Adjust session duration within template limits
            requested_duration = user_preferences.get('session_duration')
            if requested_duration:
                config['session_duration'] = max(
                    template.min_session_duration,
                    min(requested_duration, template.max_session_duration)
                )
            
            # Override auto-renewal if specified
            if 'auto_renewal' in user_preferences:
                config['auto_renewal'] = user_preferences['auto_renewal']
            
            # Add user metadata
            if 'metadata' in user_preferences:
                config['metadata'].update(user_preferences['metadata'])
        
        return config
    
    def get_all_templates(self) -> List[WorkflowTemplate]:
        """
        Get all registered templates.
        
        Returns:
            List of all WorkflowTemplate objects
        """
        return list(self.templates.values())
    
    def get_categories(self) -> List[str]:
        """
        Get all template categories.
        
        Returns:
            List of category names
        """
        return list(self.templates_by_category.keys())
    
    def get_supported_providers(self) -> List[str]:
        """
        Get all supported providers across templates.
        
        Returns:
            List of provider names
        """
        return list(self.templates_by_provider.keys())
    
    def export_template(self, template_id: str, file_path: str):
        """
        Export template to file.
        
        Args:
            template_id: Template ID to export
            file_path: Output file path
        """
        template = self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")
        
        with open(file_path, 'w') as f:
            json.dump(template.to_dict(), f, indent=2)
    
    def import_template(self, file_path: str) -> str:
        """
        Import template from file.
        
        Args:
            file_path: Template file path
            
        Returns:
            Template ID of imported template
        """
        with open(file_path, 'r') as f:
            template_data = json.load(f)
        
        template = WorkflowTemplate.from_dict(template_data)
        self.register_template(template)
        
        return template.template_id
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get template manager statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_templates': len(self.templates),
            'categories': len(self.templates_by_category),
            'supported_providers': len(self.templates_by_provider),
            'templates_by_category': {
                category: len(template_ids)
                for category, template_ids in self.templates_by_category.items()
            },
            'templates_by_provider': {
                provider: len(template_ids)
                for provider, template_ids in self.templates_by_provider.items()
            }
        }


# Global template manager instance
_template_manager = None


def get_template_manager() -> WorkflowTemplateManager:
    """
    Get global template manager instance.
    
    Returns:
        WorkflowTemplateManager instance
    """
    global _template_manager
    
    if _template_manager is None:
        _template_manager = WorkflowTemplateManager()
    
    return _template_manager