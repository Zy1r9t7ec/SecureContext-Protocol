"""
Tests for workflow templates system.

This module tests the workflow template management, validation,
and session configuration functionality.
"""

import unittest
import tempfile
import shutil
import json 
import os
import logging
from unittest.mock import Mock, patch
from pathlib import Path
from collections import defaultdict

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from authentication_proxy.workflow_templates import (
    WorkflowTemplate, WorkflowTemplateManager, PermissionRequirement,
    ProviderScope, DataType, PermissionLevel, get_template_manager
)


class TestWorkflowTemplate(unittest.TestCase):
    """Test WorkflowTemplate class."""
    
    def test_create_template(self):
        """Test template creation."""
        permissions = [
            PermissionRequirement(
                data_type=DataType.EMAIL,
                permission_level=PermissionLevel.READ,
                required=True,
                description="Read emails"
            )
        ]
        
        provider_scopes = [
            ProviderScope(
                provider="google",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                optional_scopes=["https://www.googleapis.com/auth/gmail.send"]
            )
        ]
        
        template = WorkflowTemplate(
            template_id="test-template",
            name="Test Template",
            description="A test template",
            version="1.0.0",
            category="test",
            permissions=permissions,
            provider_scopes=provider_scopes,
            supported_providers=["google"],
            tags=["test", "email"]
        )
        
        self.assertEqual(template.template_id, "test-template")
        self.assertEqual(template.name, "Test Template")
        self.assertEqual(template.category, "test")
        self.assertEqual(len(template.permissions), 1)
        self.assertEqual(len(template.provider_scopes), 1)
        self.assertIn("google", template.supported_providers)
        self.assertIn("test", template.tags)
    
    def test_template_validation(self):
        """Test template validation."""
        permissions = [
            PermissionRequirement(
                data_type=DataType.EMAIL,
                permission_level=PermissionLevel.READ
            )
        ]
        
        # Valid template
        provider_scopes = [
            ProviderScope(provider="google", scopes=["scope1"])
        ]
        
        template = WorkflowTemplate(
            template_id="valid-template",
            name="Valid Template",
            description="Valid template",
            version="1.0.0",
            category="test",
            permissions=permissions,
            provider_scopes=provider_scopes,
            supported_providers=["google"]
        )
        
        self.assertTrue(template.validate_provider_support("google"))
        self.assertFalse(template.validate_provider_support("microsoft"))
        
        # Invalid template - scope for unsupported provider
        with self.assertRaises(ValueError):
            WorkflowTemplate(
                template_id="invalid-template",
                name="Invalid Template",
                description="Invalid template",
                version="1.0.0",
                category="test",
                permissions=permissions,
                provider_scopes=[
                    ProviderScope(provider="unsupported", scopes=["scope1"])
                ],
                supported_providers=["google"]
            )
    
    def test_get_scopes_for_provider(self):
        """Test getting scopes for specific provider."""
        provider_scopes = [
            ProviderScope(
                provider="google",
                scopes=["gmail.readonly"],
                optional_scopes=["gmail.send"]
            ),
            ProviderScope(
                provider="microsoft",
                scopes=["Mail.Read"]
            )
        ]
        
        template = WorkflowTemplate(
            template_id="multi-provider",
            name="Multi Provider",
            description="Multi provider template",
            version="1.0.0",
            category="test",
            permissions=[],
            provider_scopes=provider_scopes,
            supported_providers=["google", "microsoft"]
        )
        
        google_scopes = template.get_scopes_for_provider("google")
        self.assertIsNotNone(google_scopes)
        self.assertEqual(google_scopes.provider, "google")
        self.assertIn("gmail.readonly", google_scopes.scopes)
        self.assertIn("gmail.send", google_scopes.optional_scopes)
        
        microsoft_scopes = template.get_scopes_for_provider("microsoft")
        self.assertIsNotNone(microsoft_scopes)
        self.assertEqual(microsoft_scopes.provider, "microsoft")
        self.assertIn("Mail.Read", microsoft_scopes.scopes)
        
        unsupported_scopes = template.get_scopes_for_provider("unsupported")
        self.assertIsNone(unsupported_scopes)
    
    def test_permission_filtering(self):
        """Test permission filtering methods."""
        permissions = [
            PermissionRequirement(
                data_type=DataType.EMAIL,
                permission_level=PermissionLevel.READ,
                required=True
            ),
            PermissionRequirement(
                data_type=DataType.EMAIL,
                permission_level=PermissionLevel.WRITE,
                required=False
            ),
            PermissionRequirement(
                data_type=DataType.CALENDAR,
                permission_level=PermissionLevel.READ,
                required=True
            )
        ]
        
        template = WorkflowTemplate(
            template_id="permission-test",
            name="Permission Test",
            description="Test permissions",
            version="1.0.0",
            category="test",
            permissions=permissions,
            provider_scopes=[],
            supported_providers=[]
        )
        
        required_perms = template.get_required_permissions()
        optional_perms = template.get_optional_permissions()
        
        self.assertEqual(len(required_perms), 2)
        self.assertEqual(len(optional_perms), 1)
        
        self.assertTrue(all(perm.required for perm in required_perms))
        self.assertTrue(all(not perm.required for perm in optional_perms))
    
    def test_template_serialization(self):
        """Test template to/from dict conversion."""
        permissions = [
            PermissionRequirement(
                data_type=DataType.EMAIL,
                permission_level=PermissionLevel.READ,
                required=True,
                description="Read emails"
            )
        ]
        
        provider_scopes = [
            ProviderScope(
                provider="google",
                scopes=["gmail.readonly"],
                optional_scopes=["gmail.send"]
            )
        ]
        
        template = WorkflowTemplate(
            template_id="serialization-test",
            name="Serialization Test",
            description="Test serialization",
            version="1.0.0",
            category="test",
            permissions=permissions,
            provider_scopes=provider_scopes,
            supported_providers=["google"],
            tags=["test"],
            author="Test Author"
        )
        
        # Convert to dict
        template_dict = template.to_dict()
        
        # Verify dict structure
        self.assertEqual(template_dict['template_id'], "serialization-test")
        self.assertEqual(template_dict['name'], "Serialization Test")
        self.assertEqual(len(template_dict['permissions']), 1)
        self.assertEqual(len(template_dict['provider_scopes']), 1)
        
        # Convert back from dict
        restored_template = WorkflowTemplate.from_dict(template_dict)
        
        # Verify restoration
        self.assertEqual(restored_template.template_id, template.template_id)
        self.assertEqual(restored_template.name, template.name)
        self.assertEqual(len(restored_template.permissions), len(template.permissions))
        self.assertEqual(len(restored_template.provider_scopes), len(template.provider_scopes))


class TestWorkflowTemplateManager(unittest.TestCase):
    """Test WorkflowTemplateManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directory for templates
        self.temp_dir = tempfile.mkdtemp()
        # Create empty template manager without loading defaults
        self.template_manager = WorkflowTemplateManager.__new__(WorkflowTemplateManager)
        self.template_manager.templates_dir = self.temp_dir
        self.template_manager.templates = {}
        self.template_manager.templates_by_category = defaultdict(list)
        self.template_manager.templates_by_provider = defaultdict(list)
        self.template_manager.logger = logging.getLogger(__name__)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_template_registration(self):
        """Test template registration."""
        template = WorkflowTemplate(
            template_id="test-registration",
            name="Test Registration",
            description="Test template registration",
            version="1.0.0",
            category="test",
            permissions=[],
            provider_scopes=[],
            supported_providers=[]
        )
        
        self.template_manager.register_template(template)
        
        # Verify registration
        retrieved_template = self.template_manager.get_template("test-registration")
        self.assertIsNotNone(retrieved_template)
        self.assertEqual(retrieved_template.name, "Test Registration")
        
        # Verify category indexing
        test_templates = self.template_manager.get_templates_by_category("test")
        self.assertEqual(len(test_templates), 1)
        self.assertEqual(test_templates[0].template_id, "test-registration")
    
    def test_provider_indexing(self):
        """Test provider indexing."""
        template1 = WorkflowTemplate(
            template_id="google-template",
            name="Google Template",
            description="Google only template",
            version="1.0.0",
            category="test",
            permissions=[],
            provider_scopes=[],
            supported_providers=["google"]
        )
        
        template2 = WorkflowTemplate(
            template_id="multi-template",
            name="Multi Template",
            description="Multi provider template",
            version="1.0.0",
            category="test",
            permissions=[],
            provider_scopes=[],
            supported_providers=["google", "microsoft"]
        )
        
        self.template_manager.register_template(template1)
        self.template_manager.register_template(template2)
        
        # Test provider filtering
        google_templates = self.template_manager.get_templates_by_provider("google")
        microsoft_templates = self.template_manager.get_templates_by_provider("microsoft")
        
        self.assertEqual(len(google_templates), 2)
        self.assertEqual(len(microsoft_templates), 1)
        
        google_template_ids = {t.template_id for t in google_templates}
        self.assertIn("google-template", google_template_ids)
        self.assertIn("multi-template", google_template_ids)
        
        self.assertEqual(microsoft_templates[0].template_id, "multi-template")
    
    def test_template_search(self):
        """Test template search functionality."""
        templates = [
            WorkflowTemplate(
                template_id="email-template",
                name="Email Management",
                description="Manage emails efficiently",
                version="1.0.0",
                category="email",
                permissions=[
                    PermissionRequirement(
                        data_type=DataType.EMAIL,
                        permission_level=PermissionLevel.READ
                    )
                ],
                provider_scopes=[],
                supported_providers=["google"],
                tags=["email", "productivity"]
            ),
            WorkflowTemplate(
                template_id="calendar-template",
                name="Calendar Scheduling",
                description="Schedule calendar events",
                version="1.0.0",
                category="calendar",
                permissions=[
                    PermissionRequirement(
                        data_type=DataType.CALENDAR,
                        permission_level=PermissionLevel.READ
                    )
                ],
                provider_scopes=[],
                supported_providers=["microsoft"],
                tags=["calendar", "scheduling"]
            )
        ]
        
        for template in templates:
            self.template_manager.register_template(template)
        
        # Test text search
        email_results = self.template_manager.search_templates(query="email")
        self.assertEqual(len(email_results), 1)
        self.assertEqual(email_results[0].template_id, "email-template")
        
        # Test category search
        calendar_results = self.template_manager.search_templates(category="calendar")
        self.assertEqual(len(calendar_results), 1)
        self.assertEqual(calendar_results[0].template_id, "calendar-template")
        
        # Test provider search
        google_results = self.template_manager.search_templates(provider="google")
        self.assertEqual(len(google_results), 1)
        self.assertEqual(google_results[0].template_id, "email-template")
        
        # Test tag search
        productivity_results = self.template_manager.search_templates(tags=["productivity"])
        self.assertEqual(len(productivity_results), 1)
        self.assertEqual(productivity_results[0].template_id, "email-template")
        
        # Test permission search
        email_perm_results = self.template_manager.search_templates(
            permissions=[DataType.EMAIL]
        )
        self.assertEqual(len(email_perm_results), 1)
        self.assertEqual(email_perm_results[0].template_id, "email-template")
    
    def test_permission_validation(self):
        """Test permission validation."""
        template = WorkflowTemplate(
            template_id="validation-test",
            name="Validation Test",
            description="Test validation",
            version="1.0.0",
            category="test",
            permissions=[],
            provider_scopes=[
                ProviderScope(
                    provider="google",
                    scopes=["gmail.readonly", "gmail.send"],
                    optional_scopes=["gmail.modify"]
                ),
                ProviderScope(
                    provider="microsoft",
                    scopes=["Mail.Read"],
                    optional_scopes=["Mail.Send"]
                )
            ],
            supported_providers=["google", "microsoft"]
        )
        
        self.template_manager.register_template(template)
        
        # Test with sufficient scopes
        available_scopes = {
            "google": ["gmail.readonly", "gmail.send", "gmail.modify"],
            "microsoft": ["Mail.Read", "Mail.Send"]
        }
        
        result = self.template_manager.validate_template_permissions(
            "validation-test",
            available_scopes
        )
        
        self.assertTrue(result['valid'])
        self.assertEqual(len(result['providers']), 2)
        self.assertTrue(result['providers']['google']['valid'])
        self.assertTrue(result['providers']['microsoft']['valid'])
        
        # Test with insufficient scopes
        insufficient_scopes = {
            "google": ["gmail.readonly"],  # Missing gmail.send
            "microsoft": ["Mail.Read"]
        }
        
        result = self.template_manager.validate_template_permissions(
            "validation-test",
            insufficient_scopes
        )
        
        self.assertFalse(result['valid'])
        self.assertFalse(result['providers']['google']['valid'])
        self.assertIn("gmail.send", result['providers']['google']['missing_required'])
        self.assertIn("gmail.modify", result['providers']['google']['missing_optional'])
    
    def test_session_config_creation(self):
        """Test session configuration creation."""
        template = WorkflowTemplate(
            template_id="config-test",
            name="Config Test",
            description="Test config creation",
            version="1.0.0",
            category="test",
            permissions=[
                PermissionRequirement(
                    data_type=DataType.EMAIL,
                    permission_level=PermissionLevel.READ,
                    required=True
                )
            ],
            provider_scopes=[
                ProviderScope(
                    provider="google",
                    scopes=["gmail.readonly"],
                    optional_scopes=["gmail.send"]
                )
            ],
            supported_providers=["google"],
            min_session_duration=1800,
            max_session_duration=7200,
            auto_renewal=True
        )
        
        self.template_manager.register_template(template)
        
        # Test basic config creation
        config = self.template_manager.create_session_config(
            "config-test",
            "google"
        )
        
        self.assertEqual(config['template_id'], "config-test")
        self.assertEqual(config['provider'], "google")
        self.assertEqual(config['scopes'], ["gmail.readonly"])
        self.assertEqual(config['session_duration'], 1800)
        self.assertTrue(config['auto_renewal'])
        
        # Test with user preferences
        user_preferences = {
            'include_optional_scopes': True,
            'session_duration': 3600,
            'auto_renewal': False,
            'metadata': {'user_id': 'test123'}
        }
        
        config = self.template_manager.create_session_config(
            "config-test",
            "google",
            user_preferences
        )
        
        self.assertIn("gmail.send", config['scopes'])
        self.assertEqual(config['session_duration'], 3600)
        self.assertFalse(config['auto_renewal'])
        self.assertEqual(config['metadata']['user_id'], 'test123')
        
        # Test with invalid provider
        with self.assertRaises(ValueError):
            self.template_manager.create_session_config(
                "config-test",
                "unsupported"
            )
        
        # Test with invalid template
        with self.assertRaises(ValueError):
            self.template_manager.create_session_config(
                "nonexistent",
                "google"
            )
    
    def test_template_file_operations(self):
        """Test template import/export."""
        template = WorkflowTemplate(
            template_id="file-test",
            name="File Test",
            description="Test file operations",
            version="1.0.0",
            category="test",
            permissions=[],
            provider_scopes=[],
            supported_providers=[]
        )
        
        self.template_manager.register_template(template)
        
        # Test export
        export_path = os.path.join(self.temp_dir, "exported_template.json")
        self.template_manager.export_template("file-test", export_path)
        
        self.assertTrue(os.path.exists(export_path))
        
        # Verify exported content
        with open(export_path, 'r') as f:
            exported_data = json.load(f)
        
        self.assertEqual(exported_data['template_id'], "file-test")
        self.assertEqual(exported_data['name'], "File Test")
        
        # Test import
        new_manager = WorkflowTemplateManager(templates_dir=tempfile.mkdtemp())
        imported_id = new_manager.import_template(export_path)
        
        self.assertEqual(imported_id, "file-test")
        
        imported_template = new_manager.get_template("file-test")
        self.assertIsNotNone(imported_template)
        self.assertEqual(imported_template.name, "File Test")
    
    def test_default_templates_creation(self):
        """Test default templates are created."""
        # Create manager with empty directory
        empty_dir = tempfile.mkdtemp()
        try:
            manager = WorkflowTemplateManager(templates_dir=empty_dir)
            
            # Should have default templates
            templates = manager.get_all_templates()
            self.assertGreater(len(templates), 0)
            
            # Check for expected default templates
            template_names = {t.name for t in templates}
            self.assertIn("Email Management", template_names)
            self.assertIn("Calendar Management", template_names)
            self.assertIn("Personal Assistant", template_names)
            
        finally:
            shutil.rmtree(empty_dir)
    
    def test_statistics(self):
        """Test statistics generation."""
        templates = [
            WorkflowTemplate(
                template_id="stats-1",
                name="Stats 1",
                description="Stats test 1",
                version="1.0.0",
                category="email",
                permissions=[],
                provider_scopes=[],
                supported_providers=["google"]
            ),
            WorkflowTemplate(
                template_id="stats-2",
                name="Stats 2",
                description="Stats test 2",
                version="1.0.0",
                category="email",
                permissions=[],
                provider_scopes=[],
                supported_providers=["microsoft"]
            ),
            WorkflowTemplate(
                template_id="stats-3",
                name="Stats 3",
                description="Stats test 3",
                version="1.0.0",
                category="calendar",
                permissions=[],
                provider_scopes=[],
                supported_providers=["google", "microsoft"]
            )
        ]
        
        for template in templates:
            self.template_manager.register_template(template)
        
        stats = self.template_manager.get_statistics()
        
        self.assertEqual(stats['total_templates'], 3)
        self.assertEqual(stats['categories'], 2)
        self.assertEqual(stats['supported_providers'], 2)
        self.assertEqual(stats['templates_by_category']['email'], 2)
        self.assertEqual(stats['templates_by_category']['calendar'], 1)
        self.assertEqual(stats['templates_by_provider']['google'], 2)
        self.assertEqual(stats['templates_by_provider']['microsoft'], 2)


if __name__ == '__main__':
    unittest.main()