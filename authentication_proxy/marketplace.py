"""
Agent marketplace integration for SecureContext Protocol.

This module provides APIs for agent marketplace platforms, capability discovery,
standardized metadata formats, and agent testing frameworks.
"""

import json
import time
import logging
import hashlib
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

try:
    from .audit_logger import get_audit_logger, AuditEventType
except ImportError:
    from audit_logger import get_audit_logger, AuditEventType


class AgentCapabilityType(Enum):
    """Types of agent capabilities."""
    DATA_ACCESS = "data_access"
    EMAIL_MANAGEMENT = "email_management"
    CALENDAR_MANAGEMENT = "calendar_management"
    FILE_MANAGEMENT = "file_management"
    CONTACT_MANAGEMENT = "contact_management"
    WORKFLOW_AUTOMATION = "workflow_automation"
    DATA_ANALYSIS = "data_analysis"
    CONTENT_GENERATION = "content_generation"
    INTEGRATION = "integration"
    CUSTOM = "custom"


class AgentStatus(Enum):
    """Agent registration status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    DEPRECATED = "deprecated"


@dataclass
class AgentCapability:
    """Represents an agent capability."""
    capability_type: AgentCapabilityType
    name: str
    description: str
    required_scopes: List[str]
    supported_providers: List[str]
    data_types: List[str]
    rate_limits: Dict[str, int]
    security_level: str = "standard"  # standard, high, enterprise
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'capability_type': self.capability_type.value,
            'name': self.name,
            'description': self.description,
            'required_scopes': self.required_scopes,
            'supported_providers': self.supported_providers,
            'data_types': self.data_types,
            'rate_limits': self.rate_limits,
            'security_level': self.security_level
        }


@dataclass
class AgentMetadata:
    """Standardized agent metadata."""
    agent_id: str
    name: str
    version: str
    description: str
    author: str
    license: str
    homepage: Optional[str]
    repository: Optional[str]
    documentation: Optional[str]
    capabilities: List[AgentCapability]
    supported_frameworks: List[str]
    minimum_scp_version: str
    tags: List[str]
    category: str
    created_at: str
    updated_at: str
    status: AgentStatus
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'agent_id': self.agent_id,
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'license': self.license,
            'homepage': self.homepage,
            'repository': self.repository,
            'documentation': self.documentation,
            'capabilities': [cap.to_dict() for cap in self.capabilities],
            'supported_frameworks': self.supported_frameworks,
            'minimum_scp_version': self.minimum_scp_version,
            'tags': self.tags,
            'category': self.category,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'status': self.status.value
        }


@dataclass
class AgentTestResult:
    """Agent testing result."""
    test_id: str
    agent_id: str
    test_type: str
    status: str  # passed, failed, error
    score: Optional[float]
    details: Dict[str, Any]
    timestamp: str
    duration_seconds: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class AgentRegistry:
    """Registry for managing agent metadata and capabilities."""
    
    def __init__(self):
        self.agents: Dict[str, AgentMetadata] = {}
        self.capabilities_index: Dict[str, Set[str]] = {}  # capability -> agent_ids
        self.provider_index: Dict[str, Set[str]] = {}  # provider -> agent_ids
        self.framework_index: Dict[str, Set[str]] = {}  # framework -> agent_ids
        self.test_results: Dict[str, List[AgentTestResult]] = {}  # agent_id -> results
    
    def register_agent(self, metadata: AgentMetadata) -> bool:
        """
        Register an agent in the marketplace.
        
        Args:
            metadata: Agent metadata
            
        Returns:
            True if registration successful
        """
        try:
            # Validate metadata
            if not self._validate_metadata(metadata):
                return False
            
            # Store agent metadata
            self.agents[metadata.agent_id] = metadata
            
            # Update indexes
            self._update_indexes(metadata)
            
            # Log registration
            audit_logger = get_audit_logger()
            audit_logger.log_event(
                event_type=AuditEventType.AGENT_AUTH,
                agent_id=metadata.agent_id,
                success=True,
                details={
                    'action': 'register',
                    'agent_name': metadata.name,
                    'version': metadata.version,
                    'capabilities': len(metadata.capabilities)
                }
            )
            
            logging.info(f"Agent registered: {metadata.agent_id} ({metadata.name})")
            return True
            
        except Exception as e:
            logging.error(f"Failed to register agent {metadata.agent_id}: {e}")
            return False
    
    def unregister_agent(self, agent_id: str) -> bool:
        """Unregister an agent."""
        if agent_id not in self.agents:
            return False
        
        metadata = self.agents[agent_id]
        
        # Remove from indexes
        self._remove_from_indexes(metadata)
        
        # Remove agent
        del self.agents[agent_id]
        
        # Remove test results
        if agent_id in self.test_results:
            del self.test_results[agent_id]
        
        logging.info(f"Agent unregistered: {agent_id}")
        return True
    
    def get_agent(self, agent_id: str) -> Optional[AgentMetadata]:
        """Get agent metadata by ID."""
        return self.agents.get(agent_id)
    
    def list_agents(self, filters: Optional[Dict[str, Any]] = None) -> List[AgentMetadata]:
        """
        List agents with optional filters.
        
        Args:
            filters: Optional filters (capability, provider, framework, status, category)
            
        Returns:
            List of matching agents
        """
        agents = list(self.agents.values())
        
        if not filters:
            return agents
        
        # Apply filters
        if 'capability' in filters:
            capability = filters['capability']
            agent_ids = self.capabilities_index.get(capability, set())
            agents = [a for a in agents if a.agent_id in agent_ids]
        
        if 'provider' in filters:
            provider = filters['provider']
            agent_ids = self.provider_index.get(provider, set())
            agents = [a for a in agents if a.agent_id in agent_ids]
        
        if 'framework' in filters:
            framework = filters['framework']
            agent_ids = self.framework_index.get(framework, set())
            agents = [a for a in agents if a.agent_id in agent_ids]
        
        if 'status' in filters:
            status = AgentStatus(filters['status'])
            agents = [a for a in agents if a.status == status]
        
        if 'category' in filters:
            category = filters['category']
            agents = [a for a in agents if a.category == category]
        
        if 'tags' in filters:
            required_tags = set(filters['tags'])
            agents = [a for a in agents if required_tags.issubset(set(a.tags))]
        
        return agents
    
    def search_agents(self, query: str) -> List[AgentMetadata]:
        """Search agents by name, description, or tags."""
        query_lower = query.lower()
        results = []
        
        for agent in self.agents.values():
            # Search in name, description, and tags
            if (query_lower in agent.name.lower() or
                query_lower in agent.description.lower() or
                any(query_lower in tag.lower() for tag in agent.tags)):
                results.append(agent)
        
        return results
    
    def get_capabilities(self) -> Dict[str, List[str]]:
        """Get all available capabilities and their supporting agents."""
        return {
            capability: list(agent_ids)
            for capability, agent_ids in self.capabilities_index.items()
        }
    
    def get_providers(self) -> Dict[str, List[str]]:
        """Get all supported providers and their supporting agents."""
        return {
            provider: list(agent_ids)
            for provider, agent_ids in self.provider_index.items()
        }
    
    def get_frameworks(self) -> Dict[str, List[str]]:
        """Get all supported frameworks and their supporting agents."""
        return {
            framework: list(agent_ids)
            for framework, agent_ids in self.framework_index.items()
        }
    
    def add_test_result(self, result: AgentTestResult):
        """Add a test result for an agent."""
        if result.agent_id not in self.test_results:
            self.test_results[result.agent_id] = []
        
        self.test_results[result.agent_id].append(result)
        
        # Keep only last 100 test results per agent
        if len(self.test_results[result.agent_id]) > 100:
            self.test_results[result.agent_id] = self.test_results[result.agent_id][-100:]
    
    def get_test_results(self, agent_id: str) -> List[AgentTestResult]:
        """Get test results for an agent."""
        return self.test_results.get(agent_id, [])
    
    def get_agent_score(self, agent_id: str) -> Optional[float]:
        """Get average test score for an agent."""
        results = self.get_test_results(agent_id)
        if not results:
            return None
        
        scores = [r.score for r in results if r.score is not None and r.status == 'passed']
        if not scores:
            return None
        
        return sum(scores) / len(scores)
    
    def _validate_metadata(self, metadata: AgentMetadata) -> bool:
        """Validate agent metadata."""
        # Check required fields
        if not all([metadata.agent_id, metadata.name, metadata.version, 
                   metadata.description, metadata.author]):
            return False
        
        # Check agent_id format
        if not metadata.agent_id.replace('-', '').replace('_', '').isalnum():
            return False
        
        # Check version format (semantic versioning)
        version_parts = metadata.version.split('.')
        if len(version_parts) != 3 or not all(part.isdigit() for part in version_parts):
            return False
        
        # Check capabilities
        if not metadata.capabilities:
            return False
        
        for capability in metadata.capabilities:
            if not capability.name or not capability.description:
                return False
        
        return True
    
    def _update_indexes(self, metadata: AgentMetadata):
        """Update search indexes."""
        agent_id = metadata.agent_id
        
        # Capability index
        for capability in metadata.capabilities:
            cap_type = capability.capability_type.value
            if cap_type not in self.capabilities_index:
                self.capabilities_index[cap_type] = set()
            self.capabilities_index[cap_type].add(agent_id)
            
            # Also index by supported providers
            for provider in capability.supported_providers:
                if provider not in self.provider_index:
                    self.provider_index[provider] = set()
                self.provider_index[provider].add(agent_id)
        
        # Framework index
        for framework in metadata.supported_frameworks:
            if framework not in self.framework_index:
                self.framework_index[framework] = set()
            self.framework_index[framework].add(agent_id)
    
    def _remove_from_indexes(self, metadata: AgentMetadata):
        """Remove agent from search indexes."""
        agent_id = metadata.agent_id
        
        # Remove from capability index
        for capability in metadata.capabilities:
            cap_type = capability.capability_type.value
            if cap_type in self.capabilities_index:
                self.capabilities_index[cap_type].discard(agent_id)
                if not self.capabilities_index[cap_type]:
                    del self.capabilities_index[cap_type]
            
            # Remove from provider index
            for provider in capability.supported_providers:
                if provider in self.provider_index:
                    self.provider_index[provider].discard(agent_id)
                    if not self.provider_index[provider]:
                        del self.provider_index[provider]
        
        # Remove from framework index
        for framework in metadata.supported_frameworks:
            if framework in self.framework_index:
                self.framework_index[framework].discard(agent_id)
                if not self.framework_index[framework]:
                    del self.framework_index[framework]


class AgentTester:
    """Framework for testing agent integrations."""
    
    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.test_suites = {}
    
    def register_test_suite(self, name: str, test_suite: Dict[str, Any]):
        """Register a test suite."""
        self.test_suites[name] = test_suite
    
    def run_tests(self, agent_id: str, test_types: Optional[List[str]] = None) -> List[AgentTestResult]:
        """
        Run tests for an agent.
        
        Args:
            agent_id: Agent to test
            test_types: Optional list of test types to run
            
        Returns:
            List of test results
        """
        agent = self.registry.get_agent(agent_id)
        if not agent:
            return []
        
        results = []
        test_types = test_types or list(self.test_suites.keys())
        
        for test_type in test_types:
            if test_type not in self.test_suites:
                continue
            
            result = self._run_test_suite(agent, test_type)
            results.append(result)
            self.registry.add_test_result(result)
        
        return results
    
    def _run_test_suite(self, agent: AgentMetadata, test_type: str) -> AgentTestResult:
        """Run a specific test suite."""
        start_time = time.time()
        test_id = str(uuid.uuid4())
        
        try:
            test_suite = self.test_suites[test_type]
            
            # Run test based on type
            if test_type == 'metadata_validation':
                score, details = self._test_metadata_validation(agent)
            elif test_type == 'capability_verification':
                score, details = self._test_capability_verification(agent)
            elif test_type == 'security_compliance':
                score, details = self._test_security_compliance(agent)
            elif test_type == 'performance_benchmark':
                score, details = self._test_performance_benchmark(agent)
            else:
                score, details = 0.0, {'error': f'Unknown test type: {test_type}'}
            
            status = 'passed' if score >= 0.7 else 'failed'
            
        except Exception as e:
            score = None
            status = 'error'
            details = {'error': str(e)}
        
        duration = time.time() - start_time
        
        return AgentTestResult(
            test_id=test_id,
            agent_id=agent.agent_id,
            test_type=test_type,
            status=status,
            score=score,
            details=details,
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=duration
        )
    
    def _test_metadata_validation(self, agent: AgentMetadata) -> tuple[float, Dict[str, Any]]:
        """Test metadata validation."""
        score = 1.0
        details = {'checks': []}
        
        # Check required fields
        required_fields = ['agent_id', 'name', 'version', 'description', 'author']
        for field in required_fields:
            value = getattr(agent, field)
            if not value:
                score -= 0.2
                details['checks'].append(f'Missing required field: {field}')
            else:
                details['checks'].append(f'✓ {field}: {value}')
        
        # Check optional but recommended fields
        recommended_fields = ['homepage', 'repository', 'documentation']
        for field in recommended_fields:
            value = getattr(agent, field)
            if not value:
                score -= 0.1
                details['checks'].append(f'Missing recommended field: {field}')
            else:
                details['checks'].append(f'✓ {field}: {value}')
        
        # Check capabilities
        if not agent.capabilities:
            score -= 0.3
            details['checks'].append('No capabilities defined')
        else:
            details['checks'].append(f'✓ {len(agent.capabilities)} capabilities defined')
        
        return max(0.0, score), details
    
    def _test_capability_verification(self, agent: AgentMetadata) -> tuple[float, Dict[str, Any]]:
        """Test capability verification."""
        score = 1.0
        details = {'capabilities': []}
        
        for capability in agent.capabilities:
            cap_score = 1.0
            cap_details = {'name': capability.name, 'checks': []}
            
            # Check required scopes
            if not capability.required_scopes:
                cap_score -= 0.3
                cap_details['checks'].append('No required scopes defined')
            else:
                cap_details['checks'].append(f'✓ {len(capability.required_scopes)} scopes required')
            
            # Check supported providers
            if not capability.supported_providers:
                cap_score -= 0.3
                cap_details['checks'].append('No supported providers defined')
            else:
                cap_details['checks'].append(f'✓ {len(capability.supported_providers)} providers supported')
            
            # Check data types
            if not capability.data_types:
                cap_score -= 0.2
                cap_details['checks'].append('No data types defined')
            else:
                cap_details['checks'].append(f'✓ {len(capability.data_types)} data types supported')
            
            cap_details['score'] = max(0.0, cap_score)
            details['capabilities'].append(cap_details)
            score = min(score, cap_score)
        
        return max(0.0, score), details
    
    def _test_security_compliance(self, agent: AgentMetadata) -> tuple[float, Dict[str, Any]]:
        """Test security compliance."""
        score = 1.0
        details = {'security_checks': []}
        
        # Check if agent has security level defined
        security_levels = set()
        for capability in agent.capabilities:
            security_levels.add(capability.security_level)
        
        if 'enterprise' in security_levels:
            details['security_checks'].append('✓ Enterprise security level supported')
        elif 'high' in security_levels:
            details['security_checks'].append('✓ High security level supported')
            score -= 0.1
        else:
            details['security_checks'].append('⚠ Only standard security level')
            score -= 0.2
        
        # Check for rate limiting
        has_rate_limits = any(
            capability.rate_limits for capability in agent.capabilities
        )
        if has_rate_limits:
            details['security_checks'].append('✓ Rate limiting configured')
        else:
            details['security_checks'].append('⚠ No rate limiting configured')
            score -= 0.2
        
        # Check license
        if agent.license:
            details['security_checks'].append(f'✓ License: {agent.license}')
        else:
            details['security_checks'].append('⚠ No license specified')
            score -= 0.1
        
        return max(0.0, score), details
    
    def _test_performance_benchmark(self, agent: AgentMetadata) -> tuple[float, Dict[str, Any]]:
        """Test performance benchmark."""
        # This is a placeholder for actual performance testing
        # In a real implementation, this would run actual performance tests
        
        score = 0.8  # Simulated score
        details = {
            'benchmark_results': {
                'response_time_ms': 150,
                'throughput_rps': 100,
                'memory_usage_mb': 50,
                'cpu_usage_percent': 25
            },
            'performance_grade': 'B+'
        }
        
        return score, details


# Global registry instance
_agent_registry = None
_agent_tester = None


def get_agent_registry() -> AgentRegistry:
    """Get the global agent registry instance."""
    global _agent_registry
    if _agent_registry is None:
        _agent_registry = AgentRegistry()
    return _agent_registry


def get_agent_tester() -> AgentTester:
    """Get the global agent tester instance."""
    global _agent_tester
    if _agent_tester is None:
        registry = get_agent_registry()
        _agent_tester = AgentTester(registry)
        
        # Register default test suites
        _agent_tester.register_test_suite('metadata_validation', {})
        _agent_tester.register_test_suite('capability_verification', {})
        _agent_tester.register_test_suite('security_compliance', {})
        _agent_tester.register_test_suite('performance_benchmark', {})
    
    return _agent_tester