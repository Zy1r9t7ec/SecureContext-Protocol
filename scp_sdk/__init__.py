"""
SecureContext Protocol (SCP) Python SDK

This SDK provides a simple interface for AI agents and applications to interact
with the SecureContext Protocol Authentication Proxy for secure OAuth token management.
"""

from .client import SCPClient
from .exceptions import (
    SCPError,
    SCPConnectionError,
    SCPAuthenticationError,
    SCPSessionError,
    SCPTimeoutError,
    SCPValidationError
)
from .session_manager import SessionManager
from .data_access import DataAccessClient
from .workflow_orchestrator import WorkflowOrchestrator, WorkflowContext, WorkflowState
from .workflow_templates import WorkflowTemplateClient, TemplateBasedWorkflow
from .retry import RetryConfig

__version__ = "1.0.0"
__all__ = [
    "SCPClient",
    "SCPError",
    "SCPConnectionError", 
    "SCPAuthenticationError",
    "SCPSessionError",
    "SCPTimeoutError",
    "SCPValidationError",
    "SessionManager",
    "DataAccessClient",
    "WorkflowOrchestrator",
    "WorkflowContext",
    "WorkflowState",
    "WorkflowTemplateClient",
    "TemplateBasedWorkflow",
    "RetryConfig"
]