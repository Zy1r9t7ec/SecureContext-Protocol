"""
Workflow orchestration for managing multiple concurrent agent workflows.

This module provides high-level orchestration capabilities for managing
multiple users, agents, and workflows concurrently with proper session
isolation and context preservation.
"""

import asyncio
import time
import threading
import logging
from typing import Dict, Any, Optional, List, Callable, Awaitable, Union
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import dataclass, field
from enum import Enum
import uuid
from collections import defaultdict

from .client import SCPClient
from .session_manager import SessionManager, SessionInfo
from .exceptions import SCPError, SCPSessionError, SCPValidationError


class WorkflowState(Enum):
    """Workflow execution state."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class WorkflowContext:
    """Context for a workflow execution."""
    workflow_id: str
    user_id: str
    agent_id: str
    workflow_type: str
    state: WorkflowState = WorkflowState.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    session_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Any] = None
    error: Optional[str] = None
    progress: float = 0.0
    current_step: Optional[str] = None
    total_steps: int = 0
    parent_workflow_id: Optional[str] = None
    child_workflow_ids: List[str] = field(default_factory=list)
    
    @property
    def duration(self) -> Optional[float]:
        """Get workflow duration in seconds."""
        if self.started_at is None:
            return None
        
        end_time = self.completed_at or time.time()
        return end_time - self.started_at
    
    @property
    def is_active(self) -> bool:
        """Check if workflow is actively running."""
        return self.state in [WorkflowState.RUNNING, WorkflowState.PAUSED]
    
    @property
    def is_finished(self) -> bool:
        """Check if workflow is finished (completed, failed, or cancelled)."""
        return self.state in [WorkflowState.COMPLETED, WorkflowState.FAILED, WorkflowState.CANCELLED]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'workflow_id': self.workflow_id,
            'user_id': self.user_id,
            'agent_id': self.agent_id,
            'workflow_type': self.workflow_type,
            'state': self.state.value,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'session_ids': self.session_ids,
            'metadata': self.metadata,
            'result': self.result,
            'error': self.error,
            'progress': self.progress,
            'current_step': self.current_step,
            'total_steps': self.total_steps,
            'parent_workflow_id': self.parent_workflow_id,
            'child_workflow_ids': self.child_workflow_ids,
            'duration': self.duration,
            'is_active': self.is_active,
            'is_finished': self.is_finished
        }


class WorkflowOrchestrator:
    """
    High-level orchestrator for managing concurrent agent workflows.
    
    Provides workflow lifecycle management, session coordination,
    and multi-user isolation for complex agent operations.
    """
    
    def __init__(
        self,
        scp_client: Optional[SCPClient] = None,
        session_manager: Optional[SessionManager] = None,
        max_concurrent_workflows: int = 100,
        max_workers: int = 10
    ):
        """
        Initialize workflow orchestrator.
        
        Args:
            scp_client: SCP client instance
            session_manager: Session manager instance
            max_concurrent_workflows: Maximum concurrent workflows
            max_workers: Maximum worker threads
        """
        self.scp_client = scp_client or SCPClient()
        self.session_manager = session_manager or SessionManager(self.scp_client)
        self.max_concurrent_workflows = max_concurrent_workflows
        self.max_workers = max_workers
        
        # Workflow storage
        self._workflows: Dict[str, WorkflowContext] = {}
        self._user_workflows: Dict[str, List[str]] = defaultdict(list)
        self._agent_workflows: Dict[str, List[str]] = defaultdict(list)
        
        # Execution management
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._running_futures: Dict[str, Future] = {}
        
        # Thread synchronization
        self._lock = threading.RLock()
        
        # Event callbacks
        self._workflow_callbacks: Dict[str, List[Callable]] = defaultdict(list)
        
        self.logger = logging.getLogger(__name__)
    
    def register_workflow_callback(
        self,
        event_type: str,
        callback: Callable[[WorkflowContext], None]
    ):
        """
        Register callback for workflow events.
        
        Args:
            event_type: Event type (started, completed, failed, etc.)
            callback: Callback function
        """
        self._workflow_callbacks[event_type].append(callback)
    
    def create_workflow(
        self,
        user_id: str,
        agent_id: str,
        workflow_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        parent_workflow_id: Optional[str] = None
    ) -> str:
        """
        Create a new workflow.
        
        Args:
            user_id: User identifier
            agent_id: Agent identifier
            workflow_type: Type of workflow
            metadata: Optional workflow metadata
            parent_workflow_id: Optional parent workflow ID
            
        Returns:
            Workflow ID
            
        Raises:
            RuntimeError: If workflow limit exceeded
        """
        with self._lock:
            if len(self._workflows) >= self.max_concurrent_workflows:
                # Clean up finished workflows
                self._cleanup_finished_workflows()
                
                if len(self._workflows) >= self.max_concurrent_workflows:
                    raise RuntimeError(f"Workflow limit exceeded ({self.max_concurrent_workflows})")
            
            workflow_id = str(uuid.uuid4())
            
            workflow = WorkflowContext(
                workflow_id=workflow_id,
                user_id=user_id,
                agent_id=agent_id,
                workflow_type=workflow_type,
                metadata=metadata or {},
                parent_workflow_id=parent_workflow_id
            )
            
            # Store workflow
            self._workflows[workflow_id] = workflow
            self._user_workflows[user_id].append(workflow_id)
            self._agent_workflows[agent_id].append(workflow_id)
            
            # Handle parent-child relationships
            if parent_workflow_id and parent_workflow_id in self._workflows:
                self._workflows[parent_workflow_id].child_workflow_ids.append(workflow_id)
            
            self.logger.info(
                f"Created workflow {workflow_id} for user {user_id}, "
                f"agent {agent_id}, type {workflow_type}"
            )
            
            return workflow_id
    
    def execute_workflow(
        self,
        workflow_id: str,
        workflow_func: Callable,
        *args,
        **kwargs
    ) -> Future:
        """
        Execute a workflow asynchronously.
        
        Args:
            workflow_id: Workflow ID
            workflow_func: Workflow function to execute
            *args: Positional arguments for workflow function
            **kwargs: Keyword arguments for workflow function
            
        Returns:
            Future object for the workflow execution
            
        Raises:
            SCPValidationError: If workflow not found or already running
        """
        with self._lock:
            if workflow_id not in self._workflows:
                raise SCPValidationError(f"Workflow {workflow_id} not found")
            
            workflow = self._workflows[workflow_id]
            
            if workflow.state != WorkflowState.PENDING:
                raise SCPValidationError(f"Workflow {workflow_id} is not in pending state")
            
            # Mark as running
            workflow.state = WorkflowState.RUNNING
            workflow.started_at = time.time()
            
            # Execute workflow
            future = self._executor.submit(
                self._execute_workflow_wrapper,
                workflow_id,
                workflow_func,
                *args,
                **kwargs
            )
            
            self._running_futures[workflow_id] = future
            
            # Trigger callbacks
            self._trigger_callbacks('started', workflow)
            
            self.logger.info(f"Started execution of workflow {workflow_id}")
            
            return future
    
    def execute_parallel_workflows(
        self,
        workflow_specs: List[Dict[str, Any]]
    ) -> Dict[str, Future]:
        """
        Execute multiple workflows in parallel.
        
        Args:
            workflow_specs: List of workflow specifications
                Each spec should contain: user_id, agent_id, workflow_type,
                workflow_func, args (optional), kwargs (optional), metadata (optional)
        
        Returns:
            Dictionary mapping workflow IDs to Future objects
        """
        futures = {}
        
        for spec in workflow_specs:
            # Create workflow
            workflow_id = self.create_workflow(
                user_id=spec['user_id'],
                agent_id=spec['agent_id'],
                workflow_type=spec['workflow_type'],
                metadata=spec.get('metadata')
            )
            
            # Execute workflow
            future = self.execute_workflow(
                workflow_id,
                spec['workflow_func'],
                *spec.get('args', []),
                **spec.get('kwargs', {})
            )
            
            futures[workflow_id] = future
        
        return futures
    
    def wait_for_workflows(
        self,
        workflow_ids: List[str],
        timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Wait for multiple workflows to complete.
        
        Args:
            workflow_ids: List of workflow IDs to wait for
            timeout: Optional timeout in seconds
            
        Returns:
            Dictionary with workflow results
        """
        futures = {}
        
        with self._lock:
            for workflow_id in workflow_ids:
                if workflow_id in self._running_futures:
                    futures[workflow_id] = self._running_futures[workflow_id]
        
        results = {}
        
        try:
            for workflow_id, future in futures.items():
                try:
                    result = future.result(timeout=timeout)
                    results[workflow_id] = {'success': True, 'result': result}
                except Exception as e:
                    results[workflow_id] = {'success': False, 'error': str(e)}
        except Exception as e:
            self.logger.error(f"Error waiting for workflows: {e}")
        
        return results
    
    def cancel_workflow(self, workflow_id: str) -> bool:
        """
        Cancel a running workflow.
        
        Args:
            workflow_id: Workflow ID to cancel
            
        Returns:
            True if successfully cancelled
        """
        with self._lock:
            if workflow_id not in self._workflows:
                return False
            
            workflow = self._workflows[workflow_id]
            
            if workflow.state not in [WorkflowState.RUNNING, WorkflowState.PENDING]:
                return False
            
            # Mark workflow as cancelled
            workflow.state = WorkflowState.CANCELLED
            workflow.completed_at = time.time()
            
            # Try to cancel future if it hasn't started yet
            if workflow_id in self._running_futures:
                future = self._running_futures[workflow_id]
                future.cancel()  # This may or may not succeed
                
                # Remove from running futures regardless
                del self._running_futures[workflow_id]
            
            # Clean up sessions
            self._cleanup_workflow_sessions(workflow_id)
            
            # Trigger callbacks
            self._trigger_callbacks('cancelled', workflow)
            
            self.logger.info(f"Cancelled workflow {workflow_id}")
            return True
    
    def pause_workflow(self, workflow_id: str) -> bool:
        """
        Pause a running workflow.
        
        Args:
            workflow_id: Workflow ID to pause
            
        Returns:
            True if successfully paused
        """
        with self._lock:
            if workflow_id not in self._workflows:
                return False
            
            workflow = self._workflows[workflow_id]
            
            if workflow.state != WorkflowState.RUNNING:
                return False
            
            workflow.state = WorkflowState.PAUSED
            
            # Trigger callbacks
            self._trigger_callbacks('paused', workflow)
            
            self.logger.info(f"Paused workflow {workflow_id}")
            return True
    
    def resume_workflow(self, workflow_id: str) -> bool:
        """
        Resume a paused workflow.
        
        Args:
            workflow_id: Workflow ID to resume
            
        Returns:
            True if successfully resumed
        """
        with self._lock:
            if workflow_id not in self._workflows:
                return False
            
            workflow = self._workflows[workflow_id]
            
            if workflow.state != WorkflowState.PAUSED:
                return False
            
            workflow.state = WorkflowState.RUNNING
            
            # Trigger callbacks
            self._trigger_callbacks('resumed', workflow)
            
            self.logger.info(f"Resumed workflow {workflow_id}")
            return True
    
    def get_workflow(self, workflow_id: str) -> Optional[WorkflowContext]:
        """
        Get workflow by ID.
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            WorkflowContext or None if not found
        """
        with self._lock:
            return self._workflows.get(workflow_id)
    
    def get_user_workflows(self, user_id: str) -> List[WorkflowContext]:
        """
        Get all workflows for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of WorkflowContext objects
        """
        with self._lock:
            workflow_ids = self._user_workflows.get(user_id, [])
            return [
                self._workflows[wid] for wid in workflow_ids
                if wid in self._workflows
            ]
    
    def get_agent_workflows(self, agent_id: str) -> List[WorkflowContext]:
        """
        Get all workflows for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of WorkflowContext objects
        """
        with self._lock:
            workflow_ids = self._agent_workflows.get(agent_id, [])
            return [
                self._workflows[wid] for wid in workflow_ids
                if wid in self._workflows
            ]
    
    def get_active_workflows(self) -> List[WorkflowContext]:
        """
        Get all active workflows.
        
        Returns:
            List of active WorkflowContext objects
        """
        with self._lock:
            return [
                workflow for workflow in self._workflows.values()
                if workflow.is_active
            ]
    
    def cleanup_user_workflows(self, user_id: str) -> int:
        """
        Clean up all workflows for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of workflows cleaned up
        """
        with self._lock:
            workflow_ids = self._user_workflows.get(user_id, []).copy()
            cleaned_count = 0
            
            for workflow_id in workflow_ids:
                if self._remove_workflow(workflow_id):
                    cleaned_count += 1
            
            return cleaned_count
    
    def cleanup_agent_workflows(self, agent_id: str) -> int:
        """
        Clean up all workflows for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Number of workflows cleaned up
        """
        with self._lock:
            workflow_ids = self._agent_workflows.get(agent_id, []).copy()
            cleaned_count = 0
            
            for workflow_id in workflow_ids:
                if self._remove_workflow(workflow_id):
                    cleaned_count += 1
            
            return cleaned_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get orchestrator statistics.
        
        Returns:
            Dictionary with statistics
        """
        with self._lock:
            state_counts = defaultdict(int)
            for workflow in self._workflows.values():
                state_counts[workflow.state.value] += 1
            
            return {
                'total_workflows': len(self._workflows),
                'active_workflows': len(self.get_active_workflows()),
                'user_count': len(self._user_workflows),
                'agent_count': len(self._agent_workflows),
                'running_futures': len(self._running_futures),
                'state_counts': dict(state_counts),
                'max_concurrent_workflows': self.max_concurrent_workflows,
                'max_workers': self.max_workers
            }
    
    def _execute_workflow_wrapper(
        self,
        workflow_id: str,
        workflow_func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Wrapper for workflow execution with error handling.
        
        Args:
            workflow_id: Workflow ID
            workflow_func: Workflow function
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Workflow result
        """
        workflow = None
        
        try:
            with self._lock:
                workflow = self._workflows.get(workflow_id)
                if not workflow:
                    raise SCPValidationError(f"Workflow {workflow_id} not found")
            
            # Add orchestrator context to kwargs
            kwargs['orchestrator'] = self
            kwargs['workflow_id'] = workflow_id
            kwargs['session_manager'] = self.session_manager
            
            # Execute workflow function
            result = workflow_func(*args, **kwargs)
            
            # Mark as completed
            with self._lock:
                workflow.state = WorkflowState.COMPLETED
                workflow.completed_at = time.time()
                workflow.result = result
                workflow.progress = 100.0
                
                # Remove from running futures
                self._running_futures.pop(workflow_id, None)
            
            # Trigger callbacks
            self._trigger_callbacks('completed', workflow)
            
            self.logger.info(f"Completed workflow {workflow_id}")
            return result
            
        except Exception as e:
            # Mark as failed
            if workflow:
                with self._lock:
                    workflow.state = WorkflowState.FAILED
                    workflow.completed_at = time.time()
                    workflow.error = str(e)
                    
                    # Remove from running futures
                    self._running_futures.pop(workflow_id, None)
                
                # Clean up sessions
                self._cleanup_workflow_sessions(workflow_id)
                
                # Trigger callbacks
                self._trigger_callbacks('failed', workflow)
            
            self.logger.error(f"Failed workflow {workflow_id}: {e}", exc_info=True)
            raise
    
    def _cleanup_workflow_sessions(self, workflow_id: str):
        """Clean up sessions for a workflow."""
        try:
            self.session_manager.cleanup_workflow_sessions(workflow_id)
        except Exception as e:
            self.logger.error(f"Error cleaning up sessions for workflow {workflow_id}: {e}")
    
    def _cleanup_finished_workflows(self) -> int:
        """Clean up finished workflows."""
        finished_workflows = []
        
        for workflow_id, workflow in self._workflows.items():
            if workflow.is_finished:
                finished_workflows.append(workflow_id)
        
        cleaned_count = 0
        for workflow_id in finished_workflows:
            if self._remove_workflow(workflow_id):
                cleaned_count += 1
        
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} finished workflows")
        
        return cleaned_count
    
    def _remove_workflow(self, workflow_id: str) -> bool:
        """Remove workflow completely."""
        if workflow_id not in self._workflows:
            return False
        
        workflow = self._workflows[workflow_id]
        
        # Cancel if running
        if workflow_id in self._running_futures:
            future = self._running_futures[workflow_id]
            future.cancel()
            del self._running_futures[workflow_id]
        
        # Clean up sessions
        self._cleanup_workflow_sessions(workflow_id)
        
        # Remove from indexes
        self._user_workflows[workflow.user_id] = [
            wid for wid in self._user_workflows[workflow.user_id]
            if wid != workflow_id
        ]
        
        self._agent_workflows[workflow.agent_id] = [
            wid for wid in self._agent_workflows[workflow.agent_id]
            if wid != workflow_id
        ]
        
        # Handle parent-child relationships
        if workflow.parent_workflow_id and workflow.parent_workflow_id in self._workflows:
            parent = self._workflows[workflow.parent_workflow_id]
            parent.child_workflow_ids = [
                cid for cid in parent.child_workflow_ids
                if cid != workflow_id
            ]
        
        # Remove child workflows
        for child_id in workflow.child_workflow_ids:
            if child_id in self._workflows:
                self._workflows[child_id].parent_workflow_id = None
        
        # Remove workflow
        del self._workflows[workflow_id]
        
        return True
    
    def _trigger_callbacks(self, event_type: str, workflow: WorkflowContext):
        """Trigger callbacks for workflow events."""
        callbacks = self._workflow_callbacks.get(event_type, [])
        
        for callback in callbacks:
            try:
                callback(workflow)
            except Exception as e:
                self.logger.error(f"Error in workflow callback: {e}", exc_info=True)
    
    def close(self):
        """Clean up resources."""
        # Cancel all running workflows
        with self._lock:
            for workflow_id in list(self._running_futures.keys()):
                self.cancel_workflow(workflow_id)
        
        # Shutdown executor
        self._executor.shutdown(wait=True)
        
        # Close session manager
        if hasattr(self.session_manager, 'close'):
            self.session_manager.close()
        
        self.logger.info("Workflow orchestrator closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()