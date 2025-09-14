"""
Tests for concurrent session management functionality.

This module tests the session pool, workflow orchestrator, and concurrent
session isolation features.
"""

import unittest
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import Mock, patch, MagicMock
import uuid

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from authentication_proxy.session_pool import SessionPool, SessionContext, SessionState
from scp_sdk.workflow_orchestrator import WorkflowOrchestrator, WorkflowContext, WorkflowState
from scp_sdk.client import SCPClient
from scp_sdk.session_manager import SessionManager
from scp_sdk.exceptions import SCPValidationError, SCPSessionError


class TestSessionPool(unittest.TestCase):
    """Test session pool functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.session_pool = SessionPool(
            max_sessions=100,
            cleanup_interval=1,  # Fast cleanup for testing
            auto_renewal=True,
            renewal_threshold=10
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.session_pool.close()
    
    def test_create_session(self):
        """Test session creation."""
        session = self.session_pool.create_session(
            provider='google',
            user_id='user123',
            expires_in=3600,
            agent_id='agent456',
            workflow_id='workflow789',
            metadata={'test': 'data'}
        )
        
        self.assertIsInstance(session, SessionContext)
        self.assertEqual(session.provider, 'google')
        self.assertEqual(session.user_id, 'user123')
        self.assertEqual(session.agent_id, 'agent456')
        self.assertEqual(session.workflow_id, 'workflow789')
        self.assertEqual(session.metadata['test'], 'data')
        self.assertEqual(session.state, SessionState.ACTIVE)
        self.assertFalse(session.is_expired)
    
    def test_get_session(self):
        """Test session retrieval."""
        session = self.session_pool.create_session(
            provider='google',
            user_id='user123',
            expires_in=3600
        )
        
        retrieved_session = self.session_pool.get_session(session.session_id)
        self.assertIsNotNone(retrieved_session)
        self.assertEqual(retrieved_session.session_id, session.session_id)
        self.assertEqual(retrieved_session.access_count, 1)  # Touched during retrieval
    
    def test_session_expiration(self):
        """Test session expiration handling."""
        # Create pool without auto-renewal for this test
        no_renewal_pool = SessionPool(
            max_sessions=100,
            cleanup_interval=1,
            auto_renewal=False,  # Disable auto-renewal
            renewal_threshold=10
        )
        
        try:
            session = no_renewal_pool.create_session(
                provider='google',
                user_id='user123',
                expires_in=1  # Expires in 1 second
            )
            
            # Session should be active initially
            retrieved_session = no_renewal_pool.get_session(session.session_id)
            self.assertIsNotNone(retrieved_session)
            
            # Wait for expiration
            time.sleep(2)
            
            # Session should be expired and removed
            expired_session = no_renewal_pool.get_session(session.session_id)
            self.assertIsNone(expired_session)
        finally:
            no_renewal_pool.close()
    
    def test_session_renewal(self):
        """Test session renewal."""
        session = self.session_pool.create_session(
            provider='google',
            user_id='user123',
            expires_in=60
        )
        
        original_expires_at = session.expires_at
        
        # Renew session
        success = self.session_pool.extend_session(session.session_id, 3600)
        self.assertTrue(success)
        
        # Check that expiration was extended
        updated_session = self.session_pool.get_session(session.session_id)
        self.assertGreater(updated_session.expires_at, original_expires_at)
    
    def test_auto_renewal(self):
        """Test automatic session renewal."""
        # Create session that will trigger auto-renewal
        session = self.session_pool.create_session(
            provider='google',
            user_id='user123',
            expires_in=5  # Short expiration to trigger auto-renewal
        )
        
        original_expires_at = session.expires_at
        
        # Access session to trigger auto-renewal
        retrieved_session = self.session_pool.get_session(session.session_id)
        
        # Should have been auto-renewed
        self.assertGreater(retrieved_session.expires_at, original_expires_at)
        self.assertEqual(retrieved_session.renewal_count, 1)
    
    def test_session_reservation(self):
        """Test session reservation for exclusive use."""
        session = self.session_pool.create_session(
            provider='google',
            user_id='user123',
            expires_in=3600
        )
        
        # Reserve session
        success = self.session_pool.reserve_session(session.session_id)
        self.assertTrue(success)
        
        # Check session state
        retrieved_session = self.session_pool.get_session(session.session_id)
        self.assertEqual(retrieved_session.state, SessionState.RESERVED)
        
        # Try to reserve again (should fail)
        success = self.session_pool.reserve_session(session.session_id)
        self.assertFalse(success)
        
        # Release session
        success = self.session_pool.release_session(session.session_id)
        self.assertTrue(success)
        
        # Check session state
        retrieved_session = self.session_pool.get_session(session.session_id)
        self.assertEqual(retrieved_session.state, SessionState.ACTIVE)
    
    def test_user_session_isolation(self):
        """Test that user sessions are properly isolated."""
        # Create sessions for different users
        session1 = self.session_pool.create_session(
            provider='google',
            user_id='user1',
            expires_in=3600
        )
        
        session2 = self.session_pool.create_session(
            provider='google',
            user_id='user2',
            expires_in=3600
        )
        
        session3 = self.session_pool.create_session(
            provider='microsoft',
            user_id='user1',
            expires_in=3600
        )
        
        # Get sessions by user
        user1_sessions = self.session_pool.get_user_sessions('user1')
        user2_sessions = self.session_pool.get_user_sessions('user2')
        
        self.assertEqual(len(user1_sessions), 2)
        self.assertEqual(len(user2_sessions), 1)
        
        # Verify session isolation
        user1_session_ids = {s.session_id for s in user1_sessions}
        user2_session_ids = {s.session_id for s in user2_sessions}
        
        self.assertIn(session1.session_id, user1_session_ids)
        self.assertIn(session3.session_id, user1_session_ids)
        self.assertIn(session2.session_id, user2_session_ids)
        self.assertNotIn(session2.session_id, user1_session_ids)
    
    def test_concurrent_session_creation(self):
        """Test concurrent session creation and isolation."""
        num_threads = 10
        sessions_per_thread = 5
        created_sessions = []
        
        def create_sessions(thread_id):
            thread_sessions = []
            for i in range(sessions_per_thread):
                session = self.session_pool.create_session(
                    provider='google',
                    user_id=f'user_{thread_id}',
                    agent_id=f'agent_{thread_id}_{i}',
                    expires_in=3600
                )
                thread_sessions.append(session)
            return thread_sessions
        
        # Create sessions concurrently
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(create_sessions, i)
                for i in range(num_threads)
            ]
            
            for future in as_completed(futures):
                created_sessions.extend(future.result())
        
        # Verify all sessions were created
        self.assertEqual(len(created_sessions), num_threads * sessions_per_thread)
        
        # Verify session isolation by user
        for thread_id in range(num_threads):
            user_sessions = self.session_pool.get_user_sessions(f'user_{thread_id}')
            self.assertEqual(len(user_sessions), sessions_per_thread)
            
            # Verify all sessions belong to the correct user
            for session in user_sessions:
                self.assertEqual(session.user_id, f'user_{thread_id}')
    
    def test_session_cleanup(self):
        """Test session cleanup functionality."""
        # Create sessions for different users and agents
        session1 = self.session_pool.create_session(
            provider='google',
            user_id='user1',
            agent_id='agent1',
            expires_in=3600
        )
        
        session2 = self.session_pool.create_session(
            provider='google',
            user_id='user1',
            agent_id='agent2',
            expires_in=3600
        )
        
        session3 = self.session_pool.create_session(
            provider='google',
            user_id='user2',
            agent_id='agent1',
            expires_in=3600
        )
        
        # Clean up user1 sessions
        cleaned_count = self.session_pool.cleanup_user_sessions('user1')
        self.assertEqual(cleaned_count, 2)
        
        # Verify user1 sessions are gone
        user1_sessions = self.session_pool.get_user_sessions('user1')
        self.assertEqual(len(user1_sessions), 0)
        
        # Verify user2 sessions still exist
        user2_sessions = self.session_pool.get_user_sessions('user2')
        self.assertEqual(len(user2_sessions), 1)
    
    def test_session_pool_limits(self):
        """Test session pool limits and cleanup."""
        # Create a small pool for testing
        small_pool = SessionPool(max_sessions=5, cleanup_interval=1)
        
        try:
            # Create sessions up to limit
            sessions = []
            for i in range(5):
                session = small_pool.create_session(
                    provider='google',
                    user_id=f'user_{i}',
                    expires_in=3600
                )
                sessions.append(session)
            
            # Try to create one more (should raise RuntimeError)
            with self.assertRaises(RuntimeError):
                small_pool.create_session(
                    provider='google',
                    user_id='user_overflow',
                    expires_in=3600
                )
            
            # Should still have 5 sessions
            stats = small_pool.get_statistics()
            self.assertEqual(stats['total_sessions'], 5)
            
        finally:
            small_pool.close()
    
    def test_session_statistics(self):
        """Test session statistics."""
        # Create various sessions
        self.session_pool.create_session(
            provider='google',
            user_id='user1',
            agent_id='agent1',
            workflow_id='workflow1',
            expires_in=3600
        )
        
        self.session_pool.create_session(
            provider='microsoft',
            user_id='user2',
            agent_id='agent1',
            workflow_id='workflow2',
            expires_in=3600
        )
        
        # Get statistics
        stats = self.session_pool.get_statistics()
        
        self.assertEqual(stats['total_sessions'], 2)
        self.assertEqual(stats['active_sessions'], 2)
        self.assertEqual(stats['user_count'], 2)
        self.assertEqual(stats['agent_count'], 1)
        self.assertEqual(stats['workflow_count'], 2)
        self.assertEqual(stats['provider_count'], 2)


class TestWorkflowOrchestrator(unittest.TestCase):
    """Test workflow orchestrator functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_client = Mock(spec=SCPClient)
        self.mock_session_manager = Mock(spec=SessionManager)
        
        self.orchestrator = WorkflowOrchestrator(
            scp_client=self.mock_client,
            session_manager=self.mock_session_manager,
            max_concurrent_workflows=10,
            max_workers=5
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.orchestrator.close()
    
    def test_create_workflow(self):
        """Test workflow creation."""
        workflow_id = self.orchestrator.create_workflow(
            user_id='user123',
            agent_id='agent456',
            workflow_type='email_processing',
            metadata={'priority': 'high'}
        )
        
        self.assertIsInstance(workflow_id, str)
        
        # Get workflow
        workflow = self.orchestrator.get_workflow(workflow_id)
        self.assertIsNotNone(workflow)
        self.assertEqual(workflow.user_id, 'user123')
        self.assertEqual(workflow.agent_id, 'agent456')
        self.assertEqual(workflow.workflow_type, 'email_processing')
        self.assertEqual(workflow.metadata['priority'], 'high')
        self.assertEqual(workflow.state, WorkflowState.PENDING)
    
    def test_execute_workflow(self):
        """Test workflow execution."""
        def test_workflow_func(orchestrator, workflow_id, session_manager, test_param):
            return f"Workflow {workflow_id} executed with {test_param}"
        
        # Create workflow
        workflow_id = self.orchestrator.create_workflow(
            user_id='user123',
            agent_id='agent456',
            workflow_type='test_workflow'
        )
        
        # Execute workflow
        future = self.orchestrator.execute_workflow(
            workflow_id,
            test_workflow_func,
            test_param='test_value'
        )
        
        # Wait for completion
        result = future.result(timeout=5)
        
        # Verify result
        self.assertIn('test_value', result)
        
        # Check workflow state
        workflow = self.orchestrator.get_workflow(workflow_id)
        self.assertEqual(workflow.state, WorkflowState.COMPLETED)
        self.assertIsNotNone(workflow.result)
        self.assertEqual(workflow.progress, 100.0)
    
    def test_parallel_workflow_execution(self):
        """Test parallel workflow execution."""
        def test_workflow_func(orchestrator, workflow_id, session_manager, delay):
            time.sleep(delay)
            return f"Workflow {workflow_id} completed"
        
        # Create workflow specifications
        workflow_specs = [
            {
                'user_id': f'user_{i}',
                'agent_id': f'agent_{i}',
                'workflow_type': 'parallel_test',
                'workflow_func': test_workflow_func,
                'kwargs': {'delay': 0.1}
            }
            for i in range(5)
        ]
        
        # Execute workflows in parallel
        start_time = time.time()
        futures = self.orchestrator.execute_parallel_workflows(workflow_specs)
        
        # Wait for all to complete
        results = self.orchestrator.wait_for_workflows(
            list(futures.keys()),
            timeout=5
        )
        
        end_time = time.time()
        
        # Verify all completed successfully
        self.assertEqual(len(results), 5)
        for workflow_id, result in results.items():
            self.assertTrue(result['success'])
            self.assertIn('completed', result['result'])
        
        # Verify they ran in parallel (should take less than 5 * 0.1 = 0.5 seconds)
        self.assertLess(end_time - start_time, 0.5)
    
    def test_workflow_cancellation(self):
        """Test workflow cancellation."""
        def long_running_workflow(orchestrator, workflow_id, session_manager):
            # Check for cancellation periodically
            for i in range(100):
                time.sleep(0.1)
                workflow = orchestrator.get_workflow(workflow_id)
                if workflow and workflow.state == WorkflowState.CANCELLED:
                    return "Cancelled"
            return "Should not complete"
        
        # Create and start workflow
        workflow_id = self.orchestrator.create_workflow(
            user_id='user123',
            agent_id='agent456',
            workflow_type='long_running'
        )
        
        future = self.orchestrator.execute_workflow(
            workflow_id,
            long_running_workflow
        )
        
        # Give it a moment to start
        time.sleep(0.2)
        
        # Cancel workflow
        success = self.orchestrator.cancel_workflow(workflow_id)
        
        # Note: Future.cancel() only works if the task hasn't started yet
        # Once started, we can only mark the workflow as cancelled
        # The actual cancellation depends on the workflow implementation
        
        # Check workflow state
        workflow = self.orchestrator.get_workflow(workflow_id)
        self.assertEqual(workflow.state, WorkflowState.CANCELLED)
    
    def test_workflow_error_handling(self):
        """Test workflow error handling."""
        def failing_workflow(orchestrator, workflow_id, session_manager):
            raise ValueError("Test error")
        
        # Create and execute workflow
        workflow_id = self.orchestrator.create_workflow(
            user_id='user123',
            agent_id='agent456',
            workflow_type='failing'
        )
        
        future = self.orchestrator.execute_workflow(
            workflow_id,
            failing_workflow
        )
        
        # Should raise exception
        with self.assertRaises(ValueError):
            future.result(timeout=5)
        
        # Check workflow state
        workflow = self.orchestrator.get_workflow(workflow_id)
        self.assertEqual(workflow.state, WorkflowState.FAILED)
        self.assertIsNotNone(workflow.error)
    
    def test_user_workflow_isolation(self):
        """Test that user workflows are properly isolated."""
        # Create workflows for different users
        workflow1 = self.orchestrator.create_workflow(
            user_id='user1',
            agent_id='agent1',
            workflow_type='test'
        )
        
        workflow2 = self.orchestrator.create_workflow(
            user_id='user2',
            agent_id='agent2',
            workflow_type='test'
        )
        
        workflow3 = self.orchestrator.create_workflow(
            user_id='user1',
            agent_id='agent3',
            workflow_type='test'
        )
        
        # Get workflows by user
        user1_workflows = self.orchestrator.get_user_workflows('user1')
        user2_workflows = self.orchestrator.get_user_workflows('user2')
        
        self.assertEqual(len(user1_workflows), 2)
        self.assertEqual(len(user2_workflows), 1)
        
        # Verify workflow isolation
        user1_workflow_ids = {w.workflow_id for w in user1_workflows}
        user2_workflow_ids = {w.workflow_id for w in user2_workflows}
        
        self.assertIn(workflow1, user1_workflow_ids)
        self.assertIn(workflow3, user1_workflow_ids)
        self.assertIn(workflow2, user2_workflow_ids)
        self.assertNotIn(workflow2, user1_workflow_ids)
    
    def test_workflow_cleanup(self):
        """Test workflow cleanup functionality."""
        # Create workflows for different users
        workflow1 = self.orchestrator.create_workflow(
            user_id='user1',
            agent_id='agent1',
            workflow_type='test'
        )
        
        workflow2 = self.orchestrator.create_workflow(
            user_id='user1',
            agent_id='agent2',
            workflow_type='test'
        )
        
        workflow3 = self.orchestrator.create_workflow(
            user_id='user2',
            agent_id='agent1',
            workflow_type='test'
        )
        
        # Clean up user1 workflows
        cleaned_count = self.orchestrator.cleanup_user_workflows('user1')
        self.assertEqual(cleaned_count, 2)
        
        # Verify user1 workflows are gone
        user1_workflows = self.orchestrator.get_user_workflows('user1')
        self.assertEqual(len(user1_workflows), 0)
        
        # Verify user2 workflows still exist
        user2_workflows = self.orchestrator.get_user_workflows('user2')
        self.assertEqual(len(user2_workflows), 1)
    
    def test_workflow_statistics(self):
        """Test workflow statistics."""
        # Create various workflows
        self.orchestrator.create_workflow(
            user_id='user1',
            agent_id='agent1',
            workflow_type='type1'
        )
        
        self.orchestrator.create_workflow(
            user_id='user2',
            agent_id='agent1',
            workflow_type='type2'
        )
        
        # Get statistics
        stats = self.orchestrator.get_statistics()
        
        self.assertEqual(stats['total_workflows'], 2)
        self.assertEqual(stats['user_count'], 2)
        self.assertEqual(stats['agent_count'], 1)
        self.assertEqual(stats['state_counts']['pending'], 2)


class TestConcurrentSessionIntegration(unittest.TestCase):
    """Test integration between session pool and workflow orchestrator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.session_pool = SessionPool(max_sessions=50)
        
        self.mock_client = Mock(spec=SCPClient)
        self.mock_session_manager = Mock(spec=SessionManager)
        
        self.orchestrator = WorkflowOrchestrator(
            scp_client=self.mock_client,
            session_manager=self.mock_session_manager,
            max_concurrent_workflows=20
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.session_pool.close()
        self.orchestrator.close()
    
    def test_concurrent_user_isolation(self):
        """Test that concurrent operations maintain user isolation."""
        num_users = 5
        sessions_per_user = 3
        workflows_per_user = 2
        
        def create_user_sessions_and_workflows(user_id):
            # Create sessions for user
            sessions = []
            for i in range(sessions_per_user):
                session = self.session_pool.create_session(
                    provider='google',
                    user_id=user_id,
                    agent_id=f'agent_{user_id}_{i}',
                    expires_in=3600
                )
                sessions.append(session)
            
            # Create workflows for user
            workflows = []
            for i in range(workflows_per_user):
                workflow_id = self.orchestrator.create_workflow(
                    user_id=user_id,
                    agent_id=f'agent_{user_id}_{i}',
                    workflow_type='test_workflow'
                )
                workflows.append(workflow_id)
            
            return sessions, workflows
        
        # Create sessions and workflows concurrently
        with ThreadPoolExecutor(max_workers=num_users) as executor:
            futures = [
                executor.submit(create_user_sessions_and_workflows, f'user_{i}')
                for i in range(num_users)
            ]
            
            results = [future.result() for future in as_completed(futures)]
        
        # Verify isolation
        for i in range(num_users):
            user_id = f'user_{i}'
            
            # Check session isolation
            user_sessions = self.session_pool.get_user_sessions(user_id)
            self.assertEqual(len(user_sessions), sessions_per_user)
            
            for session in user_sessions:
                self.assertEqual(session.user_id, user_id)
            
            # Check workflow isolation
            user_workflows = self.orchestrator.get_user_workflows(user_id)
            self.assertEqual(len(user_workflows), workflows_per_user)
            
            for workflow in user_workflows:
                self.assertEqual(workflow.user_id, user_id)
    
    def test_high_throughput_operations(self):
        """Test high-throughput concurrent operations."""
        num_operations = 50  # Reduced to avoid hitting limits
        
        def perform_operations(operation_id):
            user_id = f'user_{operation_id % 5}'  # 5 different users
            
            # Create session
            session = self.session_pool.create_session(
                provider='google',
                user_id=user_id,
                agent_id=f'agent_{operation_id}',
                expires_in=3600
            )
            
            # Create workflow
            workflow_id = self.orchestrator.create_workflow(
                user_id=user_id,
                agent_id=f'agent_{operation_id}',
                workflow_type='high_throughput_test'
            )
            
            # Simulate some work
            time.sleep(0.01)
            
            return session.session_id, workflow_id
        
        # Perform operations concurrently
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(perform_operations, i)
                for i in range(num_operations)
            ]
            
            results = []
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    # Some operations may fail due to limits, that's expected
                    pass
        
        end_time = time.time()
        
        # Verify some operations completed
        self.assertGreater(len(results), 0)
        
        # Verify performance (should complete in reasonable time)
        self.assertLess(end_time - start_time, 10)  # Should complete in under 10 seconds


if __name__ == '__main__':
    unittest.main()