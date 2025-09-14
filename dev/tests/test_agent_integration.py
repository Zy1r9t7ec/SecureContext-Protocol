#!/usr/bin/env python3
"""
Simple test script for agent integration APIs.

This script tests the new agent-specific API endpoints to ensure they work correctly.
"""

import requests
import json
import sys
import time
from datetime import datetime


def test_agent_integration_apis():
    """Test the agent integration API endpoints."""
    base_url = "http://localhost:5000"
    
    print("Testing Agent Integration APIs")
    print("=" * 50)
    
    # Test 1: Agent Auth Endpoint
    print("\n1. Testing POST /api/agent/auth")
    auth_data = {
        "provider": "google",
        "agent_id": "test_agent_001",
        "workflow_id": "test_workflow_001"
    }
    
    try:
        response = requests.post(f"{base_url}/api/agent/auth", json=auth_data)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Authorization URL generated: {bool(data.get('data', {}).get('authorization_url'))}")
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to server. Make sure the application is running on localhost:5000")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    
    # Test 2: Agent Sessions Endpoint
    print("\n2. Testing GET /api/agent/sessions")
    try:
        response = requests.get(f"{base_url}/api/agent/sessions")
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Sessions count: {data.get('data', {}).get('count', 0)}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 3: Agent Sessions with filters
    print("\n3. Testing GET /api/agent/sessions with filters")
    try:
        params = {
            "agent_id": "test_agent_001",
            "status": "active"
        }
        response = requests.get(f"{base_url}/api/agent/sessions", params=params)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Filtered sessions count: {data.get('data', {}).get('count', 0)}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 4: Agent Data Access (will fail without valid session, but should return proper error)
    print("\n4. Testing GET /api/agent/data/<provider>/<session_id>")
    fake_session_id = "12345678-1234-4567-8901-123456789012"  # Valid UUID format
    try:
        response = requests.get(f"{base_url}/api/agent/data/google/{fake_session_id}")
        print(f"Status Code: {response.status_code}")
        if response.status_code == 404:
            data = response.json()
            print(f"Expected 404 error: {data.get('error', {}).get('message')}")
        else:
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 5: Session Extension (will fail without valid session, but should return proper error)
    print("\n5. Testing POST /api/agent/sessions/<session_id>/extend")
    try:
        extend_data = {
            "additional_seconds": 3600,
            "reason": "Test extension"
        }
        response = requests.post(f"{base_url}/api/agent/sessions/{fake_session_id}/extend", json=extend_data)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 404:
            data = response.json()
            print(f"Expected 404 error: {data.get('error', {}).get('message')}")
        else:
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 6: Session Cleanup
    print("\n6. Testing POST /api/agent/sessions/cleanup")
    try:
        cleanup_data = {
            "cleanup_type": "expired"
        }
        response = requests.post(f"{base_url}/api/agent/sessions/cleanup", json=cleanup_data)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Sessions cleaned: {data.get('data', {}).get('sessions_cleaned', 0)}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 7: Audit Log (will be empty but should work)
    print("\n7. Testing GET /api/audit/<session_id>")
    try:
        response = requests.get(f"{base_url}/api/audit/{fake_session_id}")
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Audit events count: {data.get('data', {}).get('event_count', 0)}")
        else:
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 8: Audit Analytics
    print("\n8. Testing GET /api/audit/analytics")
    try:
        response = requests.get(f"{base_url}/api/audit/analytics")
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Total events: {data.get('data', {}).get('total_events', 0)}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n" + "=" * 50)
    print("Agent Integration API Tests Completed")
    print("Note: Some tests expect 404 errors for non-existent sessions - this is normal.")
    return True


if __name__ == "__main__":
    success = test_agent_integration_apis()
    sys.exit(0 if success else 1)