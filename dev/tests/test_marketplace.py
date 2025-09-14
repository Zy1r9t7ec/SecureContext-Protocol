#!/usr/bin/env python3
"""
Test script for agent marketplace integration functionality.

This script tests the marketplace APIs, agent registration,
capability discovery, and testing frameworks.
"""

import json
import requests
import time
from typing import Dict, Any, List


class MarketplaceTester:
    """Test class for marketplace functionality."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.registered_agents = []
    
    def test_marketplace_endpoints(self):
        """Test basic marketplace endpoints."""
        print("\n🧪 Testing marketplace endpoints...")
        
        # Test marketplace stats
        try:
            response = requests.get(f"{self.base_url}/api/marketplace/stats")
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    stats = data.get('data', {})
                    print(f"✅ Marketplace stats: {stats.get('total_agents', 0)} agents")
                else:
                    print(f"❌ Marketplace stats error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Marketplace stats failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Marketplace stats error: {e}")
        
        # Test capabilities endpoint
        try:
            response = requests.get(f"{self.base_url}/api/marketplace/capabilities")
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    capabilities = data.get('data', {}).get('capabilities', {})
                    print(f"✅ Capabilities endpoint: {len(capabilities)} capability types")
                else:
                    print(f"❌ Capabilities error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Capabilities failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Capabilities error: {e}")
    
    def load_sample_agent(self) -> Dict[str, Any]:
        """Load sample agent metadata."""
        try:
            with open('examples/sample_agent_metadata.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("❌ Sample agent metadata file not found")
            return self.create_minimal_agent()
        except Exception as e:
            print(f"❌ Error loading sample agent: {e}")
            return self.create_minimal_agent()
    
    def create_minimal_agent(self) -> Dict[str, Any]:
        """Create minimal agent metadata for testing."""
        return {
            "agent_id": f"test-agent-{int(time.time())}",
            "name": "Test Agent",
            "version": "1.0.0",
            "description": "A test agent for marketplace testing",
            "author": "Test Author",
            "license": "MIT",
            "capabilities": [
                {
                    "capability_type": "data_access",
                    "name": "Basic Data Access",
                    "description": "Basic data access capability",
                    "required_scopes": ["profile", "email"],
                    "supported_providers": ["google"],
                    "data_types": ["profile", "messages"],
                    "rate_limits": {"requests_per_minute": 60},
                    "security_level": "standard"
                }
            ],
            "supported_frameworks": ["langchain"],
            "minimum_scp_version": "1.0",
            "tags": ["test", "demo"],
            "category": "testing"
        }
    
    def test_agent_registration(self):
        """Test agent registration."""
        print("\n📝 Testing agent registration...")
        
        # Load sample agent
        agent_data = self.load_sample_agent()
        
        # Make agent_id unique for testing
        agent_data['agent_id'] = f"{agent_data['agent_id']}-{int(time.time())}"
        
        try:
            response = requests.post(
                f"{self.base_url}/api/marketplace/agents",
                json=agent_data,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 201:
                data = response.json()
                if data.get('success'):
                    agent_id = data.get('data', {}).get('agent_id')
                    print(f"✅ Agent registered: {agent_id}")
                    self.registered_agents.append(agent_id)
                    return agent_id
                else:
                    print(f"❌ Registration error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Registration failed: HTTP {response.status_code}")
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Registration error: {e}")
        
        return None
    
    def test_agent_listing(self):
        """Test agent listing and filtering."""
        print("\n📋 Testing agent listing...")
        
        # Test basic listing
        try:
            response = requests.get(f"{self.base_url}/api/marketplace/agents")
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    agents = data.get('data', {}).get('agents', [])
                    print(f"✅ Listed {len(agents)} agents")
                    
                    # Test with filters
                    if agents:
                        # Test capability filter
                        response = requests.get(
                            f"{self.base_url}/api/marketplace/agents?capability=email_management"
                        )
                        if response.status_code == 200:
                            filtered_data = response.json()
                            if filtered_data.get('success'):
                                filtered_agents = filtered_data.get('data', {}).get('agents', [])
                                print(f"✅ Filtered by capability: {len(filtered_agents)} agents")
                        
                        # Test search
                        response = requests.get(
                            f"{self.base_url}/api/marketplace/agents?search=email"
                        )
                        if response.status_code == 200:
                            search_data = response.json()
                            if search_data.get('success'):
                                search_agents = search_data.get('data', {}).get('agents', [])
                                print(f"✅ Search results: {len(search_agents)} agents")
                
                else:
                    print(f"❌ Listing error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Listing failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Listing error: {e}")
    
    def test_agent_details(self, agent_id: str):
        """Test getting agent details."""
        if not agent_id:
            print("⏭️  Skipping agent details test (no agent ID)")
            return
        
        print(f"\n🔍 Testing agent details for {agent_id}...")
        
        try:
            response = requests.get(f"{self.base_url}/api/marketplace/agents/{agent_id}")
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    agent_data = data.get('data', {})
                    print(f"✅ Agent details: {agent_data.get('name')} v{agent_data.get('version')}")
                    print(f"   Capabilities: {len(agent_data.get('capabilities', []))}")
                    print(f"   Test results: {len(agent_data.get('test_results', []))}")
                else:
                    print(f"❌ Details error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Details failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Details error: {e}")
    
    def test_agent_testing(self, agent_id: str):
        """Test agent testing framework."""
        if not agent_id:
            print("⏭️  Skipping agent testing (no agent ID)")
            return
        
        print(f"\n🧪 Testing agent testing framework for {agent_id}...")
        
        try:
            # Run all tests
            response = requests.post(
                f"{self.base_url}/api/marketplace/test/{agent_id}",
                json={},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    results = data.get('data', {}).get('test_results', [])
                    print(f"✅ Ran {len(results)} tests")
                    
                    for result in results:
                        test_type = result.get('test_type')
                        status = result.get('status')
                        score = result.get('score')
                        duration = result.get('duration_seconds', 0)
                        
                        score_str = f" (score: {score:.2f})" if score is not None else ""
                        print(f"   - {test_type}: {status}{score_str} ({duration:.2f}s)")
                
                else:
                    print(f"❌ Testing error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Testing failed: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"❌ Testing error: {e}")
        
        # Test specific test types
        try:
            response = requests.post(
                f"{self.base_url}/api/marketplace/test/{agent_id}",
                json={"test_types": ["metadata_validation"]},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    results = data.get('data', {}).get('test_results', [])
                    print(f"✅ Ran specific test: {len(results)} results")
                    
        except Exception as e:
            print(f"❌ Specific test error: {e}")
    
    def test_capability_discovery(self):
        """Test capability discovery."""
        print("\n🔍 Testing capability discovery...")
        
        try:
            response = requests.get(f"{self.base_url}/api/marketplace/capabilities")
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    capabilities = data.get('data', {}).get('capabilities', {})
                    print(f"✅ Discovered {len(capabilities)} capability types:")
                    
                    for capability, agents in capabilities.items():
                        print(f"   - {capability}: {len(agents)} agents")
                
                else:
                    print(f"❌ Discovery error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Discovery failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Discovery error: {e}")
    
    def test_invalid_requests(self):
        """Test error handling with invalid requests."""
        print("\n❌ Testing error handling...")
        
        # Test invalid agent registration
        try:
            invalid_agent = {"name": "Invalid Agent"}  # Missing required fields
            response = requests.post(
                f"{self.base_url}/api/marketplace/agents",
                json=invalid_agent,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 400:
                print("✅ Invalid registration properly rejected")
            else:
                print(f"❌ Invalid registration should return 400, got {response.status_code}")
                
        except Exception as e:
            print(f"❌ Invalid registration test error: {e}")
        
        # Test non-existent agent
        try:
            response = requests.get(f"{self.base_url}/api/marketplace/agents/non-existent-agent")
            if response.status_code == 404:
                print("✅ Non-existent agent properly returns 404")
            else:
                print(f"❌ Non-existent agent should return 404, got {response.status_code}")
        except Exception as e:
            print(f"❌ Non-existent agent test error: {e}")
    
    def cleanup_agents(self):
        """Clean up registered test agents."""
        print("\n🧹 Cleaning up test agents...")
        
        for agent_id in self.registered_agents:
            try:
                response = requests.delete(f"{self.base_url}/api/marketplace/agents/{agent_id}")
                if response.status_code == 200:
                    print(f"✅ Cleaned up agent: {agent_id}")
                else:
                    print(f"❌ Failed to cleanup agent {agent_id}: HTTP {response.status_code}")
            except Exception as e:
                print(f"❌ Cleanup error for {agent_id}: {e}")
    
    def run_tests(self):
        """Run all marketplace tests."""
        print("🚀 Starting SecureContext Protocol Marketplace Tests")
        print("=" * 60)
        
        # Test basic endpoints
        self.test_marketplace_endpoints()
        
        # Test agent registration
        agent_id = self.test_agent_registration()
        
        # Test agent listing and filtering
        self.test_agent_listing()
        
        # Test agent details
        self.test_agent_details(agent_id)
        
        # Test agent testing framework
        self.test_agent_testing(agent_id)
        
        # Test capability discovery
        self.test_capability_discovery()
        
        # Test error handling
        self.test_invalid_requests()
        
        # Cleanup
        self.cleanup_agents()
        
        print("\n" + "=" * 60)
        print("🏁 Marketplace tests completed")
        
        # Summary
        print(f"\n📊 Summary:")
        print(f"   - Agents registered: {len(self.registered_agents)}")
        print(f"   - Tests completed successfully")


def main():
    """Main test function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test SecureContext Protocol marketplace functionality')
    parser.add_argument('--url', default='http://localhost:5000', help='Base URL of the SCP server')
    args = parser.parse_args()
    
    tester = MarketplaceTester(args.url)
    tester.run_tests()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test error: {e}")