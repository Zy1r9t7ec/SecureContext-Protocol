#!/usr/bin/env python3
"""
Core Functionality Testing for SecureContext Protocol - Task 26.1

This script tests all core functionality including:
- OAuth flows end-to-end (mocked)
- Token storage, retrieval, and cleanup mechanisms
- Session ID generation, validation, and uniqueness
- API endpoints with various input scenarios
- Error handling for all failure modes
"""

import os
import sys
import time
import uuid
import threading
import requests
import subprocess
from typing import Dict, List, Tuple, Any
from unittest.mock import patch, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed

class CoreFunctionalityTester:
    """Core functionality tester for SCP."""
    
    def __init__(self):
        self.results = []
        self.base_url = "http://localhost:5001"  # Use different port for testing
        self.server_process = None
        
    def log_result(self, name: str, passed: bool, message: str = "", details: str = ""):
        """Log a test result."""
        result = {
            'name': name,
            'passed': passed,
            'message': message,
            'details': details,
            'timestamp': time.time()
        }
        self.results.append(result)
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {name}")
        if message:
            print(f"    {message}")
        if details and not passed:
            print(f"    Details: {details}")
    
    def test_session_id_functionality(self):
        """Test session ID generation, validation, and uniqueness."""
        print("\n🔑 Testing Session ID Functionality...")
        
        try:
            from authentication_proxy.app import TokenStorage
            
            # Test session ID generation
            session_ids = set()
            for i in range(100):
                session_id = TokenStorage.generate_session_id()
                session_ids.add(session_id)
                
                # Validate format
                if not TokenStorage.validate_session_id(session_id):
                    self.log_result(
                        "Session ID validation", False,
                        f"Generated invalid session ID: {session_id}"
                    )
                    return
            
            # Check uniqueness
            if len(session_ids) == 100:
                self.log_result("Session ID generation and uniqueness", True)
            else:
                self.log_result(
                    "Session ID generation and uniqueness", False,
                    f"Generated {len(session_ids)} unique IDs out of 100"
                )
            
            # Test invalid session ID validation
            invalid_ids = [
                "invalid-id",
                "12345",
                "",
                None,
                "not-a-uuid",
                "123e4567-e89b-12d3-a456-42661417400",  # Too short
                "123e4567-e89b-12d3-a456-426614174000-extra"  # Too long
            ]
            
            for invalid_id in invalid_ids:
                if TokenStorage.validate_session_id(invalid_id):
                    self.log_result(
                        "Invalid session ID rejection", False,
                        f"Accepted invalid session ID: {invalid_id}"
                    )
                    return
            
            self.log_result("Invalid session ID rejection", True)
            
        except Exception as e:
            self.log_result(
                "Session ID functionality", False,
                str(e)
            )
    
    def test_token_storage_mechanisms(self):
        """Test token storage, retrieval, and cleanup mechanisms."""
        print("\n💾 Testing Token Storage Mechanisms...")
        
        try:
            from authentication_proxy.app import TokenStorage, token_storage, storage_lock
            
            # Clear storage first
            with storage_lock:
                token_storage.clear()
            
            # Test token storage
            session_id = TokenStorage.store_tokens(
                provider='google',
                access_token='test_access_token_123',
                refresh_token='test_refresh_token_456',
                expires_in=3600,
                scope='test_scope'
            )
            
            if not session_id:
                self.log_result("Token storage", False, "Failed to store tokens")
                return
            
            self.log_result("Token storage", True, f"Stored with session ID: {session_id}")
            
            # Test token retrieval
            retrieved_tokens = TokenStorage.retrieve_tokens(session_id)
            if not retrieved_tokens:
                self.log_result("Token retrieval", False, "Failed to retrieve tokens")
                return
            
            # Verify token data
            expected_fields = ['access_token', 'refresh_token', 'expires_at', 'scope', 'provider']
            for field in expected_fields:
                if field not in retrieved_tokens:
                    self.log_result(
                        "Token data integrity", False,
                        f"Missing field: {field}"
                    )
                    return
            
            if retrieved_tokens['access_token'] != 'test_access_token_123':
                self.log_result(
                    "Token data integrity", False,
                    "Access token mismatch"
                )
                return
            
            self.log_result("Token retrieval and data integrity", True)
            
            # Test session isolation - store multiple tokens
            session_id_2 = TokenStorage.store_tokens(
                provider='microsoft',
                access_token='ms_access_token_789',
                refresh_token='ms_refresh_token_012',
                expires_in=7200,
                scope='ms_scope'
            )
            
            # Verify isolation
            tokens_1 = TokenStorage.retrieve_tokens(session_id)
            tokens_2 = TokenStorage.retrieve_tokens(session_id_2)
            
            if (tokens_1['access_token'] == 'test_access_token_123' and 
                tokens_2['access_token'] == 'ms_access_token_789'):
                self.log_result("Session isolation", True)
            else:
                self.log_result("Session isolation", False, "Token data mixed between sessions")
            
            # Test cleanup mechanism
            with storage_lock:
                initial_count = len(token_storage)
            
            # Remove one token
            TokenStorage.remove_session(session_id)
            
            with storage_lock:
                after_removal_count = len(token_storage)
            
            if after_removal_count == initial_count - 1:
                self.log_result("Token cleanup", True)
            else:
                self.log_result(
                    "Token cleanup", False,
                    f"Expected {initial_count - 1} tokens, got {after_removal_count}"
                )
            
            # Test retrieval of removed token
            removed_tokens = TokenStorage.retrieve_tokens(session_id)
            if removed_tokens is None:
                self.log_result("Token removal verification", True)
            else:
                self.log_result("Token removal verification", False, "Removed token still retrievable")
            
        except Exception as e:
            self.log_result(
                "Token storage mechanisms", False,
                str(e)
            )
    
    def start_test_server(self) -> bool:
        """Start the Flask application for testing."""
        print("\n🌐 Starting Test Server...")
        
        try:
            # Set environment variable for different port
            env = os.environ.copy()
            env['PORT'] = '5001'
            
            # Start server in background
            self.server_process = subprocess.Popen([
                sys.executable, 'run.py'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            
            # Wait for server to start
            for i in range(15):  # Wait up to 15 seconds
                try:
                    response = requests.get(f"{self.base_url}/", timeout=5)
                    if response.status_code == 200:
                        self.log_result("Server startup", True)
                        return True
                except requests.exceptions.RequestException:
                    time.sleep(1)
            
            # Check if process is still running and get output
            if self.server_process and self.server_process.poll() is None:
                # Process is running but not responding
                self.log_result("Server startup", False, "Server process running but not responding")
            elif self.server_process:
                # Process has terminated, get output
                stdout, stderr = self.server_process.communicate()
                error_msg = f"Server process terminated. stderr: {stderr.decode()[:200]}"
                self.log_result("Server startup", False, error_msg)
            else:
                self.log_result("Server startup", False, "Failed to start server process")
            
            if self.server_process:
                self.server_process.terminate()
            return False
            
        except Exception as e:
            self.log_result("Server startup", False, str(e))
            return False
    
    def test_api_endpoints(self):
        """Test API endpoints with various input scenarios."""
        print("\n🔌 Testing API Endpoints...")
        
        # Test invalid session ID formats
        invalid_session_ids = [
            "invalid-id",
            "12345",
            "",
            "not-a-uuid",
            "123e4567-e89b-12d3-a456-42661417400",  # Too short
        ]
        
        for invalid_id in invalid_session_ids:
            try:
                response = requests.get(f"{self.base_url}/api/tokens/{invalid_id}", timeout=10)
                if response.status_code == 400:
                    continue  # Expected
                else:
                    self.log_result(
                        f"Invalid session ID handling ({invalid_id})", False,
                        f"Expected 400, got {response.status_code}"
                    )
                    return
            except Exception as e:
                self.log_result(
                    f"Invalid session ID handling ({invalid_id})", False,
                    str(e)
                )
                return
        
        self.log_result("Invalid session ID handling", True)
        
        # Test non-existent session ID
        try:
            fake_session_id = str(uuid.uuid4())
            response = requests.get(f"{self.base_url}/api/tokens/{fake_session_id}", timeout=10)
            if response.status_code == 404:
                self.log_result("Non-existent session handling", True)
            else:
                self.log_result(
                    "Non-existent session handling", False,
                    f"Expected 404, got {response.status_code}"
                )
        except Exception as e:
            self.log_result("Non-existent session handling", False, str(e))
        
        # Test providers API endpoint
        try:
            response = requests.get(f"{self.base_url}/api/providers", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'success' in data and 'data' in data:
                    self.log_result("Providers API endpoint", True)
                else:
                    self.log_result(
                        "Providers API endpoint", False,
                        "Invalid response format"
                    )
            else:
                self.log_result(
                    "Providers API endpoint", False,
                    f"HTTP {response.status_code}"
                )
        except Exception as e:
            self.log_result("Providers API endpoint", False, str(e))
        
        # Test storage stats endpoint
        try:
            response = requests.get(f"{self.base_url}/api/storage/stats", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'success' in data and 'data' in data:
                    self.log_result("Storage stats endpoint", True)
                else:
                    self.log_result(
                        "Storage stats endpoint", False,
                        "Invalid response format"
                    )
            else:
                self.log_result(
                    "Storage stats endpoint", False,
                    f"HTTP {response.status_code}"
                )
        except Exception as e:
            self.log_result("Storage stats endpoint", False, str(e))
    
    def test_oauth_flow_initiation(self):
        """Test OAuth flow initiation (without completing)."""
        print("\n🔐 Testing OAuth Flow Initiation...")
        
        # Test Google OAuth initiation
        try:
            response = requests.get(
                f"{self.base_url}/oauth/google/authorize",
                allow_redirects=False,
                timeout=10
            )
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'accounts.google.com' in location:
                    self.log_result("Google OAuth initiation", True)
                else:
                    self.log_result(
                        "Google OAuth initiation", False,
                        f"Unexpected redirect: {location}"
                    )
            else:
                self.log_result(
                    "Google OAuth initiation", False,
                    f"Expected 302, got {response.status_code}"
                )
        except Exception as e:
            self.log_result("Google OAuth initiation", False, str(e))
        
        # Test Microsoft OAuth initiation
        try:
            response = requests.get(
                f"{self.base_url}/oauth/microsoft/authorize",
                allow_redirects=False,
                timeout=10
            )
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'login.microsoftonline.com' in location:
                    self.log_result("Microsoft OAuth initiation", True)
                else:
                    self.log_result(
                        "Microsoft OAuth initiation", False,
                        f"Unexpected redirect: {location}"
                    )
            else:
                self.log_result(
                    "Microsoft OAuth initiation", False,
                    f"Expected 302, got {response.status_code}"
                )
        except Exception as e:
            self.log_result("Microsoft OAuth initiation", False, str(e))
    
    def test_error_handling(self):
        """Test error handling for all failure modes."""
        print("\n⚠️ Testing Error Handling...")
        
        # Test 404 handling
        try:
            response = requests.get(f"{self.base_url}/nonexistent-page", timeout=10)
            if response.status_code == 404:
                self.log_result("404 error handling", True)
            else:
                self.log_result(
                    "404 error handling", False,
                    f"Expected 404, got {response.status_code}"
                )
        except Exception as e:
            self.log_result("404 error handling", False, str(e))
        
        # Test OAuth callback with error
        try:
            response = requests.get(
                f"{self.base_url}/oauth/google/callback?error=access_denied",
                timeout=10
            )
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'error=access_denied' in location:
                    self.log_result("OAuth error handling", True)
                else:
                    self.log_result(
                        "OAuth error handling", False,
                        f"Error not properly handled: {location}"
                    )
            else:
                self.log_result(
                    "OAuth error handling", False,
                    f"Expected 302, got {response.status_code}"
                )
        except Exception as e:
            self.log_result("OAuth error handling", False, str(e))
        
        # Test malformed requests
        malformed_requests = [
            f"{self.base_url}/api/tokens/",  # Missing session ID
            f"{self.base_url}/oauth/invalid/authorize",  # Invalid provider
            f"{self.base_url}/oauth/google/invalid",  # Invalid endpoint
        ]
        
        for url in malformed_requests:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code in [400, 404]:
                    continue  # Expected error response
                else:
                    self.log_result(
                        f"Malformed request handling ({url})", False,
                        f"Expected 400/404, got {response.status_code}"
                    )
                    return
            except Exception as e:
                self.log_result(
                    f"Malformed request handling ({url})", False,
                    str(e)
                )
                return
        
        self.log_result("Malformed request handling", True)
    
    def test_concurrent_access(self):
        """Test concurrent access and thread safety."""
        print("\n🔄 Testing Concurrent Access...")
        
        def make_request(url):
            try:
                response = requests.get(url, timeout=10)
                return response.status_code == 200
            except:
                return False
        
        # Test concurrent requests to main page
        urls = [f"{self.base_url}/" for _ in range(20)]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, url) for url in urls]
            results = [future.result() for future in as_completed(futures)]
        
        success_count = sum(results)
        if success_count == len(urls):
            self.log_result("Concurrent main page requests", True)
        else:
            self.log_result(
                "Concurrent main page requests", False,
                f"Only {success_count}/{len(urls)} requests succeeded"
            )
        
        # Test concurrent API requests
        api_urls = [f"{self.base_url}/api/providers" for _ in range(10)]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, url) for url in api_urls]
            results = [future.result() for future in as_completed(futures)]
        
        success_count = sum(results)
        if success_count == len(api_urls):
            self.log_result("Concurrent API requests", True)
        else:
            self.log_result(
                "Concurrent API requests", False,
                f"Only {success_count}/{len(api_urls)} requests succeeded"
            )
    
    def test_application_creation(self):
        """Test application creation and configuration."""
        print("\n🚀 Testing Application Creation...")
        
        try:
            from authentication_proxy.app import create_app
            app, socketio = create_app()
            
            if app and socketio:
                self.log_result("Application creation", True)
                
                # Test basic configuration
                if app.config.get('SECRET_KEY'):
                    self.log_result("Flask secret key configuration", True)
                else:
                    self.log_result("Flask secret key configuration", False, "SECRET_KEY not set")
                
                # Test provider manager
                if hasattr(app, 'provider_manager'):
                    self.log_result("Provider manager initialization", True)
                else:
                    self.log_result("Provider manager initialization", False, "Provider manager not found")
                
            else:
                self.log_result("Application creation", False, "Failed to create app or socketio")
                
        except Exception as e:
            self.log_result("Application creation", False, str(e))
    
    def test_basic_app_functionality(self):
        """Test basic app functionality without server."""
        print("\n🔧 Testing Basic App Functionality...")
        
        try:
            from authentication_proxy.app import create_app
            app, socketio = create_app()
            
            # Test app context
            with app.app_context():
                # Test route registration
                routes = [str(rule) for rule in app.url_map.iter_rules()]
                
                expected_routes = [
                    '/oauth/google/authorize',
                    '/oauth/microsoft/authorize',
                    '/api/providers',
                    '/api/tokens/<session_id>'
                ]
                
                for expected_route in expected_routes:
                    if any(expected_route in route for route in routes):
                        continue
                    else:
                        self.log_result(
                            f"Route registration ({expected_route})", False,
                            f"Route not found in: {routes[:5]}..."
                        )
                        return
                
                self.log_result("Route registration", True)
                
                # Test provider configuration
                providers = app.provider_manager.get_all_providers()
                if 'google' in providers and 'microsoft' in providers:
                    self.log_result("Provider configuration", True)
                else:
                    self.log_result(
                        "Provider configuration", False,
                        f"Expected google and microsoft, got: {list(providers.keys())}"
                    )
                
        except Exception as e:
            self.log_result("Basic app functionality", False, str(e))
    
    def test_web_interface(self):
        """Test web interface functionality."""
        print("\n🌐 Testing Web Interface...")
        
        try:
            # Test main page
            response = requests.get(f"{self.base_url}/", timeout=10)
            if response.status_code == 200:
                self.log_result("Main page accessibility", True)
                
                # Check for required elements
                content = response.text
                required_elements = [
                    'SecureContext Protocol',
                    'Connect',
                    'oauth',
                    'providers'
                ]
                
                for element in required_elements:
                    if element not in content:
                        self.log_result(
                            f"Main page content ({element})", False,
                            f"Required element not found: {element}"
                        )
                        return
                
                self.log_result("Main page content", True)
            else:
                self.log_result(
                    "Main page accessibility", False,
                    f"HTTP {response.status_code}"
                )
        except Exception as e:
            self.log_result("Web interface", False, str(e))
    
    def cleanup(self):
        """Clean up test server."""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=10)
            except:
                try:
                    self.server_process.kill()
                except:
                    pass
    
    def generate_report(self):
        """Generate test report."""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r['passed'])
        failed_tests = total_tests - passed_tests
        
        print(f"\n📊 Core Functionality Test Results:")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
        
        if failed_tests > 0:
            print(f"\n❌ Failed Tests:")
            for result in self.results:
                if not result['passed']:
                    print(f"  - {result['name']}: {result['message']}")
        
        return failed_tests == 0
    
    def run_all_tests(self):
        """Run all core functionality tests."""
        print("🔍 Starting Core Functionality Tests for SecureContext Protocol")
        print("=" * 70)
        
        start_time = time.time()
        
        # Run tests that don't require server
        self.test_session_id_functionality()
        self.test_token_storage_mechanisms()
        
        # Test application creation without server
        self.test_application_creation()
        
        # Start server for integration tests
        server_started = self.start_test_server()
        
        if server_started:
            try:
                self.test_web_interface()
                self.test_api_endpoints()
                self.test_oauth_flow_initiation()
                self.test_error_handling()
                self.test_concurrent_access()
            finally:
                self.cleanup()
        else:
            print("⚠️ Skipping server-dependent tests due to startup failure")
            # Still test basic application functionality
            self.test_basic_app_functionality()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n⏱️ Tests completed in {duration:.1f} seconds")
        
        # Generate report
        all_passed = self.generate_report()
        
        return 0 if all_passed else 1

def main():
    """Main function."""
    tester = CoreFunctionalityTester()
    return tester.run_all_tests()

if __name__ == '__main__':
    sys.exit(main())