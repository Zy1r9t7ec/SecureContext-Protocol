#!/usr/bin/env python3
"""
Comprehensive Testing Suite for SecureContext Protocol.

This script runs extensive tests across all aspects of the project to identify
and help resolve any issues before production deployment.
"""

import os
import sys
import subprocess
import time
import requests
import threading
import json
import platform
from pathlib import Path
from typing import Dict, List, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

class TestResult:
    """Container for test results."""
    def __init__(self, name: str, passed: bool, message: str = "", details: str = ""):
        self.name = name
        self.passed = passed
        self.message = message
        self.details = details
        self.timestamp = time.time()

class ComprehensiveTestSuite:
    """Comprehensive test suite for the SecureContext Protocol."""
    
    def __init__(self):
        self.results: List[TestResult] = []
        self.base_url = "http://localhost:5000"
        self.test_session_id = None
        
    def log_result(self, result: TestResult):
        """Log a test result."""
        self.results.append(result)
        status = "✅ PASS" if result.passed else "❌ FAIL"
        print(f"{status} {result.name}")
        if result.message:
            print(f"    {result.message}")
        if result.details and not result.passed:
            print(f"    Details: {result.details}")
    
    def run_command(self, command: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
        """Run a command and return success, stdout, stderr."""
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", str(e)
    
    def test_python_environment(self):
        """Test Python environment and dependencies."""
        print("\n🐍 Testing Python Environment...")
        
        # Test Python version
        version = sys.version_info
        if version >= (3, 10):
            self.log_result(TestResult(
                "Python Version", True, 
                f"Python {version.major}.{version.minor}.{version.micro}"
            ))
        else:
            self.log_result(TestResult(
                "Python Version", False,
                f"Python {version.major}.{version.minor} < 3.10 (required)"
            ))
        
        # Test platform
        self.log_result(TestResult(
            "Platform", True,
            f"{platform.system()} {platform.release()}"
        ))
        
        # Test dependencies
        required_packages = ['flask', 'authlib', 'dotenv', 'requests', 'pytest']
        for package in required_packages:
            try:
                __import__(package)
                self.log_result(TestResult(f"Package: {package}", True))
            except ImportError:
                self.log_result(TestResult(
                    f"Package: {package}", False,
                    "Package not installed"
                ))
    
    def test_project_structure(self):
        """Test project file structure."""
        print("\n📁 Testing Project Structure...")
        
        required_files = [
            'requirements.txt',
            'run.py',
            'start.py',
            'setup_oauth.py',
            'test_setup.py',
            '.env.example',
            'README.md',
            'authentication_proxy/app.py',
            'authentication_proxy/config.py',
            'authentication_proxy/templates/index.html',
            'tests/test_oauth_flows.py',
            'tests/test_token_storage.py',
            'tests/test_api_endpoints.py'
        ]
        
        for file_path in required_files:
            if Path(file_path).exists():
                self.log_result(TestResult(f"File: {file_path}", True))
            else:
                self.log_result(TestResult(
                    f"File: {file_path}", False,
                    "Required file missing"
                ))
    
    def test_configuration(self):
        """Test configuration and environment setup."""
        print("\n⚙️ Testing Configuration...")
        
        # Test .env file
        env_file = Path('.env')
        if env_file.exists():
            self.log_result(TestResult(".env file", True, "File exists"))
            
            # Check for placeholder values
            with open('.env', 'r') as f:
                content = f.read()
            
            if 'your_google_client_id' in content or 'your_microsoft_client_id' in content:
                self.log_result(TestResult(
                    ".env configuration", False,
                    "Contains placeholder values - run setup_oauth.py"
                ))
            else:
                self.log_result(TestResult(".env configuration", True))
        else:
            self.log_result(TestResult(
                ".env file", False,
                "File missing - copy from .env.example"
            ))
        
        # Test configuration loading
        try:
            from authentication_proxy.config import get_config
            config = get_config()
            self.log_result(TestResult("Configuration loading", True))
            
            # Test OAuth configs
            for provider in ['google', 'microsoft']:
                try:
                    oauth_config = config.get_oauth_config(provider)
                    if oauth_config['client_id'] and oauth_config['client_secret']:
                        self.log_result(TestResult(f"{provider} OAuth config", True))
                    else:
                        self.log_result(TestResult(
                            f"{provider} OAuth config", False,
                            "Missing client credentials"
                        ))
                except Exception as e:
                    self.log_result(TestResult(
                        f"{provider} OAuth config", False,
                        str(e)
                    ))
                    
        except Exception as e:
            self.log_result(TestResult(
                "Configuration loading", False,
                str(e)
            ))
    
    def test_unit_tests(self):
        """Run unit tests."""
        print("\n🧪 Running Unit Tests...")
        
        # Run pytest
        success, stdout, stderr = self.run_command([
            sys.executable, '-m', 'pytest', 'tests/', '-v'
        ], timeout=60)
        
        if success:
            self.log_result(TestResult("Unit tests", True, "All tests passed"))
        else:
            self.log_result(TestResult(
                "Unit tests", False,
                "Some tests failed",
                f"stdout: {stdout}\nstderr: {stderr}"
            ))
    
    def test_application_startup(self):
        """Test application startup."""
        print("\n🚀 Testing Application Startup...")
        
        # Test import
        try:
            from authentication_proxy.app import create_app
            app, socketio = create_app()
            self.log_result(TestResult("App creation", True))
            
            # Test app configuration
            if app.config.get('SECRET_KEY'):
                self.log_result(TestResult("Flask secret key", True))
            else:
                self.log_result(TestResult(
                    "Flask secret key", False,
                    "SECRET_KEY not configured"
                ))
                
        except Exception as e:
            self.log_result(TestResult(
                "App creation", False,
                str(e)
            ))
    
    def start_test_server(self) -> subprocess.Popen:
        """Start the Flask application for testing."""
        print("\n🌐 Starting Test Server...")
        
        # Start server in background
        process = subprocess.Popen([
            sys.executable, 'run.py'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait for server to start
        for i in range(30):  # Wait up to 30 seconds
            try:
                response = requests.get(f"{self.base_url}/", timeout=5)
                if response.status_code == 200:
                    self.log_result(TestResult("Server startup", True))
                    return process
            except requests.exceptions.RequestException:
                time.sleep(1)
        
        self.log_result(TestResult(
            "Server startup", False,
            "Server failed to start within 30 seconds"
        ))
        process.terminate()
        return None
    
    def test_web_interface(self):
        """Test web interface."""
        print("\n🌐 Testing Web Interface...")
        
        try:
            # Test main page
            response = requests.get(f"{self.base_url}/", timeout=10)
            if response.status_code == 200:
                self.log_result(TestResult("Main page", True))
                
                # Check for required elements
                content = response.text
                if 'Connect Google Account' in content:
                    self.log_result(TestResult("Google OAuth button", True))
                else:
                    self.log_result(TestResult(
                        "Google OAuth button", False,
                        "Button not found in HTML"
                    ))
                
                if 'Connect Microsoft Account' in content:
                    self.log_result(TestResult("Microsoft OAuth button", True))
                else:
                    self.log_result(TestResult(
                        "Microsoft OAuth button", False,
                        "Button not found in HTML"
                    ))
            else:
                self.log_result(TestResult(
                    "Main page", False,
                    f"HTTP {response.status_code}"
                ))
                
        except Exception as e:
            self.log_result(TestResult(
                "Web interface", False,
                str(e)
            ))
    
    def test_api_endpoints(self):
        """Test API endpoints."""
        print("\n🔌 Testing API Endpoints...")
        
        # Test invalid session ID
        try:
            response = requests.get(f"{self.base_url}/api/tokens/invalid-session-id")
            if response.status_code == 400:
                self.log_result(TestResult("Invalid session ID handling", True))
            else:
                self.log_result(TestResult(
                    "Invalid session ID handling", False,
                    f"Expected 400, got {response.status_code}"
                ))
        except Exception as e:
            self.log_result(TestResult(
                "Invalid session ID handling", False,
                str(e)
            ))
        
        # Test non-existent session ID
        try:
            import uuid
            fake_session_id = str(uuid.uuid4())
            response = requests.get(f"{self.base_url}/api/tokens/{fake_session_id}")
            if response.status_code == 404:
                self.log_result(TestResult("Non-existent session handling", True))
            else:
                self.log_result(TestResult(
                    "Non-existent session handling", False,
                    f"Expected 404, got {response.status_code}"
                ))
        except Exception as e:
            self.log_result(TestResult(
                "Non-existent session handling", False,
                str(e)
            ))
        
        # Test storage stats endpoint
        try:
            response = requests.get(f"{self.base_url}/api/storage/stats")
            if response.status_code == 200:
                data = response.json()
                if 'success' in data and 'data' in data:
                    self.log_result(TestResult("Storage stats endpoint", True))
                else:
                    self.log_result(TestResult(
                        "Storage stats endpoint", False,
                        "Invalid response format"
                    ))
            else:
                self.log_result(TestResult(
                    "Storage stats endpoint", False,
                    f"HTTP {response.status_code}"
                ))
        except Exception as e:
            self.log_result(TestResult(
                "Storage stats endpoint", False,
                str(e)
            ))
    
    def test_oauth_flows(self):
        """Test OAuth flow initiation (without completing)."""
        print("\n🔐 Testing OAuth Flows...")
        
        # Test Google OAuth initiation
        try:
            response = requests.get(
                f"{self.base_url}/oauth/google/authorize",
                allow_redirects=False
            )
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'accounts.google.com' in location:
                    self.log_result(TestResult("Google OAuth initiation", True))
                else:
                    self.log_result(TestResult(
                        "Google OAuth initiation", False,
                        f"Unexpected redirect: {location}"
                    ))
            else:
                self.log_result(TestResult(
                    "Google OAuth initiation", False,
                    f"Expected 302, got {response.status_code}"
                ))
        except Exception as e:
            self.log_result(TestResult(
                "Google OAuth initiation", False,
                str(e)
            ))
        
        # Test Microsoft OAuth initiation
        try:
            response = requests.get(
                f"{self.base_url}/oauth/microsoft/authorize",
                allow_redirects=False
            )
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'login.microsoftonline.com' in location:
                    self.log_result(TestResult("Microsoft OAuth initiation", True))
                else:
                    self.log_result(TestResult(
                        "Microsoft OAuth initiation", False,
                        f"Unexpected redirect: {location}"
                    ))
            else:
                self.log_result(TestResult(
                    "Microsoft OAuth initiation", False,
                    f"Expected 302, got {response.status_code}"
                ))
        except Exception as e:
            self.log_result(TestResult(
                "Microsoft OAuth initiation", False,
                str(e)
            ))
    
    def test_token_storage(self):
        """Test token storage functionality."""
        print("\n💾 Testing Token Storage...")
        
        try:
            from authentication_proxy.app import TokenStorage
            
            # Test session ID generation
            session_id = TokenStorage.generate_session_id()
            if TokenStorage.validate_session_id(session_id):
                self.log_result(TestResult("Session ID generation", True))
            else:
                self.log_result(TestResult(
                    "Session ID generation", False,
                    "Generated invalid session ID"
                ))
            
            # Test token storage
            stored_session_id = TokenStorage.store_tokens(
                provider='google',
                access_token='test_access_token',
                refresh_token='test_refresh_token',
                expires_in=3600,
                scope='test_scope'
            )
            
            if stored_session_id:
                self.log_result(TestResult("Token storage", True))
                
                # Test token retrieval
                retrieved_tokens = TokenStorage.retrieve_tokens(stored_session_id)
                if retrieved_tokens and retrieved_tokens['access_token'] == 'test_access_token':
                    self.log_result(TestResult("Token retrieval", True))
                else:
                    self.log_result(TestResult(
                        "Token retrieval", False,
                        "Retrieved tokens don't match stored tokens"
                    ))
            else:
                self.log_result(TestResult(
                    "Token storage", False,
                    "Failed to store tokens"
                ))
                
        except Exception as e:
            self.log_result(TestResult(
                "Token storage", False,
                str(e)
            ))
    
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
        urls = [f"{self.base_url}/" for _ in range(10)]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, url) for url in urls]
            results = [future.result() for future in as_completed(futures)]
        
        success_count = sum(results)
        if success_count == len(urls):
            self.log_result(TestResult("Concurrent requests", True))
        else:
            self.log_result(TestResult(
                "Concurrent requests", False,
                f"Only {success_count}/{len(urls)} requests succeeded"
            ))
    
    def test_error_handling(self):
        """Test error handling scenarios."""
        print("\n⚠️ Testing Error Handling...")
        
        # Test 404 handling
        try:
            response = requests.get(f"{self.base_url}/nonexistent-page")
            if response.status_code == 404:
                self.log_result(TestResult("404 error handling", True))
            else:
                self.log_result(TestResult(
                    "404 error handling", False,
                    f"Expected 404, got {response.status_code}"
                ))
        except Exception as e:
            self.log_result(TestResult(
                "404 error handling", False,
                str(e)
            ))
        
        # Test OAuth callback with error
        try:
            response = requests.get(
                f"{self.base_url}/oauth/google/callback?error=access_denied"
            )
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'error=access_denied' in location:
                    self.log_result(TestResult("OAuth error handling", True))
                else:
                    self.log_result(TestResult(
                        "OAuth error handling", False,
                        f"Error not properly handled: {location}"
                    ))
            else:
                self.log_result(TestResult(
                    "OAuth error handling", False,
                    f"Expected 302, got {response.status_code}"
                ))
        except Exception as e:
            self.log_result(TestResult(
                "OAuth error handling", False,
                str(e)
            ))
    
    def test_security_features(self):
        """Test security features."""
        print("\n🔒 Testing Security Features...")
        
        # Test CSRF protection (state parameter)
        try:
            # Make OAuth request without session
            response = requests.get(
                f"{self.base_url}/oauth/google/callback?code=test&state=invalid"
            )
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'error' in location:
                    self.log_result(TestResult("CSRF protection", True))
                else:
                    self.log_result(TestResult(
                        "CSRF protection", False,
                        "Invalid state not rejected"
                    ))
            else:
                self.log_result(TestResult(
                    "CSRF protection", False,
                    f"Unexpected response: {response.status_code}"
                ))
        except Exception as e:
            self.log_result(TestResult(
                "CSRF protection", False,
                str(e)
            ))
    
    def test_setup_scripts(self):
        """Test setup and utility scripts."""
        print("\n📜 Testing Setup Scripts...")
        
        # Test setup validation script
        success, stdout, stderr = self.run_command([
            sys.executable, 'test_setup.py'
        ])
        
        if success:
            self.log_result(TestResult("Setup validation script", True))
        else:
            self.log_result(TestResult(
                "Setup validation script", False,
                f"Script failed: {stderr}"
            ))
    
    def generate_report(self):
        """Generate comprehensive test report."""
        print("\n📊 Generating Test Report...")
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_tests = total_tests - passed_tests
        
        report = f"""
# SecureContext Protocol - Comprehensive Test Report

**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}
**Platform:** {platform.system()} {platform.release()}
**Python:** {sys.version}

## Summary
- **Total Tests:** {total_tests}
- **Passed:** {passed_tests} ✅
- **Failed:** {failed_tests} ❌
- **Success Rate:** {(passed_tests/total_tests*100):.1f}%

## Test Results

"""
        
        # Group results by category
        categories = {}
        for result in self.results:
            category = result.name.split(':')[0] if ':' in result.name else 'General'
            if category not in categories:
                categories[category] = []
            categories[category].append(result)
        
        for category, results in categories.items():
            report += f"### {category}\n\n"
            for result in results:
                status = "✅" if result.passed else "❌"
                report += f"- {status} **{result.name}**"
                if result.message:
                    report += f": {result.message}"
                report += "\n"
                if result.details and not result.passed:
                    report += f"  - Details: {result.details}\n"
            report += "\n"
        
        # Add recommendations
        if failed_tests > 0:
            report += """## Recommendations

### Critical Issues
Fix the following issues before production deployment:

"""
            for result in self.results:
                if not result.passed and any(keyword in result.name.lower() 
                                           for keyword in ['security', 'oauth', 'configuration']):
                    report += f"- **{result.name}**: {result.message}\n"
            
            report += """
### General Issues
Address these issues to improve reliability:

"""
            for result in self.results:
                if not result.passed and not any(keyword in result.name.lower() 
                                                for keyword in ['security', 'oauth', 'configuration']):
                    report += f"- **{result.name}**: {result.message}\n"
        else:
            report += """## Recommendations

🎉 **All tests passed!** Your SecureContext Protocol implementation is ready for production.

### Next Steps:
1. Deploy to your chosen hosting platform
2. Set up monitoring and alerting
3. Configure production OAuth applications
4. Test with real user workflows
"""
        
        # Save report
        with open('TEST_REPORT.md', 'w') as f:
            f.write(report)
        
        print(f"📄 Test report saved to TEST_REPORT.md")
        return passed_tests == total_tests
    
    def run_all_tests(self):
        """Run all comprehensive tests."""
        print("🔍 Starting Comprehensive Test Suite for SecureContext Protocol")
        print("=" * 70)
        
        start_time = time.time()
        
        # Run all test categories
        self.test_python_environment()
        self.test_project_structure()
        self.test_configuration()
        self.test_unit_tests()
        self.test_application_startup()
        self.test_token_storage()
        self.test_setup_scripts()
        
        # Start server for integration tests
        server_process = self.start_test_server()
        
        if server_process:
            try:
                self.test_web_interface()
                self.test_api_endpoints()
                self.test_oauth_flows()
                self.test_concurrent_access()
                self.test_error_handling()
                self.test_security_features()
            finally:
                # Clean up server
                server_process.terminate()
                server_process.wait(timeout=10)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n⏱️ Tests completed in {duration:.1f} seconds")
        
        # Generate report
        all_passed = self.generate_report()
        
        if all_passed:
            print("\n🎉 All tests passed! Your implementation is ready for production.")
            return 0
        else:
            print("\n⚠️ Some tests failed. Please review the test report and fix issues.")
            return 1

def main():
    """Main function."""
    suite = ComprehensiveTestSuite()
    return suite.run_all_tests()

if __name__ == '__main__':
    sys.exit(main())