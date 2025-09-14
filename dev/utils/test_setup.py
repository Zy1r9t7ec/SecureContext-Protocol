#!/usr/bin/env python3
"""
Quick setup test for the SecureContext Protocol Authentication Proxy.

This script tests the basic setup and configuration without requiring OAuth credentials.
"""

import sys
import os
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported."""
    try:
        from authentication_proxy.config import get_config, ConfigurationError
        from authentication_proxy.app import create_app, TokenStorage
        print("✅ All imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_dependencies():
    """Test that all required dependencies are installed."""
    required_packages = ['flask', 'authlib', 'dotenv', 'requests']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Run: pip install -r requirements.txt")
        return False
    else:
        print("✅ All dependencies installed")
        return True

def test_env_file():
    """Test environment file setup."""
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    if not env_example.exists():
        print("❌ .env.example file missing")
        return False
    
    if not env_file.exists():
        print("⚠️  .env file not found")
        print("💡 Copy .env.example to .env and fill in your OAuth credentials")
        return False
    
    # Check if .env has the required variables (even if empty)
    required_vars = [
        'GOOGLE_CLIENT_ID',
        'GOOGLE_CLIENT_SECRET',
        'MICROSOFT_CLIENT_ID',
        'MICROSOFT_CLIENT_SECRET',
        'FLASK_SECRET_KEY'
    ]
    
    with open('.env', 'r') as f:
        env_content = f.read()
    
    missing_vars = []
    for var in required_vars:
        if var not in env_content:
            missing_vars.append(var)
    
    if missing_vars:
        print(f"⚠️  Missing variables in .env: {', '.join(missing_vars)}")
        return False
    
    print("✅ .env file configured")
    return True

def test_token_storage():
    """Test token storage functionality."""
    try:
        from authentication_proxy.app import TokenStorage
        
        # Test session ID generation
        session_id = TokenStorage.generate_session_id()
        if not TokenStorage.validate_session_id(session_id):
            print("❌ Session ID validation failed")
            return False
        
        # Test token storage and retrieval
        stored_session_id = TokenStorage.store_tokens(
            provider='google',
            access_token='test_token',
            refresh_token='test_refresh',
            expires_in=3600,
            scope='test_scope'
        )
        
        retrieved_tokens = TokenStorage.retrieve_tokens(stored_session_id)
        if not retrieved_tokens or retrieved_tokens['access_token'] != 'test_token':
            print("❌ Token storage/retrieval failed")
            return False
        
        print("✅ Token storage working")
        return True
        
    except Exception as e:
        print(f"❌ Token storage error: {e}")
        return False

def test_flask_app_creation():
    """Test Flask app creation (without OAuth credentials)."""
    try:
        # Temporarily set dummy environment variables
        os.environ['GOOGLE_CLIENT_ID'] = 'dummy'
        os.environ['GOOGLE_CLIENT_SECRET'] = 'dummy'
        os.environ['MICROSOFT_CLIENT_ID'] = 'dummy'
        os.environ['MICROSOFT_CLIENT_SECRET'] = 'dummy'
        os.environ['FLASK_SECRET_KEY'] = 'dummy_secret_key'
        
        from authentication_proxy.app import create_app
        app = create_app()
        
        if app is None:
            print("❌ Flask app creation failed")
            return False
        
        print("✅ Flask app creation successful")
        return True
        
    except Exception as e:
        print(f"❌ Flask app creation error: {e}")
        return False

def print_next_steps():
    """Print next steps for setup."""
    print("\n🚀 Next Steps:")
    print("1. Set up OAuth applications:")
    print("   - Google: https://console.cloud.google.com/")
    print("   - Microsoft: https://portal.azure.com/")
    print("2. Fill in your .env file with real OAuth credentials")
    print("3. Run: python run.py")
    print("4. Visit: http://localhost:5000")
    print("\n📖 For detailed setup instructions, see SETUP.md")
    print("🌐 For hosting options, see HOSTING.md")

def main():
    """Run all setup tests."""
    print("🔧 Testing SecureContext Protocol setup...\n")
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Imports", test_imports),
        ("Environment File", test_env_file),
        ("Token Storage", test_token_storage),
        ("Flask App Creation", test_flask_app_creation)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Testing {test_name}...")
        if test_func():
            passed += 1
        else:
            print(f"   Fix the issues above before proceeding")
    
    print(f"\n📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your setup looks good.")
        print_next_steps()
    else:
        print("⚠️  Some tests failed. Please fix the issues above.")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())