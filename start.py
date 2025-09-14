#!/usr/bin/env python3
"""
One-click starter for SecureContext Protocol.

This script handles the complete setup and startup process.
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 10):
        print("❌ Python 3.10 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True

def install_dependencies():
    """Install required dependencies."""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def check_env_file():
    """Check if .env file exists and is configured."""
    env_file = Path('.env')
    
    if not env_file.exists():
        print("⚠️  .env file not found")
        print("🔧 Running OAuth setup wizard...")
        try:
            subprocess.run([sys.executable, 'setup_oauth.py'])
            return env_file.exists()
        except KeyboardInterrupt:
            print("\n👋 Setup cancelled")
            return False
    
    # Check if .env has actual values (not just placeholders)
    with open('.env', 'r') as f:
        content = f.read()
    
    if 'your_google_client_id' in content or 'your_microsoft_client_id' in content:
        print("⚠️  .env file contains placeholder values")
        print("🔧 Please run: python setup_oauth.py")
        return False
    
    print("✅ .env file configured")
    return True

def run_tests():
    """Run setup tests."""
    print("🧪 Running setup tests...")
    try:
        result = subprocess.run([sys.executable, 'test_setup.py'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ All tests passed")
            return True
        else:
            print("❌ Some tests failed:")
            print(result.stdout)
            return False
            
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False

def start_application():
    """Start the Flask application."""
    print("🚀 Starting SecureContext Protocol...")
    print("=" * 50)
    
    try:
        subprocess.run([sys.executable, 'run.py'])
    except KeyboardInterrupt:
        print("\n👋 Application stopped")
    except Exception as e:
        print(f"❌ Error starting application: {e}")

def print_banner():
    """Print application banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                 SecureContext Protocol (SCP)                ║
║              OAuth 2.0 Authentication Proxy                 ║
║                                                              ║
║  🔐 Secure, user-consented OAuth 2.0 access mediation      ║
║  🤖 Built for AI agents and agentic workflows              ║
║  🌐 Open source and extensible                             ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def main():
    """Main startup function."""
    print_banner()
    
    # Step 1: Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Step 2: Install dependencies
    if not install_dependencies():
        print("\n💡 Try running: pip install -r requirements.txt")
        sys.exit(1)
    
    # Step 3: Check environment configuration
    if not check_env_file():
        print("\n💡 Please set up your OAuth credentials first")
        print("   Run: python setup_oauth.py")
        sys.exit(1)
    
    # Step 4: Run tests
    if not run_tests():
        print("\n💡 Please fix the issues above before starting")
        response = input("\nDo you want to continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            sys.exit(1)
    
    # Step 5: Start application
    print("\n🎉 Setup complete! Starting application...")
    start_application()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)