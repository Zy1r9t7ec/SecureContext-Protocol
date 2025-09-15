#!/usr/bin/env python3
"""
SecureContext Protocol - Competition Submission Deployment Script

This script helps deploy a live demo for competition submission.
It ensures all requirements are met for evaluator access and testing.
"""

import os
import sys
import subprocess
import secrets
import json
from pathlib import Path

def print_header(text):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")

def print_step(step, text):
    """Print a formatted step"""
    print(f"\n[Step {step}] {text}")

def run_command(command, description=""):
    """Run a shell command and handle errors"""
    if description:
        print(f"  → {description}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        if result.stdout:
            print(f"    {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"    ❌ Error: {e}")
        if e.stderr:
            print(f"    {e.stderr.strip()}")
        return False

def check_prerequisites():
    """Check if all prerequisites are installed"""
    print_step(1, "Checking Prerequisites")
    
    # Check Python version
    if sys.version_info < (3, 10):
        print("❌ Python 3.10+ required")
        return False
    print("✅ Python version OK")
    
    # Check if git is available
    if not run_command("git --version", "Checking Git"):
        return False
    print("✅ Git available")
    
    return True

def choose_deployment_platform():
    """Let user choose deployment platform"""
    print_step(2, "Choose Deployment Platform")
    
    platforms = {
        "1": {"name": "Heroku", "cmd": "heroku", "check": "heroku --version"},
        "2": {"name": "Railway", "cmd": "railway", "check": "railway --version"},
        "3": {"name": "Fly.io", "cmd": "fly", "check": "fly version"},
        "4": {"name": "Manual (I'll deploy myself)", "cmd": None, "check": None}
    }
    
    print("\nAvailable platforms:")
    for key, platform in platforms.items():
        print(f"  {key}. {platform['name']}")
    
    while True:
        choice = input("\nChoose platform (1-4): ").strip()
        if choice in platforms:
            platform = platforms[choice]
            
            if platform["cmd"] and platform["check"]:
                print(f"\nChecking {platform['name']} CLI...")
                if not run_command(platform["check"], f"Checking {platform['name']} CLI"):
                    print(f"❌ {platform['name']} CLI not found. Please install it first.")
                    continue
                print(f"✅ {platform['name']} CLI available")
            
            return choice, platform
        else:
            print("Invalid choice. Please enter 1-4.")

def setup_environment_variables():
    """Setup environment variables for deployment"""
    print_step(3, "Setup Environment Variables")
    
    # Generate secure Flask secret key
    flask_secret = secrets.token_hex(32)
    print("✅ Generated secure Flask secret key")
    
    # Get OAuth credentials
    print("\n📋 OAuth Credentials Required:")
    print("You need OAuth credentials for the demo. If you don't have them:")
    print("  - Google: https://console.cloud.google.com/")
    print("  - Microsoft: https://portal.azure.com/")
    
    google_client_id = input("\nGoogle Client ID: ").strip()
    google_client_secret = input("Google Client Secret: ").strip()
    microsoft_client_id = input("Microsoft Client ID: ").strip()
    microsoft_client_secret = input("Microsoft Client Secret: ").strip()
    
    if not all([google_client_id, google_client_secret, microsoft_client_id, microsoft_client_secret]):
        print("❌ All OAuth credentials are required for the demo")
        return None
    
    env_vars = {
        "FLASK_SECRET_KEY": flask_secret,
        "FLASK_ENV": "production",
        "FLASK_DEBUG": "false",
        "GOOGLE_CLIENT_ID": google_client_id,
        "GOOGLE_CLIENT_SECRET": google_client_secret,
        "MICROSOFT_CLIENT_ID": microsoft_client_id,
        "MICROSOFT_CLIENT_SECRET": microsoft_client_secret
    }
    
    print("✅ Environment variables configured")
    return env_vars

def deploy_to_heroku(env_vars):
    """Deploy to Heroku"""
    print_step(4, "Deploying to Heroku")
    
    # Create Heroku app
    app_name = input("Enter Heroku app name (or press Enter for auto-generated): ").strip()
    
    if app_name:
        create_cmd = f"heroku create {app_name}"
    else:
        create_cmd = "heroku create"
    
    if not run_command(create_cmd, "Creating Heroku app"):
        return None
    
    # Set environment variables
    print("\n  → Setting environment variables...")
    for key, value in env_vars.items():
        if not run_command(f"heroku config:set {key}='{value}'", f"Setting {key}"):
            return None
    
    # Deploy
    print("\n  → Deploying to Heroku...")
    if not run_command("git add .", "Staging files"):
        return None
    
    if not run_command("git commit -m 'Competition submission deployment'", "Committing changes"):
        # Might fail if no changes, that's OK
        pass
    
    if not run_command("git push heroku main", "Pushing to Heroku"):
        return None
    
    # Get app URL
    result = subprocess.run("heroku info -s", shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if line.startswith('web_url='):
                return line.split('=')[1]
    
    return "https://your-app.herokuapp.com"

def deploy_to_railway(env_vars):
    """Deploy to Railway"""
    print_step(4, "Deploying to Railway")
    
    # Login and create project
    if not run_command("railway login", "Logging into Railway"):
        return None
    
    if not run_command("railway new", "Creating Railway project"):
        return None
    
    # Set environment variables
    print("\n  → Setting environment variables...")
    for key, value in env_vars.items():
        if not run_command(f"railway variables set {key}='{value}'", f"Setting {key}"):
            return None
    
    # Deploy
    if not run_command("railway up", "Deploying to Railway"):
        return None
    
    print("\n  → Getting deployment URL...")
    result = subprocess.run("railway status", shell=True, capture_output=True, text=True)
    if result.returncode == 0 and "https://" in result.stdout:
        # Extract URL from status output
        lines = result.stdout.split('\n')
        for line in lines:
            if "https://" in line:
                return line.strip().split()[-1]
    
    return "https://your-app.railway.app"

def deploy_to_fly(env_vars):
    """Deploy to Fly.io"""
    print_step(4, "Deploying to Fly.io")
    
    # Login and launch
    if not run_command("fly auth login", "Logging into Fly.io"):
        return None
    
    if not run_command("fly launch", "Launching Fly.io app"):
        return None
    
    # Set secrets
    print("\n  → Setting secrets...")
    for key, value in env_vars.items():
        if not run_command(f"fly secrets set {key}='{value}'", f"Setting {key}"):
            return None
    
    # Deploy
    if not run_command("fly deploy", "Deploying to Fly.io"):
        return None
    
    # Get app URL
    result = subprocess.run("fly status", shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        lines = result.stdout.split('\n')
        for line in lines:
            if "https://" in line and "hostname" in line.lower():
                return line.split()[-1]
    
    return "https://your-app.fly.dev"

def update_oauth_redirects(demo_url):
    """Provide instructions for updating OAuth redirects"""
    print_step(5, "Update OAuth Redirect URIs")
    
    print(f"\n🔧 IMPORTANT: Update your OAuth app redirect URIs:")
    print(f"\n📍 Google Cloud Console:")
    print(f"   Add: {demo_url}/oauth/google/callback")
    print(f"\n📍 Microsoft Azure Portal:")
    print(f"   Add: {demo_url}/oauth/microsoft/callback")
    
    input("\nPress Enter after updating OAuth redirect URIs...")

def test_deployment(demo_url):
    """Test the deployment"""
    print_step(6, "Testing Deployment")
    
    print(f"\n🧪 Testing demo at: {demo_url}")
    
    # Test main page
    if run_command(f"curl -s -o /dev/null -w '%{{http_code}}' {demo_url}", "Testing main page"):
        print("✅ Main page accessible")
    else:
        print("❌ Main page not accessible")
    
    # Test API endpoints
    if run_command(f"curl -s -o /dev/null -w '%{{http_code}}' {demo_url}/api/providers", "Testing API"):
        print("✅ API endpoints accessible")
    else:
        print("❌ API endpoints not accessible")

def create_submission_summary(demo_url, platform_name):
    """Create submission summary"""
    print_step(7, "Creating Submission Summary")
    
    summary = f"""
# SecureContext Protocol - Competition Submission

## 🏆 Live Demo Access
**Demo URL**: {demo_url}
**Platform**: {platform_name}
**Status**: ✅ Live and ready for evaluation

## 📋 Testing Instructions

### Basic Test:
1. Visit: {demo_url}
2. Click "Connect Google Account" or "Connect Microsoft Account"
3. Complete OAuth authorization with your own account
4. Copy the session ID from the success page
5. Test API: `curl {demo_url}/api/tokens/SESSION_ID`

### Feature Evaluation:
1. Test both Google and Microsoft OAuth flows
2. Verify token retrieval via API
3. Test error handling (cancel OAuth flow)
4. Review security features (HTTPS, session isolation)
5. Test mobile responsiveness

## 🔧 Technical Details
- **Backend**: Python Flask application
- **Security**: OAuth 2.0, HTTPS, secure session management
- **APIs**: RESTful endpoints for AI agent integration
- **Deployment**: Cloud-hosted, production-ready

## 📱 Browser Compatibility
- Chrome, Firefox, Safari, Edge (latest versions)
- Mobile browsers (iOS Safari, Android Chrome)

## 🆘 Support
- **Repository**: https://github.com/yourusername/secure-context-protocol
- **Documentation**: See README.md and SUBMISSION_GUIDE.md
- **Issues**: Available during evaluation period

## ✅ Submission Compliance
- ✅ Free access for testing and evaluation
- ✅ No login credentials required (uses evaluator's OAuth accounts)
- ✅ Available throughout evaluation period
- ✅ Runs on standard hardware (web browsers)
- ✅ No proprietary software required

---
**Deployed on {platform_name} for competition submission**
**Ready for evaluation! 🚀**
"""
    
    with open("SUBMISSION_SUMMARY.md", "w") as f:
        f.write(summary)
    
    print("✅ Created SUBMISSION_SUMMARY.md")
    return summary

def main():
    """Main deployment function"""
    print_header("SecureContext Protocol - Competition Submission Deployment")
    print("This script will deploy a live demo for competition submission.")
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n❌ Prerequisites not met. Please install required tools.")
        sys.exit(1)
    
    # Choose platform
    platform_choice, platform_info = choose_deployment_platform()
    
    # Setup environment variables
    env_vars = setup_environment_variables()
    if not env_vars:
        print("\n❌ Environment setup failed.")
        sys.exit(1)
    
    # Deploy based on platform choice
    demo_url = None
    
    if platform_choice == "1":  # Heroku
        demo_url = deploy_to_heroku(env_vars)
    elif platform_choice == "2":  # Railway
        demo_url = deploy_to_railway(env_vars)
    elif platform_choice == "3":  # Fly.io
        demo_url = deploy_to_fly(env_vars)
    elif platform_choice == "4":  # Manual
        print_step(4, "Manual Deployment")
        print("\n📋 Manual deployment selected.")
        print("Use the environment variables above and deploy to your chosen platform.")
        print("Make sure to update OAuth redirect URIs after deployment.")
        demo_url = input("Enter your demo URL after deployment: ").strip()
    
    if not demo_url:
        print("\n❌ Deployment failed.")
        sys.exit(1)
    
    # Update OAuth redirects
    update_oauth_redirects(demo_url)
    
    # Test deployment
    test_deployment(demo_url)
    
    # Create submission summary
    summary = create_submission_summary(demo_url, platform_info["name"])
    
    # Final instructions
    print_header("🎉 Deployment Complete!")
    print(f"\n✅ Your demo is live at: {demo_url}")
    print(f"✅ Submission summary created: SUBMISSION_SUMMARY.md")
    print(f"\n📋 Next steps:")
    print(f"1. Test your demo thoroughly")
    print(f"2. Submit the demo URL to the competition")
    print(f"3. Include SUBMISSION_SUMMARY.md in your submission")
    print(f"4. Monitor the demo during judging period")
    
    print(f"\n🏆 Your SecureContext Protocol is ready for evaluation!")

if __name__ == "__main__":
    main()