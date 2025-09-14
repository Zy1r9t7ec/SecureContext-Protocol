#!/usr/bin/env python3
"""
OAuth Setup Helper for SecureContext Protocol.

This script provides step-by-step guidance for setting up OAuth applications
with Google and Microsoft.
"""

import secrets
import webbrowser
from urllib.parse import quote

def generate_flask_secret():
    """Generate a secure Flask secret key."""
    return secrets.token_hex(32)

def print_google_setup():
    """Print Google OAuth setup instructions."""
    print("🔵 GOOGLE OAUTH SETUP")
    print("=" * 50)
    print("1. Go to Google Cloud Console:")
    print("   https://console.cloud.google.com/")
    print()
    print("2. Create a new project or select existing one")
    print()
    print("3. Enable APIs:")
    print("   - Go to 'APIs & Services' → 'Library'")
    print("   - Search and enable: 'Google+ API'")
    print("   - Search and enable: 'Gmail API'")
    print("   - Search and enable: 'Google Calendar API'")
    print()
    print("4. Create OAuth 2.0 Credentials:")
    print("   - Go to 'APIs & Services' → 'Credentials'")
    print("   - Click 'Create Credentials' → 'OAuth 2.0 Client IDs'")
    print("   - Choose 'Web application'")
    print("   - Name: 'SecureContext Protocol'")
    print()
    print("5. Add Authorized Redirect URIs:")
    print("   - http://localhost:5000/oauth/google/callback")
    print("   - http://127.0.0.1:5000/oauth/google/callback")
    print("   - (Add your production domain later)")
    print()
    print("6. Copy the Client ID and Client Secret")
    print()

def print_microsoft_setup():
    """Print Microsoft OAuth setup instructions."""
    print("🔷 MICROSOFT OAUTH SETUP")
    print("=" * 50)
    print("1. Go to Azure Portal:")
    print("   https://portal.azure.com/")
    print()
    print("2. Navigate to Azure Active Directory:")
    print("   - Search for 'Azure Active Directory'")
    print("   - Go to 'App registrations'")
    print()
    print("3. Create new registration:")
    print("   - Click 'New registration'")
    print("   - Name: 'SecureContext Protocol'")
    print("   - Supported account types: 'Accounts in any organizational directory and personal Microsoft accounts'")
    print("   - Redirect URI: 'Web' → 'http://localhost:5000/oauth/microsoft/callback'")
    print()
    print("4. Note the Application (client) ID")
    print()
    print("5. Create client secret:")
    print("   - Go to 'Certificates & secrets'")
    print("   - Click 'New client secret'")
    print("   - Description: 'SCP Secret'")
    print("   - Expires: '24 months' (recommended)")
    print("   - Copy the secret VALUE (not the ID)")
    print()
    print("6. Configure API permissions (optional for basic setup):")
    print("   - Go to 'API permissions'")
    print("   - Add permissions for Microsoft Graph:")
    print("     - User.Read (usually already added)")
    print("     - Mail.Read")
    print("     - Calendars.Read")
    print()

def create_env_file():
    """Create .env file with user input."""
    print("📝 CREATING .ENV FILE")
    print("=" * 50)
    
    # Check if .env already exists
    try:
        with open('.env', 'r') as f:
            print("⚠️  .env file already exists!")
            response = input("Do you want to overwrite it? (y/N): ").strip().lower()
            if response != 'y':
                print("Keeping existing .env file.")
                return
    except FileNotFoundError:
        pass
    
    print("Please enter your OAuth credentials:")
    print("(Press Enter to skip any field)")
    print()
    
    # Collect credentials
    google_client_id = input("Google Client ID: ").strip()
    google_client_secret = input("Google Client Secret: ").strip()
    microsoft_client_id = input("Microsoft Client ID: ").strip()
    microsoft_client_secret = input("Microsoft Client Secret: ").strip()
    
    # Generate Flask secret key
    flask_secret = generate_flask_secret()
    print(f"Generated Flask Secret Key: {flask_secret}")
    
    # Create .env content
    env_content = f"""# Google OAuth 2.0 Configuration
GOOGLE_CLIENT_ID={google_client_id}
GOOGLE_CLIENT_SECRET={google_client_secret}

# Microsoft OAuth 2.0 Configuration
MICROSOFT_CLIENT_ID={microsoft_client_id}
MICROSOFT_CLIENT_SECRET={microsoft_client_secret}

# Flask Configuration
FLASK_SECRET_KEY={flask_secret}

# Optional Flask Configuration
FLASK_DEBUG=true
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
"""
    
    # Write .env file
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("✅ .env file created successfully!")
    print()
    print("🔒 Security Note:")
    print("- Never commit your .env file to version control")
    print("- Keep your OAuth credentials secure")
    print("- Regenerate secrets if compromised")
    print()

def test_setup():
    """Test the setup by running the test script."""
    print("🧪 TESTING SETUP")
    print("=" * 50)
    
    try:
        import subprocess
        result = subprocess.run([sys.executable, 'test_setup.py'], 
                              capture_output=True, text=True)
        
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False

def print_quick_start():
    """Print quick start instructions."""
    print("🚀 QUICK START")
    print("=" * 50)
    print("1. Run the application:")
    print("   python run.py")
    print()
    print("2. Open your browser:")
    print("   http://localhost:5000")
    print()
    print("3. Test OAuth flows:")
    print("   - Click 'Connect Google Account'")
    print("   - Click 'Connect Microsoft Account'")
    print()
    print("4. Test token retrieval:")
    print("   python verify_tokens.py <session_id>")
    print()

def main():
    """Main setup wizard."""
    print("🔧 SecureContext Protocol OAuth Setup Wizard")
    print("=" * 60)
    print()
    
    while True:
        print("What would you like to do?")
        print("1. View Google OAuth setup instructions")
        print("2. View Microsoft OAuth setup instructions")
        print("3. Create/update .env file")
        print("4. Test current setup")
        print("5. View quick start guide")
        print("6. Open OAuth consoles in browser")
        print("7. Exit")
        print()
        
        choice = input("Enter your choice (1-7): ").strip()
        
        if choice == '1':
            print_google_setup()
            input("\nPress Enter to continue...")
            
        elif choice == '2':
            print_microsoft_setup()
            input("\nPress Enter to continue...")
            
        elif choice == '3':
            create_env_file()
            input("\nPress Enter to continue...")
            
        elif choice == '4':
            if test_setup():
                print("🎉 Setup test passed!")
            else:
                print("⚠️  Setup test failed. Please fix the issues above.")
            input("\nPress Enter to continue...")
            
        elif choice == '5':
            print_quick_start()
            input("\nPress Enter to continue...")
            
        elif choice == '6':
            print("Opening OAuth consoles in your browser...")
            webbrowser.open('https://console.cloud.google.com/')
            webbrowser.open('https://portal.azure.com/')
            input("\nPress Enter to continue...")
            
        elif choice == '7':
            print("👋 Happy coding with SecureContext Protocol!")
            break
            
        else:
            print("❌ Invalid choice. Please try again.")
        
        print("\n" + "=" * 60 + "\n")

if __name__ == '__main__':
    import sys
    main()