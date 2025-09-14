#!/usr/bin/env python3
"""
Startup script for the SecureContext Protocol Authentication Proxy.

This script initializes and runs the Flask application with proper error handling
and configuration validation.
"""

import sys
import os
from authentication_proxy.app import create_app
from authentication_proxy.config import ConfigurationError

def main():
    """Main entry point for the application."""
    try:
        # Create Flask application with WebSocket support
        app, socketio = create_app()
        
        # Get configuration
        host = app.config.get('HOST', '127.0.0.1')
        port = app.config.get('PORT', 5000)
        debug = app.config.get('DEBUG', False)
        
        print(f"🚀 Starting SecureContext Protocol Authentication Proxy with WebSocket support...")
        print(f"📍 Server will be available at: http://{host}:{port}")
        print(f"🔧 Debug mode: {'ON' if debug else 'OFF'}")
        print(f"📋 Environment: {'Development' if debug else 'Production'}")
        print(f"🌐 WebSocket support: ENABLED")
        print()
        print("📖 Setup Instructions:")
        print("1. Make sure you have set up OAuth credentials in your .env file")
        print("2. Visit the URL above in your browser to test OAuth flows")
        print("3. Use the /api/tokens/<session_id> endpoint to retrieve tokens")
        print("4. Connect to WebSocket for real-time streaming")
        print()
        print("🛑 Press Ctrl+C to stop the server")
        print("-" * 60)
        
        # Run the Flask application with SocketIO
        socketio.run(
            app,
            host=host,
            port=port,
            debug=debug,
            use_reloader=debug
        )
        
    except ConfigurationError as e:
        print(f"❌ Configuration Error: {e}", file=sys.stderr)
        print("\n💡 Quick Fix:")
        print("1. Copy .env.example to .env")
        print("2. Fill in your OAuth credentials")
        print("3. Run the application again")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n👋 Shutting down SecureContext Protocol Authentication Proxy...")
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()