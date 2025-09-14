#!/usr/bin/env python3
"""
Simple Flask app for performance testing without SocketIO dependencies
"""

import os
import sys
from flask import Flask, jsonify, render_template_string

# Add the authentication_proxy directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'authentication_proxy'))

def create_simple_app():
    """Create a simplified Flask app for performance testing"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'test_secret_key')
    
    # Simple HTML template
    index_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureContext Protocol - Performance Test</title>
    </head>
    <body>
        <h1>SecureContext Protocol</h1>
        <p>Performance testing mode - simplified app</p>
        <div>
            <button>Connect Google Account</button>
            <button>Connect Microsoft Account</button>
        </div>
    </body>
    </html>
    """
    
    @app.route('/')
    def index():
        return render_template_string(index_template)
    
    @app.route('/api/providers')
    def get_providers():
        return jsonify({
            "success": True,
            "providers": [
                {
                    "name": "google",
                    "display_name": "Google Account",
                    "available": True
                },
                {
                    "name": "microsoft", 
                    "display_name": "Microsoft Account",
                    "available": True
                }
            ]
        })
    
    @app.route('/api/tokens/<session_id>')
    def get_tokens(session_id):
        # Mock token response for testing
        return jsonify({
            "success": True,
            "data": {
                "access_token": f"mock_access_token_{session_id}",
                "refresh_token": f"mock_refresh_token_{session_id}",
                "expires_at": "2024-12-31T23:59:59Z",
                "scope": "profile email",
                "provider": "google"
            }
        })
    
    @app.route('/api/agent/sessions')
    def get_agent_sessions():
        return jsonify({
            "success": True,
            "sessions": []
        })
    
    @app.route('/health')
    def health_check():
        return jsonify({"status": "healthy", "mode": "performance_test"})
    
    return app

if __name__ == '__main__':
    app = create_simple_app()
    port = int(os.getenv('FLASK_PORT', 5000))
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    
    print(f"Starting simple performance test app on {host}:{port}")
    app.run(host=host, port=port, debug=debug)