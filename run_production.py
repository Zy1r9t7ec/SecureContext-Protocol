
import sys
import os
from authentication_proxy.app import create_app
from authentication_proxy.config import ConfigurationError

def main():
    try:
        # Force production mode
        os.environ['FLASK_DEBUG'] = 'false'
        os.environ['DEBUG'] = 'false'
        
        # Create Flask application with WebSocket support
        app, socketio = create_app()
        
        # Force production settings
        app.config['DEBUG'] = False
        
        # Get configuration
        host = app.config.get('HOST', '127.0.0.1')
        port = app.config.get('PORT', 5000)
        
        print(f"🚀 Starting SCP in Production Mode...")
        print(f"📍 Server: http://{host}:{port}")
        print(f"🔧 Debug: OFF (forced)")
        print("-" * 40)
        
        # Run without reloader
        socketio.run(
            app,
            host=host,
            port=port,
            debug=False,
            use_reloader=False
        )
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
