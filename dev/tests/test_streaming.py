#!/usr/bin/env python3
"""
Test script for real-time data streaming functionality.

This script tests the WebSocket endpoints and streaming APIs
to verify that the real-time features are working correctly.
"""

import asyncio
import json
import time
import requests
import socketio
from typing import Dict, Any, Optional


class StreamingTester:
    """Test class for streaming functionality."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.session_id = None
        self.stream_id = None
        self.sio = socketio.AsyncClient()
        self.events_received = []
        
        # Set up event handlers
        self.sio.on('connect', self.on_connect)
        self.sio.on('disconnect', self.on_disconnect)
        self.sio.on('stream_event', self.on_stream_event)
        self.sio.on('error', self.on_error)
    
    async def on_connect(self):
        """Handle WebSocket connection."""
        print("✅ WebSocket connected")
    
    async def on_disconnect(self):
        """Handle WebSocket disconnection."""
        print("❌ WebSocket disconnected")
    
    async def on_stream_event(self, data):
        """Handle stream events."""
        print(f"📡 Stream event received: {data['event_type']}")
        self.events_received.append(data)
    
    async def on_error(self, error):
        """Handle WebSocket errors."""
        print(f"❌ WebSocket error: {error}")
    
    def test_api_endpoints(self):
        """Test basic API endpoints."""
        print("\n🧪 Testing API endpoints...")
        
        # Test providers endpoint
        try:
            response = requests.get(f"{self.base_url}/api/providers")
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    providers = data.get('data', {}).get('providers', [])
                    print(f"✅ Providers endpoint: {len(providers)} providers available")
                else:
                    print(f"❌ Providers endpoint error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Providers endpoint failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Providers endpoint error: {e}")
        
        # Test streams endpoint
        try:
            response = requests.get(f"{self.base_url}/api/streams")
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    streams = data.get('data', {}).get('streams', {})
                    print(f"✅ Streams endpoint: {len(streams)} active streams")
                else:
                    print(f"❌ Streams endpoint error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Streams endpoint failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Streams endpoint error: {e}")
    
    def create_mock_session(self) -> Optional[str]:
        """Create a mock session for testing (requires manual OAuth)."""
        print("\n🔑 Mock session creation...")
        print("Note: For full testing, you need to complete OAuth flow manually")
        print("Visit the web UI and complete OAuth, then use the session ID here")
        
        # For testing purposes, we'll simulate having a session
        # In real testing, you'd get this from completing OAuth
        mock_session_id = input("Enter session ID from OAuth flow (or press Enter to skip): ").strip()
        
        if mock_session_id:
            self.session_id = mock_session_id
            print(f"✅ Using session ID: {mock_session_id}")
            return mock_session_id
        else:
            print("⏭️  Skipping session-dependent tests")
            return None
    
    async def test_websocket_connection(self):
        """Test WebSocket connection."""
        if not self.session_id:
            print("⏭️  Skipping WebSocket test (no session ID)")
            return
        
        print("\n🔌 Testing WebSocket connection...")
        
        try:
            # Connect with session ID
            await self.sio.connect(
                self.base_url,
                socketio_path='/socket.io/',
                wait_timeout=10,
                query={'session_id': self.session_id}
            )
            
            # Wait a bit for connection to stabilize
            await asyncio.sleep(2)
            
            if self.sio.connected:
                print("✅ WebSocket connection successful")
                
                # Test subscription
                await self.sio.emit('subscribe_data', {
                    'session_id': self.session_id,
                    'data_types': ['gmail_messages', 'calendar_events']
                })
                
                # Wait for subscription confirmation
                await asyncio.sleep(1)
                print("✅ Data subscription sent")
                
            else:
                print("❌ WebSocket connection failed")
                
        except Exception as e:
            print(f"❌ WebSocket connection error: {e}")
    
    def test_stream_api(self):
        """Test streaming API endpoints."""
        if not self.session_id:
            print("⏭️  Skipping stream API test (no session ID)")
            return
        
        print("\n🌊 Testing streaming API...")
        
        # Test starting a stream
        try:
            stream_data = {
                'session_id': self.session_id,
                'stream_type': 'gmail_messages',
                'batch_size': 10,
                'max_results': 50,
                'real_time': True
            }
            
            response = requests.post(
                f"{self.base_url}/api/stream/start",
                json=stream_data,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.stream_id = data.get('data', {}).get('stream_id')
                    print(f"✅ Stream started: {self.stream_id}")
                else:
                    print(f"❌ Stream start error: {data.get('error', {}).get('message')}")
            else:
                print(f"❌ Stream start failed: HTTP {response.status_code}")
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Stream start error: {e}")
        
        # Test stream status
        if self.stream_id:
            try:
                time.sleep(2)  # Wait a bit for stream to start
                
                response = requests.get(f"{self.base_url}/api/stream/{self.stream_id}/status")
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        status = data.get('data', {}).get('status')
                        items = data.get('data', {}).get('items_streamed', 0)
                        print(f"✅ Stream status: {status}, items streamed: {items}")
                    else:
                        print(f"❌ Stream status error: {data.get('error', {}).get('message')}")
                else:
                    print(f"❌ Stream status failed: HTTP {response.status_code}")
            except Exception as e:
                print(f"❌ Stream status error: {e}")
    
    async def test_real_time_events(self):
        """Test real-time event reception."""
        if not self.sio.connected:
            print("⏭️  Skipping real-time events test (not connected)")
            return
        
        print("\n⏱️  Testing real-time events...")
        print("Waiting for stream events (10 seconds)...")
        
        initial_count = len(self.events_received)
        await asyncio.sleep(10)
        
        new_events = len(self.events_received) - initial_count
        if new_events > 0:
            print(f"✅ Received {new_events} real-time events")
            for event in self.events_received[-new_events:]:
                print(f"   - {event.get('event_type')}: {event.get('data', {}).get('data_type', 'unknown')}")
        else:
            print("ℹ️  No real-time events received (this is normal if no data is being streamed)")
    
    def cleanup_stream(self):
        """Clean up test stream."""
        if self.stream_id:
            try:
                response = requests.post(f"{self.base_url}/api/stream/{self.stream_id}/stop")
                if response.status_code == 200:
                    print(f"✅ Stream {self.stream_id} stopped")
                else:
                    print(f"❌ Failed to stop stream: HTTP {response.status_code}")
            except Exception as e:
                print(f"❌ Stream cleanup error: {e}")
    
    async def disconnect_websocket(self):
        """Disconnect WebSocket."""
        if self.sio.connected:
            await self.sio.disconnect()
            print("✅ WebSocket disconnected")
    
    async def run_tests(self):
        """Run all tests."""
        print("🚀 Starting SecureContext Protocol Streaming Tests")
        print("=" * 60)
        
        # Test basic API endpoints
        self.test_api_endpoints()
        
        # Create or get session ID
        session_id = self.create_mock_session()
        
        if session_id:
            # Test WebSocket connection
            await self.test_websocket_connection()
            
            # Test streaming API
            self.test_stream_api()
            
            # Test real-time events
            await self.test_real_time_events()
            
            # Cleanup
            self.cleanup_stream()
            await self.disconnect_websocket()
        
        print("\n" + "=" * 60)
        print("🏁 Tests completed")
        
        # Summary
        print(f"\n📊 Summary:")
        print(f"   - Events received: {len(self.events_received)}")
        print(f"   - Session ID used: {self.session_id or 'None'}")
        print(f"   - Stream ID created: {self.stream_id or 'None'}")


async def main():
    """Main test function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test SecureContext Protocol streaming functionality')
    parser.add_argument('--url', default='http://localhost:5000', help='Base URL of the SCP server')
    args = parser.parse_args()
    
    tester = StreamingTester(args.url)
    await tester.run_tests()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test error: {e}")