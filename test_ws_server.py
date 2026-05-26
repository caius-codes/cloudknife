#!/usr/bin/env python3
"""
Quick test script to verify WebSocket server starts correctly.
"""

import asyncio
import sys
from src.webserver.ws_server import WebSocketServer


async def test_server():
    """Test that server starts and stops cleanly."""
    print("Testing WebSocket server startup...")

    server = WebSocketServer(host="localhost", port=8765)

    try:
        # Start server
        await server.start()
        print("✓ Server started successfully")

        # Wait a bit
        await asyncio.sleep(2)

        # Stop server
        await server.stop()
        print("✓ Server stopped successfully")

        return True

    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    success = asyncio.run(test_server())
    sys.exit(0 if success else 1)
