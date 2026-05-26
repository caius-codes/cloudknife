"""
CloudKnife WebSocket Server

Provides real-time bidirectional communication between CLI and Web Interface.
"""

import asyncio
import logging
from typing import Set
import websockets
from websockets.server import WebSocketServerProtocol

from .ws_messages import WebSocketMessage, WebSocketResponse
from .ws_handlers import WebSocketCommandHandler
from .session_watcher import SessionDirectoryWatcher

logger = logging.getLogger(__name__)


class WebSocketServer:
    """WebSocket server for CloudKnife CLI <-> Web communication."""

    def __init__(self, host: str = "localhost", port: int = 8765):
        """
        Initialize WebSocket server.

        Args:
            host: Host to bind to
            port: Port to bind to
        """
        self.host = host
        self.port = port
        self.clients: Set[WebSocketServerProtocol] = set()
        self.handler = WebSocketCommandHandler(broadcast_callback=self.broadcast)
        self.server = None
        self.session_watcher = None

    async def register(self, websocket: WebSocketServerProtocol):
        """Register a new client connection."""
        self.clients.add(websocket)
        logger.info(f"Client connected. Total clients: {len(self.clients)}")

        # Send existing graph state to newly connected client
        try:
            from .ws_messages import create_success_response

            # Send all nodes
            for node in self.handler.graph_state.get('nodes', []):
                message = create_success_response('graph.node.add', {'node': node})
                await websocket.send(message.to_json())

            # Send all edges
            for edge in self.handler.graph_state.get('edges', []):
                message = create_success_response('graph.edge.add', {'edge': edge})
                await websocket.send(message.to_json())

            logger.info(f"Sent {len(self.handler.graph_state.get('nodes', []))} nodes and {len(self.handler.graph_state.get('edges', []))} edges to new client")

        except Exception as e:
            logger.error(f"Error sending initial graph state to client: {e}", exc_info=True)

    async def unregister(self, websocket: WebSocketServerProtocol):
        """Unregister a client connection."""
        self.clients.discard(websocket)
        logger.info(f"Client disconnected. Total clients: {len(self.clients)}")

    async def broadcast(self, message: WebSocketResponse):
        """
        Broadcast a message to all connected clients.

        Args:
            message: Message to broadcast
        """
        if not self.clients:
            return

        message_json = message.to_json()
        await asyncio.gather(
            *[client.send(message_json) for client in self.clients],
            return_exceptions=True
        )

    async def handle_client(self, websocket: WebSocketServerProtocol):
        """
        Handle a client connection.

        Args:
            websocket: WebSocket connection
        """
        await self.register(websocket)

        try:
            async for message_data in websocket:
                try:
                    # Parse incoming message
                    message = WebSocketMessage.from_json(message_data)
                    logger.info(f"Received message: {message.type}")

                    # Handle message
                    response = await self.handler.handle_message(message)

                    # Send response back to client
                    await websocket.send(response.to_json())

                except Exception as e:
                    logger.error(f"Error processing message: {e}", exc_info=True)
                    error_response = WebSocketResponse(
                        type="error",
                        success=False,
                        error=str(e)
                    )
                    await websocket.send(error_response.to_json())

        except websockets.exceptions.ConnectionClosed:
            logger.info("Client connection closed")
        finally:
            await self.unregister(websocket)

    async def start(self):
        """Start the WebSocket server."""
        logger.info(f"Starting WebSocket server on {self.host}:{self.port}")

        # Import existing CLI sessions before starting the server
        logger.info("Importing existing CLI sessions...")
        await self.handler.import_cli_sessions_on_startup()

        # Start session file watcher
        logger.info("Starting session file watcher...")
        loop = asyncio.get_event_loop()
        self.session_watcher = SessionDirectoryWatcher(
            broadcast_callback=self.broadcast,
            graph_state=self.handler.graph_state,
            loop=loop,
            on_session_created_callback=self.handler.on_cli_session_created
        )
        self.session_watcher.start()
        logger.info("✓ Session file watcher started")

        self.server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port
        )

        logger.info(f"✓ WebSocket server running on ws://{self.host}:{self.port}")
        logger.info("  Web interface can now connect to this server")
        logger.info("  Press Ctrl+C to stop")

    async def stop(self):
        """Stop the WebSocket server."""
        # Stop session watcher
        if self.session_watcher:
            logger.info("Stopping session file watcher...")
            self.session_watcher.stop()
            logger.info("✓ Session file watcher stopped")

        if self.server:
            logger.info("Stopping WebSocket server...")
            self.server.close()
            await self.server.wait_closed()
            logger.info("✓ WebSocket server stopped")

    async def run_forever(self):
        """Run the server until interrupted."""
        await self.start()

        # Keep running until interrupted
        try:
            await asyncio.Future()  # Run forever
        except KeyboardInterrupt:
            logger.info("\nReceived interrupt signal")
        finally:
            await self.stop()


async def run_server(host: str = "localhost", port: int = 8765):
    """
    Run the WebSocket server.

    Args:
        host: Host to bind to
        port: Port to bind to
    """
    server = WebSocketServer(host, port)
    await server.run_forever()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Run server
    asyncio.run(run_server())
