"""
Graph synchronization handler for WebSocket operations.
"""

import logging
from typing import Dict, Any

from .base_handler import BaseHandler
from ..ws_messages import (
    WebSocketMessage,
    WebSocketResponse,
    create_success_response,
    create_error_response,
)

logger = logging.getLogger(__name__)


class GraphHandler(BaseHandler):
    """Handler for graph synchronization operations."""

    async def handle_graph_sync(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Return all graph nodes and edges to sync client state.

        This method retrieves the current graph state (nodes and edges) and returns
        it to the client for synchronization purposes. Used when clients connect or
        need to refresh their local graph state.

        Args:
            message: WebSocket message containing the sync request

        Returns:
            WebSocketResponse with graph nodes and edges, or error response

        Raises:
            No exceptions raised directly; all errors caught and returned as error responses
        """
        try:
            logger.info(
                f"[GraphSync] Syncing graph state - {len(self.graph_state['nodes'])} nodes, "
                f"{len(self.graph_state['edges'])} edges"
            )

            return create_success_response(
                message.type,
                {
                    'nodes': self.graph_state['nodes'],
                    'edges': self.graph_state['edges'],
                },
                message.request_id
            )

        except Exception as e:
            logger.error(f"Error syncing graph: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)
