"""
Base handler with shared utilities for all WebSocket handlers.
"""

import logging
from typing import Dict, Any, Optional, Callable
from rich.console import Console as RichConsole

from ..ws_messages import (
    WebSocketMessage,
    WebSocketResponse,
    create_success_response,
    create_error_response,
)

logger = logging.getLogger(__name__)


class BaseHandler:
    """Base class for WebSocket message handlers."""

    def __init__(self, broadcast_callback: Optional[Callable] = None):
        """
        Initialize base handler.

        Args:
            broadcast_callback: Function to broadcast messages to all connected clients
        """
        self.broadcast_callback = broadcast_callback
        self.graph_state: Dict[str, list] = {
            'nodes': [],
            'edges': [],
        }
        self.current_session = None
        self.current_session_id = None
        self.current_cloud = None
        self.session_managers: Dict[str, Any] = {}

    async def _broadcast_module_output(self, execution_id: str, line: str) -> None:
        """
        Broadcast module output line to all clients.

        Args:
            execution_id: Unique execution ID
            line: Output line to broadcast
        """
        if self.broadcast_callback:
            logger.info(f"[Module] Broadcasting output for {execution_id}: {line[:100]}")
            await self.broadcast_callback(
                create_success_response(
                    'module.output',
                    {'executionId': execution_id, 'line': line}
                )
            )
        else:
            logger.warning("[Module] No broadcast callback set, cannot send output")

    async def _broadcast_module_complete(
        self,
        execution_id: str,
        success: bool,
        error: Optional[str] = None
    ) -> None:
        """
        Broadcast module completion to all clients.

        Args:
            execution_id: Unique execution ID
            success: Whether module execution succeeded
            error: Optional error message
        """
        logger.info(f"[Module] Complete - execution_id={execution_id}, success={success}, error={error}")
        if self.broadcast_callback:
            await self.broadcast_callback(
                create_success_response(
                    'module.complete',
                    {
                        'executionId': execution_id,
                        'success': success,
                        'error': error
                    }
                )
            )

    async def _broadcast_module_error(self, execution_id: str, error: str) -> None:
        """
        Broadcast module error and complete.

        Args:
            execution_id: Unique execution ID
            error: Error message
        """
        await self._broadcast_module_output(execution_id, f"[red bold]ERROR: {error}[/red bold]")
        await self._broadcast_module_complete(execution_id, success=False, error=error)

    async def _add_or_update_node(self, node: Dict[str, Any]) -> None:
        """
        Add a node to graph state or update if exists.

        Args:
            node: Node data with 'id' field
        """
        node_id = node.get('id')
        if not node_id:
            logger.warning("[Graph] Cannot add node without ID")
            return

        # Find existing node
        existing_idx = next(
            (i for i, n in enumerate(self.graph_state['nodes']) if n['id'] == node_id),
            None
        )

        if existing_idx is not None:
            # Update existing node
            self.graph_state['nodes'][existing_idx] = node
            logger.debug(f"[Graph] Updated node: {node_id}")

            # Broadcast update
            if self.broadcast_callback:
                await self.broadcast_callback(
                    create_success_response('graph.node.update', {'node': node})
                )
        else:
            # Add new node
            self.graph_state['nodes'].append(node)
            logger.debug(f"[Graph] Added node: {node_id}")

            # Broadcast addition
            if self.broadcast_callback:
                await self.broadcast_callback(
                    create_success_response('graph.node.add', {'node': node})
                )

    async def _add_edge(self, edge: Dict[str, Any]) -> None:
        """
        Add an edge to graph state if it doesn't exist.

        Args:
            edge: Edge data with 'id', 'source', 'target'
        """
        edge_id = edge.get('id')
        if not edge_id:
            logger.warning("[Graph] Cannot add edge without ID")
            return

        # Check if edge already exists
        exists = any(e['id'] == edge_id for e in self.graph_state['edges'])
        if exists:
            logger.debug(f"[Graph] Edge already exists: {edge_id}")
            return

        # Add edge
        self.graph_state['edges'].append(edge)
        logger.debug(f"[Graph] Added edge: {edge_id}")

        # Broadcast addition
        if self.broadcast_callback:
            await self.broadcast_callback(
                create_success_response('graph.edge.add', {'edge': edge})
            )

    def _find_node_by_id(self, node_id: str) -> Optional[Dict[str, Any]]:
        """
        Find a node in graph state by ID.

        Args:
            node_id: Node ID to search for

        Returns:
            Node dict if found, None otherwise
        """
        return next(
            (node for node in self.graph_state['nodes'] if node['id'] == node_id),
            None
        )

    def _find_nodes_by_type(self, node_type: str) -> list:
        """
        Find all nodes of a specific type.

        Args:
            node_type: Node type to filter by

        Returns:
            List of matching nodes
        """
        return [node for node in self.graph_state['nodes'] if node.get('type') == node_type]

    def _remove_nodes_by_session(self, session_id: str) -> int:
        """
        Remove all nodes discovered by a specific session.

        Args:
            session_id: Session ID to filter by

        Returns:
            Number of nodes removed
        """
        initial_count = len(self.graph_state['nodes'])
        self.graph_state['nodes'] = [
            node for node in self.graph_state['nodes']
            if session_id not in node.get('discoveredBy', [])
        ]
        removed = initial_count - len(self.graph_state['nodes'])
        logger.info(f"[Graph] Removed {removed} nodes for session {session_id}")
        return removed

    def _remove_edges_by_session(self, session_id: str) -> int:
        """
        Remove all edges discovered by a specific session.

        Args:
            session_id: Session ID to filter by

        Returns:
            Number of edges removed
        """
        initial_count = len(self.graph_state['edges'])
        self.graph_state['edges'] = [
            edge for edge in self.graph_state['edges']
            if session_id not in edge.get('discoveredBy', [])
        ]
        removed = initial_count - len(self.graph_state['edges'])
        logger.info(f"[Graph] Removed {removed} edges for session {session_id}")
        return removed
