"""
Session management handlers for CloudKnife WebSocket operations.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from .base_handler import BaseHandler
from ..ws_messages import (
    WebSocketMessage,
    WebSocketResponse,
    create_success_response,
    create_error_response,
)

logger = logging.getLogger(__name__)


class SessionHandler(BaseHandler):
    """Handles session-related WebSocket commands."""

    async def handle_session_create(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Create a new session for a specific cloud provider.

        Args:
            message: WebSocket message containing:
                - cloud: Cloud provider ('aws', 'gcp', or 'azure')
                - session_name: Name for the new session

        Returns:
            WebSocketResponse with session data or error
        """
        try:
            payload = message.payload
            cloud = payload.get('cloud')
            session_name = payload.get('session_name')

            if not cloud or not session_name:
                return create_error_response(
                    message.type,
                    "Missing required fields: cloud, session_name",
                    message.request_id
                )

            # Import session manager for specific cloud
            sessions_base = Path.home() / '.cloudknife' / 'sessions'

            if cloud == 'aws':
                from src.clouds.aws.aws_session import AWSSessionManager
                manager = AWSSessionManager(str(sessions_base / 'aws'))
            elif cloud == 'gcp':
                from src.clouds.gcp.gcp_session import GCPSessionManager
                manager = GCPSessionManager(str(sessions_base / 'gcp'))
            elif cloud == 'azure':
                from src.clouds.azure.azure_session import AzureSessionManager
                manager = AzureSessionManager(str(sessions_base / 'azure'))
            else:
                return create_error_response(
                    message.type,
                    f"Unsupported cloud provider: {cloud}",
                    message.request_id
                )

            # Create or load session
            manager.create_or_load_session(session_name)

            # Store current session
            self.current_session = session_name
            self.current_session_id = manager.session_id
            self.current_cloud = cloud
            self.session_managers[cloud] = manager

            # Get session data
            session_data = {
                'id': manager.session_id,
                'name': session_name,
                'cloud': cloud,
                'created_at': datetime.now().isoformat(),
                'session_id': manager.session_id,
            }

            return create_success_response(
                message.type,
                {'session': session_data},
                message.request_id
            )

        except Exception as e:
            logger.error(f"Error creating session: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)

    async def handle_session_list(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        List all sessions for a specific cloud provider.

        Args:
            message: WebSocket message containing:
                - cloud: Cloud provider to list sessions for

        Returns:
            WebSocketResponse with list of sessions or error
        """
        try:
            payload = message.payload
            cloud = payload.get('cloud')

            if not cloud:
                return create_error_response(
                    message.type,
                    "Missing required field: cloud",
                    message.request_id
                )

            # Get session directory
            session_dir = Path.home() / '.cloudknife' / 'sessions' / cloud

            if not session_dir.exists():
                return create_success_response(
                    message.type,
                    {'sessions': []},
                    message.request_id
                )

            # List all session files
            sessions = []
            for session_file in session_dir.glob('*.json'):
                # Skip enumeration files and service account key files
                if session_file.stem.endswith('_enum') or session_file.stem.endswith('_key'):
                    continue

                try:
                    with open(session_file, 'r') as f:
                        session_data = json.load(f)
                        sessions.append({
                            'id': session_file.stem,
                            'name': session_file.stem,
                            'cloud': cloud,
                            'created_at': session_data.get('created_at'),
                            'is_active': session_file.stem == self.current_session,
                        })
                except Exception as e:
                    logger.warning(f"Error reading session {session_file}: {e}")

            return create_success_response(
                message.type,
                {'sessions': sessions},
                message.request_id
            )

        except Exception as e:
            logger.error(f"Error listing sessions: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)

    async def handle_session_switch(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Switch to a different session.

        Args:
            message: WebSocket message containing:
                - session_name: Name of session to switch to
                - cloud: Cloud provider of the session
                - session_id: Optional UUID for discoveredBy tracking

        Returns:
            WebSocketResponse with session data or error
        """
        try:
            payload = message.payload
            session_name = payload.get('session_name')
            cloud = payload.get('cloud')
            session_id = payload.get('session_id')

            if not session_name or not cloud:
                return create_error_response(
                    message.type,
                    "Missing required fields: session_name, cloud",
                    message.request_id
                )

            # Import session manager
            sessions_base = Path.home() / '.cloudknife' / 'sessions'

            if cloud == 'aws':
                from src.clouds.aws.aws_session import AWSSessionManager
                manager = AWSSessionManager(str(sessions_base / 'aws'))
            elif cloud == 'gcp':
                from src.clouds.gcp.gcp_session import GCPSessionManager
                manager = GCPSessionManager(str(sessions_base / 'gcp'))
            elif cloud == 'azure':
                from src.clouds.azure.azure_session import AzureSessionManager
                manager = AzureSessionManager(str(sessions_base / 'azure'))
            else:
                return create_error_response(
                    message.type,
                    f"Unsupported cloud provider: {cloud}",
                    message.request_id
                )

            # Check if session exists
            session_file = manager.sessions_dir / f"{session_name}.json"
            if not session_file.exists():
                return create_error_response(
                    message.type,
                    f"Session '{session_name}' not found",
                    message.request_id
                )

            # Load session
            manager.create_or_load_session(session_name)

            # Update current session
            self.current_session = session_name
            self.current_session_id = manager.session_id
            self.current_cloud = cloud
            self.session_managers[cloud] = manager

            logger.info(f"[Session] Switched to session: {session_name} (ID: {self.current_session_id})")

            return create_success_response(
                message.type,
                {
                    'session': {
                        'id': session_name,
                        'name': session_name,
                        'cloud': cloud,
                    }
                },
                message.request_id
            )

        except Exception as e:
            logger.error(f"Error switching session: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)

    async def handle_session_delete(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Delete a session from both web and CLI storage.

        This method:
        1. Deletes CLI session files (session.json and enumeration file)
        2. Clears session from memory and session managers
        3. Removes all associated nodes and edges from graph state
        4. Broadcasts deletion to all connected clients

        Args:
            message: WebSocket message containing:
                - session_name: Name of session to delete
                - cloud: Cloud provider of the session

        Returns:
            WebSocketResponse with deletion summary or error
        """
        try:
            payload = message.payload
            session_name = payload.get('session_name')
            cloud = payload.get('cloud')

            if not session_name or not cloud:
                return create_error_response(
                    message.type,
                    "Missing required fields: session_name, cloud",
                    message.request_id
                )

            logger.info(f"[SessionDelete] Deleting session: {session_name} (cloud: {cloud})")

            # 1. Delete CLI files (so it's deleted from CLI too)
            session_file = Path.home() / '.cloudknife' / 'sessions' / cloud / f'{session_name}.json'
            enum_file = Path.home() / '.cloudknife' / 'sessions' / cloud / f'{session_name}_enum.json'
            key_file = Path.home() / '.cloudknife' / 'sessions' / cloud / f'{session_name}_key.json'

            if session_file.exists():
                session_file.unlink()
                logger.info(f"[SessionDelete] Deleted session file: {session_file}")
            if enum_file.exists():
                enum_file.unlink()
                logger.info(f"[SessionDelete] Deleted enumeration file: {enum_file}")
            if key_file.exists():
                key_file.unlink()
                logger.info(f"[SessionDelete] Deleted service account key file: {key_file}")

            # 2. Get session manager and delete from memory
            manager = self.session_managers.get(cloud)
            if manager:
                # Clear enumerated data for this session (even if it's current/last session)
                if session_name in manager.enumerated_data:
                    del manager.enumerated_data[session_name]
                    logger.info(f"[SessionDelete] Cleared enumerated_data for session: {session_name}")

                # If this is the current session, clear it from manager
                if manager.current_session == session_name:
                    manager.current_session = None
                    manager.current_session_data = {}
                    logger.info(f"[SessionDelete] Cleared current_session from SessionManager")

            # 3. Clear current session if deleted
            if self.current_session == session_name:
                self.current_session = None
                self.current_session_id = None
                self.current_cloud = None

            # 4. Remove nodes and edges from graph state
            # Find the session node by name to get its UUID
            session_node = next(
                (n for n in self.graph_state['nodes']
                 if n.get('type') == f'{cloud}-session' and
                 n.get('data', {}).get('sessionName') == session_name),
                None
            )

            if not session_node:
                logger.warning(f"[SessionDelete] Session node not found in graph state: {session_name}")
                # Continue anyway to delete from filesystem
                session_node_id = None
            else:
                session_node_id = session_node['id']

            # Get all nodes discovered by this session (if found in graph)
            if session_node_id:
                nodes_to_remove = [n for n in self.graph_state['nodes'] if session_node_id in n.get('discoveredBy', [])]
                edges_to_remove = [e for e in self.graph_state['edges'] if session_node_id in e.get('discoveredBy', [])]

                # Remove session node itself
                nodes_to_remove.extend([n for n in self.graph_state['nodes'] if n['id'] == session_node_id])
            else:
                nodes_to_remove = []
                edges_to_remove = []

            # Update graph state
            self.graph_state['nodes'] = [n for n in self.graph_state['nodes'] if n not in nodes_to_remove]
            self.graph_state['edges'] = [e for e in self.graph_state['edges'] if e not in edges_to_remove]

            logger.info(f"[SessionDelete] Removed {len(nodes_to_remove)} nodes and {len(edges_to_remove)} edges from graph")

            # 5. Broadcast deletion to all clients
            if self.broadcast_callback:
                # Broadcast session deletion
                await self.broadcast_callback(
                    create_success_response(
                        'session.deleted',
                        {'session_name': session_name, 'cloud': cloud}
                    )
                )

                # Broadcast node removals
                for node in nodes_to_remove:
                    await self.broadcast_callback(
                        create_success_response(
                            'graph.node.remove',
                            {'node_id': node['id']}
                        )
                    )

                # Broadcast edge removals
                for edge in edges_to_remove:
                    await self.broadcast_callback(
                        create_success_response(
                            'graph.edge.remove',
                            {'edge_id': edge['id']}
                        )
                    )

            return create_success_response(
                message.type,
                {
                    'deleted': session_name,
                    'nodes_removed': len(nodes_to_remove),
                    'edges_removed': len(edges_to_remove),
                },
                message.request_id
            )

        except Exception as e:
            logger.error(f"Error deleting session: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)

    async def handle_session_clear_all(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Clear all sessions from all cloud providers and reset graph state.

        This method:
        1. Calls delete_all_sessions() on each session manager
        2. Clears WebSocket handler state (current session)
        3. Resets graph state to empty
        4. Broadcasts graph clear to all clients

        Args:
            message: WebSocket message (no payload required)

        Returns:
            WebSocketResponse with summary of deleted sessions and cleared graph data
        """
        try:
            logger.info("[SessionClearAll] Clearing all sessions from all cloud providers")

            total_deleted = 0
            clouds_cleared = []

            # Clear sessions for each cloud provider
            for cloud, manager in self.session_managers.items():
                try:
                    deleted_count = manager.delete_all_sessions()
                    total_deleted += deleted_count
                    clouds_cleared.append(cloud)
                    logger.info(f"[SessionClearAll] Cleared {deleted_count} sessions from {cloud}")
                except Exception as e:
                    logger.error(f"[SessionClearAll] Error clearing {cloud} sessions: {e}", exc_info=True)

            # Clear WebSocket handler state
            self.current_session = None
            self.current_session_id = None
            self.current_cloud = None

            # Clear graph state
            nodes_count = len(self.graph_state['nodes'])
            edges_count = len(self.graph_state['edges'])
            self.graph_state = {
                'nodes': [],
                'edges': [],
            }

            logger.info(f"[SessionClearAll] Cleared graph state: {nodes_count} nodes, {edges_count} edges")

            # Broadcast graph clear to all clients
            if self.broadcast_callback:
                await self.broadcast_callback(
                    create_success_response(
                        'graph.clear',
                        {
                            'total_sessions_deleted': total_deleted,
                            'clouds_cleared': clouds_cleared,
                            'nodes_removed': nodes_count,
                            'edges_removed': edges_count,
                        }
                    )
                )

            return create_success_response(
                message.type,
                {
                    'total_deleted': total_deleted,
                    'clouds_cleared': clouds_cleared,
                    'nodes_removed': nodes_count,
                    'edges_removed': edges_count,
                },
                message.request_id
            )

        except Exception as e:
            logger.error(f"[SessionClearAll] Error clearing all sessions: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)
