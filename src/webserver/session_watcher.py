"""
File watcher for monitoring CLI session deletions.

This module watches the ~/.cloudknife/sessions directory for session deletions
and broadcasts updates to connected web clients.
"""

import asyncio
import logging
from pathlib import Path
from typing import Callable, Dict, Set, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileDeletedEvent

from .ws_messages import create_success_response, MessageType

logger = logging.getLogger(__name__)


class SessionFileWatcher(FileSystemEventHandler):
    """Watches for session file deletions in the CLI."""

    def __init__(
        self,
        cloud: str,
        session_dir: Path,
        broadcast_callback: Callable,
        graph_state: Dict,
        loop: asyncio.AbstractEventLoop,
        on_session_created_callback: Optional[Callable] = None
    ):
        """
        Initialize the session file watcher.

        Args:
            cloud: Cloud provider (aws, gcp, azure)
            session_dir: Directory to watch
            broadcast_callback: Async function to broadcast updates to web clients
            graph_state: Reference to the graph state dict
            loop: Event loop for async operations
            on_session_created_callback: Optional async callback when session is created (session_name, cloud, session_id)
        """
        self.cloud = cloud
        self.session_dir = session_dir
        self.broadcast_callback = broadcast_callback
        self.graph_state = graph_state
        self.loop = loop
        self.deleted_sessions: Set[str] = set()
        self.on_session_created_callback = on_session_created_callback

    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return

        # Only process .json session files (not _enum.json or _key.json)
        file_path = Path(event.src_path)
        if not file_path.name.endswith('.json'):
            return
        if file_path.name.endswith('_enum.json') or file_path.name.endswith('_key.json'):
            return

        # Extract session name from filename
        session_name = file_path.stem

        logger.info(f"[SessionWatcher] Detected creation of session: {session_name} ({self.cloud})")

        # Schedule async import with a small delay to ensure file is fully written
        asyncio.run_coroutine_threadsafe(
            self._handle_session_creation_delayed(session_name),
            self.loop
        )

    async def _handle_session_creation_delayed(self, session_name: str):
        """Handle session creation with a delay to ensure file is fully written."""
        # Wait a bit to ensure the file is fully written
        await asyncio.sleep(0.5)
        await self._handle_session_creation(session_name)

    def on_deleted(self, event):
        """Handle file deletion events."""
        if event.is_directory:
            return

        # Only process .json session files (not _enum.json or _key.json)
        file_path = Path(event.src_path)
        if not file_path.name.endswith('.json'):
            return
        if file_path.name.endswith('_enum.json') or file_path.name.endswith('_key.json'):
            return

        # Extract session name from filename
        session_name = file_path.stem

        # Avoid duplicate processing
        if session_name in self.deleted_sessions:
            logger.debug(f"[SessionWatcher] Skipping duplicate deletion event for: {session_name}")
            return

        logger.info(f"[SessionWatcher] ⚠️ Detected deletion of session file: {session_name} ({self.cloud})")
        self.deleted_sessions.add(session_name)

        # Schedule async cleanup
        try:
            asyncio.run_coroutine_threadsafe(
                self._handle_session_deletion(session_name),
                self.loop
            )
            logger.debug(f"[SessionWatcher] Scheduled deletion handler for: {session_name}")
        except Exception as e:
            logger.error(f"[SessionWatcher] Failed to schedule deletion handler: {e}", exc_info=True)
            self.deleted_sessions.discard(session_name)

    async def _handle_session_creation(self, session_name: str):
        """
        Handle session creation: import session and add to graph.

        Args:
            session_name: Name of the created session
        """
        try:
            logger.info(f"[SessionWatcher] Processing creation of session: {session_name}")

            # Import the session using session_importer
            from .session_importer import import_single_session

            session_file = self.session_dir / f"{session_name}.json"
            if not session_file.exists():
                logger.warning(f"[SessionWatcher] Session file not found: {session_file}")
                return

            # Import session and get node/edges (synchronous call)
            session_node, session_edges = import_single_session(
                session_file,
                self.cloud
            )

            if not session_node:
                logger.warning(f"[SessionWatcher] Failed to import session: {session_name}")
                return

            # Check if session already exists in graph
            existing_node = self._find_node_by_id(session_node['id'])
            if existing_node:
                logger.info(f"[SessionWatcher] Session {session_name} already exists in graph, skipping")
                return

            # Add session node to graph state
            self.graph_state['nodes'].append(session_node)

            # Add edges to graph state
            for edge in session_edges:
                self.graph_state['edges'].append(edge)

            # Broadcast session creation
            await self.broadcast_callback(
                create_success_response(
                    'session.created',
                    {
                        'session_id': session_node['id'],
                        'session_name': session_name,
                        'cloud': self.cloud,
                    }
                )
            )

            # Broadcast node creation
            await self.broadcast_callback(
                create_success_response(
                    'graph.node.add',
                    {'node': session_node}
                )
            )

            # Broadcast edges
            for edge in session_edges:
                await self.broadcast_callback(
                    create_success_response(
                        'graph.edge.add',
                        {'edge': edge}
                    )
                )

            logger.info(
                f"[SessionWatcher] Broadcasted creation of session '{session_name}' "
                f"with {len(session_edges)} edges"
            )

            # Call the callback to notify handler (e.g., to auto-switch to this session)
            if self.on_session_created_callback:
                await self.on_session_created_callback(session_name, self.cloud, session_node['id'])

        except Exception as e:
            logger.error(f"[SessionWatcher] Error handling session creation: {e}", exc_info=True)

    async def _handle_session_deletion(self, session_name: str):
        """
        Handle session deletion: remove session and orphaned nodes.

        Args:
            session_name: Name of the deleted session
        """
        try:
            logger.info(f"[SessionWatcher] Processing deletion of session: {session_name}")

            # Find session ID from graph state
            session_id = self._find_session_id(session_name)
            orphaned_node_ids = set()

            if session_id:
                # Find nodes that are ONLY connected to this session
                orphaned_node_ids = self._find_orphaned_nodes(session_id)

                # Remove orphaned nodes and their edges
                if orphaned_node_ids:
                    await self._remove_nodes_and_edges(orphaned_node_ids)
                    logger.info(f"[SessionWatcher] Removed {len(orphaned_node_ids)} orphaned nodes")
            else:
                logger.warning(
                    f"[SessionWatcher] Session ID not found in graph for: {session_name}. "
                    "Broadcasting deletion anyway to clean up client state."
                )

            # Broadcast session deletion (even if session_id not found)
            # This ensures the client removes the session from the UI
            await self.broadcast_callback(
                create_success_response(
                    MessageType.SESSION_DELETE,
                    {
                        'session_id': session_id,  # May be None if not found
                        'session_name': session_name,
                        'cloud': self.cloud,
                        'deleted_node_ids': list(orphaned_node_ids) if orphaned_node_ids else []
                    }
                )
            )

            logger.info(
                f"[SessionWatcher] Broadcasted deletion of session '{session_name}' "
                f"(session_id: {session_id or 'not found'}, nodes: {len(orphaned_node_ids)})"
            )

            # Clean up tracking
            self.deleted_sessions.discard(session_name)

        except Exception as e:
            logger.error(f"[SessionWatcher] Error handling session deletion: {e}", exc_info=True)
            self.deleted_sessions.discard(session_name)

    def _find_session_id(self, session_name: str) -> Optional[str]:
        """Find session ID from session name by looking at graph nodes."""
        # Look for a session node in the graph
        # Session nodes have type '{cloud}-session' (e.g., 'aws-session')
        session_type = f'{self.cloud}-session'
        for node in self.graph_state['nodes']:
            if (node.get('type') == session_type and
                node.get('data', {}).get('sessionName') == session_name):
                return node.get('id')
        return None

    def _find_orphaned_nodes(self, session_id: str) -> Set[str]:
        """
        Find nodes that are connected ONLY to the deleted session.

        Args:
            session_id: ID of the deleted session

        Returns:
            Set of node IDs that are orphaned (only connected to this session)
        """
        # Find all nodes connected to this session
        connected_nodes = set()
        for edge in self.graph_state['edges']:
            if edge['source'] == session_id:
                connected_nodes.add(edge['target'])
            elif edge['target'] == session_id:
                connected_nodes.add(edge['source'])

        # For each connected node, check if it has connections to other sessions
        orphaned_nodes = set()
        for node_id in connected_nodes:
            # Skip if this is a session node itself
            node = self._find_node_by_id(node_id)
            if node and node.get('type', '').endswith('-session'):
                continue

            # Check if node is connected to any other session
            other_session_connections = 0
            for edge in self.graph_state['edges']:
                # Check if edge connects this node to another session
                other_node_id = None
                if edge['source'] == node_id:
                    other_node_id = edge['target']
                elif edge['target'] == node_id:
                    other_node_id = edge['source']

                if other_node_id and other_node_id != session_id:
                    other_node = self._find_node_by_id(other_node_id)
                    if other_node and other_node.get('type', '').endswith('-session'):
                        other_session_connections += 1
                        break

            # If no other session connections, this node is orphaned
            if other_session_connections == 0:
                orphaned_nodes.add(node_id)

        # Also include the session node itself
        orphaned_nodes.add(session_id)

        return orphaned_nodes

    def _find_node_by_id(self, node_id: str) -> Optional[Dict]:
        """Find a node by its ID."""
        for node in self.graph_state['nodes']:
            if node.get('id') == node_id:
                return node
        return None

    async def _remove_nodes_and_edges(self, node_ids: Set[str]):
        """
        Remove nodes and their associated edges from graph state.

        Args:
            node_ids: Set of node IDs to remove
        """
        # Remove edges connected to these nodes
        edges_to_remove = []
        for edge in self.graph_state['edges']:
            if edge['source'] in node_ids or edge['target'] in node_ids:
                edges_to_remove.append(edge)

        for edge in edges_to_remove:
            self.graph_state['edges'].remove(edge)

        # Remove nodes
        nodes_to_remove = []
        for node in self.graph_state['nodes']:
            if node.get('id') in node_ids:
                nodes_to_remove.append(node)

        for node in nodes_to_remove:
            self.graph_state['nodes'].remove(node)

        logger.info(
            f"[SessionWatcher] Removed {len(nodes_to_remove)} nodes "
            f"and {len(edges_to_remove)} edges from graph state"
        )


class SessionDirectoryWatcher:
    """Manages file watchers for all session directories."""

    def __init__(
        self,
        broadcast_callback: Callable,
        graph_state: Dict,
        loop: asyncio.AbstractEventLoop,
        on_session_created_callback: Optional[Callable] = None
    ):
        """
        Initialize the directory watcher.

        Args:
            broadcast_callback: Async function to broadcast updates to web clients
            graph_state: Reference to the graph state dict
            loop: Event loop for async operations
            on_session_created_callback: Optional async callback when session is created
        """
        self.broadcast_callback = broadcast_callback
        self.graph_state = graph_state
        self.loop = loop
        self.on_session_created_callback = on_session_created_callback
        self.observers = []
        self.sessions_base = Path.home() / '.cloudknife' / 'sessions'

    def start(self):
        """Start watching all session directories."""
        clouds = ['aws', 'gcp', 'azure']

        for cloud in clouds:
            session_dir = self.sessions_base / cloud
            if not session_dir.exists():
                logger.info(f"[SessionWatcher] Directory does not exist, skipping: {session_dir}")
                continue

            # Create event handler
            event_handler = SessionFileWatcher(
                cloud=cloud,
                session_dir=session_dir,
                broadcast_callback=self.broadcast_callback,
                graph_state=self.graph_state,
                loop=self.loop,
                on_session_created_callback=self.on_session_created_callback
            )

            # Create and start observer
            observer = Observer()
            observer.schedule(event_handler, str(session_dir), recursive=False)
            observer.start()
            self.observers.append(observer)

            logger.info(f"[SessionWatcher] Started watching: {session_dir}")

    def stop(self):
        """Stop all observers."""
        for observer in self.observers:
            observer.stop()
            observer.join()
        logger.info("[SessionWatcher] Stopped all observers")
