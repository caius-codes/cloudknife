"""
GCP-specific WebSocket handlers.
Handles all GCP module execution and graph node creation.
"""

import asyncio
import logging
import json
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from rich.console import Console as RichConsole
from io import StringIO
from concurrent.futures import ThreadPoolExecutor

from ..base_handler import BaseHandler
from ...ws_messages import (
    WebSocketMessage,
    WebSocketResponse,
    create_success_response,
    create_error_response,
)

logger = logging.getLogger(__name__)


class GCPHandler(BaseHandler):
    """
    Handler for GCP-specific WebSocket operations.

    Handles:
    - Compute Engine enumeration
    - Cloud Storage enumeration
    - IAM policy and service account enumeration
    - Secret Manager operations
    - Quick enumeration across services
    - Graph node creation for all GCP resources
    """

    class BroadcastConsole(RichConsole):
        """Console that broadcasts output via WebSocket."""
        def __init__(self, broadcast_func, exec_id, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.broadcast_func = broadcast_func
            self.exec_id = exec_id
            self.loop = asyncio.get_event_loop()

        def print(self, *objects, **kwargs):
            # Get the rendered text
            output = StringIO()
            temp_console = RichConsole(file=output, width=120, force_terminal=False)
            temp_console.print(*objects, **kwargs)
            text = output.getvalue().rstrip('\n')

            # Broadcast it
            if text:
                asyncio.run_coroutine_threadsafe(
                    self.broadcast_func(self.exec_id, text),
                    self.loop
                )

            # Also write to parent
            super().print(*objects, **kwargs)

    # ==================== Module Execution ====================

    async def _run_gcp_enumerate_compute(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Compute Engine instances."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            # Broadcast start
            await self._broadcast_module_output(execution_id, "[bold]Enumerating Compute Engine instances...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_compute,
                    manager,
                    execution_id,
                    params
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} Compute Engine instance(s)[/green]"
                )

                # Create graph nodes
                await self._create_compute_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No instances found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_compute: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_enumerate_storage(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Cloud Storage buckets."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Cloud Storage buckets...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_storage,
                    manager,
                    execution_id
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} Cloud Storage bucket(s)[/green]"
                )

                # Create graph nodes
                await self._create_storage_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No buckets found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_storage: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_enumerate_iam(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate IAM policies and service accounts."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating IAM policies...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_iam,
                    manager,
                    execution_id
                )

            if result:
                service_accounts = result.get('service_accounts', [])
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(service_accounts)} service account(s)[/green]"
                )

                # Create graph nodes
                await self._create_iam_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No IAM data found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_iam: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_enumerate_secrets(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Secret Manager secrets."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Secret Manager secrets...[/bold]")

            project_id = params.get('project') or params.get('project_id')

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_secrets,
                    manager,
                    execution_id,
                    project_id
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} secret(s)[/green]"
                )

                # Create graph nodes
                await self._create_secret_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No secrets found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_secrets: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_quick_enum(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Run quick enumeration across GCP services."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Running quick enumeration...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                await loop.run_in_executor(
                    executor,
                    self._execute_quick_enum,
                    manager,
                    execution_id
                )

            await self._broadcast_module_output(execution_id, "[green]✓ Quick enumeration complete[/green]")
            await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in quick_enum: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    # ==================== Helper Methods ====================

    def _get_or_create_gcp_manager(self):
        """Get or create GCP session manager."""
        try:
            if 'gcp' in self.session_managers:
                return self.session_managers['gcp']

            # Create new manager
            from src.clouds.gcp.gcp_session import GCPSessionManager
            sessions_base = Path.home() / '.cloudknife' / 'sessions'
            manager = GCPSessionManager(str(sessions_base / 'gcp'))

            # Load current session
            if self.current_session:
                manager.create_or_load_session(self.current_session)

            self.session_managers['gcp'] = manager
            return manager

        except Exception as e:
            logger.error(f"Error creating GCP manager: {e}", exc_info=True)
            return None

    def _execute_enumerate_compute(self, manager, execution_id: str, params: Dict[str, Any]):
        """Execute compute enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.compute_instances import enumerate_compute_instances

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.compute_instances as compute_module
        original_console = compute_module.console

        try:
            compute_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            result = enumerate_compute_instances(manager)
            return result
        finally:
            compute_module.console = original_console

    def _execute_enumerate_storage(self, manager, execution_id: str):
        """Execute storage enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.storage_buckets import enumerate_storage_buckets

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.storage_buckets as storage_module
        original_console = storage_module.console

        try:
            storage_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            result = enumerate_storage_buckets(manager)
            return result
        finally:
            storage_module.console = original_console

    def _execute_enumerate_iam(self, manager, execution_id: str):
        """Execute IAM enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.iam_policies import enumerate_iam_policies

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.iam_policies as iam_module
        original_console = iam_module.console

        try:
            iam_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            result = enumerate_iam_policies(manager)
            return result
        finally:
            iam_module.console = original_console

    def _execute_enumerate_secrets(self, manager, execution_id: str, project_id: Optional[str]):
        """Execute secrets enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.secret_manager import enumerate_secrets

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.secret_manager as secrets_module
        original_console = secrets_module.console

        try:
            secrets_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            # Override Prompt to avoid interactive input
            from rich.prompt import Prompt
            original_prompt_ask = Prompt.ask

            def mock_prompt_ask(prompt, **kwargs):
                # Return default or current project
                if 'Project ID' in prompt:
                    return project_id or manager.current_session_data.get('project_id', '')
                return kwargs.get('default', '')

            Prompt.ask = mock_prompt_ask

            try:
                result = enumerate_secrets(manager, project_id=project_id, include_versions=True)
                return result
            finally:
                Prompt.ask = original_prompt_ask

        finally:
            secrets_module.console = original_console

    def _execute_quick_enum(self, manager, execution_id: str):
        """Execute quick enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.quick_enum import quick_enum

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.quick_enum as quick_module
        original_console = quick_module.console

        try:
            quick_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            quick_enum(manager)
        finally:
            quick_module.console = original_console

    # ==================== Graph Node Creation ====================

    async def _create_compute_nodes(self, instances: list) -> None:
        """Create graph nodes for Compute Engine instances."""
        for instance in instances:
            node_id = f"gcp-compute-{instance['project']}-{instance['zone']}-{instance['name']}"

            node = {
                'id': node_id,
                'type': 'gcp-compute',
                'label': instance['name'],
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': None,
                'data': {
                    'project': instance['project'],
                    'zone': instance['zone'],
                    'machine_type': instance.get('machine_type'),
                    'status': instance.get('status'),
                    'internal_ip': instance.get('internal_ip'),
                    'external_ip': instance.get('external_ip'),
                    'service_accounts': instance.get('service_accounts', []),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_compute',
                    'resourceId': instance.get('id'),
                },
                'level': 2,  # Compute level
            }

            await self._add_or_update_node(node)

            # Create edge from session to instance
            if self.current_session_id:
                session_node_id = f"gcp-session-{self.current_session}"
                edge = {
                    'id': f"{session_node_id}-owns-{node_id}",
                    'source': session_node_id,
                    'target': node_id,
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }
                await self._add_edge(edge)

    async def _create_storage_nodes(self, buckets: list) -> None:
        """Create graph nodes for Cloud Storage buckets."""
        for bucket in buckets:
            node_id = f"gcp-storage-{bucket['project']}-{bucket['name']}"

            node = {
                'id': node_id,
                'type': 'gcp-storage',
                'label': bucket['name'],
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': None,
                'data': {
                    'project': bucket['project'],
                    'location': bucket.get('location'),
                    'storage_class': bucket.get('storage_class'),
                    'is_public': bucket.get('is_public', False),
                    'versioning_enabled': bucket.get('versioning_enabled', False),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_storage',
                    'resourceId': bucket.get('id'),
                },
                'level': 3,  # Data level
            }

            await self._add_or_update_node(node)

            # Create edge from session to bucket
            if self.current_session_id:
                session_node_id = f"gcp-session-{self.current_session}"
                edge = {
                    'id': f"{session_node_id}-owns-{node_id}",
                    'source': session_node_id,
                    'target': node_id,
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }
                await self._add_edge(edge)

    async def _create_iam_nodes(self, iam_data: dict) -> None:
        """Create graph nodes for IAM service accounts."""
        service_accounts = iam_data.get('service_accounts', [])

        for sa in service_accounts:
            node_id = f"gcp-sa-{sa['project']}-{sa['email']}"

            node = {
                'id': node_id,
                'type': 'gcp-sa',
                'label': sa['email'],
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': None,
                'data': {
                    'project': sa['project'],
                    'email': sa['email'],
                    'display_name': sa.get('display_name'),
                    'disabled': sa.get('disabled', False),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_iam',
                    'resourceId': sa.get('unique_id'),
                },
                'level': 1,  # IAM level
            }

            await self._add_or_update_node(node)

            # Create edge from session to service account
            if self.current_session_id:
                session_node_id = f"gcp-session-{self.current_session}"
                edge = {
                    'id': f"{session_node_id}-owns-{node_id}",
                    'source': session_node_id,
                    'target': node_id,
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }
                await self._add_edge(edge)

    async def _create_secret_nodes(self, secrets: list) -> None:
        """Create graph nodes for Secret Manager secrets."""
        for secret in secrets:
            node_id = f"gcp-secret-{secret['project']}-{secret['name']}"

            node = {
                'id': node_id,
                'type': 'gcp-secret',
                'label': secret['name'],
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': None,
                'data': {
                    'project': secret['project'],
                    'location': secret.get('location', 'global'),
                    'version_count': secret.get('version_count', 0),
                    'replication': secret.get('replication'),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_secrets',
                    'resourceId': secret.get('full_name'),
                },
                'level': 4,  # Secrets level
            }

            await self._add_or_update_node(node)

            # Create edge from session to secret
            if self.current_session_id:
                session_node_id = f"gcp-session-{self.current_session}"
                edge = {
                    'id': f"{session_node_id}-owns-{node_id}",
                    'source': session_node_id,
                    'target': node_id,
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }
                await self._add_edge(edge)
