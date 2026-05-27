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
        def __init__(self, broadcast_func, exec_id, loop, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.broadcast_func = broadcast_func
            self.exec_id = exec_id
            self.loop = loop  # Pass loop from main thread, not get_event_loop() in worker thread

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
                    params,
                    loop  # Pass loop to thread
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
                    execution_id,
                    loop  # Pass loop to thread
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
                    execution_id,
                    loop  # Pass loop to thread
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
                    project_id,
                    loop  # Pass loop to thread
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
                    execution_id,
                    loop  # Pass loop to thread
                )

            await self._broadcast_module_output(execution_id, "[green]✓ Quick enumeration complete[/green]")
            await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in quick_enum: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_enumerate_artifact_packages(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate packages in an Artifact Registry repository."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            # Extract repository info from params
            repository_name = params.get('repository_name')  # Full resource name
            if not repository_name:
                # Build from components
                project = params.get('project')
                location = params.get('location')
                repository_id = params.get('repository_id')
                if not all([project, location, repository_id]):
                    await self._broadcast_module_error(
                        execution_id,
                        "Missing required parameters: repository_name or (project, location, repository_id)"
                    )
                    return
                repository_name = f"projects/{project}/locations/{location}/repositories/{repository_id}"

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Enumerating packages in repository...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_artifact_packages,
                    manager,
                    execution_id,
                    repository_name,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} package(s)[/green]"
                )

                logger.info(f"[GCP Packages] Received {len(result)} packages from executor")
                logger.debug(f"[GCP Packages] Sample package data: {result[0] if result else 'None'}")

                # Create graph nodes
                await self._create_artifact_package_nodes(result)

                await self._broadcast_module_output(
                    execution_id,
                    f"[cyan]Created {len(result)} package node(s) in graph[/cyan]"
                )

                # Update the repository node with packagesEnumerated flag
                node_id = params.get('node_id')
                if node_id:
                    from ...ws_messages import create_success_response

                    update_data = {
                        'packagesEnumerated': True,
                        'totalPackages': len(result)
                    }

                    logger.info(f"[GCP Packages] Preparing to update node {node_id}")
                    logger.info(f"[GCP Packages] Total packages: {len(result)}")
                    logger.info(f"[GCP Packages] Update data: {update_data}")

                    message = create_success_response('graph.node.update', {
                        'node': {
                            'id': node_id,
                            'data': update_data
                        }
                    })
                    logger.info(f"[GCP Packages] Broadcasting message: {message}")

                    await self.broadcast_callback(message)
                    logger.info(f"[GCP Packages] ✅ Broadcasted node update for {node_id}")

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No packages found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_artifact_packages: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_enumerate_artifact_versions(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate versions of an Artifact Registry package."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            # Extract package info from params
            package_name = params.get('package_name')  # Full resource name
            if not package_name:
                await self._broadcast_module_error(
                    execution_id,
                    "Missing required parameter: package_name"
                )
                return

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Enumerating versions for package...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_artifact_versions,
                    manager,
                    execution_id,
                    package_name,
                    loop
                )

            if result:
                versions_count = len(result.get('versions', []))
                tags_count = len(result.get('tags', []))
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {versions_count} version(s) and {tags_count} tag(s)[/green]"
                )

                # Update the package node with versions and tags data
                node_id = params.get('node_id')
                if node_id:
                    versions = result.get('versions', [])
                    tags = result.get('tags', [])

                    # Prepare versions data for frontend
                    versions_data = []
                    for v in versions:
                        versions_data.append({
                            'name': v.get('version_id', ''),
                            'createTime': v.get('create_time', ''),
                            'updateTime': v.get('update_time', ''),
                            'tags': v.get('related_tags', [])
                        })

                    # Prepare tags data (just tag names)
                    tags_data = [t.get('tag_id', '') for t in tags]

                    # Send graph node update with versions and tags
                    from ...ws_messages import create_success_response

                    update_data = {
                        'versions': versions_data,
                        'packageTags': tags_data,
                        'totalVersions': len(versions_data),
                        'totalTags': len(tags_data),
                        'versionsEnumerated': True
                    }

                    logger.info(f"[GCP Versions] Preparing to update node {node_id}")
                    logger.info(f"[GCP Versions] Versions count: {len(versions_data)}")
                    logger.info(f"[GCP Versions] Tags count: {len(tags_data)}")
                    logger.info(f"[GCP Versions] Sample version: {versions_data[0] if versions_data else 'None'}")
                    logger.info(f"[GCP Versions] Update data: {update_data}")

                    message = create_success_response('graph.node.update', {
                        'node': {
                            'id': node_id,
                            'data': update_data
                        }
                    })
                    logger.info(f"[GCP Versions] Broadcasting message: {message}")

                    await self.broadcast_callback(message)
                    logger.info(f"[GCP Versions] ✅ Broadcasted node update for {node_id}")

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No versions found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_artifact_versions: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_enumerate_artifact_repositories(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Artifact Registry repositories."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            # Broadcast start
            await self._broadcast_module_output(execution_id, "[bold]Enumerating Artifact Registry repositories...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_artifact_repositories,
                    manager,
                    execution_id,
                    params,
                    loop  # Pass loop to thread
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} Artifact Registry repositories[/green]"
                )

                # Create graph nodes
                await self._create_artifact_repository_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No repositories found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_artifact_repositories: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_describe_role(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Describe an IAM role with permissions analysis."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            # Extract role name from params
            role_name = params.get('role_name')
            if not role_name:
                await self._broadcast_module_error(
                    execution_id,
                    "Missing required parameter: role_name"
                )
                return

            project_id = params.get('project_id')

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Describing role: {role_name}[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_describe_role,
                    manager,
                    execution_id,
                    role_name,
                    project_id,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Role described: {result.get('title', role_name)}[/green]"
                )

                # Find or create the role node
                node_id = params.get('node_id')

                if not node_id:
                    # Standalone mode: find existing node or create new one
                    # Extract short name for node ID
                    role_short = role_name.split('/')[-1] if '/' in role_name else role_name
                    potential_node_id = f"gcp-role-{role_short}"

                    # Check if node exists by reading from graph store
                    # If not, create it
                    await self._create_or_update_role_node(
                        role_name=role_name,
                        role_short=role_short,
                        result=result,
                        project_id=project_id
                    )
                    node_id = potential_node_id
                    logger.info(f"[GCP Role] Created/updated standalone role node {node_id}")
                else:
                    # Node-triggered mode: update existing node
                    from ...ws_messages import create_success_response

                    update_data = {
                        'roleDescribed': True,
                        'roleDetails': result
                    }

                    logger.info(f"[GCP Role] Updating node {node_id} with role details")

                    message = create_success_response('graph.node.update', {
                        'node': {
                            'id': node_id,
                            'data': update_data
                        }
                    })

                    await self.broadcast_callback(message)
                    logger.info(f"[GCP Role] ✅ Broadcasted node update for {node_id}")

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]Failed to describe role[/yellow]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"Error in describe_role: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    async def _run_gcp_describe_service_account_iam_policy(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Describe IAM policy for a service account."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            # Extract service account email from params
            service_account_email = params.get('service_account_email')
            if not service_account_email:
                await self._broadcast_module_error(
                    execution_id,
                    "Missing required parameter: service_account_email"
                )
                return

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Describing IAM policy for: {service_account_email}[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_describe_service_account_iam_policy,
                    manager,
                    execution_id,
                    service_account_email,
                    loop
                )

            if result:
                bindings_count = len(result.get('bindings', []))
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {bindings_count} IAM binding(s)[/green]"
                )

                # Find or create the service account node
                node_id = params.get('node_id')

                if not node_id:
                    # Standalone mode: find existing node or create new one
                    # Extract SA name for node ID
                    sa_name = service_account_email.split('@')[0]
                    potential_node_id = f"gcp-sa-{sa_name}"

                    # Check if node exists or create it
                    await self._create_or_update_sa_node(
                        service_account_email=service_account_email,
                        result=result
                    )
                    node_id = potential_node_id
                    logger.info(f"[GCP SA] Created/updated standalone SA node {node_id}")
                else:
                    # Node-triggered mode: update existing node
                    from ...ws_messages import create_success_response

                    update_data = {
                        'iamPolicyDescribed': True,
                        'iamPolicy': result
                    }

                    logger.info(f"[GCP SA] Updating node {node_id} with IAM policy")

                    message = create_success_response('graph.node.update', {
                        'node': {
                            'id': node_id,
                            'data': update_data
                        }
                    })

                    await self.broadcast_callback(message)
                    logger.info(f"[GCP SA] ✅ Broadcasted node update for {node_id}")

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]Failed to describe IAM policy[/yellow]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"Error in describe_service_account_iam_policy: {e}", exc_info=True)
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

    def _execute_enumerate_compute(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute compute enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.compute_instances import enumerate_compute_instances

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.compute_instances as compute_module
        original_console = compute_module.console

        try:
            compute_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,  # Pass loop from main thread
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            result = enumerate_compute_instances(manager)
            return result
        finally:
            compute_module.console = original_console

    def _execute_enumerate_storage(self, manager, execution_id: str, loop):
        """Execute storage enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.storage_buckets import enumerate_storage_buckets

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.storage_buckets as storage_module
        original_console = storage_module.console

        try:
            storage_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,  # Pass loop from main thread
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            result = enumerate_storage_buckets(manager)
            return result
        finally:
            storage_module.console = original_console

    def _execute_enumerate_iam(self, manager, execution_id: str, loop):
        """Execute IAM enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.iam_policies import enumerate_iam_policies

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.iam_policies as iam_module
        original_console = iam_module.console

        try:
            iam_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,  # Pass loop from main thread
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            result = enumerate_iam_policies(manager)
            return result
        finally:
            iam_module.console = original_console

    def _execute_enumerate_secrets(self, manager, execution_id: str, project_id: Optional[str], loop):
        """Execute secrets enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.secret_manager import enumerate_secrets

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.secret_manager as secrets_module
        original_console = secrets_module.console

        try:
            secrets_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,  # Pass loop from main thread
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

    def _execute_enumerate_artifact_repositories(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute artifact repositories enumeration in thread."""
        # Use importlib to avoid name conflicts with file/function having same name
        import importlib
        import sys

        # Import the module using importlib
        module_name = 'src.clouds.gcp.modules.enumeration.enumerate_artifact_repositories'
        if module_name in sys.modules:
            # Reload if already imported to avoid stale cache
            artifact_module = importlib.reload(sys.modules[module_name])
        else:
            artifact_module = importlib.import_module(module_name)

        # Replace console with broadcast console
        original_console = artifact_module.console

        try:
            artifact_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,  # Pass loop from main thread
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            # Get project_id from params or use session default
            project_id = params.get('project_id') or manager.current_session_data.get('project_id')

            # Call the enumeration function from the properly loaded module
            # The CLI function handles project_id=None gracefully
            artifact_module.enumerate_artifact_repositories(manager, project_id=project_id)

            # Load enumeration data that was saved by the function
            # The CLI function saves data using save_enumeration_data()
            result = manager.get_enumeration_data('artifact_repositories') or []

            return result
        finally:
            artifact_module.console = original_console

    def _execute_quick_enum(self, manager, execution_id: str, loop):
        """Execute quick enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.quick_enum import quick_enum

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.quick_enum as quick_module
        original_console = quick_module.console

        try:
            quick_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,  # Pass loop from main thread
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            quick_enum(manager)
        finally:
            quick_module.console = original_console

    def _execute_enumerate_artifact_packages(self, manager, execution_id: str, repository_name: str, loop):
        """Execute artifact packages enumeration in thread."""
        from google.cloud import artifactregistry_v1

        # Get credentials
        credentials = manager.get_credentials()
        if not credentials:
            raise Exception("No credentials configured")

        # Create broadcast console
        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        all_packages = []

        try:
            client = artifactregistry_v1.ArtifactRegistryClient(credentials=credentials)

            # Parse repository info from name
            # Format: projects/{project}/locations/{location}/repositories/{repository_id}
            parts = repository_name.split('/')
            project = parts[1] if len(parts) > 1 else ''
            location = parts[3] if len(parts) > 3 else ''
            repository_id = parts[5] if len(parts) > 5 else ''

            broadcast_console.print(
                f"[dim]Scanning repository:[/dim] [cyan]{repository_id}[/cyan] [dim]({location})[/dim]"
            )

            request = artifactregistry_v1.ListPackagesRequest(parent=repository_name)
            packages = client.list_packages(request=request)

            for package in packages:
                package_data = {
                    "repository_id": repository_id,
                    "repository_location": location,
                    "repository_name": repository_name,  # Store parent for later use
                    "project": project,
                    "name": package.name,
                    "package_id": package.name.split("/")[-1],
                    "display_name": package.display_name or package.name.split("/")[-1],
                    "create_time": str(package.create_time) if package.create_time else "",
                    "update_time": str(package.update_time) if package.update_time else "",
                }

                all_packages.append(package_data)
                broadcast_console.print(f"  📦 [green]{package_data['package_id']}[/green]")

            broadcast_console.print(f"[dim]Found {len(all_packages)} package(s)[/dim]")

            # Save to enumeration data
            if all_packages:
                existing_packages = manager.get_enumeration_data('artifact_packages') or []
                # Merge with existing, avoiding duplicates
                existing_names = {p['name'] for p in existing_packages}
                new_packages = [p for p in all_packages if p['name'] not in existing_names]
                manager.save_enumeration_data('artifact_packages', existing_packages + new_packages)

            return all_packages

        except Exception as e:
            broadcast_console.print(f"[red]❌ Error: {str(e)[:200]}[/red]")
            raise

    def _execute_enumerate_artifact_versions(self, manager, execution_id: str, package_name: str, loop):
        """Execute artifact versions enumeration in thread."""
        from google.cloud import artifactregistry_v1

        # Get credentials
        credentials = manager.get_credentials()
        if not credentials:
            raise Exception("No credentials configured")

        # Create broadcast console
        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        all_versions = []
        all_tags = []

        try:
            client = artifactregistry_v1.ArtifactRegistryClient(credentials=credentials)

            # Parse package info from name
            package_id = package_name.split("/")[-1]

            broadcast_console.print(f"[dim]Scanning package:[/dim] [cyan]{package_id}[/cyan]")

            # List versions
            version_request = artifactregistry_v1.ListVersionsRequest(parent=package_name)
            versions = client.list_versions(request=version_request)

            for version in versions:
                version_data = {
                    "package_id": package_id,
                    "package_name": package_name,
                    "name": version.name,
                    "version_id": version.name.split("/")[-1],
                    "create_time": str(version.create_time) if version.create_time else "",
                    "update_time": str(version.update_time) if version.update_time else "",
                    "related_tags": [],
                }

                all_versions.append(version_data)

            broadcast_console.print(f"  [green]✓[/green] Found {len(all_versions)} version(s)")

            # List tags
            try:
                tag_request = artifactregistry_v1.ListTagsRequest(parent=package_name)
                tags = client.list_tags(request=tag_request)

                for tag in tags:
                    tag_data = {
                        "package_id": package_id,
                        "name": tag.name,
                        "tag_id": tag.name.split("/")[-1],
                        "version": tag.version,
                    }

                    all_tags.append(tag_data)

                    # Link tag to version
                    version_id = tag.version.split("/")[-1] if tag.version else None
                    if version_id:
                        for v in all_versions:
                            if v["version_id"] == version_id:
                                v["related_tags"].append(tag_data["tag_id"])

                if all_tags:
                    broadcast_console.print(f"  [blue]✓[/blue] Found {len(all_tags)} tag(s)")

            except Exception as e:
                if "PERMISSION_DENIED" not in str(e):
                    broadcast_console.print(f"  [yellow]⚠ Error listing tags: {str(e)[:80]}[/yellow]")

            # Save to enumeration data
            if all_versions:
                existing_versions = manager.get_enumeration_data('artifact_versions') or []
                # Merge with existing
                existing_names = {v['name'] for v in existing_versions}
                new_versions = [v for v in all_versions if v['name'] not in existing_names]
                manager.save_enumeration_data('artifact_versions', existing_versions + new_versions)

            if all_tags:
                existing_tags = manager.get_enumeration_data('artifact_tags') or []
                existing_names = {t['name'] for t in existing_tags}
                new_tags = [t for t in all_tags if t['name'] not in existing_names]
                manager.save_enumeration_data('artifact_tags', existing_tags + new_tags)

            return {
                'versions': all_versions,
                'tags': all_tags
            }

        except Exception as e:
            broadcast_console.print(f"[red]❌ Error: {str(e)[:200]}[/red]")
            raise

    def _execute_describe_role(self, manager, execution_id: str, role_name: str, project_id: Optional[str], loop):
        """Execute role description in thread."""
        from src.clouds.gcp.modules.enumeration import role_describe

        # Replace console with broadcast console
        original_console = role_describe.console

        try:
            broadcast_console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,
                file=StringIO(),
                width=120,
                force_terminal=False
            )
            role_describe.console = broadcast_console

            # Call the describe_role function
            result = role_describe.describe_role(
                manager,
                role_name=role_name,
                project_id=project_id
            )

            return result

        except Exception as e:
            broadcast_console.print(f"[red]❌ Error: {str(e)[:200]}[/red]")
            raise
        finally:
            role_describe.console = original_console

    def _execute_describe_service_account_iam_policy(self, manager, execution_id: str, service_account_email: str, loop):
        """Execute service account IAM policy description in thread."""
        from src.clouds.gcp.modules.enumeration import service_account_iam

        # Replace console with broadcast console
        original_console = service_account_iam.console

        try:
            broadcast_console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,
                file=StringIO(),
                width=120,
                force_terminal=False
            )
            service_account_iam.console = broadcast_console

            # Call the describe_service_account_iam_policy function
            result = service_account_iam.describe_service_account_iam_policy(
                manager,
                service_account_email=service_account_email
            )

            return result

        except Exception as e:
            broadcast_console.print(f"[red]❌ Error: {str(e)[:200]}[/red]")
            raise
        finally:
            service_account_iam.console = original_console

    async def _create_or_update_role_node(
        self,
        role_name: str,
        role_short: str,
        result: Dict[str, Any],
        project_id: Optional[str]
    ) -> None:
        """Create or update a role node from standalone describe_role execution."""
        from datetime import datetime
        from ...ws_messages import create_success_response

        node_id = f"gcp-role-{role_short}"

        # Determine if predefined or custom
        is_predefined = role_name.startswith('roles/')

        node = {
            'id': node_id,
            'type': 'gcp-role',
            'label': result.get('title') or role_short,
            'provider': 'gcp',
            'discoveredBy': [self.current_session_id] if self.current_session_id else [],
            'parentId': None,  # No category parent in standalone mode
            'data': {
                'role_name': role_name,
                'role_short': role_short,
                'project': project_id or 'predefined',
                'custom': not is_predefined,
                'title': result.get('title'),
                'description': result.get('description'),
                'stage': result.get('stage'),
                'permission_count': result.get('permission_count'),
                'roleDescribed': True,
                'roleDetails': result,
            },
            'metadata': {
                'discoveredAt': datetime.now().isoformat(),
                'moduleUsed': 'gcp_describe_role',
                'fullName': role_name,
            },
            'level': 1,
        }

        await self._add_or_update_node(node)

        # Create edge from session to role
        if self.current_session_id:
            edge = {
                'id': f"{self.current_session_id}-owns-{node_id}",
                'source': self.current_session_id,
                'target': node_id,
                'type': 'owns',
                'discoveredBy': [self.current_session_id],
            }
            await self._add_edge(edge)

    async def _create_or_update_sa_node(
        self,
        service_account_email: str,
        result: Dict[str, Any]
    ) -> None:
        """Create or update a service account node from standalone describe_service_account_iam_policy execution."""
        from datetime import datetime
        from ...ws_messages import create_success_response

        sa_name = service_account_email.split('@')[0]
        node_id = f"gcp-sa-{sa_name}"

        # Extract project from email
        project = None
        if '.iam.gserviceaccount.com' in service_account_email:
            project = service_account_email.split('@')[1].replace('.iam.gserviceaccount.com', '')

        node = {
            'id': node_id,
            'type': 'gcp-sa',
            'label': sa_name,
            'provider': 'gcp',
            'discoveredBy': [self.current_session_id] if self.current_session_id else [],
            'parentId': None,  # No category parent in standalone mode
            'data': {
                'email': service_account_email,
                'name': sa_name,
                'project': project or result.get('project'),
                'iamPolicyDescribed': True,
                'iamPolicy': result,
            },
            'metadata': {
                'discoveredAt': datetime.now().isoformat(),
                'moduleUsed': 'gcp_describe_service_account_iam_policy',
                'email': service_account_email,
            },
            'level': 1,
        }

        await self._add_or_update_node(node)

        # Create edge from session to SA
        if self.current_session_id:
            edge = {
                'id': f"{self.current_session_id}-owns-{node_id}",
                'source': self.current_session_id,
                'target': node_id,
                'type': 'owns',
                'discoveredBy': [self.current_session_id],
            }
            await self._add_edge(edge)

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
                edge = {
                    'id': f"{self.current_session_id}-owns-{node_id}",
                    'source': self.current_session_id,  # Use UUID, not name-based ID
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
        """
        Create comprehensive IAM graph nodes and relationships.

        Creates nodes for:
        - Users (from IAM bindings)
        - Service Accounts (with keys)
        - Groups (from IAM bindings)
        - Roles (both custom and predefined)
        - Bindings (edges between principals and roles)
        """
        logger.info("[GCP IAM] Creating comprehensive IAM graph")

        # Track created nodes to avoid duplicates
        created_users = set()
        created_groups = set()
        created_roles = set()
        created_projects = set()

        # 0. Create category nodes first
        from .gcp_iam_graph_helpers import create_category_nodes
        category_nodes = await create_category_nodes(self)

        # 1. Create Service Account nodes (existing logic + enhancements)
        await self._create_service_account_nodes(iam_data, created_projects, category_nodes)

        # 2. Process project policies to extract users, groups, and bindings
        from .gcp_iam_graph_helpers import create_nodes_from_project_policies
        await create_nodes_from_project_policies(
            self, iam_data, created_users, created_groups, created_roles, created_projects, category_nodes
        )

        # 3. Process gcloud policies for additional detail
        from .gcp_iam_graph_helpers import create_nodes_from_gcloud_policies
        await create_nodes_from_gcloud_policies(
            self, iam_data, created_users, created_groups, created_roles, created_projects, category_nodes
        )

        # 4. Create custom role nodes
        from .gcp_iam_graph_helpers import create_custom_role_nodes
        await create_custom_role_nodes(self, iam_data, created_roles, created_projects, category_nodes)

        # 5. Process organization policy if available
        from .gcp_iam_graph_helpers import create_nodes_from_org_policy
        await create_nodes_from_org_policy(
            self, iam_data, created_users, created_groups, created_roles, category_nodes
        )

        logger.info(
            f"[GCP IAM] Created {len(created_users)} users, {len(created_groups)} groups, "
            f"{len(created_roles)} roles, {len(created_projects)} projects"
        )

    async def _create_service_account_nodes(
        self, iam_data: dict, created_projects: set, category_nodes: dict
    ) -> None:
        """Create service account nodes with enhanced metadata."""
        service_accounts = iam_data.get('service_accounts', [])
        sa_keys = iam_data.get('service_account_keys', [])

        # Build key count map
        key_count_map = {}
        for key in sa_keys:
            sa_email = key.get('service_account')
            if sa_email:
                key_count_map[sa_email] = key_count_map.get(sa_email, 0) + 1

        logger.info(f"[GCP IAM] Creating {len(service_accounts)} service account nodes")

        for sa in service_accounts:
            node_id = f"gcp-sa-{sa['email']}"
            key_count = key_count_map.get(sa['email'], 0)

            node = {
                'id': node_id,
                'type': 'gcp-sa',
                'label': sa.get('display_name') or sa['email'].split('@')[0],
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': category_nodes.get('service_accounts'),  # Set parent to SA category
                'data': {
                    'project': sa['project'],
                    'email': sa['email'],
                    'display_name': sa.get('display_name'),
                    'description': sa.get('description'),
                    'disabled': sa.get('disabled', False),
                    'oauth2_client_id': sa.get('oauth2_client_id'),
                    'user_managed_keys': key_count,
                    'has_keys': key_count > 0,
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_iam',
                    'resourceId': sa.get('unique_id'),
                    'fullName': sa.get('name'),
                },
                'level': 2,  # Child level (under category)
            }

            await self._add_or_update_node(node)
            created_projects.add(sa['project'])

            # Create edge: Service Accounts category -> SA
            sa_category_id = category_nodes.get('service_accounts')
            if sa_category_id:
                edge = {
                    'id': f"{sa_category_id}-contains-{node_id}",
                    'source': sa_category_id,
                    'target': node_id,
                    'type': 'contains',
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

    async def _create_artifact_repository_nodes(self, repositories: list) -> None:
        """Create graph nodes for Artifact Registry repositories."""
        logger.info(f"[GCP Artifact] Creating {len(repositories)} repository node(s)")

        for repo in repositories:
            # Create unique node ID based on project, location, and repository ID
            node_id = f"gcp-artifact-{repo['project']}-{repo['location']}-{repo['repository_id']}"

            # Format icon mapping
            format_icon = {
                "DOCKER": "🐳",
                "MAVEN": "☕",
                "NPM": "📦",
                "PYTHON": "🐍",
                "APT": "📦",
                "YUM": "📦",
                "GO": "🔷",
            }.get(repo['format'], "📦")

            node = {
                'id': node_id,
                'type': 'gcp-artifact-repository',
                'label': f"{format_icon} {repo['repository_id']}",
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': None,
                'data': {
                    'project': repo['project'],
                    'location': repo['location'],
                    'repository_id': repo['repository_id'],
                    'format': repo['format'],
                    'mode': repo['mode'],
                    'description': repo.get('description', ''),
                    'size_bytes': repo.get('size_bytes', 0),
                    'create_time': repo.get('create_time', ''),
                    'update_time': repo.get('update_time', ''),
                    'kms_key_name': repo.get('kms_key_name', ''),
                    'labels': repo.get('labels', {}),
                    # Docker-specific
                    'immutable_tags': repo.get('immutable_tags', False),
                    # Maven-specific
                    'maven_allow_snapshot_overwrites': repo.get('maven_allow_snapshot_overwrites', False),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_artifact_repositories',
                    'resourceName': repo.get('name', ''),
                    'fullPath': f"projects/{repo['project']}/locations/{repo['location']}/repositories/{repo['repository_id']}",
                },
                'level': 3,  # Data/Storage level (same as Cloud Storage)
            }

            await self._add_or_update_node(node)

            # Create edge from session to repository
            if self.current_session_id:
                edge = {
                    'id': f"{self.current_session_id}-owns-{node_id}",
                    'source': self.current_session_id,  # Use UUID, not name-based ID
                    'target': node_id,
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }
                await self._add_edge(edge)

        logger.info(f"[GCP Artifact] Successfully created {len(repositories)} repository node(s) and edge(s)")

    async def _create_artifact_package_nodes(self, packages: list) -> None:
        """Create graph nodes for Artifact Registry packages."""
        logger.info(f"[GCP Artifact Packages] Creating {len(packages)} package node(s)")

        for pkg in packages:
            # Create unique node ID based on full resource name
            node_id = f"gcp-artifact-package-{pkg['project']}-{pkg['repository_location']}-{pkg['repository_id']}-{pkg['package_id']}"

            # Find parent repository node ID
            parent_repo_node_id = f"gcp-artifact-{pkg['project']}-{pkg['repository_location']}-{pkg['repository_id']}"

            logger.debug(f"[GCP Artifact Packages] Creating node {node_id} with parent {parent_repo_node_id}")

            node = {
                'id': node_id,
                'type': 'gcp-artifact-package',
                'label': f"📦 {pkg['package_id']}",
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': parent_repo_node_id,  # Set repository as parent
                'data': {
                    'project': pkg['project'],
                    'repository_id': pkg['repository_id'],
                    'repository_location': pkg['repository_location'],
                    'package_id': pkg['package_id'],
                    'package_name': pkg['name'],  # Full resource name
                    'display_name': pkg.get('display_name', ''),
                    'create_time': pkg.get('create_time', ''),
                    'update_time': pkg.get('update_time', ''),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_artifact_packages',
                    'resourceName': pkg.get('name', ''),
                    'fullPath': pkg.get('name', ''),
                },
                'level': 4,  # Package level (child of repository)
            }

            await self._add_or_update_node(node)
            logger.debug(f"[GCP Artifact Packages] Node {node_id} added to graph_state")

            # Create edge from repository to package
            if parent_repo_node_id:
                edge = {
                    'id': f"{parent_repo_node_id}-contains-{node_id}",
                    'source': parent_repo_node_id,  # Repository node
                    'target': node_id,
                    'type': 'contains',
                    'label': 'contains',
                    'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                }
                await self._add_edge(edge)
                logger.debug(f"[GCP Artifact Packages] Edge {edge['id']} added to graph_state")

        logger.info(f"[GCP Artifact Packages] Successfully created {len(packages)} package node(s) and edge(s)")
