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

            bucket_name = params.get('bucket')

            if bucket_name:
                await self._broadcast_module_output(execution_id, f"[bold]Analyzing bucket: {bucket_name}...[/bold]")
            else:
                await self._broadcast_module_output(execution_id, "[bold]Enumerating Cloud Storage buckets...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_storage,
                    manager,
                    execution_id,
                    loop,  # Pass loop to thread
                    bucket_name  # Pass bucket_name parameter
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

    async def _run_gcp_enumerate_objects(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate objects in a Cloud Storage bucket."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            bucket_name = params.get('bucket')
            prefix = params.get('prefix', '')

            if not bucket_name:
                await self._broadcast_module_error(execution_id, "Bucket name is required")
                return

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Enumerating objects in bucket: {bucket_name}...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_objects,
                    manager,
                    execution_id,
                    loop,
                    bucket_name,
                    prefix
                )

            if result:
                total_objects = len(result)
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {total_objects} object(s) in bucket {bucket_name}[/green]"
                )

                # Create nodes for objects (limited to 10)
                await self._create_storage_object_nodes(bucket_name, result[:10])

                if total_objects > 10:
                    await self._broadcast_module_output(
                        execution_id,
                        f"[cyan]ℹ️  Created 10 object nodes in graph (out of {total_objects} total objects)[/cyan]"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        f"[green]✓ Created {total_objects} object nodes in attack graph[/green]"
                    )

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(
                    execution_id,
                    f"[yellow]No objects found in bucket {bucket_name}[/yellow]"
                )
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_objects: {e}", exc_info=True)
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

    async def _run_gcp_enumerate_exploitable_sas(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate service accounts with dangerous permissions."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]🎯 Testing service accounts for dangerous permissions...[/bold]")

            project_id = params.get('project') or params.get('project_id')

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_exploitable_sas,
                    manager,
                    execution_id,
                    project_id,
                    loop
                )

            if result:
                exploitable = result.get('exploitable', [])
                total_sas = result.get('total_sas', 0)

                if exploitable:
                    critical_count = sum(
                        1 for sa in exploitable
                        if any(p.get('severity') == 'CRITICAL' for p in sa.get('permissions', []))
                    )

                    await self._broadcast_module_output(
                        execution_id,
                        f"[green]✓ Found {len(exploitable)}/{total_sas} exploitable service account(s)[/green]"
                    )

                    if critical_count > 0:
                        await self._broadcast_module_output(
                            execution_id,
                            f"[red]⚠️  {critical_count} with CRITICAL permissions![/red]"
                        )

                    # Update SA nodes with exploitable data
                    await self._update_exploitable_sa_nodes(exploitable)
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        f"[yellow]No exploitable service accounts found (tested {total_sas})[/yellow]"
                    )

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No service accounts to test[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Error in enumerate_exploitable_sas: {e}", exc_info=True)
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

    async def _run_gcp_get_secret_value(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Get the value of a specific GCP secret."""
        try:
            import base64
            import requests

            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            secret_name = params.get('secret_name')
            project_id = params.get('project') or params.get('project_id')
            node_id = params.get('node_id')

            if not secret_name:
                await self._broadcast_module_error(execution_id, "Secret name is required")
                return

            # Get current project from session if not provided
            if not project_id:
                project_id = manager.current_session_data.get('project_id')

            if not project_id:
                await self._broadcast_module_error(execution_id, "Project ID is required")
                return

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Getting secret value for: {secret_name}[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_get_secret_value,
                    manager,
                    secret_name,
                    project_id,
                )

            if result and result.get('success'):
                secret_value = result.get('value', '')

                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Secret value retrieved ({len(secret_value)} characters)[/green]"
                )

                # Update node with secret value
                if node_id:
                    await self._update_secret_node_with_value(node_id, secret_value)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                error_msg = result.get('error', 'Failed to retrieve secret') if result else 'Failed to retrieve secret'
                await self._broadcast_module_output(execution_id, f"[red]✗ {error_msg}[/red]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"Error in get_secret_value: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_get_secret_value(
        self,
        manager,
        secret_name: str,
        project_id: str,
    ) -> Dict[str, Any]:
        """Execute secret value retrieval (runs in thread pool)."""
        import base64
        import requests

        try:
            # Get credentials and token
            credentials = manager.get_credentials()
            if not credentials:
                return {"success": False, "error": "No credentials configured"}

            auth_method = manager.current_session_data.get("auth_method")

            if auth_method == "access_token":
                token = manager.current_session_data.get("access_token")
            else:
                from google.auth.transport.requests import Request
                credentials.refresh(Request())
                token = credentials.token

            if not token:
                return {"success": False, "error": "Failed to get access token"}

            headers = {"Authorization": f"Bearer {token}"}

            # Build full secret name and access URL
            # Format: projects/{project}/secrets/{secret}/versions/latest
            full_name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
            url = f"https://secretmanager.googleapis.com/v1/{full_name}:access"

            # Make API request
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code != 200:
                error_detail = response.json().get('error', {}).get('message', 'Unknown error') if response.text else f"HTTP {response.status_code}"
                return {"success": False, "error": f"API error: {error_detail}"}

            data = response.json()

            # Extract and decode secret value
            payload = data.get("payload", {})
            if isinstance(payload, dict) and "data" in payload:
                raw_data = payload["data"]
                try:
                    # Secret Manager always returns base64 encoded data
                    decoded = base64.b64decode(raw_data).decode("utf-8")
                    return {"success": True, "value": decoded}
                except UnicodeDecodeError:
                    # Binary data - return as base64
                    return {"success": True, "value": raw_data, "is_binary": True}
                except Exception as e:
                    return {"success": False, "error": f"Failed to decode secret: {str(e)}"}

            return {"success": False, "error": "No payload data in response"}

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {str(e)}"}

    async def _update_secret_node_with_value(self, node_id: str, secret_value: str) -> None:
        """Update secret node with the retrieved value."""
        for node in self.graph_state['nodes']:
            if node.get('id') == node_id:
                # Update node data
                node['data']['secretValue'] = secret_value
                node['data']['detailedInfoFetched'] = True
                node['metadata']['lastUpdated'] = datetime.now().isoformat()

                # Broadcast update
                await self.broadcast_callback(
                    create_success_response('graph.node.update', {'node': node})
                )
                logger.info(f"[GCP Secret] Updated node {node_id} with secret value")
                break

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

    def _execute_enumerate_storage(self, manager, execution_id: str, loop, bucket_name: Optional[str] = None):
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

            result = enumerate_storage_buckets(manager, bucket_name=bucket_name)
            return result
        finally:
            storage_module.console = original_console

    def _execute_enumerate_objects(self, manager, execution_id: str, loop, bucket_name: str, prefix: str = ''):
        """Execute storage objects enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.storage_objects import enumerate_bucket_objects

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.storage_objects as objects_module
        original_console = objects_module.console

        try:
            objects_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            result = enumerate_bucket_objects(manager, bucket_name=bucket_name, prefix=prefix if prefix else None)
            return result
        finally:
            objects_module.console = original_console

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

    def _execute_enumerate_exploitable_sas(self, manager, execution_id: str, project_id: Optional[str], loop):
        """Execute exploitable SAs enumeration in thread."""
        from src.clouds.gcp.modules.enumeration.sa_exploitation_targets import enumerate_exploitable_sas

        # Replace console with broadcast console
        import src.clouds.gcp.modules.enumeration.sa_exploitation_targets as sa_targets_module
        original_console = sa_targets_module.console

        try:
            sa_targets_module.console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                loop,
                file=StringIO(),
                width=120,
                force_terminal=False
            )

            # Override Prompt to avoid interactive input
            from rich.prompt import Prompt
            original_prompt_ask = Prompt.ask

            def mock_prompt_ask(prompt, **kwargs):
                if 'Project ID' in prompt:
                    return project_id or manager.current_session_data.get('project_id', '')
                return kwargs.get('default', '')

            Prompt.ask = mock_prompt_ask

            try:
                exploitable = enumerate_exploitable_sas(manager, project_id=project_id)

                # Get total SAs from enumeration data
                service_accounts = manager.get_enumeration_data('service_accounts') or []

                # Return structured data
                return {
                    'project_id': project_id or manager.current_session_data.get('project_id'),
                    'total_sas': len(service_accounts),
                    'exploitable': exploitable,
                }
            finally:
                Prompt.ask = original_prompt_ask

        finally:
            sa_targets_module.console = original_console

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

    async def _create_storage_object_nodes(self, bucket_name: str, objects: list) -> None:
        """Create graph nodes for discovered GCP Storage objects (limited to 10)."""
        # Find bucket node ID - search by bucket name in label or data
        # Handle both 'bucket-name' and 'gs://bucket-name' formats
        bucket_node_id = None
        search_names = [
            bucket_name,
            f"gs://{bucket_name}",
            bucket_name.replace("gs://", "")  # Remove gs:// if present
        ]

        for node in self.graph_state['nodes']:
            if node.get('type') == 'gcp-storage':
                node_bucket_name = node.get('data', {}).get('bucketName') or node.get('label')
                # Try matching with all possible name formats
                if node_bucket_name in search_names or any(node_bucket_name == name for name in search_names):
                    bucket_node_id = node['id']
                    break

        if not bucket_node_id:
            logger.error(f"[GCP Storage] Cannot find bucket node for '{bucket_name}'")
            return

        for idx, obj in enumerate(objects, 1):
            object_name = obj.get('name', '')
            # Create safe node ID
            safe_name = object_name.replace('/', '-').replace('.', '-')
            object_id = f"gcp-obj-{bucket_name}-{safe_name}"[:100]  # Limit ID length

            # Create node for storage object
            node = {
                'id': object_id,
                'type': 'gcp-storage-object',
                'label': object_name.split('/')[-1] or object_name,  # Show only filename
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': bucket_node_id,
                'data': {
                    'objectName': object_name,
                    'bucketName': bucket_name,
                    'size': obj.get('size', 0),
                    'contentType': obj.get('content_type', 'application/octet-stream'),
                    'created': obj.get('created', ''),
                    'updated': obj.get('updated', ''),
                    'storageClass': obj.get('storage_class', 'STANDARD'),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_objects',
                    'fullName': object_name,
                },
                'level': 2,
            }

            await self._add_or_update_node(node)

            # Create edge from bucket to object
            edge = {
                'id': f"edge-{bucket_node_id}-{object_id}",
                'source': bucket_node_id,
                'target': object_id,
                'type': 'contains',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
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
                'parentId': self.current_session_id,  # Link to session as parent
                'data': {
                    'project': bucket['project'],
                    'location': bucket.get('location'),
                    'storage_class': bucket.get('storage_class'),
                    'is_public': bucket.get('is_public', False),
                    'versioning_enabled': bucket.get('versioning_enabled', False),
                    'bucketName': bucket['name'],  # For enumerate objects action
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_storage',
                    'resourceId': bucket.get('id'),
                },
                'level': 1,  # Same level as other enumerated resources
            }

            await self._add_or_update_node(node)

            # Create edge from session to bucket
            if self.current_session_id:
                edge = {
                    'id': f"edge-{self.current_session_id}-{node_id}",
                    'source': self.current_session_id,
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

    async def _update_exploitable_sa_nodes(self, exploitable_sas: list) -> None:
        """Update service account nodes with exploitable permissions data."""
        logger.info(f"[GCP Exploitable SAs] Updating {len(exploitable_sas)} SA nodes with exploitable data")

        for sa_data in exploitable_sas:
            sa_email = sa_data.get('email')
            if not sa_email:
                continue

            node_id = f"gcp-sa-{sa_email}"

            # Find existing node
            existing_node = self._find_node_by_id(node_id)
            if not existing_node:
                logger.warning(f"[GCP Exploitable SAs] Node {node_id} not found, skipping update")
                continue

            # Extract dangerous permissions with severity
            permissions = sa_data.get('permissions', [])
            dangerous_perms = []
            max_severity = 'LOW'

            for perm in permissions:
                perm_data = {
                    'permission': perm.get('permission'),
                    'description': perm.get('description'),
                    'severity': perm.get('severity'),
                }
                dangerous_perms.append(perm_data)

                # Track highest severity
                severity = perm.get('severity', 'LOW')
                if severity == 'CRITICAL':
                    max_severity = 'CRITICAL'
                elif severity == 'HIGH' and max_severity != 'CRITICAL':
                    max_severity = 'HIGH'
                elif severity == 'MEDIUM' and max_severity not in ('CRITICAL', 'HIGH'):
                    max_severity = 'MEDIUM'

            # Update node data
            updates = {
                'data': {
                    **existing_node.get('data', {}),
                    'isExploitable': True,
                    'dangerousPermissions': dangerous_perms,
                    'maxSeverity': max_severity,
                    'disabled': sa_data.get('disabled', False),
                },
            }

            await self._add_or_update_node({**existing_node, **updates})
            logger.info(f"[GCP Exploitable SAs] Updated {node_id} with {len(dangerous_perms)} dangerous permission(s), severity: {max_severity}")

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
                'parentId': self.current_session_id,  # Link to session as parent
                'data': {
                    'project': secret['project'],
                    'location': secret.get('location', 'global'),
                    'version_count': secret.get('version_count', 0),
                    'replication': secret.get('replication'),
                    'secretName': secret['name'],  # For exfil action
                    'fullName': secret.get('full_name'),  # Full resource name
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_secrets',
                    'resourceId': secret.get('full_name'),
                },
                'level': 1,  # Same level as other enumerated resources
            }

            await self._add_or_update_node(node)

            # Create edge from session to secret
            if self.current_session_id:
                edge = {
                    'id': f"edge-{self.current_session_id}-{node_id}",
                    'source': self.current_session_id,
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

    # ==================== IAM Bruteforce ====================

    async def _run_gcp_bruteforce_permissions(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute GCP IAM permissions bruteforce module."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            # Extract mode parameter (default: fast)
            mode = params.get('mode', 'fast')
            services_arg = params.get('services')  # Optional: comma-separated services

            mode_label = {
                'fast': 'Fast (High-value permissions)',
                'full': 'Full (Extended common services)',
                'low': 'Low (Comprehensive)'
            }.get(mode, mode)

            await self._broadcast_module_output(
                execution_id,
                f"🔍 Starting IAM permissions bruteforce ({mode_label} mode)..."
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_bruteforce_permissions,
                    manager,
                    execution_id,
                    services_arg,
                    mode,
                    loop
                )

            if result:
                total_granted = result.get('total_granted', 0)
                total_tested = result.get('total_tested', 0)
                dangerous_count = len(result.get('dangerous_found', []))

                logger.info(f"[GCP Bruteforce] Result keys: {result.keys()}")
                logger.info(f"[GCP Bruteforce] by_service data: {result.get('by_service', {})}")

                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Bruteforce complete: {total_granted}/{total_tested} permissions granted[/green]"
                )

                if dangerous_count > 0:
                    await self._broadcast_module_output(
                        execution_id,
                        f"[red]⚠️  Found {dangerous_count} DANGEROUS permission(s)![/red]"
                    )

                # Create graph nodes for permissions
                await self._create_gcp_permission_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                logger.warning("[GCP Bruteforce] No results returned from bruteforce")
                await self._broadcast_module_error(execution_id, "No results returned from bruteforce")

        except Exception as e:
            logger.error(f"GCP IAM bruteforce failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_bruteforce_permissions(
        self,
        manager,
        execution_id: str,
        services_arg: Optional[str],
        mode: str,
        loop
    ):
        """Execute bruteforce in thread with broadcast console."""
        import src.clouds.gcp.modules.enumeration.iam_bruteforce as bruteforce_module
        from rich.prompt import Prompt
        from rich.progress import Progress

        # Create broadcast console
        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        # Monkey-patch the console, Prompt, and Progress in the module
        original_console = bruteforce_module.console
        original_prompt = Prompt.ask
        original_progress = Progress
        bruteforce_module.console = broadcast_console

        # Override Prompt.ask to use default_project without prompting
        def mock_prompt_ask(prompt_text, default=""):
            # Should never be called since we have default_project set
            # But if it is, return the default silently
            return default

        Prompt.ask = mock_prompt_ask

        # Override Progress to be a no-op context manager that just yields nothing
        # This prevents Rich Progress from blocking in non-terminal mode
        class NoOpProgress:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def add_task(self, *args, **kwargs):
                return 0  # Return dummy task id

            def update(self, *args, **kwargs):
                pass

            def advance(self, *args, **kwargs):
                pass

        # Monkey-patch Progress in the bruteforce module
        import src.clouds.gcp.modules.enumeration.iam_bruteforce as bf_module
        bf_module.Progress = NoOpProgress

        try:
            result = bruteforce_module.enumerate_bruteforce_permissions(
                manager,
                services_arg=services_arg,
                mode=mode
            )
            return result
        finally:
            # Restore original console, prompt, and Progress
            bruteforce_module.console = original_console
            Prompt.ask = original_prompt
            bf_module.Progress = original_progress

    async def _create_gcp_permission_nodes(self, bruteforce_result: Dict[str, Any]) -> None:
        """
        Create GCP permission nodes with shared service nodes across modes.

        Structure:
        - Session node (root)
          ├─ gcp-permissions (FAST mode parent)
          ├─ gcp-permissions (FULL mode parent)
          ├─ gcp-permissions (LOW mode parent)
          ├─ gcp-iam-perms (shared service node)
          ├─ gcp-storage-perms (shared service node)
          └─ gcp-compute-perms (shared service node)

        Edges:
        - Session → FAST parent
        - Session → FULL parent
        - Session → LOW parent
        - FAST parent → IAM service (if IAM found in FAST)
        - FULL parent → IAM service (if IAM found in FULL)
        - FULL parent → Compute service (if Compute found in FULL)

        Service nodes accumulate permissions from all modes.
        """
        logger.info("[GCP Bruteforce] Creating permission nodes from bruteforce results")

        if not self.current_session_id:
            logger.warning("[GCP Bruteforce] No current session ID, cannot create nodes")
            return

        by_service = bruteforce_result.get('by_service', {})

        if not by_service:
            logger.warning("[GCP Bruteforce] No service data in results")
            return

        mode = bruteforce_result.get('mode', 'fast')
        project_id = bruteforce_result.get('project_id', 'unknown')

        # Create mode-specific parent permissions node
        parent_node_id = f"permissions-{self.current_session_id}-{mode}"

        parent_node = {
            'id': parent_node_id,
            'type': 'gcp-permissions',
            'label': f'Permissions Enumerated ({mode.upper()})',
            'provider': 'gcp',
            'discoveredBy': [self.current_session_id],
            'parentId': self.current_session_id,
            'data': {
                'project': project_id,
                'mode': mode,
                'totalGranted': bruteforce_result.get('total_granted', 0),
                'totalTested': bruteforce_result.get('total_tested', 0),
                'dangerousCount': len(bruteforce_result.get('dangerous_found', [])),
                'dangerousPermissions': bruteforce_result.get('dangerous_found', []),
            },
            'metadata': {
                'discoveredAt': datetime.now().isoformat(),
                'moduleUsed': 'gcp_bruteforce_permissions',
                'project': project_id,
                'mode': mode,
            },
            'level': 1,
        }

        # Add parent node to graph
        await self._add_or_update_node(parent_node)

        # Create edge from session to parent permissions node
        edge = {
            'id': f"edge-{self.current_session_id}-{parent_node_id}",
            'source': self.current_session_id,
            'target': parent_node_id,
            'type': 'owns',
            'label': 'bruteforced',
            'discoveredBy': [self.current_session_id],
        }
        await self._add_edge(edge)

        # Create or update shared service nodes (only for services with granted permissions)
        services_with_grants = {k: v for k, v in by_service.items() if v.get('granted', 0) > 0}
        logger.info(f"[GCP Bruteforce] Processing {len(services_with_grants)} services for mode {mode.upper()}")

        for service_name, perms in services_with_grants.items():
            # Shared service node ID (NOT mode-specific)
            service_node_id = f"gcp-{service_name}-perms-{self.current_session_id}"

            # Count dangerous permissions for this service
            dangerous_in_service = [
                p for p in perms['granted_permissions']
                if p in bruteforce_result.get('dangerous_found', [])
            ]

            # Check if service node already exists
            existing_node = self._find_node_by_id(service_node_id)

            if existing_node:
                # Merge permissions into existing node
                logger.info(f"[GCP Bruteforce] Updating existing service node: {service_name}")

                # Merge allowed permissions (union of sets)
                existing_allowed = set(existing_node['data'].get('allowedPermissions', []))
                new_allowed = set(perms['granted_permissions'])
                merged_allowed = list(existing_allowed | new_allowed)

                # Merge denied permissions (union of sets)
                existing_denied = set(existing_node['data'].get('deniedPermissions', []))
                new_denied = set(perms['denied_permissions'])
                merged_denied = list(existing_denied | new_denied)

                # Merge dangerous permissions
                existing_dangerous = set(existing_node['data'].get('dangerousPermissions', []))
                new_dangerous = set(dangerous_in_service)
                merged_dangerous = list(existing_dangerous | new_dangerous)

                # Update modes list
                existing_modes = existing_node['data'].get('modes', [])
                if mode not in existing_modes:
                    existing_modes.append(mode)

                # Update node data
                existing_node['data']['modes'] = existing_modes
                existing_node['data']['totalPermissions'] = len(merged_allowed) + len(merged_denied)
                existing_node['data']['allowedCount'] = len(merged_allowed)
                existing_node['data']['deniedCount'] = len(merged_denied)
                existing_node['data']['dangerousCount'] = len(merged_dangerous)
                existing_node['data']['allowedPermissions'] = merged_allowed
                existing_node['data']['deniedPermissions'] = merged_denied
                existing_node['data']['dangerousPermissions'] = merged_dangerous
                existing_node['metadata']['lastUpdated'] = datetime.now().isoformat()

                # Broadcast update
                await self.broadcast_callback(
                    create_success_response('graph.node.update', {'node': existing_node})
                )
            else:
                # Create new shared service node
                logger.info(f"[GCP Bruteforce] Creating new service node: {service_name}")

                service_node = {
                    'id': service_node_id,
                    'type': f'gcp-{service_name}-perms',
                    'label': service_name.upper(),
                    'provider': 'gcp',
                    'discoveredBy': [self.current_session_id],
                    'parentId': None,  # No single parent - connected to multiple mode parents
                    'data': {
                        'service': service_name,
                        'modes': [mode],
                        'totalPermissions': perms['total'],
                        'allowedCount': perms['granted'],
                        'deniedCount': perms['denied'],
                        'dangerousCount': len(dangerous_in_service),
                        'allowedPermissions': perms['granted_permissions'],
                        'deniedPermissions': perms['denied_permissions'],
                        'dangerousPermissions': dangerous_in_service,
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'lastUpdated': datetime.now().isoformat(),
                        'moduleUsed': 'gcp_bruteforce_permissions',
                        'service': service_name,
                        'project': project_id,
                    },
                    'level': 2,
                }

                await self._add_or_update_node(service_node)

            # Create edge from mode parent to service node
            edge = {
                'id': f"edge-{parent_node_id}-{service_node_id}",
                'source': parent_node_id,
                'target': service_node_id,
                'type': 'contains',
                'label': service_name,
                'discoveredBy': [self.current_session_id],
            }
            await self._add_edge(edge)

        logger.info(f"[GCP Bruteforce] Successfully processed permission node for {mode.upper()} with {len(services_with_grants)} services")

    # ==================== Cloud Functions ====================

    async def _run_gcp_enumerate_functions(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Cloud Functions."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Cloud Functions...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_functions,
                    manager,
                    execution_id,
                    params,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} Cloud Function(s)[/green]"
                )

                # Create graph nodes
                await self._create_function_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No Cloud Functions found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"[GCP Functions] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_enumerate_functions(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute Cloud Functions enumeration in thread pool."""
        from src.clouds.gcp.modules.enumeration.cloud_functions import enumerate_cloud_functions

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            functions = enumerate_cloud_functions(manager)

        return functions

    async def _create_function_nodes(self, functions: list):
        """Create graph nodes for Cloud Functions."""
        if not functions:
            return

        category_node_id = await self._get_or_create_category_node('functions', 'Functions')

        for func in functions:
            node_id = f"gcp-function-{func.get('project', '')}-{func.get('name', '')}"

            node = {
                'id': node_id,
                'type': 'gcp-function',
                'label': func.get('name', ''),
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': category_node_id,
                'data': {
                    'project': func.get('project', ''),
                    'name': func.get('name', ''),
                    'generation': func.get('generation', ''),
                    'location': func.get('location', ''),
                    'runtime': func.get('runtime', ''),
                    'entry_point': func.get('entry_point', ''),
                    'status': func.get('status', ''),
                    'trigger_type': func.get('trigger_type', ''),
                    'trigger_url': func.get('trigger_url', ''),
                    'service_account': func.get('service_account', ''),
                    'environment_variables': func.get('environment_variables', {}),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_functions',
                },
                'level': 2,
            }

            await self._add_or_update_node(node)

            # Create edge
            if category_node_id:
                edge = {
                    'id': f"{category_node_id}-contains-{node_id}",
                    'source': category_node_id,
                    'target': node_id,
                    'type': 'contains',
                    'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                }
                await self._add_edge(edge)

    # ==================== Parameters ====================

    async def _run_gcp_enumerate_parameters(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Parameter Manager parameters."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Parameter Manager...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_parameters,
                    manager,
                    execution_id,
                    params,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} parameter(s)[/green]"
                )

                # Create graph nodes
                await self._create_parameter_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No parameters found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"[GCP Parameters] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_enumerate_parameters(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute Parameter Manager enumeration in thread pool."""
        from src.clouds.gcp.modules.enumeration.parameter_manager import enumerate_parameters

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        project_id = params.get('project')

        with broadcast_console.capture():
            parameters = enumerate_parameters(manager, project_id=project_id)

        return parameters

    async def _create_parameter_nodes(self, parameters: list):
        """Create graph nodes for Parameter Manager parameters."""
        if not parameters:
            return

        category_node_id = await self._get_or_create_category_node('parameters', 'Parameters')

        for param in parameters:
            node_id = f"gcp-parameter-{param.get('project', '')}-{param.get('name', '')}"

            node = {
                'id': node_id,
                'type': 'gcp-parameter',
                'label': param.get('name', ''),
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': category_node_id,
                'data': {
                    'project': param.get('project', ''),
                    'name': param.get('name', ''),
                    'location': param.get('location', ''),
                    'format': param.get('format', ''),
                    'version_count': param.get('version_count', 0),
                    'labels': param.get('labels', {}),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_parameters',
                },
                'level': 2,
            }

            await self._add_or_update_node(node)

            # Create edge
            if category_node_id:
                edge = {
                    'id': f"{category_node_id}-contains-{node_id}",
                    'source': category_node_id,
                    'target': node_id,
                    'type': 'contains',
                    'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                }
                await self._add_edge(edge)

    # ==================== Cloud SQL ====================

    async def _run_gcp_enumerate_sql(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Cloud SQL instances."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Cloud SQL instances...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_sql,
                    manager,
                    execution_id,
                    params,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} Cloud SQL instance(s)[/green]"
                )

                # Create graph nodes
                await self._create_sql_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No Cloud SQL instances found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"[GCP Cloud SQL] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_enumerate_sql(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute Cloud SQL enumeration in thread pool."""
        from src.clouds.gcp.modules.enumeration.cloud_sql import enumerate_cloud_sql

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            instances = enumerate_cloud_sql(manager)

        return instances

    async def _create_sql_nodes(self, instances: list):
        """Create graph nodes for Cloud SQL instances."""
        if not instances:
            return

        category_node_id = await self._get_or_create_category_node('cloudsql', 'Cloud SQL')

        for instance in instances:
            node_id = f"gcp-cloudsql-{instance.get('project', '')}-{instance.get('name', '')}"

            # Determine severity based on security issues
            severity = 'LOW'
            if instance.get('has_open_access'):
                severity = 'CRITICAL'
            elif instance.get('has_public_ip') and not instance.get('require_ssl'):
                severity = 'HIGH'
            elif instance.get('has_public_ip'):
                severity = 'MEDIUM'

            node = {
                'id': node_id,
                'type': 'gcp-cloudsql',
                'label': instance.get('name', ''),
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': category_node_id,
                'data': {
                    'project': instance.get('project', ''),
                    'name': instance.get('name', ''),
                    'database_type': instance.get('database_type', ''),
                    'database_version': instance.get('database_version', ''),
                    'state': instance.get('state', ''),
                    'region': instance.get('region', ''),
                    'public_ip': instance.get('public_ip'),
                    'private_ip': instance.get('private_ip'),
                    'has_public_ip': instance.get('has_public_ip', False),
                    'has_open_access': instance.get('has_open_access', False),
                    'require_ssl': instance.get('require_ssl', False),
                    'connection_name': instance.get('connection_name', ''),
                    'databases': instance.get('databases', []),
                    'users': instance.get('users', []),
                    'severity': severity,
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_sql',
                },
                'level': 2,
            }

            await self._add_or_update_node(node)

            # Create edge
            if category_node_id:
                edge = {
                    'id': f"{category_node_id}-contains-{node_id}",
                    'source': category_node_id,
                    'target': node_id,
                    'type': 'contains',
                    'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                }
                await self._add_edge(edge)
# Temporary file for the 4 additional handlers
# Cloud Build, Cloud Run, Compute Metadata, Google Drive, Resource Permissions

    # ==================== Cloud Build ====================

    async def _run_gcp_enumerate_cloud_build(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Cloud Build triggers."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Cloud Build triggers...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_cloud_build,
                    manager,
                    execution_id,
                    params,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} Cloud Build trigger(s)[/green]"
                )

                # Create graph nodes
                await self._create_cloud_build_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No Cloud Build triggers found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"[GCP Cloud Build] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_enumerate_cloud_build(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute Cloud Build enumeration in thread pool."""
        from src.clouds.gcp.modules.enumeration.cloud_build import enumerate_cloud_build_triggers

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            triggers = enumerate_cloud_build_triggers(manager)

        return triggers

    async def _create_cloud_build_nodes(self, triggers: list):
        """Create graph nodes for Cloud Build triggers."""
        if not triggers:
            return

        category_node_id = await self._get_or_create_category_node('cloudbuild', 'Cloud Build')

        for trigger in triggers:
            node_id = f"gcp-cloudbuild-{trigger.get('project', '')}-{trigger.get('id', '')}"

            node = {
                'id': node_id,
                'type': 'gcp-cloudbuild',
                'label': trigger.get('name', ''),
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': category_node_id,
                'data': {
                    'project': trigger.get('project', ''),
                    'name': trigger.get('name', ''),
                    'description': trigger.get('description', ''),
                    'disabled': trigger.get('disabled', False),
                    'repository_type': trigger.get('repository_type', ''),
                    'repository_name': trigger.get('repository_name', ''),
                    'service_account': trigger.get('service_account', ''),
                    'substitutions': trigger.get('substitutions', {}),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_cloud_build',
                },
                'level': 2,
            }

            await self._add_or_update_node(node)

            # Create edge
            if category_node_id:
                edge = {
                    'id': f"{category_node_id}-contains-{node_id}",
                    'source': category_node_id,
                    'target': node_id,
                    'type': 'contains',
                    'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                }
                await self._add_edge(edge)

    # ==================== Cloud Run ====================

    async def _run_gcp_enumerate_cloud_run(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Cloud Run services."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Cloud Run services...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_cloud_run,
                    manager,
                    execution_id,
                    params,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} Cloud Run service(s)[/green]"
                )

                # Create graph nodes
                await self._create_cloud_run_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No Cloud Run services found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"[GCP Cloud Run] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_enumerate_cloud_run(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute Cloud Run enumeration in thread pool."""
        from src.clouds.gcp.modules.enumeration.cloud_run_services import enumerate_cloud_run_services

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            services = enumerate_cloud_run_services(manager)

        return services

    async def _create_cloud_run_nodes(self, services: list):
        """Create graph nodes for Cloud Run services."""
        if not services:
            return

        category_node_id = await self._get_or_create_category_node('cloudrun', 'Cloud Run')

        for service in services:
            node_id = f"gcp-cloudrun-{service.get('project', '')}-{service.get('name', '')}"

            node = {
                'id': node_id,
                'type': 'gcp-cloudrun',
                'label': service.get('name', ''),
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': category_node_id,
                'data': {
                    'project': service.get('project', ''),
                    'name': service.get('name', ''),
                    'region': service.get('region', ''),
                    'url': service.get('url', ''),
                    'ingress': service.get('ingress', ''),
                    'service_account': service.get('service_account', ''),
                    'image': service.get('image', ''),
                    'environment_variables': service.get('environment_variables', {}),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_cloud_run',
                },
                'level': 2,
            }

            await self._add_or_update_node(node)

            # Create edge
            if category_node_id:
                edge = {
                    'id': f"{category_node_id}-contains-{node_id}",
                    'source': category_node_id,
                    'target': node_id,
                    'type': 'contains',
                    'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                }
                await self._add_edge(edge)

    # ==================== Compute Metadata ====================

    async def _run_gcp_enumerate_compute_metadata(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Compute Engine metadata."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Compute Engine metadata...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_compute_metadata,
                    manager,
                    execution_id,
                    params,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Extracted metadata from {len(result)} instance(s)[/green]"
                )

                # Metadata enriches existing compute nodes, no new nodes created
                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No compute metadata found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"[GCP Compute Metadata] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_enumerate_compute_metadata(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute Compute metadata enumeration in thread pool."""
        from src.clouds.gcp.modules.enumeration.compute_metadata import enumerate_compute_metadata

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            metadata = enumerate_compute_metadata(manager)

        return metadata

    # ==================== Google Drive ====================

    async def _run_gcp_enumerate_google_drive(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Enumerate Google Drive files."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            await self._broadcast_module_output(execution_id, "[bold]Enumerating Google Drive files...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_enumerate_google_drive,
                    manager,
                    execution_id,
                    params,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} Drive file(s)[/green]"
                )

                # Create graph nodes
                await self._create_google_drive_nodes(result)

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No Google Drive files found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"[GCP Google Drive] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_enumerate_google_drive(self, manager, execution_id: str, params: Dict[str, Any], loop):
        """Execute Google Drive enumeration in thread pool."""
        from src.clouds.gcp.modules.enumeration.google_drive import enumerate_google_drive

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            files = enumerate_google_drive(manager)

        return files

    async def _create_google_drive_nodes(self, files: list):
        """Create graph nodes for Google Drive files."""
        if not files:
            return

        category_node_id = await self._get_or_create_category_node('google-drive', 'Google Drive')

        for file in files:
            node_id = f"gcp-drive-{file.get('id', '')}"

            node = {
                'id': node_id,
                'type': 'gcp-drive',
                'label': file.get('name', ''),
                'provider': 'gcp',
                'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                'parentId': category_node_id,
                'data': {
                    'file_id': file.get('id', ''),
                    'name': file.get('name', ''),
                    'mime_type': file.get('mimeType', ''),
                    'size': file.get('size', 0),
                    'created_time': file.get('createdTime', ''),
                    'modified_time': file.get('modifiedTime', ''),
                    'shared': file.get('shared', False),
                    'owners': file.get('owners', []),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'gcp_enumerate_google_drive',
                },
                'level': 2,
            }

            await self._add_or_update_node(node)

            # Create edge
            if category_node_id:
                edge = {
                    'id': f"{category_node_id}-contains-{node_id}",
                    'source': category_node_id,
                    'target': node_id,
                    'type': 'contains',
                    'discoveredBy': [self.current_session_id] if self.current_session_id else [],
                }
                await self._add_edge(edge)

    # ==================== Resource Permissions ====================

    async def _run_gcp_resource_permissions(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Get permissions for a specific resource."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            resource = params.get('resource')
            if not resource:
                await self._broadcast_module_error(execution_id, "Missing required parameter: resource")
                return

            await self._broadcast_module_output(execution_id, f"[bold]Getting permissions for {resource}...[/bold]")

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_resource_permissions,
                    manager,
                    execution_id,
                    resource,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Retrieved permissions for {resource}[/green]"
                )

                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No permissions found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"[GCP Resource Permissions] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_resource_permissions(self, manager, execution_id: str, resource: str, loop):
        """Execute resource permissions query in thread pool."""
        from src.clouds.gcp.modules.enumeration.resource_permissions import get_resource_permissions

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            permissions = get_resource_permissions(manager, resource)

        return permissions

    # ==================== Exfiltration ====================

    async def _run_gcp_download_object(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Download a Cloud Storage object."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            bucket = params.get('bucket')
            object_name = params.get('object')

            if not bucket or not object_name:
                await self._broadcast_module_error(execution_id, "Missing required parameters: bucket and object")
                return

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Downloading gs://{bucket}/{object_name}...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_download_object,
                    manager,
                    execution_id,
                    bucket,
                    object_name,
                    params.get('output'),
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Downloaded to: {result}[/green]"
                )
                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[red]Download failed[/red]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"[GCP Download Object] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_download_object(self, manager, execution_id: str, bucket: str, object_name: str, output: Optional[str], loop):
        """Execute storage object download in thread pool."""
        from src.clouds.gcp.modules.exfiltration.storage_exfil import download_object

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            result = download_object(manager, bucket, object_name, output)

        return result

    async def _run_gcp_exfil_parameter(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Get a specific parameter value."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            param_name = params.get('name')
            project = params.get('project')

            if not param_name:
                await self._broadcast_module_error(execution_id, "Missing required parameter: name")
                return

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Getting parameter value: {param_name}...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_exfiltrate_parameter,
                    manager,
                    execution_id,
                    param_name,
                    project,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Retrieved parameter value[/green]"
                )
                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]Failed to get parameter value[/yellow]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"[GCP Get Parameter] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_exfiltrate_parameter(self, manager, execution_id: str, param_name: str, project: Optional[str], loop):
        """Execute parameter value retrieval in thread pool."""
        from src.clouds.gcp.modules.exfiltration.parameter_exfil import exfiltrate_parameter

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            result = exfiltrate_parameter(manager, param_name, project)

        return result

    # ==================== Lateral Movement ====================

    async def _run_gcp_map_impersonation(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Map service account impersonation graph."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            project = params.get('project')

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Mapping impersonation graph{' for ' + project if project else ''}...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_map_impersonation,
                    manager,
                    execution_id,
                    project,
                    loop
                )

            if result:
                graph = result.get('graph', {})
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Mapped {len(graph)} service account(s)[/green]"
                )
                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No impersonation graph created[/yellow]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"[GCP Map Impersonation] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_map_impersonation(self, manager, execution_id: str, project: Optional[str], loop):
        """Execute impersonation mapping in thread pool."""
        from src.clouds.gcp.modules.lateral_movement.implicit_delegation import map_impersonation_graph

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            result = map_impersonation_graph(manager, project_id=project)

        return result

    async def _run_gcp_find_chains(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Find service account delegation chains."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            target_sa = params.get('target_sa')
            if not target_sa:
                await self._broadcast_module_error(execution_id, "Missing required parameter: target_sa")
                return

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Finding delegation chains to {target_sa}...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_find_chains,
                    manager,
                    execution_id,
                    target_sa,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Found {len(result)} delegation chain(s)[/green]"
                )
                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[yellow]No delegation chains found[/yellow]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"[GCP Find Chains] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_find_chains(self, manager, execution_id: str, target_sa: str, loop):
        """Execute chain finding in thread pool."""
        from src.clouds.gcp.modules.lateral_movement.implicit_delegation import find_delegation_chains

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            chains = find_delegation_chains(manager, target_sa=target_sa)

        return chains

    async def _run_gcp_impersonate(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Impersonate a service account."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            service_account = params.get('service_account')
            if not service_account:
                await self._broadcast_module_error(execution_id, "Missing required parameter: service_account")
                return

            delegates_str = params.get('delegates', '')
            delegates = [d.strip() for d in delegates_str.split(',')] if delegates_str else None

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Impersonating {service_account}...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_impersonate,
                    manager,
                    execution_id,
                    service_account,
                    delegates,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Successfully impersonated {service_account}[/green]"
                )
                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[red]Impersonation failed[/red]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"[GCP Impersonate] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_impersonate(self, manager, execution_id: str, service_account: str, delegates: Optional[List[str]], loop):
        """Execute impersonation in thread pool."""
        from src.clouds.gcp.modules.lateral_movement.implicit_delegation import impersonate_service_account

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            # Convert delegates list to chain format if provided
            chain_index = None
            if delegates:
                # Store delegates in a temporary chain for the function to use
                # The function will pick them up from session data
                pass
            
            success = impersonate_service_account(
                manager,
                target_sa=service_account,
                chain_index=chain_index,
                show_curl=True
            )

        return success

    async def _run_gcp_sign_jwt(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Sign JWT as a service account."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            service_account = params.get('service_account')
            if not service_account:
                await self._broadcast_module_error(execution_id, "Missing required parameter: service_account")
                return

            payload = params.get('payload')
            if payload and isinstance(payload, str):
                import json
                try:
                    payload = json.loads(payload)
                except:
                    payload = None

            delegates_str = params.get('delegates', '')
            delegates = [d.strip() for d in delegates_str.split(',')] if delegates_str else None

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Signing JWT as {service_account}...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_sign_jwt,
                    manager,
                    execution_id,
                    service_account,
                    payload,
                    delegates,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ JWT signed successfully[/green]"
                )
                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[red]JWT signing failed[/red]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"[GCP Sign JWT] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_sign_jwt(self, manager, execution_id: str, service_account: str, payload: Optional[Dict], delegates: Optional[List[str]], loop):
        """Execute JWT signing in thread pool."""
        from src.clouds.gcp.modules.lateral_movement.sign_jwt import sign_jwt

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        with broadcast_console.capture():
            result = sign_jwt(
                manager,
                service_account_email=service_account,
                payload=payload,
                delegates=delegates
            )

        return result

    async def _run_gcp_sign_blob(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Sign blob as a service account."""
        try:
            manager = self._get_or_create_gcp_manager()
            if not manager:
                await self._broadcast_module_error(execution_id, "No GCP session manager")
                return

            service_account = params.get('service_account')
            data = params.get('data')

            if not service_account:
                await self._broadcast_module_error(execution_id, "Missing required parameter: service_account")
                return

            if not data:
                await self._broadcast_module_error(execution_id, "Missing required parameter: data")
                return

            delegates_str = params.get('delegates', '')
            delegates = [d.strip() for d in delegates_str.split(',')] if delegates_str else None

            await self._broadcast_module_output(
                execution_id,
                f"[bold]Signing blob as {service_account}...[/bold]"
            )

            # Execute in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor,
                    self._execute_sign_blob,
                    manager,
                    execution_id,
                    service_account,
                    data,
                    delegates,
                    loop
                )

            if result:
                await self._broadcast_module_output(
                    execution_id,
                    f"[green]✓ Blob signed successfully[/green]"
                )
                await self._broadcast_module_complete(execution_id, success=True)
            else:
                await self._broadcast_module_output(execution_id, "[red]Blob signing failed[/red]")
                await self._broadcast_module_complete(execution_id, success=False)

        except Exception as e:
            logger.error(f"[GCP Sign Blob] Error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _execute_sign_blob(self, manager, execution_id: str, service_account: str, data: str, delegates: Optional[List[str]], loop):
        """Execute blob signing in thread pool."""
        from src.clouds.gcp.modules.lateral_movement.sign_jwt import sign_blob

        broadcast_console = self.BroadcastConsole(
            self._broadcast_module_output_sync,
            execution_id,
            loop,
            file=StringIO(),
            width=120,
            force_terminal=False
        )

        # Convert string to bytes
        blob = data.encode('utf-8')

        with broadcast_console.capture():
            result = sign_blob(
                manager,
                service_account_email=service_account,
                blob=blob,
                delegates=delegates
            )

        return result
