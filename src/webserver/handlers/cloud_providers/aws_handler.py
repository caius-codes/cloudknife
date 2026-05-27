"""
AWS-specific WebSocket handlers.
Extracted from ws_handlers.py - handles all AWS module execution and graph node creation.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import json
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


class AWSHandler(BaseHandler):
    """
    Handler for AWS-specific WebSocket operations.
    
    Handles:
    - IAM enumeration (roles, users, groups, policies)
    - Permission bruteforcing and privilege escalation analysis
    - Secrets Manager operations
    - S3, EC2, Lambda, RDS, DynamoDB operations
    - Role assumption and lateral movement
    - Graph node creation for all AWS resources
    """

    class BroadcastConsole(RichConsole):
        def __init__(self, broadcast_func, exec_id, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.broadcast_func = broadcast_func
            self.exec_id = exec_id
            self.loop = asyncio.get_event_loop()

        def print(self, *objects, **kwargs):
            # Get the rendered text
            from io import StringIO
            output = StringIO()
            temp_console = RichConsole(file=output, width=120, force_terminal=False)
            temp_console.print(*objects, **kwargs)
            text = output.getvalue().rstrip('\n')

            # Broadcast it
            if text:
                import asyncio
                asyncio.run_coroutine_threadsafe(
                    self.broadcast_func(self.exec_id, text),
                    self.loop
                )

            # Also write to parent
            super().print(*objects, **kwargs)


    async def _handle_assume_role(self, message: WebSocketMessage) -> WebSocketResponse:
        """Handle assume role request."""
        try:
            payload = message.payload
            role_arn = payload.get('role_arn')  # Optional: if not provided, enumerate and assume all
            new_session_name = payload.get('new_session_name')
            auto_assume_all = payload.get('auto_assume_all', False)  # Flag for auto-assume all roles

            if not self.current_session or not self.current_cloud:
                return create_error_response(
                    message.type,
                    "No active session. Create or switch to a session first.",
                    message.request_id
                )

            if self.current_cloud != 'aws':
                return create_error_response(
                    message.type,
                    "Assume role is only supported for AWS",
                    message.request_id
                )

            # Generate execution ID
            execution_id = f"assume-role-{message.request_id}"

            # Start assume role execution in background
            if not role_arn or auto_assume_all:
                # No role specified or auto_assume_all flag: enumerate and assume all assumable roles
                asyncio.create_task(
                    self._execute_assume_all_roles_async(
                        execution_id
                    )
                )
            else:
                # Single role specified
                asyncio.create_task(
                    self._execute_assume_role_async(
                        role_arn,
                        new_session_name,
                        execution_id
                    )
                )

            return create_success_response(
                message.type,
                {
                    'execution_id': execution_id,
                    'role_arn': role_arn or 'auto',
                    'status': 'started',
                },
                message.request_id
            )

        except Exception as e:
            logger.error(f"Error handling assume role: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)


    async def _execute_assume_role_async(
        self,
        role_arn: str,
        new_session_name: Optional[str],
        execution_id: str
    ) -> None:
        """Execute assume role in background and stream output."""
        logger.info(f"[AssumeRole] Starting: {role_arn} (execution_id: {execution_id})")
        try:
            from concurrent.futures import ThreadPoolExecutor
            from io import StringIO
            from botocore.exceptions import ClientError

            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Check if current session has credentials
            if not manager.current_session_data.get("access_key"):
                await self._broadcast_module_error(
                    execution_id,
                    "No credentials in current session"
                )
                return

            # Generate new session name if not provided
            if not new_session_name:
                base_session_name = self.current_session or "default"
                new_session_name = f"{base_session_name}-{role_arn.split('/')[-1]}"

            # Validate session name
            if not manager.validate_session_name(new_session_name):
                await self._broadcast_module_error(
                    execution_id,
                    "Invalid session name. Only alphanumeric characters, hyphens (-), and underscores (_) are allowed."
                )
                return

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Broadcast start
            await self._broadcast_module_output(execution_id, "🔁 Lateral movement via sts:AssumeRole")
            await self._broadcast_module_output(execution_id, f"Base session: {self.current_session}")
            await self._broadcast_module_output(execution_id, f"Role ARN:     {role_arn}")
            await self._broadcast_module_output(execution_id, f"New session:  {new_session_name}")
            await self._broadcast_module_output(execution_id, f"Region:       {manager.default_region}")

            # Call sts:AssumeRole
            loop = asyncio.get_event_loop()

            def assume_role_sync():
                base_boto_sess = manager.get_boto3_session()
                sts = base_boto_sess.client("sts")
                try:
                    resp = sts.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=f"cloudknife-{self.current_session}",
                        DurationSeconds=3600,
                    )
                    return resp, None
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    return None, f"AssumeRole failed: {code} - {str(e)[:200]}"
                except Exception as e:
                    return None, f"AssumeRole failed: {str(e)[:200]}"

            with ThreadPoolExecutor() as executor:
                resp, error = await loop.run_in_executor(executor, assume_role_sync)

            if error:
                await self._broadcast_module_output(execution_id, f"❌ {error}")
                await self._broadcast_module_error(execution_id, error)
                return

            # Extract credentials
            creds = resp["Credentials"]
            access_key = creds["AccessKeyId"]
            secret_key = creds["SecretAccessKey"]
            session_token = creds["SessionToken"]
            expiration = creds.get("Expiration", "")

            # Save current session name to restore later
            original_session = manager.current_session

            # Create new session
            manager.create_or_load_session(new_session_name)
            manager.current_session_data.update({
                "access_key": access_key,
                "secret_key": secret_key,
                "session_token": session_token,
                "region": manager.default_region,
            })
            manager.save_current_session()

            # Get the UUID of the new session before restoring original
            new_session_id = manager.current_session_data.get("session_id", new_session_name)

            # Restore original session
            manager.create_or_load_session(original_session)

            await self._broadcast_module_output(execution_id, "✓ New session created with assumed-role credentials")
            await self._broadcast_module_output(execution_id, f"\n✅ Assumed role credentials configured")
            await self._broadcast_module_output(execution_id, f"Session: {new_session_name}")
            if expiration:
                await self._broadcast_module_output(execution_id, f"Expiration: {str(expiration)[:19]}")
            await self._broadcast_module_output(execution_id, f"Region: {manager.default_region}")

            # Create graph nodes and edges
            try:
                await self._create_assume_role_nodes(role_arn, new_session_name, new_session_id, manager)
            except Exception as node_error:
                logger.error(f"Error creating assume role nodes: {node_error}", exc_info=True)
                await self._broadcast_module_output(execution_id, f"⚠️  Warning: Could not create graph nodes: {node_error}")

            await self._broadcast_module_output(execution_id, "\n✓ Assume role completed successfully")
            await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"AssumeRole execution failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_assume_role_nodes(self, role_arn: str, new_session_name: str, new_session_id: str, manager) -> None:
        """Create graph nodes for assumed role and new session."""
        logger.info(f"[_create_assume_role_nodes] START - role_arn={role_arn}, new_session_name={new_session_name}, new_session_id={new_session_id}")

        if not self.broadcast_callback:
            logger.warning("[AssumeRole] Cannot create nodes - no broadcast callback")
            return

        from datetime import datetime

        # Extract role name from ARN
        role_name = role_arn.split('/')[-1]
        logger.info(f"[_create_assume_role_nodes] Creating nodes for role: {role_name}")

        # Create node for the IAM role
        role_node = {
            'id': f"role-{role_arn}",
            'type': 'aws-role',
            'label': role_name,
            'provider': 'aws',
            'discoveredBy': [self.current_session_id],
            'parentId': self.current_session_id,
            'data': {
                'roleArn': role_arn,
                'roleName': role_name,
                'assumedAt': datetime.now().isoformat(),
            },
            'metadata': {
                'arn': role_arn,
                'discoveredAt': datetime.now().isoformat(),
                'moduleUsed': 'assume_role',
            },
            'level': 1,
        }

        # Create node for new session
        new_session_node = {
            'id': new_session_id,
            'type': 'aws-session',
            'label': new_session_name,
            'provider': 'aws',
            'discoveredBy': [new_session_id],  # New session discovers itself
            'parentId': None,
            'data': {
                'sessionName': new_session_name,
                'sessionId': new_session_id,
                'createdAt': datetime.now().isoformat(),
                'assumedFrom': self.current_session,
                'roleArn': role_arn,
            },
            'metadata': {
                'discoveredAt': datetime.now().isoformat(),
                'moduleUsed': 'assume_role',
            },
            'level': 0,
        }

        # Create edge from original session to role
        edge1 = {
            'id': f'edge-{self.current_session}-{role_arn}',
            'source': self.current_session_id,
            'target': f'role-{role_arn}',
            'label': 'can assume',
            'type': 'assume',
            'discoveredBy': [self.current_session_id],
        }

        # Create edge from role to new session
        edge2 = {
            'id': f'edge-{role_arn}-{new_session_id}',
            'source': f'role-{role_arn}',
            'target': new_session_id,
            'label': 'creates',
            'type': 'creates_session',
            'discoveredBy': [new_session_id],  # New session discovers this edge
        }

        # Add to graph state
        self.graph_state['nodes'].append(role_node)
        self.graph_state['nodes'].append(new_session_node)
        self.graph_state['edges'].append(edge1)
        self.graph_state['edges'].append(edge2)

        # Broadcast to clients
        logger.info(f"[_create_assume_role_nodes] Broadcasting role node: {role_node['id']}")
        await self.broadcast_callback(
            create_success_response(
                'graph.node.add',
                {'node': role_node}
            )
        )
        logger.info(f"[_create_assume_role_nodes] Broadcasting session node: {new_session_node['id']}")
        await self.broadcast_callback(
            create_success_response(
                'graph.node.add',
                {'node': new_session_node}
            )
        )
        logger.info(f"[_create_assume_role_nodes] Broadcasting edge 1: {edge1['id']}")
        await self.broadcast_callback(
            create_success_response(
                'graph.edge.add',
                {'edge': edge1}
            )
        )
        logger.info(f"[_create_assume_role_nodes] Broadcasting edge 2: {edge2['id']}")
        await self.broadcast_callback(
            create_success_response(
                'graph.edge.add',
                {'edge': edge2}
            )
        )

        logger.info(f"[_create_assume_role_nodes] COMPLETED - Created nodes for role {role_name} and session {new_session_name}")


    async def _execute_assume_all_roles_async(
        self,
        execution_id: str
    ) -> None:
        """Enumerate all roles and automatically assume all assumable roles."""
        logger.info(f"[AssumeAll] Starting auto-assume all roles (execution_id: {execution_id})")
        try:
            from concurrent.futures import ThreadPoolExecutor
            from io import StringIO
            from botocore.exceptions import ClientError
            from src.clouds.aws.modules.enumeration.iam_roles import enumerate_roles

            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Check if current session has credentials
            if not manager.current_session_data.get("access_key"):
                await self._broadcast_module_error(
                    execution_id,
                    "No credentials in current session"
                )
                return

            # Save current session name to restore later
            original_session = manager.current_session

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Broadcast start
            await self._broadcast_module_output(execution_id, "🔁 Auto Assume All Roles - Enumerating and testing permissions...")

            # Replace console in module
            import src.clouds.aws.modules.enumeration.iam_roles as iam_roles_module
            original_console = iam_roles_module.console
            iam_roles_module.console = console

            try:
                # Run enumeration with assume testing in thread pool
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_roles, manager)

                # Get enumeration data
                roles = manager.get_enumeration_data('iam_roles')
                logger.info(f"[AssumeAll] Retrieved {len(roles) if roles else 0} IAM roles")

                if not roles:
                    await self._broadcast_module_output(execution_id, "\n❌ No IAM roles found")
                    await self._broadcast_module_complete(execution_id, success=True)
                    return

                # Filter only ALLOWED roles
                assumable_roles = [r for r in roles if r.get('AssumeStatus') == 'ALLOWED']

                await self._broadcast_module_output(
                    execution_id,
                    f"\n✓ Found {len(assumable_roles)} assumable roles out of {len(roles)} total roles"
                )

                if not assumable_roles:
                    await self._broadcast_module_output(
                        execution_id,
                        "❌ No roles can be assumed with current permissions"
                    )
                    await self._broadcast_module_complete(execution_id, success=True)
                    return

                # Assume each role and create sessions
                assumed_count = 0
                for role in assumable_roles:
                    role_arn = role['Arn']
                    role_name = role['RoleName']
                    new_session_name = f"{self.current_session}-{role_name}"

                    # Validate session name
                    if not manager.validate_session_name(new_session_name):
                        # Fallback to a simpler name
                        new_session_name = f"assumed-{role_name}"
                        if not manager.validate_session_name(new_session_name):
                            await self._broadcast_module_output(
                                execution_id,
                                f"⚠️  Skipping {role_name}: invalid session name"
                            )
                            continue

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n🔁 Assuming role: {role_name}"
                    )

                    # Call sts:AssumeRole
                    def assume_role_sync():
                        base_boto_sess = manager.get_boto3_session()
                        sts = base_boto_sess.client("sts")
                        try:
                            resp = sts.assume_role(
                                RoleArn=role_arn,
                                RoleSessionName=f"cloudknife-{self.current_session}",
                                DurationSeconds=3600,
                            )
                            return resp, None
                        except Exception as e:
                            return None, str(e)

                    with ThreadPoolExecutor() as executor:
                        resp, error = await loop.run_in_executor(executor, assume_role_sync)

                    if error:
                        await self._broadcast_module_output(
                            execution_id,
                            f"   ❌ Failed: {error[:100]}"
                        )
                        continue

                    # Extract credentials
                    creds = resp["Credentials"]
                    access_key = creds["AccessKeyId"]
                    secret_key = creds["SecretAccessKey"]
                    session_token = creds["SessionToken"]

                    # Create new session
                    manager.create_or_load_session(new_session_name)
                    manager.current_session_data.update({
                        "access_key": access_key,
                        "secret_key": secret_key,
                        "session_token": session_token,
                        "region": manager.default_region,
                    })
                    manager.save_current_session()

                    await self._broadcast_module_output(
                        execution_id,
                        f"   ✅ Session created: {new_session_name}"
                    )

                    # Create graph nodes and edges
                    await self._create_assume_role_nodes(role_arn, new_session_name, manager)

                    assumed_count += 1

                await self._broadcast_module_output(
                    execution_id,
                    f"\n✅ Successfully assumed {assumed_count} role(s) and created sessions"
                )
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original session
                if original_session:
                    manager.create_or_load_session(original_session)
                # Restore original console
                iam_roles_module.console = original_console

        except Exception as e:
            logger.error(f"AssumeAll execution failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_iam_roles(self, execution_id: str) -> None:
        """Execute AWS IAM roles enumeration module (simple mode - no assume test)."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from src.clouds.aws.modules.enumeration.iam_roles_simple import enumerate_roles_simple

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Broadcast start
            await self._broadcast_module_output(execution_id, "🔍 Starting IAM roles enumeration (simple mode)...")

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.iam_roles_simple as iam_roles_module
            original_console = iam_roles_module.console
            iam_roles_module.console = console

            try:
                # Run enumeration in thread pool to avoid blocking event loop
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_roles_simple, manager)

                # Get enumeration data
                roles = manager.get_enumeration_data('iam_roles_simple')
                logger.info(f"[Module] Retrieved {len(roles) if roles else 0} IAM roles from enumeration data")

                if roles:
                    # Create graph nodes for IAM roles
                    await self._create_iam_role_nodes(roles)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Created {len(roles)} IAM role nodes in graph"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nNo IAM roles found"
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                iam_roles_module.console = original_console

        except Exception as e:
            logger.error(f"IAM roles enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_iam_role_nodes(self, roles: list) -> None:
        """Create graph nodes for discovered IAM roles."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create IAM role nodes - no broadcast callback")
            return

        total_count = len(roles)
        MAX_NODES = 500  # Limite massimo nodi per prevenire UI freeze

        # Invia warning se ci sono più nodi del limite
        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} IAM roles found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} IAM roles. Consider using filters to refine results.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_iam_roles'
            }))
            roles = roles[:MAX_NODES]

        logger.info(f"[Module] Creating {len(roles)} IAM role nodes (total available: {total_count})")

        # BATCH PROCESSING per evitare WebSocket overflow
        BATCH_SIZE = 50  # Invia 50 nodi + 50 edge alla volta
        nodes_batch = []
        edges_batch = []

        for i, role in enumerate(roles):
            try:
                # Determine if this is a service role
                is_service_role = role.get('IsServiceRole', False)

                # Create node for IAM role
                node = {
                    'id': f"role-{role['Arn']}",
                    'type': 'aws-role',
                    'label': role['RoleName'],
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'roleName': role['RoleName'],
                        'roleArn': role['Arn'],
                        'createDate': role.get('CreateDate', ''),
                        'maxSessionDuration': role.get('MaxSessionDuration', ''),
                        'description': role.get('Description', ''),
                        'path': role.get('Path', '/'),
                        'isServiceRole': is_service_role,
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_iam_roles_simple',
                        'arn': role['Arn'],
                    }
                }

                # Add to graph state
                self.graph_state['nodes'].append(node)

                # Create edge from session to role
                edge = {
                    'id': f"edge-{self.current_session_id}-{role['Arn']}",
                    'source': self.current_session_id,
                    'target': f"role-{role['Arn']}",
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                # Add to graph state
                self.graph_state['edges'].append(edge)

                nodes_batch.append(node)
                edges_batch.append(edge)

                # Invia batch quando raggiungiamo BATCH_SIZE o siamo all'ultimo
                if len(nodes_batch) >= BATCH_SIZE or i == len(roles) - 1:
                    # Invia tutti i nodi in un unico messaggio
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    # Invia tutti gli edge in un unico messaggio
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))

                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(roles)})")

                    # Svuota batch
                    nodes_batch = []
                    edges_batch = []

                    # Piccolo delay per non saturare il WebSocket
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for role {role.get('RoleName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(roles)} IAM role nodes")


    async def _run_aws_enumerate_iam_users(self, execution_id: str) -> None:
        """Execute AWS IAM users enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from src.clouds.aws.modules.enumeration.iam_users import enumerate_users

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Broadcast start
            await self._broadcast_module_output(execution_id, "🔍 Starting IAM users enumeration...")

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.iam_users as iam_users_module
            original_console = iam_users_module.console
            iam_users_module.console = console

            try:
                # Run enumeration in thread pool to avoid blocking event loop
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_users, manager)

                # Get enumeration data
                users = manager.get_enumeration_data('iam_users')
                logger.info(f"[Module] Retrieved {len(users) if users else 0} IAM users from enumeration data")

                if users:
                    # Create graph nodes for IAM users
                    await self._create_iam_user_nodes(users)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Created {len(users)} IAM user nodes in graph"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nNo IAM users found"
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                iam_users_module.console = original_console

        except Exception as e:
            logger.error(f"IAM users enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_iam_user_nodes(self, users: list) -> None:
        """Create graph nodes for discovered IAM users."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create IAM user nodes - no broadcast callback")
            return

        total_count = len(users)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} IAM users found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} IAM users.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_iam_users'
            }))
            users = users[:MAX_NODES]

        logger.info(f"[Module] Creating {len(users)} IAM user nodes (total available: {total_count})")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, user in enumerate(users):
            try:
                node = {
                    'id': f"user-{user['Arn']}",
                    'type': 'aws-user',
                    'label': user['UserName'],
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'userName': user['UserName'],
                        'userArn': user['Arn'],
                        'userId': user['UserId'],
                        'createDate': user.get('CreateDate', ''),
                        'path': user.get('Path', '/'),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_iam_users',
                        'arn': user['Arn'],
                    }
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{user['Arn']}",
                    'source': self.current_session_id,
                    'target': f"user-{user['Arn']}",
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(users) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(users)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for user {user.get('UserName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(users)} IAM user nodes")


    async def _run_aws_enumerate_iam_groups(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS IAM groups enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from src.clouds.aws.modules.enumeration.iam_groups import enumerate_groups

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Extract parameters
            include_members = params.get('include_members', False)

            # Broadcast start
            if include_members:
                await self._broadcast_module_output(execution_id, "🔍 Starting IAM groups enumeration (including members)...")
            else:
                await self._broadcast_module_output(execution_id, "🔍 Starting IAM groups enumeration...")

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.iam_groups as iam_groups_module
            from rich.prompt import Confirm

            original_console = iam_groups_module.console
            iam_groups_module.console = console

            # Monkey-patch Confirm.ask to avoid interactive prompts
            # Always return False to skip the interactive question in the CLI module
            original_confirm_ask = Confirm.ask
            def non_interactive_confirm(prompt: str, **kwargs) -> bool:
                # The module will use include_members parameter, so we always return False here
                # to avoid the interactive prompt at the end
                return False
            Confirm.ask = staticmethod(non_interactive_confirm)

            try:
                # Store reference to groups list and members to capture during enumeration
                captured_groups = []
                captured_members = {}

                # Monkey-patch save_enumeration_data to capture groups and members
                original_save = manager.save_enumeration_data
                def capture_save(data_type: str, data: Any) -> None:
                    if data_type == 'iam_groups':
                        captured_groups.extend(data)
                        logger.info(f"[Module] Captured {len(data)} groups during enumeration")
                    elif data_type == 'iam_group_members':
                        captured_members.update(data)
                        logger.info(f"[Module] Captured group members: {len(data)} groups have members")
                    original_save(data_type, data)

                manager.save_enumeration_data = capture_save

                try:
                    # Run enumeration in thread pool to avoid blocking event loop
                    loop = asyncio.get_event_loop()
                    with ThreadPoolExecutor() as executor:
                        await loop.run_in_executor(
                            executor,
                            lambda: enumerate_groups(manager, include_members=include_members)
                        )
                finally:
                    # Restore original method
                    manager.save_enumeration_data = original_save

                # Use captured groups
                groups = captured_groups if captured_groups else manager.get_enumeration_data('iam_groups')
                logger.info(f"[Module] Current session: {manager.current_session}")
                logger.info(f"[Module] Enumeration data keys: {list(manager.enumerated_data.get(manager.current_session, {}).keys())}")
                logger.info(f"[Module] Final groups count: {len(groups) if groups else 0}")

                if groups:
                    # Create graph nodes for IAM groups
                    await self._create_iam_group_nodes(groups)

                    # If members were fetched, create edges to existing user nodes
                    if include_members and captured_members:
                        members_data = captured_members if captured_members else manager.get_enumeration_data('iam_group_members')
                        if members_data:
                            await self._create_group_membership_edges(groups, members_data)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Created {len(groups)} IAM group nodes in graph"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nNo IAM groups found"
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console and Confirm.ask
                iam_groups_module.console = original_console
                Confirm.ask = original_confirm_ask

        except Exception as e:
            logger.error(f"IAM groups enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_iam_group_nodes(self, groups: list) -> None:
        """Create graph nodes for discovered IAM groups."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create IAM group nodes - no broadcast callback")
            return

        total_count = len(groups)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} IAM groups found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} IAM groups.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_iam_groups'
            }))
            groups = groups[:MAX_NODES]

        logger.info(f"[Module] Creating {len(groups)} IAM group nodes (total available: {total_count})")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, group in enumerate(groups):
            try:
                node = {
                    'id': f"group-{group['Arn']}",
                    'type': 'aws-group',
                    'label': group['GroupName'],
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'groupName': group['GroupName'],
                        'groupArn': group['Arn'],
                        'groupId': group['GroupId'],
                        'createDate': group.get('CreateDate', ''),
                        'path': group.get('Path', '/'),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_iam_groups',
                        'arn': group['Arn'],
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{group['Arn']}",
                    'source': self.current_session_id,
                    'target': f"group-{group['Arn']}",
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(groups) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(groups)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for group {group.get('GroupName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(groups)} IAM group nodes")


    async def _create_group_membership_edges(self, groups: list, members_data: Dict[str, list]) -> None:
        """Create edges between IAM groups and their member users."""
        import asyncio

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create group membership edges - no broadcast callback")
            return

        logger.info(f"[Module] Creating group membership edges for {len(groups)} groups")

        edges_batch = []
        BATCH_SIZE = 50
        total_edges = 0

        for group in groups:
            group_name = group['GroupName']
            group_arn = group['Arn']
            group_node_id = f"group-{group_arn}"

            # Get members for this group
            members = members_data.get(group_name, [])
            if not members:
                continue

            logger.info(f"[Module] Processing {len(members)} members for group '{group_name}'")

            for member in members:
                member_arn = member.get('Arn')
                if not member_arn:
                    continue

                # Check if user node exists in graph
                user_node_id = f"user-{member_arn}"
                user_exists = any(n.get('id') == user_node_id for n in self.graph_state['nodes'])

                if user_exists:
                    # Create edge: group -> user (membership)
                    edge = {
                        'id': f"edge-group-member-{group_arn}-{member_arn}",
                        'source': group_node_id,
                        'target': user_node_id,
                        'label': 'has member',
                        'type': 'contains',
                        'discoveredBy': [self.current_session_id],
                    }

                    self.graph_state['edges'].append(edge)
                    edges_batch.append(edge)
                    total_edges += 1

                    # Send batch when full
                    if len(edges_batch) >= BATCH_SIZE:
                        await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                        logger.info(f"[Module] Sent batch of {len(edges_batch)} group membership edges")
                        edges_batch = []
                        await asyncio.sleep(0.05)
                else:
                    logger.debug(f"[Module] User node '{user_node_id}' not found in graph, skipping edge creation")

        # Send remaining edges
        if edges_batch:
            await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
            logger.info(f"[Module] Sent final batch of {len(edges_batch)} group membership edges")

        logger.info(f"[Module] Created {total_edges} group membership edges")


    async def _run_aws_bruteforce_permissions(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS IAM permissions bruteforce module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from src.clouds.aws.modules.enumeration.iam_bruteforce import enumerate_bruteforce_permissions

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Extract parameters
            mode = params.get('mode', 'fast')
            services = params.get('services', None)

            # Broadcast start
            mode_label = mode.upper()
            await self._broadcast_module_output(
                execution_id,
                f"🔍 Starting IAM permissions bruteforce ({mode_label} mode)..."
            )

            if services:
                await self._broadcast_module_output(
                    execution_id,
                    f"📋 Target services: {services}"
                )

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.iam_bruteforce as bruteforce_module
            original_console = bruteforce_module.console
            bruteforce_module.console = console

            try:
                # Store reference to results to capture them during enumeration
                captured_results = []

                # Monkey-patch save_enumeration_data to capture results
                original_save = manager.save_enumeration_data
                def capture_save(data_type: str, data: Any) -> None:
                    if data_type == 'iam_bruteforce':
                        captured_results.clear()
                        captured_results.extend(data)
                        logger.info(f"[Module] Captured {len(data)} bruteforce results")
                    original_save(data_type, data)

                manager.save_enumeration_data = capture_save

                try:
                    # Run enumeration in thread pool to avoid blocking event loop
                    loop = asyncio.get_event_loop()
                    with ThreadPoolExecutor() as executor:
                        await loop.run_in_executor(
                            executor,
                            lambda: enumerate_bruteforce_permissions(manager, services, mode)
                        )
                finally:
                    # Restore original method
                    manager.save_enumeration_data = original_save

                # Use captured results
                results = captured_results if captured_results else manager.get_enumeration_data('iam_bruteforce')
                logger.info(f"[Module] Final results count: {len(results) if results else 0}")

                if results:
                    # Count permissions by status
                    allowed = [r for r in results if r['status'] == 'ALLOWED']
                    denied = [r for r in results if r['status'] == 'DENIED']
                    skipped = [r for r in results if r['status'] == 'SKIPPED']

                    # Create single aggregated node for all permissions
                    await self._create_permissions_enumerated_node(results, mode)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Permissions enumerated: {len(allowed)} allowed, {len(denied)} denied, {len(skipped)} skipped"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nNo permissions enumerated"
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                bruteforce_module.console = original_console

        except Exception as e:
            logger.error(f"IAM permissions bruteforce failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_permissions_enumerated_node(self, results: list, mode: str) -> None:
        """Create a single graph node containing all enumerated permissions."""
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create permissions node - no broadcast callback")
            return

        logger.info(f"[Module] Creating permissions enumerated node with {len(results)} results")

        # Aggregate permissions by status
        allowed_permissions = []
        denied_permissions = []
        dangerous_permissions = []

        from src.data.aws_privesc_techniques import is_dangerous_permission

        for r in results:
            full_action = f"{r['service']}:{r['action']}"
            perm_entry = {
                'service': r['service'],
                'action': r['action'],
                'status': r['status'],
                'error': r.get('error', ''),
            }

            if r['status'] == 'ALLOWED':
                allowed_permissions.append(perm_entry)
                # Check for dangerous permissions
                if is_dangerous_permission(full_action):
                    dangerous_permissions.append(perm_entry)
            elif r['status'] == 'DENIED':
                denied_permissions.append(perm_entry)

        # Create single node with all permissions
        node_id = f"permissions-{self.current_session_id}-{mode}"
        node = {
            'id': node_id,
            'type': 'aws-permissions',
            'label': f'Permissions Enumerated ({mode.upper()})',
            'provider': 'aws',
            'discoveredBy': [self.current_session_id],
            'parentId': self.current_session_id,
            'data': {
                'mode': mode,
                'totalPermissions': len(results),
                'allowedCount': len(allowed_permissions),
                'deniedCount': len(denied_permissions),
                'dangerousCount': len(dangerous_permissions),
                'allowedPermissions': allowed_permissions,
                'deniedPermissions': denied_permissions,
                'dangerousPermissions': dangerous_permissions,
            },
            'metadata': {
                'discoveredAt': datetime.now().isoformat(),
                'moduleUsed': 'bruteforce_permissions',
                'mode': mode,
            },
            'level': 1,
        }

        # Add to graph state
        self.graph_state['nodes'].append(node)

        # Broadcast to clients
        await self.broadcast_callback(
            create_success_response(
                'graph.node.add',
                {'node': node}
            )
        )

        # Create edge from session to permissions node
        edge = {
            'id': f"edge-{self.current_session_id}-{node_id}",
            'source': self.current_session_id,
            'target': node_id,
            'label': 'bruteforced',
            'type': 'owns',
            'discoveredBy': [self.current_session_id],
        }

        # Add to graph state
        self.graph_state['edges'].append(edge)

        # Broadcast edge
        await self.broadcast_callback(
            create_success_response(
                'graph.edge.add',
                {'edge': edge}
            )
        )

        logger.info(f"[Module] Created permissions enumerated node: {len(allowed_permissions)} allowed, {len(dangerous_permissions)} dangerous")

        # Group permissions by service and create sub-nodes
        await self._create_service_permission_subnodes(results, mode, node_id)


    async def _create_service_permission_subnodes(self, results: list, mode: str, parent_node_id: str) -> None:
        """Create sub-nodes for each service category containing permissions for that service."""
        from datetime import datetime
        from collections import defaultdict
        from src.data.aws_privesc_techniques import is_dangerous_permission

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create service permission subnodes - no broadcast callback")
            return

        # Group permissions by service
        permissions_by_service = defaultdict(lambda: {
            'allowed': [],
            'denied': [],
            'dangerous': []
        })

        for r in results:
            service = r['service']
            full_action = f"{service}:{r['action']}"
            perm_entry = {
                'service': service,
                'action': r['action'],
                'status': r['status'],
                'error': r.get('error', ''),
            }

            if r['status'] == 'ALLOWED':
                permissions_by_service[service]['allowed'].append(perm_entry)
                if is_dangerous_permission(full_action):
                    permissions_by_service[service]['dangerous'].append(perm_entry)
            elif r['status'] == 'DENIED':
                permissions_by_service[service]['denied'].append(perm_entry)

        logger.info(f"[Module] Processing {len(permissions_by_service)} service permission subnodes")

        # Create or update a sub-node for each service
        for service_name, perms in permissions_by_service.items():
            # Skip services with no allowed permissions
            if not perms['allowed']:
                continue

            # Create node ID (without mode, so it's shared across all modes)
            service_node_id = f"permissions-{self.current_session_id}-{service_name}"

            # Check if node already exists
            existing_node = None
            for node in self.graph_state['nodes']:
                if node.get('id') == service_node_id:
                    existing_node = node
                    break

            if existing_node:
                # Node exists - merge permissions and update modes
                logger.info(f"[Module] Updating existing service node: {service_name}")

                # Get existing data
                existing_data = existing_node.get('data', {})
                existing_modes = existing_data.get('modes', [])

                # Add current mode if not already present
                if mode not in existing_modes:
                    existing_modes.append(mode)

                # Merge permissions (avoid duplicates)
                def merge_permissions(existing, new):
                    # Create set of existing permission signatures
                    existing_sigs = {f"{p['service']}:{p['action']}" for p in existing}
                    # Add only new permissions not already present
                    for p in new:
                        sig = f"{p['service']}:{p['action']}"
                        if sig not in existing_sigs:
                            existing.append(p)
                    return existing

                existing_allowed = existing_data.get('allowedPermissions', [])
                existing_denied = existing_data.get('deniedPermissions', [])
                existing_dangerous = existing_data.get('dangerousPermissions', [])

                merged_allowed = merge_permissions(existing_allowed, perms['allowed'])
                merged_denied = merge_permissions(existing_denied, perms['denied'])
                merged_dangerous = merge_permissions(existing_dangerous, perms['dangerous'])

                # Update node data
                existing_node['data'] = {
                    'service': service_name,
                    'modes': existing_modes,
                    'totalPermissions': len(merged_allowed) + len(merged_denied),
                    'allowedCount': len(merged_allowed),
                    'deniedCount': len(merged_denied),
                    'dangerousCount': len(merged_dangerous),
                    'allowedPermissions': merged_allowed,
                    'deniedPermissions': merged_denied,
                    'dangerousPermissions': merged_dangerous,
                }

                # Update metadata
                existing_node['metadata']['modes'] = existing_modes
                existing_node['metadata']['lastUpdatedAt'] = datetime.now().isoformat()

                # Broadcast update
                await self.broadcast_callback(
                    create_success_response(
                        'graph.node.update',
                        {'node': existing_node}
                    )
                )
            else:
                # Node doesn't exist - create new one
                logger.info(f"[Module] Creating new service node: {service_name}")

                service_node = {
                    'id': service_node_id,
                    'type': f'aws-{service_name}-perms',
                    'label': service_name.upper(),
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': parent_node_id,
                    'data': {
                        'service': service_name,
                        'modes': [mode],
                        'totalPermissions': len(perms['allowed']) + len(perms['denied']),
                        'allowedCount': len(perms['allowed']),
                        'deniedCount': len(perms['denied']),
                        'dangerousCount': len(perms['dangerous']),
                        'allowedPermissions': perms['allowed'],
                        'deniedPermissions': perms['denied'],
                        'dangerousPermissions': perms['dangerous'],
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'bruteforce_permissions',
                        'modes': [mode],
                        'service': service_name,
                    },
                    'level': 2,
                }

                # Add to graph state
                self.graph_state['nodes'].append(service_node)

                # Broadcast to clients
                await self.broadcast_callback(
                    create_success_response(
                        'graph.node.add',
                        {'node': service_node}
                    )
                )

            # Create edge from parent permissions node to service node (if not exists)
            edge_id = f"edge-{parent_node_id}-{service_node_id}"

            # Check if edge already exists
            edge_exists = False
            for edge in self.graph_state['edges']:
                if edge.get('source') == parent_node_id and edge.get('target') == service_node_id:
                    edge_exists = True
                    logger.info(f"[Module] Edge already exists from {parent_node_id} to {service_node_id}")
                    break

            if not edge_exists:
                service_edge = {
                    'id': edge_id,
                    'source': parent_node_id,
                    'target': service_node_id,
                    'label': '',
                    'type': 'contains',
                    'discoveredBy': [self.current_session_id],
                }

                # Add to graph state
                self.graph_state['edges'].append(service_edge)

                # Broadcast edge
                await self.broadcast_callback(
                    create_success_response(
                        'graph.edge.add',
                        {'edge': service_edge}
                    )
                )

        logger.info(f"[Module] Created {len([s for s, p in permissions_by_service.items() if p['allowed']])} service permission subnodes")


    async def _run_aws_privesc_paths(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS privilege escalation paths analysis module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from src.clouds.aws.modules.enumeration.iam_privilege_escalation import analyze_privilege_escalation

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Check if bruteforce data exists
            bruteforce_data = manager.get_enumeration_data('iam_bruteforce')
            if not bruteforce_data:
                await self._broadcast_module_error(
                    execution_id,
                    "No IAM bruteforce data found. Run 'bruteforce_permissions' first."
                )
                return

            # Broadcast start
            await self._broadcast_module_output(
                execution_id,
                "🔍 Analyzing IAM permissions for privilege escalation paths..."
            )

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.iam_privilege_escalation as privesc_module
            original_console = privesc_module.console
            privesc_module.console = console

            try:
                # Run analysis in thread pool to avoid blocking event loop
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: analyze_privilege_escalation(manager)
                    )

                # Get results from session data
                session_data = manager.get_enumeration_data('privilege_escalation_paths')

                if session_data and session_data.get('escalation_paths'):
                    paths = session_data['escalation_paths']

                    # Create nodes in graph
                    await self._create_privesc_nodes(paths, session_data)

                    complete = session_data.get('complete_paths', 0)
                    partial = session_data.get('partial_paths', 0)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Found {len(paths)} escalation paths: {complete} complete, {partial} partial"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\n✓ No privilege escalation paths detected"
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                privesc_module.console = original_console

        except Exception as e:
            logger.error(f"Privilege escalation analysis failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_privesc_nodes(self, paths: list, session_data: dict) -> None:
        """Create graph nodes for privilege escalation paths."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create privesc nodes - no broadcast callback")
            return

        logger.info(f"[Module] Creating privilege escalation nodes for {len(paths)} paths")

        # Find the aws-permissions node for the current session
        permissions_node_id = None
        for node in self.graph_state['nodes']:
            if (node['type'] == 'aws-permissions' and
                self.current_session_id in node['discoveredBy']):
                permissions_node_id = node['id']
                break

        # Determine parent: aws-permissions if found, otherwise session
        if permissions_node_id:
            parent_id = permissions_node_id
            edge_label = 'analyzed'
            logger.info(f"[Module] Linking privesc analysis to permissions node: {permissions_node_id}")
        else:
            parent_id = self.current_session_id
            edge_label = 'discovered'
            logger.warning(f"[Module] No permissions node found, linking to session")

        # Create central privesc analysis node
        analysis_node_id = f"privesc-analysis-{self.current_session_id}"

        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for path in paths:
            severity = path['technique'].get('severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        analysis_node = {
            'id': analysis_node_id,
            'type': 'aws-privesc-analysis',
            'label': f"Privesc Analysis ({session_data.get('total_paths', 0)} paths)",
            'provider': 'aws',
            'discoveredBy': [self.current_session_id],
            'parentId': parent_id,
            'data': {
                'totalPaths': session_data.get('total_paths', 0),
                'completePaths': session_data.get('complete_paths', 0),
                'partialPaths': session_data.get('partial_paths', 0),
                'totalPermissions': session_data.get('total_permissions', 0),
                'severityCounts': severity_counts,
            },
            'metadata': {
                'discoveredAt': datetime.now().isoformat(),
                'moduleUsed': 'privesc_paths',
            },
            'level': 2 if permissions_node_id else 1,
        }

        self.graph_state['nodes'].append(analysis_node)

        # Create edge from parent to analysis node
        analysis_edge = {
            'id': f"edge-{parent_id}-{analysis_node_id}",
            'source': parent_id,
            'target': analysis_node_id,
            'label': edge_label,
            'type': 'analyzes' if permissions_node_id else 'owns',
            'discoveredBy': [self.current_session_id],
        }

        self.graph_state['edges'].append(analysis_edge)

        # Broadcast central node
        await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': [analysis_node]}))
        await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': [analysis_edge]}))
        logger.info(f"[Module] Created privesc analysis node")

        # Create individual path nodes
        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, path in enumerate(paths):
            try:
                technique = path['technique']

                # Create unique node ID
                path_id = f"privesc-path-{self.current_session_id}-{technique['name'].replace(' ', '-').lower()}"

                # Determine color based on severity
                severity = technique.get('severity', 'LOW')

                node = {
                    'id': path_id,
                    'type': 'aws-privesc-path',
                    'label': technique['name'],
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': analysis_node_id,
                    'data': {
                        'technique': technique['name'],
                        'description': technique.get('description', ''),
                        'severity': severity,
                        'category': technique.get('category', ''),
                        'target': technique.get('target', ''),
                        'isComplete': path['is_complete'],
                        'matchPercentage': path['match_percentage'],
                        'availablePermissions': path['available_permissions'],
                        'missingPermissions': path['missing_permissions'],
                        'requiredPermissions': technique.get('required_permissions', []),
                        'exploitationSteps': technique.get('exploitation_steps', []),
                        'references': technique.get('references', []),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'privesc_paths',
                        'severity': severity,
                        'complete': path['is_complete'],
                    },
                    'level': 3 if permissions_node_id else 2,
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{analysis_node_id}-{path_id}",
                    'source': analysis_node_id,
                    'target': path_id,
                    'label': 'found',
                    'type': 'contains',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(paths) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} path nodes ({i+1}/{len(paths)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node for path {technique.get('name', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(paths)} privilege escalation path nodes")


    async def _create_iam_policy_nodes(self, policies: list, policy_type: str, entity_type: str = None) -> None:
        """Create graph nodes for discovered IAM policies."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create IAM policy nodes - no broadcast callback")
            return

        total_count = len(policies)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} IAM policies found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} IAM policies ({policy_type}).',
                'total': total_count,
                'shown': MAX_NODES,
                'module': f'enumerate_iam_policies_{policy_type}'
            }))
            policies = policies[:MAX_NODES]

        logger.info(f"[Module] Creating {len(policies)} IAM policy nodes (type: {policy_type}, total available: {total_count})")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, policy in enumerate(policies):
            try:
                # Generate unique ID based on policy type
                if policy_type == 'managed':
                    policy_id = f"policy-{policy['Arn']}"
                    policy_label = policy['PolicyName']
                    policy_arn = policy['Arn']
                else:  # inline or attached
                    entity_name = policy.get('EntityName', '')
                    policy_name = policy.get('PolicyName', '')
                    policy_id = f"policy-{entity_name}-{policy_name}".replace(' ', '-')
                    policy_label = f"{policy_name} ({entity_name})"
                    policy_arn = policy.get('PolicyArn', f"inline:{entity_name}:{policy_name}")

                node = {
                    'id': policy_id,
                    'type': 'aws-policy',
                    'label': policy_label,
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'policyName': policy.get('PolicyName', ''),
                        'policyArn': policy_arn,
                        'policyType': policy_type,
                        'entityType': policy.get('EntityType', entity_type),
                        'entityName': policy.get('EntityName', ''),
                        'attachmentCount': policy.get('AttachmentCount', 0),
                        'isAttachable': policy.get('IsAttachable', True),
                        'createDate': policy.get('CreateDate', ''),
                        'updateDate': policy.get('UpdateDate', ''),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': f'enumerate_iam_policies_{policy_type}',
                        'arn': policy_arn,
                    },
                    'level': 1,
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{policy_id}",
                    'source': self.current_session_id,
                    'target': policy_id,
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(policies) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(policies)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for policy {policy.get('PolicyName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(policies)} IAM policy nodes")


    async def _run_aws_enumerate_iam_policies(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS IAM policies enumeration module with multiple options."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Extract parameters
            policy_type = params.get('policy_type', 'managed')
            entity_type = params.get('entity_type', 'user')

            # Broadcast start
            await self._broadcast_module_output(execution_id, f"🔍 Starting IAM policies enumeration (type: {policy_type})...")

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Import module and prepare to replace console
            import src.clouds.aws.modules.enumeration.iam_policies as iam_policies_module
            original_console = iam_policies_module.console
            iam_policies_module.console = console

            try:
                loop = asyncio.get_event_loop()

                # Route to appropriate function based on policy_type and entity_type
                if policy_type == 'managed':
                    # Managed policies enumeration
                    from src.clouds.aws.modules.enumeration.iam_policies import enumerate_policies

                    scope = params.get('scope', 'All')
                    only_attached = params.get('only_attached', False)

                    with ThreadPoolExecutor() as executor:
                        await loop.run_in_executor(
                            executor,
                            lambda: enumerate_policies(manager, scope=scope, only_attached=only_attached)
                        )

                    policies = manager.get_enumeration_data('iam_policies')
                    logger.info(f"[Module] Retrieved {len(policies) if policies else 0} managed policies")

                    if policies:
                        await self._create_iam_policy_nodes(policies, 'managed')
                        await self._broadcast_module_output(
                            execution_id,
                            f"\n✓ Created {len(policies)} managed policy nodes in graph"
                        )

                elif policy_type == 'inline':
                    # Inline policies enumeration
                    if entity_type == 'user':
                        from src.clouds.aws.modules.enumeration.iam_policies import enumerate_inline_user_policies
                        username = params.get('username', None)

                        with ThreadPoolExecutor() as executor:
                            await loop.run_in_executor(
                                executor,
                                lambda: enumerate_inline_user_policies(manager, username=username)
                            )

                        policies = manager.get_enumeration_data('iam_inline_user_policies')
                        logger.info(f"[Module] Retrieved {len(policies) if policies else 0} inline user policies")

                        if policies:
                            await self._create_iam_policy_nodes(policies, 'inline', 'user')
                            await self._broadcast_module_output(
                                execution_id,
                                f"\n✓ Created {len(policies)} inline user policy nodes in graph"
                            )

                    else:  # entity_type == 'role'
                        from src.clouds.aws.modules.enumeration.iam_policies import enumerate_inline_role_policies
                        rolename = params.get('rolename', None)

                        with ThreadPoolExecutor() as executor:
                            await loop.run_in_executor(
                                executor,
                                lambda: enumerate_inline_role_policies(manager, rolename=rolename)
                            )

                        policies = manager.get_enumeration_data('iam_inline_role_policies')
                        logger.info(f"[Module] Retrieved {len(policies) if policies else 0} inline role policies")

                        if policies:
                            await self._create_iam_policy_nodes(policies, 'inline', 'role')
                            await self._broadcast_module_output(
                                execution_id,
                                f"\n✓ Created {len(policies)} inline role policy nodes in graph"
                            )

                elif policy_type == 'attached':
                    # Attached policies enumeration
                    if entity_type == 'user':
                        from src.clouds.aws.modules.enumeration.iam_policies import enumerate_attached_user_policies
                        username = params.get('username', None)

                        with ThreadPoolExecutor() as executor:
                            await loop.run_in_executor(
                                executor,
                                lambda: enumerate_attached_user_policies(manager, username=username)
                            )

                        policies = manager.get_enumeration_data('iam_attached_user_policies')
                        logger.info(f"[Module] Retrieved {len(policies) if policies else 0} attached user policies")

                        if policies:
                            await self._create_iam_policy_nodes(policies, 'attached', 'user')
                            await self._broadcast_module_output(
                                execution_id,
                                f"\n✓ Created {len(policies)} attached user policy nodes in graph"
                            )

                    else:  # entity_type == 'role'
                        from src.clouds.aws.modules.enumeration.iam_policies import enumerate_attached_role_policies
                        rolename = params.get('rolename', None)

                        with ThreadPoolExecutor() as executor:
                            await loop.run_in_executor(
                                executor,
                                lambda: enumerate_attached_role_policies(manager, rolename=rolename)
                            )

                        policies = manager.get_enumeration_data('iam_attached_role_policies')
                        logger.info(f"[Module] Retrieved {len(policies) if policies else 0} attached role policies")

                        if policies:
                            await self._create_iam_policy_nodes(policies, 'attached', 'role')
                            await self._broadcast_module_output(
                                execution_id,
                                f"\n✓ Created {len(policies)} attached role policy nodes in graph"
                            )

                else:
                    await self._broadcast_module_error(
                        execution_id,
                        f"Unknown policy type: {policy_type}"
                    )
                    return

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                iam_policies_module.console = original_console

        except Exception as e:
            logger.error(f"IAM policies enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_secrets(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS Secrets Manager enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from rich.prompt import Prompt
        from src.clouds.aws.modules.enumeration.secrets_list import enumerate_secrets

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Get optional region parameter
            region = params.get('region')

            # Save original configured_regions
            original_configured_regions = manager.configured_regions.copy()

            # If region is specified, override configured_regions temporarily
            if region:
                manager.set_regions([region])
                await self._broadcast_module_output(
                    execution_id,
                    f"🔍 Starting Secrets Manager enumeration in region: {region}..."
                )
            else:
                await self._broadcast_module_output(
                    execution_id,
                    "🔍 Starting Secrets Manager enumeration..."
                )

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.secrets_list as secrets_module
            original_console = secrets_module.console
            secrets_module.console = console

            # Patch Prompt.ask to skip the "retrieve secret values?" prompt
            original_prompt = Prompt.ask
            def auto_skip(*args, **kwargs):
                # Return "3" to skip secret value retrieval (we'll do it separately)
                return "3"
            Prompt.ask = auto_skip

            try:
                # Run enumeration in thread pool to avoid blocking event loop
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_secrets, manager)

                # Get enumeration data
                secrets = manager.get_enumeration_data('secrets_manager')
                logger.info(f"[Module] Retrieved {len(secrets) if secrets else 0} secrets from enumeration data")

                if secrets:
                    # Create graph nodes for secrets
                    await self._create_secret_nodes(secrets)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Created {len(secrets)} secret nodes in graph"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nNo secrets found in the selected regions"
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console and Prompt
                secrets_module.console = original_console
                Prompt.ask = original_prompt
                # Restore original configured_regions
                manager.set_regions(original_configured_regions)

        except Exception as e:
            logger.error(f"Secrets enumeration failed: {e}", exc_info=True)
            # Ensure we restore configured_regions even on error
            if 'manager' in locals() and 'original_configured_regions' in locals():
                manager.set_regions(original_configured_regions)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_secret_nodes(self, secrets: list) -> None:
        """Create graph nodes for discovered secrets."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create secret nodes - no broadcast callback")
            return

        total_count = len(secrets)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} secrets found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} secrets.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_secrets'
            }))
            secrets = secrets[:MAX_NODES]

        logger.info(f"[Module] Creating {len(secrets)} secret nodes (total available: {total_count})")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, secret in enumerate(secrets):
            try:
                # Create node for secret
                node = {
                    'id': f"secret-{secret['ARN']}",
                    'type': 'aws-secret',
                    'label': secret['Name'],
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'secretName': secret['Name'],
                        'secretArn': secret['ARN'],
                        'region': secret['Region'],
                        'description': secret.get('Description', ''),
                        'versionId': secret.get('VersionId', ''),
                        'createdDate': secret.get('CreatedDate', ''),
                        'lastChangedDate': secret.get('LastChangedDate', ''),
                        'kmsKeyId': secret.get('KmsKeyId', ''),
                        'rotationEnabled': secret.get('RotationEnabled', False),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_secrets',
                        'arn': secret['ARN'],
                        'region': secret['Region'],
                    },
                }

                self.graph_state['nodes'].append(node)

                # Create edge from session to secret
                edge = {
                    'id': f"edge-{self.current_session_id}-{secret['ARN']}",
                    'source': self.current_session_id,
                    'target': f"secret-{secret['ARN']}",
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(secrets) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(secrets)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for secret {secret.get('Name', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(secrets)} secret nodes")


    async def _run_aws_get_secret_value(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS Secrets Manager get secret value (retrieve actual secret value)."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from src.clouds.aws.utils.regions import RegionalClientFactory
        from src.clouds.aws.utils.error_handling import safe_aws_call

        try:
            # Get secret name and region from params
            secret_name = params.get('secret_name')
            region = params.get('region')
            node_id = params.get('node_id')  # Optional: ID of the secret node to update

            if not secret_name:
                await self._broadcast_module_error(
                    execution_id,
                    "Missing required parameter: secret_name"
                )
                return

            if not region:
                await self._broadcast_module_error(
                    execution_id,
                    "Missing required parameter: region"
                )
                return

            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Broadcast start
            await self._broadcast_module_output(
                execution_id,
                f"🔍 Retrieving secret value for: {secret_name}"
            )

            # Get secret value
            client_factory = RegionalClientFactory(manager)
            sm = client_factory.get_client("secretsmanager", region)

            # Call in executor using lambda to pass kwargs correctly
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                resp, error = await loop.run_in_executor(
                    executor,
                    lambda: safe_aws_call(
                        sm.get_secret_value,
                        SecretId=secret_name,
                        log_error=False,
                        default=None
                    )
                )

            if error:
                await self._broadcast_module_output(
                    execution_id,
                    f"\n✗ Access denied or error: {error.code} - {error.message}"
                )
                await self._broadcast_module_complete(execution_id, success=False)
                return

            if not resp:
                await self._broadcast_module_output(
                    execution_id,
                    "\n✗ No response from AWS"
                )
                await self._broadcast_module_complete(execution_id, success=False)
                return

            # Success - extract secret data
            secret_string = resp.get("SecretString")
            secret_binary = resp.get("SecretBinary")
            version_id = resp.get("VersionId")

            await self._broadcast_module_output(
                execution_id,
                f"\n✓ Successfully retrieved secret value!"
            )

            if secret_string:
                await self._broadcast_module_output(
                    execution_id,
                    f"\nSecret String:\n{secret_string[:200]}{'...' if len(secret_string) > 200 else ''}"
                )
            elif secret_binary:
                await self._broadcast_module_output(
                    execution_id,
                    f"\nSecret Binary (base64-encoded):\n{str(secret_binary)[:200]}"
                )

            # Update the secret node with detailed information
            await self._update_secret_node(
                node_id or f"secret-{secret_name}",
                secret_string,
                secret_binary,
                version_id
            )

            await self._broadcast_module_output(
                execution_id,
                f"\n✓ Updated secret node with value"
            )

            await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Get secret value error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _update_secret_node(
        self,
        node_identifier: str,
        secret_string: str | None,
        secret_binary: bytes | None,
        version_id: str | None
    ) -> None:
        """Update an existing secret node with the retrieved secret value."""
        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot update secret node - no broadcast callback")
            return

        from datetime import datetime
        logger.info(f"[Module] Updating secret node: {node_identifier}")

        # Create update payload with detailed information (same format as Lambda)
        node_update = {
            'id': node_identifier,
            'type': 'aws-secret',
            'data': {
                'detailedInfoFetched': True,
                'secretString': secret_string,
                'secretBinary': str(secret_binary) if secret_binary else None,
                'versionId': version_id,
            },
            'metadata': {
                'lastDetailedFetch': datetime.now().isoformat(),
            }
        }

        # Update node in graph state
        for i, node in enumerate(self.graph_state['nodes']):
            if node['id'] == node_identifier:
                # Deep merge the update into existing node
                self.graph_state['nodes'][i]['data'].update(node_update['data'])
                self.graph_state['nodes'][i]['metadata'].update(node_update['metadata'])
                logger.info(f"[Module] Updated secret node in graph state: {node_identifier}")
                break

        # Broadcast node update (same format as Lambda)
        logger.info(f"[Module] Broadcasting secret node update")
        await self.broadcast_callback(
            create_success_response(
                'graph.node.update',
                {'node': node_update}
            )
        )

        logger.info(f"[Module] Broadcasted secret value update for node: {node_identifier}")


    async def _run_aws_describe_policy(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS IAM describe policy document (get policy details)."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console

        try:
            # Get policy parameters
            policy_arn = params.get('policy_arn')
            policy_type = params.get('policy_type', 'managed')
            entity_type = params.get('entity_type')
            entity_name = params.get('entity_name')
            policy_name = params.get('policy_name')
            node_id = params.get('node_id')  # ID of the policy node to update

            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Broadcast start
            if policy_type == 'managed':
                if not policy_arn:
                    await self._broadcast_module_error(execution_id, "Missing required parameter: policy_arn")
                    return
                await self._broadcast_module_output(execution_id, f"🔍 Fetching managed policy document for: {policy_arn}")
            else:
                if not entity_type or not entity_name or not policy_name:
                    await self._broadcast_module_error(execution_id, "Missing required parameters for inline policy")
                    return
                await self._broadcast_module_output(
                    execution_id,
                    f"🔍 Fetching inline policy document: {policy_name} ({entity_type}: {entity_name})"
                )

            # Get boto3 session
            aws_sess = manager.get_boto3_session()
            iam = aws_sess.client("iam")

            loop = asyncio.get_event_loop()
            policy_data = {}

            # Call appropriate AWS API based on policy type
            if policy_type == 'managed':
                # Managed policy: get policy metadata and default version document
                with ThreadPoolExecutor() as executor:
                    # Get policy metadata
                    policy_resp = await loop.run_in_executor(
                        executor,
                        lambda: iam.get_policy(PolicyArn=policy_arn)
                    )

                    policy = policy_resp.get("Policy", {})
                    default_version_id = policy.get("DefaultVersionId")

                    await self._broadcast_module_output(
                        execution_id,
                        f"Found policy with default version: {default_version_id}"
                    )

                    # Get policy version document
                    version_resp = await loop.run_in_executor(
                        executor,
                        lambda: iam.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=default_version_id
                        )
                    )

                    document = version_resp.get("PolicyVersion", {}).get("Document")

                    # List all versions to get total count
                    versions_resp = await loop.run_in_executor(
                        executor,
                        lambda: iam.list_policy_versions(PolicyArn=policy_arn)
                    )

                    all_versions = versions_resp.get("Versions", [])

                    policy_data = {
                        "Arn": policy_arn,
                        "VersionId": default_version_id,
                        "Document": document,
                        "TotalVersions": len(all_versions)
                    }

                    await self._broadcast_module_output(
                        execution_id,
                        f"✓ Retrieved managed policy document (version {default_version_id}, {len(all_versions)} total versions)"
                    )

            else:  # inline policy
                # Inline policy: get policy document directly
                with ThreadPoolExecutor() as executor:
                    if entity_type == 'user':
                        policy_resp = await loop.run_in_executor(
                            executor,
                            lambda: iam.get_user_policy(
                                UserName=entity_name,
                                PolicyName=policy_name
                            )
                        )
                    else:  # role
                        policy_resp = await loop.run_in_executor(
                            executor,
                            lambda: iam.get_role_policy(
                                RoleName=entity_name,
                                PolicyName=policy_name
                            )
                        )

                    document = policy_resp.get("PolicyDocument")

                    policy_data = {
                        "EntityType": entity_type,
                        "EntityName": entity_name,
                        "PolicyName": policy_name,
                        "Document": document
                    }

                    await self._broadcast_module_output(
                        execution_id,
                        f"✓ Retrieved inline policy document for {entity_type}: {entity_name}"
                    )

            if policy_data and policy_data.get("Document"):
                # Update the policy node with detailed information
                await self._update_policy_node(
                    node_id,
                    policy_data,
                    policy_type
                )

                await self._broadcast_module_output(
                    execution_id,
                    "\n✓ Policy document retrieved and node updated!"
                )

            await self._broadcast_module_complete(execution_id, success=True)

        except Exception as e:
            logger.error(f"Policy document retrieval failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _update_policy_node(
        self,
        node_identifier: str,
        policy_data: Dict[str, Any],
        policy_type: str
    ) -> None:
        """Update an existing policy node with the retrieved policy document."""
        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot update policy node - no broadcast callback")
            return

        from datetime import datetime
        logger.info(f"[Module] Updating policy node: {node_identifier}")

        # Create update payload
        node_update = {
            'id': node_identifier,
            'type': 'aws-policy',
            'data': {
                'detailedInfoFetched': True,
                'policyDocument': policy_data.get('Document'),
                'versionId': policy_data.get('VersionId') if policy_type == 'managed' else None,
                'totalVersions': policy_data.get('TotalVersions') if policy_type == 'managed' else None,
            },
            'metadata': {
                'lastDetailedFetch': datetime.now().isoformat(),
            }
        }

        # Update node in graph state
        for i, node in enumerate(self.graph_state['nodes']):
            if node['id'] == node_identifier:
                # Deep merge the update into existing node
                self.graph_state['nodes'][i]['data'].update(node_update['data'])
                self.graph_state['nodes'][i]['metadata'].update(node_update['metadata'])
                logger.info(f"[Module] Updated policy node in graph state: {node_identifier}")
                break

        # Broadcast node update
        logger.info(f"[Module] Broadcasting policy node update")
        await self.broadcast_callback(
            create_success_response(
                'graph.node.update',
                {'node': node_update}
            )
        )

        logger.info(f"[Module] Broadcasted policy document update for node: {node_identifier}")


    async def _run_aws_enumerate_lambda(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS Lambda enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from rich.prompt import Confirm
        from src.clouds.aws.modules.enumeration.lambda_functions import enumerate_lambda
        from datetime import datetime
        import sys

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Extract region parameter
            region = params.get('region', None)

            # Broadcast start message
            if region:
                await self._broadcast_module_output(execution_id, f"🔍 Starting Lambda enumeration in region: {region}")
            else:
                await self._broadcast_module_output(execution_id, "🔍 Starting Lambda enumeration across all regions...")

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.lambda_functions as lambda_module
            from src.clouds.aws.utils.regions import _discover_all_regions

            original_console = lambda_module.console
            lambda_module.console = console

            # Patch resolve_regions in the lambda_module directly
            # (it has already imported resolve_regions, so we patch it there)
            original_resolve_regions = lambda_module.resolve_regions

            def custom_resolve_regions(session_mgr, service_name="service", prompt_for_all=True):
                if region:
                    # User specified a specific region
                    return [region]
                else:
                    # No region specified - discover all regions
                    return _discover_all_regions(session_mgr)

            lambda_module.resolve_regions = custom_resolve_regions

            # Patch Confirm.ask to auto-accept when running via WebSocket
            # This prevents interactive prompts from blocking execution
            original_confirm = Confirm.ask

            def auto_confirm(*args, **kwargs):
                # Auto-accept all confirmations (e.g., "scan all regions?")
                return True

            Confirm.ask = auto_confirm

            try:
                # Run enumeration in thread pool to avoid blocking event loop
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_lambda, manager)

                # Get enumeration data
                functions = manager.get_enumeration_data('lambda_functions')
                logger.info(f"[Module] Retrieved {len(functions) if functions else 0} Lambda functions from enumeration data")

                if functions:
                    # Create graph nodes for Lambda functions
                    await self._create_lambda_nodes(functions)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Created {len(functions)} Lambda function nodes in graph"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nNo Lambda functions found in the selected regions"
                    )

                # Broadcast completion
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console, Confirm, and resolve_regions
                lambda_module.console = original_console
                Confirm.ask = original_confirm
                lambda_module.resolve_regions = original_resolve_regions

        except Exception as e:
            logger.error(f"Lambda enumeration error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_describe_lambda(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS Lambda describe (get detailed info for specific function)."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from rich.prompt import Confirm
        from src.clouds.aws.modules.enumeration.lambda_details import describe_lambda_function
        from datetime import datetime

        try:
            # Get function name and region from params
            function_name = params.get('function_name')
            region = params.get('region')
            node_id = params.get('node_id')  # Optional: ID of the Lambda node to update

            if not function_name:
                await self._broadcast_module_error(
                    execution_id,
                    "Missing required parameter: function_name"
                )
                return

            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Broadcast start
            await self._broadcast_module_output(
                execution_id,
                f"🔍 Fetching details for Lambda function: {function_name}"
            )

            # Create broadcasting console (same as enumerate_lambda)
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.lambda_details as lambda_details_module
            original_console = lambda_details_module.console
            lambda_details_module.console = console

            # Patch Confirm.ask to auto-accept (don't ask about showing env vars)
            original_confirm = Confirm.ask
            def auto_confirm(*args, **kwargs):
                return True
            Confirm.ask = auto_confirm

            try:
                # Run describe in thread pool
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        describe_lambda_function,
                        manager,
                        function_name,
                        region
                    )

                # Get detailed data from session
                details = manager.get_enumeration_data('lambda_last_details')

                if details:
                    # Update the Lambda node with detailed information
                    await self._update_lambda_node(node_id or function_name, details)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Updated Lambda node with detailed information"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nNo details retrieved"
                    )

                # Broadcast completion
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console and Confirm
                lambda_details_module.console = original_console
                Confirm.ask = original_confirm

        except Exception as e:
            logger.error(f"Lambda describe error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_get_ec2_userdata(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS EC2 userdata retrieval (get userData for specific instance)."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from src.clouds.aws.modules.enumeration.ec2_userdata import describe_ec2_userdata
        from datetime import datetime

        try:
            # Get instance ID and node ID from params
            instance_id = params.get('instance_id')
            node_id = params.get('node_id')  # Optional: ID of the EC2 node to update

            if not instance_id:
                await self._broadcast_module_error(
                    execution_id,
                    "Missing required parameter: instance_id"
                )
                return

            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Broadcast start
            await self._broadcast_module_output(
                execution_id,
                f"🔍 Fetching userData for EC2 instance: {instance_id}"
            )

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.ec2_userdata as ec2_userdata_module
            original_console = ec2_userdata_module.console
            ec2_userdata_module.console = console

            try:
                # Run describe in thread pool
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        describe_ec2_userdata,
                        manager,
                        instance_id
                    )

                # Get EC2 instance data from cache
                ec2_cache = manager.get_enumeration_data('ec2_instances') or []
                target_instance = None
                for inst in ec2_cache:
                    if inst.get('InstanceId') == instance_id:
                        target_instance = inst
                        break

                if target_instance:
                    # Update the EC2 node with userData
                    await self._update_ec2_node(node_id or instance_id, target_instance)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Updated EC2 node with userData"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nInstance not found in cache"
                    )

                # Broadcast completion
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                ec2_userdata_module.console = original_console

        except Exception as e:
            logger.error(f"EC2 userData retrieval error: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_lambda_nodes(self, functions: list) -> None:
        """Create graph nodes for discovered Lambda functions."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create Lambda nodes - no broadcast callback")
            return

        total_count = len(functions)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} Lambda functions found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} Lambda functions.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_lambda'
            }))
            functions = functions[:MAX_NODES]

        logger.info(f"[Module] Creating {len(functions)} Lambda nodes (total available: {total_count})")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, fn in enumerate(functions):
            try:
                # Create node for Lambda function
                node = {
                    'id': f"lambda-{fn['FunctionArn']}",
                    'type': 'aws-lambda',
                    'label': fn['FunctionName'],
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'functionName': fn['FunctionName'],
                        'runtime': fn.get('Runtime', 'unknown'),
                        'handler': fn.get('Handler', ''),
                        'memorySize': fn.get('MemorySize', 0),
                        'timeout': fn.get('Timeout', 0),
                        'codeSize': fn.get('CodeSize', 0),
                        'role': fn.get('Role', ''),
                        'vpcId': fn.get('VpcId', ''),
                        'hasSecrets': fn.get('HasSecrets', False),
                        'isPublicUrl': fn.get('IsPublicUrl', False),
                        'hasPublicInvoke': fn.get('HasPublicInvoke', False),
                        'isDeprecatedRuntime': fn.get('IsDeprecatedRuntime', False),
                        'functionUrl': fn.get('FunctionUrl', ''),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_lambda',
                        'arn': fn['FunctionArn'],
                        'region': fn['Region'],
                        'lastModified': fn.get('LastModified', ''),
                    },
                }

                self.graph_state['nodes'].append(node)

                # Create edge from session to Lambda
                edge = {
                    'id': f"edge-{self.current_session_id}-{fn['FunctionArn']}",
                    'source': self.current_session_id,
                    'target': f"lambda-{fn['FunctionArn']}",
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                # Send batch when full or on last item
                if len(nodes_batch) >= BATCH_SIZE or i == len(functions) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(functions)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for Lambda {fn.get('FunctionName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(functions)} Lambda function nodes")


    async def _update_lambda_node(
        self,
        node_identifier: str,
        details: dict
    ) -> None:
        """Update an existing Lambda node with detailed information."""
        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot update Lambda node - no broadcast callback")
            return

        from datetime import datetime
        logger.info(f"[Module] Updating Lambda node: {node_identifier}")

        # Create update payload with detailed information
        node_update = {
            'id': node_identifier,
            'type': 'aws-lambda',
            'data': {
                'detailedInfoFetched': True,
                'configuration': details.get('Configuration', {}),
                'code': details.get('Code', {}),
                'tags': details.get('Tags', {}),
                'concurrency': details.get('Concurrency', {}),
                'environment': details.get('Configuration', {}).get('Environment', {}),
                'layers': details.get('Configuration', {}).get('Layers', []),
                'vpcConfig': details.get('Configuration', {}).get('VpcConfig', {}),
                'deadLetterConfig': details.get('Configuration', {}).get('DeadLetterConfig', {}),
            },
            'metadata': {
                'lastDetailedFetch': datetime.now().isoformat(),
            }
        }

        # Update node in graph state
        for i, node in enumerate(self.graph_state['nodes']):
            if node['id'] == node_identifier or node.get('data', {}).get('functionName') == node_identifier:
                # Deep merge the update into existing node
                self.graph_state['nodes'][i]['data'].update(node_update['data'])
                self.graph_state['nodes'][i]['metadata'].update(node_update['metadata'])
                logger.info(f"[Module] Updated Lambda node in graph state: {node_identifier}")
                break

        # Broadcast node update
        logger.info(f"[Module] Broadcasting Lambda node update")
        await self.broadcast_callback(
            create_success_response(
                'graph.node.update',
                {'node': node_update}
            )
        )

        logger.info(f"[Module] Broadcasted Lambda details update for node: {node_identifier}")


    async def _create_mq_nodes(self, brokers: list) -> None:
        """Create graph nodes for Amazon MQ brokers."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create MQ nodes - no broadcast callback")
            return

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, broker in enumerate(brokers):
            try:
                node = {
                    'id': f"mq-{broker.get('BrokerId')}",
                    'type': 'aws-mq',
                    'label': broker.get('BrokerName', broker.get('BrokerId')),
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'brokerId': broker.get('BrokerId'),
                        'brokerName': broker.get('BrokerName'),
                        'brokerArn': broker.get('BrokerArn'),
                        'region': broker.get('Region'),
                        'engineType': broker.get('EngineType'),
                        'brokerState': broker.get('BrokerState'),
                        'publiclyAccessible': broker.get('PubliclyAccessible'),
                        'deploymentMode': broker.get('DeploymentMode'),
                        'hostInstanceType': broker.get('HostInstanceType'),
                        'users': broker.get('Users'),
                    },
                    'metadata': {
                        'arn': broker.get('BrokerArn'),
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_mq',
                        'region': broker.get('Region'),
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{broker.get('BrokerId')}",
                    'source': self.current_session_id,
                    'target': f"mq-{broker.get('BrokerId')}",
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(brokers) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} MQ nodes ({i+1}/{len(brokers)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node for MQ broker {broker.get('BrokerName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(brokers)} MQ broker nodes")


    async def _create_oidc_nodes(self, providers: list) -> None:
        """Create graph nodes for OIDC providers."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create OIDC nodes - no broadcast callback")
            return

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, provider in enumerate(providers):
            try:
                provider_id = provider.get('Arn', '').split('/')[-1]
                node = {
                    'id': f"oidc-{provider_id}",
                    'type': 'aws-oidc',
                    'label': provider.get('Url', 'OIDC Provider'),
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'arn': provider.get('Arn'),
                        'url': provider.get('Url'),
                        'clientIDList': provider.get('ClientIDList'),
                        'thumbprintList': provider.get('ThumbprintList'),
                        'createDate': provider.get('CreateDate'),
                        'tags': provider.get('Tags'),
                    },
                    'metadata': {
                        'arn': provider.get('Arn'),
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_oidc_providers',
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{provider_id}",
                    'source': self.current_session_id,
                    'target': f"oidc-{provider_id}",
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(providers) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} OIDC nodes ({i+1}/{len(providers)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node for OIDC provider {provider.get('Url', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(providers)} OIDC provider nodes")


    async def _create_ssm_nodes(self, parameters: list) -> None:
        """Create graph nodes for SSM parameters."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create SSM nodes - no broadcast callback")
            return

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, param in enumerate(parameters):
            try:
                # Create safe ID from parameter name (replace / with -)
                param_id = f"{param.get('Region')}-{param.get('Name', '').replace('/', '-')}"
                node = {
                    'id': f"ssm-{param_id}",
                    'type': 'aws-ssm',
                    'label': param.get('Name'),
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'name': param.get('Name'),
                        'type': param.get('Type'),
                        'keyId': param.get('KeyId'),
                        'region': param.get('Region'),
                        'version': param.get('Version'),
                        'tier': param.get('Tier'),
                        'description': param.get('Description'),
                        'arn': param.get('ARN'),
                        'lastModifiedDate': param.get('LastModifiedDate'),
                    },
                    'metadata': {
                        'arn': param.get('ARN'),
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_ssm_parameters',
                        'region': param.get('Region'),
                        'isSecure': param.get('Type') == 'SecureString',
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{param_id}",
                    'source': self.current_session_id,
                    'target': f"ssm-{param_id}",
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(parameters) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} SSM nodes ({i+1}/{len(parameters)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node for SSM parameter {param.get('Name', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(parameters)} SSM parameter nodes")


    async def _create_launch_template_nodes(self, templates: list) -> None:
        """Create graph nodes for EC2 Launch Templates."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create Launch Template nodes - no broadcast callback")
            return

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, template in enumerate(templates):
            try:
                # Check if any version has UserData with secrets
                has_secrets = any(
                    len(v.get('UserDataHints', [])) > 0
                    for v in template.get('Versions', [])
                )

                node = {
                    'id': f"lt-{template.get('LaunchTemplateId')}",
                    'type': 'aws-ec2',
                    'label': template.get('LaunchTemplateName'),
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'launchTemplateId': template.get('LaunchTemplateId'),
                        'launchTemplateName': template.get('LaunchTemplateName'),
                        'region': template.get('Region'),
                        'latestVersionNumber': template.get('LatestVersionNumber'),
                        'defaultVersionNumber': template.get('DefaultVersionNumber'),
                        'totalVersions': template.get('TotalVersions'),
                        'hasUserData': any(v.get('HasUserData') for v in template.get('Versions', [])),
                        'hasSecrets': has_secrets,
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_launch_templates',
                        'region': template.get('Region'),
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{template.get('LaunchTemplateId')}",
                    'source': self.current_session_id,
                    'target': f"lt-{template.get('LaunchTemplateId')}",
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(templates) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} Launch Template nodes ({i+1}/{len(templates)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node for Launch Template {template.get('LaunchTemplateName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(templates)} Launch Template nodes")


    async def _create_groundstation_nodes(self, gs_data: dict) -> None:
        """Create graph nodes for Ground Station resources."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create Ground Station nodes - no broadcast callback")
            return

        # Create nodes for satellites (most important)
        satellites = gs_data.get('satellites', [])

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, satellite in enumerate(satellites):
            try:
                node = {
                    'id': f"gs-sat-{satellite.get('satelliteId')}",
                    'type': 'aws-groundstation',
                    'label': satellite.get('satelliteId', 'Satellite'),
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'satelliteId': satellite.get('satelliteId'),
                        'satelliteArn': satellite.get('satelliteArn'),
                        'noradSatelliteID': satellite.get('noradSatelliteID'),
                        'groundStations': satellite.get('groundStations', []),
                    },
                    'metadata': {
                        'arn': satellite.get('satelliteArn'),
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_groundstation',
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{satellite.get('satelliteId')}",
                    'source': self.current_session_id,
                    'target': f"gs-sat-{satellite.get('satelliteId')}",
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(satellites) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} Ground Station nodes ({i+1}/{len(satellites)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node for satellite {satellite.get('satelliteId', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(satellites)} Ground Station satellite nodes")


    async def _create_elasticbeanstalk_nodes(self, eb_data: dict) -> None:
        """Create graph nodes for Elastic Beanstalk environments."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create Elastic Beanstalk nodes - no broadcast callback")
            return

        # Extract all environments from all regions
        all_envs = []
        regions_data = eb_data.get('regions', {})
        for region, data in regions_data.items():
            for env in data.get('environments', []):
                all_envs.append({**env, '_region': region})

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, env in enumerate(all_envs):
            try:
                node = {
                    'id': f"eb-env-{env.get('EnvironmentId')}",
                    'type': 'aws-elasticbeanstalk',
                    'label': env.get('EnvironmentName'),
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'environmentId': env.get('EnvironmentId'),
                        'environmentName': env.get('EnvironmentName'),
                        'environmentArn': env.get('EnvironmentArn'),
                        'applicationName': env.get('ApplicationName'),
                        'region': env.get('_region'),
                        'health': env.get('Health'),
                        'status': env.get('Status'),
                        'versionLabel': env.get('VersionLabel'),
                        'solutionStackName': env.get('SolutionStackName'),
                        'cname': env.get('CNAME'),
                        'endpointURL': env.get('EndpointURL'),
                    },
                    'metadata': {
                        'arn': env.get('EnvironmentArn'),
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_elasticbeanstalk',
                        'region': env.get('_region'),
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-{env.get('EnvironmentId')}",
                    'source': self.current_session_id,
                    'target': f"eb-env-{env.get('EnvironmentId')}",
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(all_envs) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} Elastic Beanstalk nodes ({i+1}/{len(all_envs)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node for environment {env.get('EnvironmentName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(all_envs)} Elastic Beanstalk environment nodes")


    async def _run_aws_enumerate_s3_buckets(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute enumerate_s3_buckets module in background."""
        if not self.current_session or self.current_cloud != 'aws':
            await self._broadcast_module_error(execution_id, "No active AWS session")
            return

        bucket_name = params.get('bucket', None)

        from src.clouds.aws.modules.enumeration.s3_buckets import enumerate_s3_buckets
        manager = self.session_managers.get('aws')
        if not manager:
            await self._broadcast_module_error(execution_id, "AWS session manager not found")
            return

        try:
            if bucket_name:
                await self._broadcast_module_output(
                    execution_id,
                    f"🔍 Analyzing S3 bucket '{bucket_name}' with security configuration..."
                )
            else:
                await self._broadcast_module_output(
                    execution_id,
                    "🔍 Enumerating all S3 buckets with security analysis..."
                )

            # Run module in thread pool
            from concurrent.futures import ThreadPoolExecutor
            loop = asyncio.get_event_loop()

            # Create broadcasting console
            async def broadcast_output(exec_id, line):
                await self._broadcast_module_output(exec_id, line)

            broadcast_console = self.BroadcastConsole(broadcast_output, execution_id, width=120)

            # Replace console temporarily
            import src.clouds.aws.modules.enumeration.s3_buckets as s3_module
            original_console = s3_module.console
            s3_module.console = broadcast_console

            await self._broadcast_module_output(execution_id, "[DEBUG] Starting S3 enumeration...")

            try:
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_s3_buckets(manager, bucket_name=bucket_name)
                    )

                await self._broadcast_module_output(execution_id, "[DEBUG] Module execution completed")

                # Load enumerated data and create nodes
                try:
                    logger.info(f"[S3] Checking for enumeration data in session...")
                    await self._broadcast_module_output(execution_id, "[DEBUG] Checking for enumeration data...")

                    # Use the correct method to get enumeration data
                    buckets = manager.get_enumeration_data('s3_buckets')

                    if buckets is None:
                        buckets = []

                    logger.info(f"[S3] Found {len(buckets)} buckets in enumeration data")
                    await self._broadcast_module_output(
                        execution_id,
                        f"[DEBUG] Found {len(buckets)} buckets in enumeration data"
                    )

                    if buckets:
                        await self._broadcast_module_output(
                            execution_id,
                            f"[DEBUG] Creating {len(buckets)} S3 bucket nodes..."
                        )
                        await self._create_s3_bucket_nodes(buckets)
                        await self._broadcast_module_output(
                            execution_id,
                            f"✓ Created {len(buckets)} S3 bucket nodes in attack graph"
                        )
                    else:
                        logger.warning(f"[S3] No buckets found in enumeration data!")
                        await self._broadcast_module_output(
                            execution_id,
                            "⚠️ No buckets data found - nodes not created"
                        )

                except Exception as data_error:
                    logger.error(f"[S3] Error loading enumeration data: {data_error}", exc_info=True)
                    await self._broadcast_module_output(
                        execution_id,
                        f"[ERROR] Failed to load enumeration data: {str(data_error)}"
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                s3_module.console = original_console

        except Exception as e:
            logger.error(f"S3 enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_s3_bucket_nodes(self, buckets: list) -> None:
        """Create graph nodes for discovered S3 buckets."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create S3 bucket nodes - no broadcast callback")
            return

        total_count = len(buckets)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} S3 buckets found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} S3 buckets.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_s3_buckets'
            }))
            buckets = buckets[:MAX_NODES]

        logger.info(f"[Module] Creating {len(buckets)} S3 bucket nodes (total available: {total_count})")
        logger.info(f"[Module] Current session: {self.current_session}, Session ID: {self.current_session_id}")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, bucket in enumerate(buckets):
            try:
                bucket_name = bucket['Name']
                region = bucket.get('Region', 'us-east-1')

                # Determine security risk level
                is_public = bucket.get('PublicRead', False) or bucket.get('PublicWrite', False)
                no_encryption = bucket.get('Encryption', 'None') == 'None'
                bpa_disabled = not bucket.get('BlockPublicAccessEnabled', False)

                # Create node for S3 bucket
                node = {
                    'id': f"s3-{bucket_name}",
                    'type': 'aws-s3-bucket',
                    'label': bucket_name,
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'bucketName': bucket_name,
                        'region': region,
                        'creationDate': bucket.get('CreationDate', ''),
                        'publicRead': bucket.get('PublicRead', False),
                        'publicWrite': bucket.get('PublicWrite', False),
                        'blockPublicAccessEnabled': bucket.get('BlockPublicAccessEnabled', False),
                        'encryption': bucket.get('Encryption', 'None'),
                        'versioning': bucket.get('Versioning', 'Disabled'),
                        'loggingEnabled': bucket.get('LoggingEnabled', False),
                        'websiteHosting': bucket.get('WebsiteHosting', False),
                        'isPublic': is_public,
                        'isUnencrypted': no_encryption,
                        'isBpaDisabled': bpa_disabled,
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_s3_buckets',
                        'region': region,
                    },
                }

                self.graph_state['nodes'].append(node)

                # Create edge from session to bucket
                edge = {
                    'id': f"edge-{self.current_session_id}-{bucket_name}",
                    'source': self.current_session_id,
                    'target': f"s3-{bucket_name}",
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                # Send batch when full or on last item
                if len(nodes_batch) >= BATCH_SIZE or i == len(buckets) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(buckets)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for S3 bucket {bucket.get('Name', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(buckets)} S3 bucket nodes")


    async def _create_s3_object_nodes(self, bucket_name: str, objects: list) -> None:
        """Create graph nodes for discovered S3 objects (limited to 10)."""
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning(f"[Module] Cannot create S3 object nodes - no broadcast callback")
            return

        logger.info(f"[Module] Creating {len(objects)} S3 object nodes for bucket {bucket_name}")

        for idx, obj in enumerate(objects, 1):
            object_key = obj.get('Key', '')
            object_id = f"s3-obj-{bucket_name}-{object_key.replace('/', '-')}"[:100]  # Limit ID length

            # Create node for S3 object
            node = {
                'id': object_id,
                'type': 'aws-s3-object',
                'label': object_key.split('/')[-1] or object_key,  # Show only filename
                'provider': 'aws',
                'discoveredBy': [self.current_session_id],
                'parentId': f's3-{bucket_name}',
                'data': {
                    'objectKey': object_key,
                    'bucketName': bucket_name,
                    'size': obj.get('Size', 0),
                    'lastModified': obj.get('LastModified', ''),
                    'storageClass': obj.get('StorageClass', 'STANDARD'),
                    'versionId': obj.get('VersionId', ''),
                    'isLatest': obj.get('IsLatest', True),
                    'isDeleteMarker': obj.get('IsDeleteMarker', False),
                },
                'metadata': {
                    'discoveredAt': datetime.now().isoformat(),
                    'moduleUsed': 'enumerate_s3_objects',
                    'fullKey': object_key,
                },
                'level': 2,
            }

            # Save node to graph state
            self.graph_state['nodes'].append(node)

            # Broadcast node
            logger.info(f"[Module] Broadcasting S3 object node: {object_key}")
            await self.broadcast_callback(
                create_success_response(
                    'graph.node.add',
                    {'node': node}
                )
            )

            # Create edge from bucket to object
            edge = {
                'id': f"edge-{bucket_name}-{object_id}",
                'source': f's3-{bucket_name}',
                'target': object_id,
                'type': 'contains',
                'discoveredBy': [self.current_session_id],
            }

            # Save edge to graph state
            self.graph_state['edges'].append(edge)

            # Broadcast edge
            logger.info(f"[Module] Broadcasting edge: {bucket_name} -> {object_key}")
            await self.broadcast_callback(
                create_success_response(
                    'graph.edge.add',
                    {'edge': edge}
                )
            )


    async def _run_aws_enumerate_s3_objects(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute enumerate_s3_objects module with parameters."""
        if not self.current_session or self.current_cloud != 'aws':
            await self._broadcast_module_error(execution_id, "No active AWS session")
            return

        bucket = params.get('bucket')
        prefix = params.get('prefix', None)

        manager = self.session_managers.get('aws')
        if not manager:
            await self._broadcast_module_error(execution_id, "AWS session manager not found")
            return

        # Import asyncio at the beginning so it's available in both branches
        import asyncio
        from concurrent.futures import ThreadPoolExecutor

        # If bucket is not specified, list available buckets first
        if not bucket:
            try:
                await self._broadcast_module_output(
                    execution_id,
                    "📋 No bucket specified. Listing available S3 buckets..."
                )

                # Get boto3 session and list buckets
                from src.clouds.aws.utils.error_handling import safe_aws_call

                loop = asyncio.get_event_loop()
                aws_sess = manager.get_boto3_session()
                s3 = aws_sess.client("s3")

                # List buckets in thread pool
                with ThreadPoolExecutor() as executor:
                    resp, error = await loop.run_in_executor(
                        executor,
                        lambda: safe_aws_call(s3.list_buckets, log_error=True, default=None)
                    )

                if error or not resp:
                    await self._broadcast_module_error(
                        execution_id,
                        f"Failed to list buckets: {error.message if error else 'Unknown error'}"
                    )
                    return

                buckets = resp.get("Buckets", [])
                if not buckets:
                    await self._broadcast_module_output(execution_id, "No S3 buckets found in this account.")
                    await self._broadcast_module_complete(execution_id, success=True)
                    return

                # Display available buckets
                await self._broadcast_module_output(
                    execution_id,
                    f"\n📦 Found {len(buckets)} S3 bucket(s):"
                )

                for idx, bucket_info in enumerate(buckets, 1):
                    bucket_name = bucket_info.get("Name", "")
                    created = str(bucket_info.get("CreationDate", ""))[:19]
                    await self._broadcast_module_output(
                        execution_id,
                        f"  {idx}. {bucket_name} (created: {created})"
                    )

                await self._broadcast_module_output(
                    execution_id,
                    "\n💡 To enumerate objects in a specific bucket, re-run this module with the 'bucket' parameter."
                )

                await self._broadcast_module_complete(execution_id, success=True)
                return

            except Exception as e:
                logger.error(f"Failed to list S3 buckets: {e}", exc_info=True)
                await self._broadcast_module_error(execution_id, str(e))
                return

        # Proceed with object enumeration for specified bucket
        from src.clouds.aws.modules.enumeration.s3_objects import enumerate_s3_objects

        try:
            await self._broadcast_module_output(execution_id, f"🔍 Enumerating objects in bucket '{bucket}'...")

            # Run module in thread pool
            loop = asyncio.get_event_loop()

            # Create broadcasting console
            async def broadcast_output(exec_id, line):
                await self._broadcast_module_output(exec_id, line)

            broadcast_console = self.BroadcastConsole(broadcast_output, execution_id, width=120)

            # Replace console temporarily
            import src.clouds.aws.modules.enumeration.s3_objects as s3_obj_module
            original_console = s3_obj_module.console
            s3_obj_module.console = broadcast_console

            try:
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_s3_objects(manager, bucket=bucket, prefix=prefix)
                    )

                # Load enumerated data
                key_name = f"s3_objects_{bucket}"
                objects = manager.get_enumeration_data(key_name)
                if objects:
                    total_objects = len(objects)
                    await self._broadcast_module_output(
                        execution_id,
                        f"✓ Found {total_objects} objects in {bucket}"
                    )

                    # Create nodes for objects (limited to 10)
                    await self._create_s3_object_nodes(bucket, objects[:10])

                    if total_objects > 10:
                        await self._broadcast_module_output(
                            execution_id,
                            f"ℹ️ Created 10 object nodes in graph (out of {total_objects} total objects)"
                        )
                    else:
                        await self._broadcast_module_output(
                            execution_id,
                            f"✓ Created {total_objects} object nodes in attack graph"
                        )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                s3_obj_module.console = original_console

        except Exception as e:
            logger.error(f"S3 objects enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_ec2(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS EC2 enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from rich.console import Console
        from rich.prompt import Confirm
        from src.clouds.aws.modules.enumeration.ec2_instances import enumerate_ec2
        from datetime import datetime

        try:
            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(
                    execution_id,
                    "Session manager not initialized"
                )
                return

            # Get optional region parameter
            region = params.get('region')

            # Save original configured_regions
            original_configured_regions = manager.configured_regions.copy()

            # If region is specified, override configured_regions temporarily
            if region:
                manager.set_regions([region])
                await self._broadcast_module_output(
                    execution_id,
                    f"🔍 Starting EC2 enumeration in region: {region}..."
                )
            else:
                await self._broadcast_module_output(execution_id, "🔍 Starting EC2 enumeration...")

            # Create broadcasting console
            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            # Replace console in module
            import src.clouds.aws.modules.enumeration.ec2_instances as ec2_module
            original_console = ec2_module.console
            ec2_module.console = console

            # Patch Confirm.ask to auto-accept
            original_confirm = Confirm.ask

            def auto_confirm(*args, **kwargs):
                return True

            Confirm.ask = auto_confirm

            try:
                # Run enumeration in thread pool
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_ec2, manager)

                # Get enumeration data
                instances = manager.get_enumeration_data('ec2_instances')
                logger.info(f"[Module] Retrieved {len(instances) if instances else 0} EC2 instances from enumeration data")

                if instances:
                    # Create graph nodes for EC2 instances
                    await self._create_ec2_nodes(instances)

                    await self._broadcast_module_output(
                        execution_id,
                        f"\n✓ Created {len(instances)} EC2 instance nodes in graph"
                    )
                else:
                    await self._broadcast_module_output(
                        execution_id,
                        "\nNo EC2 instances found in the selected regions"
                    )

                # Broadcast completion
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console and Confirm
                ec2_module.console = original_console
                Confirm.ask = original_confirm
                # Restore original configured_regions
                manager.set_regions(original_configured_regions)

        except Exception as e:
            logger.error(f"EC2 enumeration error: {e}", exc_info=True)
            # Ensure we restore configured_regions even on error
            if 'manager' in locals() and 'original_configured_regions' in locals():
                manager.set_regions(original_configured_regions)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_ec2_nodes(self, instances):
        """Create graph nodes for EC2 instances."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning("[EC2] Cannot create nodes - no broadcast callback")
            return

        total_count = len(instances)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} EC2 instances found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} EC2 instances.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_ec2'
            }))
            instances = instances[:MAX_NODES]

        logger.info(f"[EC2] Creating {len(instances)} EC2 instance nodes (total available: {total_count})")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, inst in enumerate(instances):
            try:
                instance_id = inst['InstanceId']
                region = inst['Region']

                # Determine node color/style based on security posture
                has_iam_role = bool(inst.get('IamInstanceProfile'))
                is_imdsv1 = inst.get('ImdsVersion') == 'v1'
                is_public = bool(inst.get('PublicIp'))

                # Build node
                node = {
                    'id': f'ec2-{instance_id}',
                    'type': 'aws-ec2',
                    'label': inst.get('Name') or instance_id,
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'instanceId': instance_id,
                        'region': region,
                        'name': inst.get('Name', ''),
                        'state': inst.get('State', ''),
                        'instanceType': inst.get('InstanceType', ''),
                        'platform': inst.get('Platform', 'Linux'),
                        'architecture': inst.get('Architecture', ''),
                        'launchTime': inst.get('LaunchTime', ''),
                        'imageId': inst.get('ImageId', ''),

                        # Networking
                        'az': inst.get('AZ', ''),
                        'vpcId': inst.get('VpcId', ''),
                        'subnetId': inst.get('SubnetId', ''),
                        'privateIp': inst.get('PrivateIp', ''),
                        'publicIp': inst.get('PublicIp', ''),
                        'publicDnsName': inst.get('PublicDnsName', ''),
                        'securityGroups': inst.get('SecurityGroups', []),

                        # Security
                        'keyName': inst.get('KeyName', ''),
                        'iamInstanceProfile': inst.get('IamInstanceProfile', ''),
                        'imdsVersion': inst.get('ImdsVersion', ''),
                        'imdsEndpoint': inst.get('ImdsEndpoint', ''),
                        'hasUserData': inst.get('HasUserData', False),

                        # Tags
                        'tags': inst.get('Tags', {}),
                        'environment': inst.get('Environment', ''),
                        'owner': inst.get('Owner', ''),
                        'description': inst.get('Description', ''),

                        # Security flags
                        'hasIamRole': has_iam_role,
                        'isImdsv1': is_imdsv1,
                        'isPublic': is_public,
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_ec2',
                        'region': region,
                        'instanceId': instance_id,
                    },
                }

                self.graph_state['nodes'].append(node)

                # Create edge from session to instance
                edge = {
                    'id': f"edge-{self.current_session_id}-{instance_id}",
                    'source': self.current_session_id,
                    'target': f'ec2-{instance_id}',
                    'label': 'discovered',
                    'type': 'discovered',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(instances) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[EC2] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(instances)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[EC2] Failed to create node/edge for instance {inst.get('InstanceId', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[EC2] Created {len(instances)} EC2 instance nodes in graph")


    async def _run_aws_download_s3_bucket(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute download_s3_bucket module with parameters."""
        if not self.current_session or self.current_cloud != 'aws':
            await self._broadcast_module_error(execution_id, "No active AWS session")
            return

        bucket = params.get('bucket')
        prefix = params.get('prefix', None)
        dest_dir = params.get('dest_dir', None)
        include_versions = params.get('include_versions', False)

        if not bucket:
            await self._broadcast_module_error(execution_id, "Missing required parameter: bucket")
            return

        from src.clouds.aws.modules.exfiltration.s3_download_bucket import download_s3_bucket
        manager = self.session_managers.get('aws')
        if not manager:
            await self._broadcast_module_error(execution_id, "AWS session manager not found")
            return

        try:
            await self._broadcast_module_output(
                execution_id,
                f"⚠️ WARNING: Files will be downloaded to the WebSocket server, not your browser!"
            )
            await self._broadcast_module_output(
                execution_id,
                f"🔽 Downloading bucket '{bucket}' (this may take a while)..."
            )

            # Run module in thread pool
            from concurrent.futures import ThreadPoolExecutor
            loop = asyncio.get_event_loop()

            # Create broadcasting console
            async def broadcast_output(exec_id, line):
                await self._broadcast_module_output(exec_id, line)

            broadcast_console = self.BroadcastConsole(broadcast_output, execution_id, width=120)

            # Replace console temporarily
            import src.clouds.aws.modules.exfiltration.s3_download_bucket as s3_dl_module
            original_console = s3_dl_module.console
            s3_dl_module.console = broadcast_console

            try:
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: download_s3_bucket(
                            manager,
                            bucket=bucket,
                            prefix=prefix,
                            dest_dir=dest_dir,
                            include_versions=include_versions
                        )
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                s3_dl_module.console = original_console

        except Exception as e:
            logger.error(f"S3 bucket download failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_download_s3_object(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute download_s3_object module with parameters."""
        if not self.current_session or self.current_cloud != 'aws':
            await self._broadcast_module_error(execution_id, "No active AWS session")
            return

        bucket = params.get('bucket')
        key = params.get('key')
        dest = params.get('dest', None)
        version_id = params.get('version_id', None)

        if not bucket or not key:
            await self._broadcast_module_error(execution_id, "Missing required parameters: bucket and key")
            return

        from src.clouds.aws.modules.exfiltration.s3_download_object import download_s3_object
        manager = self.session_managers.get('aws')
        if not manager:
            await self._broadcast_module_error(execution_id, "AWS session manager not found")
            return

        try:
            await self._broadcast_module_output(
                execution_id,
                f"⚠️ WARNING: File will be downloaded to the WebSocket server, not your browser!"
            )
            await self._broadcast_module_output(
                execution_id,
                f"🔽 Downloading object '{key}' from bucket '{bucket}'..."
            )

            # Run module in thread pool
            from concurrent.futures import ThreadPoolExecutor
            loop = asyncio.get_event_loop()

            # Create broadcasting console
            async def broadcast_output(exec_id, line):
                await self._broadcast_module_output(exec_id, line)

            broadcast_console = self.BroadcastConsole(broadcast_output, execution_id, width=120)

            # Replace console temporarily
            import src.clouds.aws.modules.exfiltration.s3_download_object as s3_obj_dl_module
            original_console = s3_obj_dl_module.console
            s3_obj_dl_module.console = broadcast_console

            try:
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: download_s3_object(
                            manager,
                            bucket=bucket,
                            key=key,
                            dest=dest,
                            version_id=version_id
                        )
                    )

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                # Restore original console
                s3_obj_dl_module.console = original_console

        except Exception as e:
            logger.error(f"S3 object download failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    # ==================== RDS & Database Modules ====================


    async def _run_aws_enumerate_rds_instances(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS RDS instances enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.rds_instances import enumerate_rds_instances

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            # Handle region parameter - set it temporarily in the session manager
            region = params.get('region', None)
            original_regions = manager.current_session_data.get("regions", []).copy() if manager.current_session_data.get("regions") else None

            if region:
                # Set specific region for this enumeration
                manager.current_session_data["regions"] = [region]
                await self._broadcast_module_output(execution_id, f"🔍 Starting RDS instances enumeration in {region}...")
            else:
                await self._broadcast_module_output(execution_id, "🔍 Starting RDS instances enumeration in all configured regions...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.rds_instances as rds_module
            original_console = rds_module.console
            rds_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_rds_instances, manager)

                instances = manager.get_enumeration_data('rds_instances')
                logger.info(f"[Module] Retrieved {len(instances) if instances else 0} RDS instances")

                if instances:
                    await self._create_rds_instance_nodes(instances)
                    await self._broadcast_module_output(execution_id, f"\n✓ Created {len(instances)} RDS instance nodes in graph")
                else:
                    await self._broadcast_module_output(execution_id, "\nNo RDS instances found")

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                rds_module.console = original_console
                # Restore original regions configuration
                if original_regions is not None:
                    manager.current_session_data["regions"] = original_regions
                elif region:
                    # Clear the temporary region setting
                    manager.current_session_data["regions"] = []

        except Exception as e:
            logger.error(f"RDS instances enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_rds_instance_nodes(self, instances: list) -> None:
        """Create graph nodes for discovered RDS instances."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning("[Module] Cannot create RDS instance nodes - no broadcast callback")
            return

        # Filter out invalid instances first
        valid_instances = []
        for instance in instances:
            if isinstance(instance, str):
                logger.warning(f"[Module] Skipping invalid instance format: {instance}")
                continue
            db_id = instance.get('DBInstanceIdentifier', '')
            if not db_id:
                logger.warning(f"[Module] Skipping instance without identifier: {instance}")
                continue
            valid_instances.append(instance)

        total_count = len(valid_instances)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} RDS instances found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} RDS instances.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_rds_instances'
            }))
            valid_instances = valid_instances[:MAX_NODES]

        logger.info(f"[Module] Creating {len(valid_instances)} RDS instance nodes (total available: {total_count})")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, instance in enumerate(valid_instances):
            try:
                db_id = instance.get('DBInstanceIdentifier', '')

                node = {
                    'id': f"rds-{db_id}",
                    'type': 'aws-rds',
                    'label': db_id,
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'dbInstanceIdentifier': db_id,
                        'region': instance.get('Region', ''),
                        'engine': instance.get('Engine', ''),
                        'engineVersion': instance.get('EngineVersion', ''),
                        'endpoint': instance.get('Endpoint', ''),
                        'port': instance.get('Port', ''),
                        'masterUsername': instance.get('MasterUsername', ''),
                        'dbName': instance.get('DBName', ''),
                        'publiclyAccessible': instance.get('PubliclyAccessible', False),
                        'encrypted': instance.get('StorageEncrypted', False),
                        'iamAuthEnabled': instance.get('IAMDatabaseAuthenticationEnabled', False),
                        'multiAZ': instance.get('MultiAZ', False),
                        'deletionProtection': instance.get('DeletionProtection', False),
                        'vpcId': instance.get('VpcId', ''),
                        'availabilityZone': instance.get('AvailabilityZone', ''),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_rds_instances',
                        'region': instance.get('Region', ''),
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-rds-{db_id}",
                    'source': self.current_session_id,
                    'target': f"rds-{db_id}",
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(valid_instances) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(valid_instances)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for RDS instance {instance.get('DBInstanceIdentifier', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(valid_instances)} RDS instance nodes")


    async def _run_aws_enumerate_rds_snapshots(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS RDS snapshots enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.rds_snapshots import enumerate_rds_snapshots

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            # Handle region parameter
            region = params.get('region', None)
            original_regions = manager.current_session_data.get("regions", []).copy() if manager.current_session_data.get("regions") else None

            if region:
                manager.current_session_data["regions"] = [region]
                await self._broadcast_module_output(execution_id, f"🔍 Starting RDS snapshots enumeration in {region}...")
            else:
                await self._broadcast_module_output(execution_id, "🔍 Starting RDS snapshots enumeration in all configured regions...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.rds_snapshots as rds_snap_module
            original_console = rds_snap_module.console
            rds_snap_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_rds_snapshots, manager)

                snapshots = manager.get_enumeration_data('rds_snapshots')
                logger.info(f"[Module] Retrieved {len(snapshots) if snapshots else 0} RDS snapshots")

                if snapshots:
                    await self._broadcast_module_output(execution_id, f"\n✓ Found {len(snapshots)} RDS snapshots")
                else:
                    await self._broadcast_module_output(execution_id, "\nNo RDS snapshots found")

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                rds_snap_module.console = original_console
                # Restore original regions configuration
                if original_regions is not None:
                    manager.current_session_data["regions"] = original_regions
                elif region:
                    manager.current_session_data["regions"] = []

        except Exception as e:
            logger.error(f"RDS snapshots enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_rds_public_snapshots(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS RDS public snapshots enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.rds_public_snapshots import enumerate_rds_public_snapshots_interactive

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            # Handle region parameter
            region = params.get('region', None)
            original_regions = manager.current_session_data.get("regions", []).copy() if manager.current_session_data.get("regions") else None

            if region:
                manager.current_session_data["regions"] = [region]
                await self._broadcast_module_output(execution_id, f"🔍 Starting RDS public snapshots enumeration in {region}...")
            else:
                await self._broadcast_module_output(execution_id, "🔍 Starting RDS public snapshots enumeration in all configured regions...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.rds_public_snapshots as rds_pub_module
            original_console = rds_pub_module.console
            rds_pub_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_rds_public_snapshots_interactive, manager)

                snapshots = manager.get_enumeration_data('rds_public_snapshots')
                logger.info(f"[Module] Retrieved {len(snapshots) if snapshots else 0} public RDS snapshots")

                if snapshots:
                    await self._broadcast_module_output(execution_id, f"\n✓ Found {len(snapshots)} public RDS snapshots")
                else:
                    await self._broadcast_module_output(execution_id, "\nNo public RDS snapshots found")

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                rds_pub_module.console = original_console
                # Restore original regions configuration
                if original_regions is not None:
                    manager.current_session_data["regions"] = original_regions
                elif region:
                    manager.current_session_data["regions"] = []

        except Exception as e:
            logger.error(f"RDS public snapshots enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_generate_rds_token(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS RDS IAM token generation module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.exfiltration.rds_iam_token import generate_rds_token

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            hostname = params.get('hostname')
            port = params.get('port', 3306)
            username = params.get('username')
            region = params.get('region', None)

            if not hostname or not username:
                await self._broadcast_module_error(execution_id, "Missing required parameters: hostname, username")
                return

            await self._broadcast_module_output(execution_id, f"🔐 Generating RDS IAM token for {username}@{hostname}:{port}...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.exfiltration.rds_iam_token as rds_token_module
            original_console = rds_token_module.console
            rds_token_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: generate_rds_token(manager, hostname=hostname, port=port, username=username, region=region)
                    )

                await self._broadcast_module_output(execution_id, "\n✓ RDS IAM token generated successfully")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                rds_token_module.console = original_console

        except Exception as e:
            logger.error(f"RDS token generation failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_dynamodb_tables(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS DynamoDB tables enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.dynamodb_tables import enumerate_dynamodb_tables

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            # Handle region parameter
            region = params.get('region', None)
            original_regions = manager.current_session_data.get("regions", []).copy() if manager.current_session_data.get("regions") else None

            if region:
                manager.current_session_data["regions"] = [region]
                await self._broadcast_module_output(execution_id, f"🔍 Starting DynamoDB tables enumeration in {region}...")
            else:
                await self._broadcast_module_output(execution_id, "🔍 Starting DynamoDB tables enumeration in all configured regions...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.dynamodb_tables as ddb_module
            original_console = ddb_module.console
            ddb_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_dynamodb_tables, manager)

                tables = manager.get_enumeration_data('dynamodb_tables')
                logger.info(f"[Module] Retrieved {len(tables) if tables else 0} DynamoDB tables")

                if tables:
                    await self._create_dynamodb_table_nodes(tables)
                    await self._broadcast_module_output(execution_id, f"\n✓ Created {len(tables)} DynamoDB table nodes in graph")
                else:
                    await self._broadcast_module_output(execution_id, "\nNo DynamoDB tables found")

                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                ddb_module.console = original_console
                # Restore original regions configuration
                if original_regions is not None:
                    manager.current_session_data["regions"] = original_regions
                elif region:
                    manager.current_session_data["regions"] = []

        except Exception as e:
            logger.error(f"DynamoDB tables enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_dynamodb_table_nodes(self, tables: list) -> None:
        """Create graph nodes for discovered DynamoDB tables."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning("[Module] Cannot create DynamoDB table nodes - no broadcast callback")
            return

        # Filter out invalid tables first
        valid_tables = []
        for table in tables:
            if isinstance(table, str):
                logger.warning(f"[Module] Skipping invalid table format: {table}")
                continue
            table_name = table.get('TableName', '')
            if not table_name:
                logger.warning(f"[Module] Skipping table without name: {table}")
                continue
            valid_tables.append(table)

        total_count = len(valid_tables)
        MAX_NODES = 500

        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} DynamoDB tables found, limiting to {MAX_NODES} nodes")
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} DynamoDB tables.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_dynamodb_tables'
            }))
            valid_tables = valid_tables[:MAX_NODES]

        logger.info(f"[Module] Creating {len(valid_tables)} DynamoDB table nodes (total available: {total_count})")

        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, table in enumerate(valid_tables):
            try:
                table_name = table.get('TableName', '')

                node = {
                    'id': f"dynamodb-{table_name}",
                    'type': 'aws-dynamodb',
                    'label': table_name,
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'tableName': table_name,
                        'region': table.get('Region', ''),
                        'partitionKey': table.get('PartitionKey', ''),
                        'sortKey': table.get('SortKey', ''),
                        'billingMode': table.get('BillingMode', ''),
                        'readCapacity': table.get('ReadCapacity'),
                        'writeCapacity': table.get('WriteCapacity'),
                        'streamEnabled': table.get('StreamEnabled', False),
                        'encrypted': table.get('Encrypted', False),
                        'pitrEnabled': table.get('PITREnabled', False),
                        'describeOK': table.get('DescribeOK', True),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_dynamodb_tables',
                        'region': table.get('Region', ''),
                    },
                }

                self.graph_state['nodes'].append(node)

                edge = {
                    'id': f"edge-{self.current_session_id}-dynamodb-{table_name}",
                    'source': self.current_session_id,
                    'target': f"dynamodb-{table_name}",
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                if len(nodes_batch) >= BATCH_SIZE or i == len(valid_tables) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))
                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(valid_tables)})")
                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for DynamoDB table {table.get('TableName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(valid_tables)} DynamoDB table nodes")


    async def _run_aws_describe_dynamodb_table(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS DynamoDB table details module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.dynamodb_table_details import describe_dynamodb_table

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            table_name = params.get('table_name')
            region = params.get('region', None)

            if not table_name:
                await self._broadcast_module_error(execution_id, "Missing required parameter: table_name")
                return

            # Handle region parameter
            original_regions = manager.current_session_data.get("regions", []).copy() if manager.current_session_data.get("regions") else None
            if region:
                manager.current_session_data["regions"] = [region]

            await self._broadcast_module_output(execution_id, f"🔍 Getting details for DynamoDB table: {table_name}{f' in {region}' if region else ''}...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.dynamodb_table_details as ddb_details_module
            original_console = ddb_details_module.console
            ddb_details_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, lambda: describe_dynamodb_table(manager, table_name=table_name))

                await self._broadcast_module_output(execution_id, f"\n✓ Retrieved details for table: {table_name}")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                ddb_details_module.console = original_console
                # Restore original regions configuration
                if original_regions is not None:
                    manager.current_session_data["regions"] = original_regions
                elif region:
                    manager.current_session_data["regions"] = []

        except Exception as e:
            logger.error(f"DynamoDB table details failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_exfiltrate_dynamodb_table(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Execute AWS DynamoDB table scan/export module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.exfiltration.dynamodb_scan import exfiltrate_dynamodb_table

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            table_name = params.get('table_name')
            region = params.get('region', None)
            limit = params.get('limit', None)

            if not table_name:
                await self._broadcast_module_error(execution_id, "Missing required parameter: table_name")
                return

            # Handle region parameter
            original_regions = manager.current_session_data.get("regions", []).copy() if manager.current_session_data.get("regions") else None
            if region:
                manager.current_session_data["regions"] = [region]

            await self._broadcast_module_output(execution_id, f"🔽 Scanning DynamoDB table: {table_name}{f' in {region}' if region else ''}...")
            if limit:
                await self._broadcast_module_output(execution_id, f"⚠️  Limited to {limit} items")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.exfiltration.dynamodb_scan as ddb_scan_module
            original_console = ddb_scan_module.console
            ddb_scan_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: exfiltrate_dynamodb_table(manager, table_name=table_name, limit=limit)
                    )

                await self._broadcast_module_output(execution_id, f"\n✓ DynamoDB table scan completed")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                ddb_scan_module.console = original_console
                # Restore original regions configuration
                if original_regions is not None:
                    manager.current_session_data["regions"] = original_regions
                elif region:
                    manager.current_session_data["regions"] = []

        except Exception as e:
            logger.error(f"DynamoDB table scan failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    # ==================== Storage & Container Registries Modules ====================


    async def _run_aws_enumerate_ebs_snapshots(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS EBS snapshots enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.ebs_snapshots import enumerate_ebs_snapshots

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            region = params.get('region', None)

            # Handle region parameter
            original_regions = manager.current_session_data.get("regions", []).copy() if manager.current_session_data.get("regions") else None
            if region:
                manager.current_session_data["regions"] = [region]

            await self._broadcast_module_output(execution_id, f"🔍 Enumerating EBS snapshots{f' in {region}' if region else ''}...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.ebs_snapshots as ebs_module
            original_console = ebs_module.console
            ebs_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_ebs_snapshots, manager)

                # Create graph nodes
                snapshots = manager.get_enumeration_data('ebs_snapshots')
                if snapshots and isinstance(snapshots, list):
                    await self._create_ebs_snapshot_nodes(snapshots, execution_id)

                await self._broadcast_module_output(execution_id, f"\n✓ EBS snapshots enumeration completed")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                ebs_module.console = original_console
                # Restore original regions configuration
                if original_regions is not None:
                    manager.current_session_data["regions"] = original_regions
                elif region:
                    manager.current_session_data["regions"] = []

        except Exception as e:
            logger.error(f"EBS snapshots enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_ebs_snapshot_nodes(self, snapshots: list, execution_id: str) -> None:
        """Create graph nodes for EBS snapshots."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning("[Module] Cannot create EBS snapshot nodes - no broadcast callback")
            return

        total_count = len(snapshots)
        MAX_NODES = 500  # Limite massimo nodi per prevenire UI freeze

        # Invia warning se ci sono più nodi del limite
        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} EBS snapshots found, limiting to {MAX_NODES} nodes")
            await self._broadcast_module_output(
                execution_id,
                f"⚠️  Found {total_count} EBS snapshots, showing first {MAX_NODES} to prevent UI overload"
            )
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} EBS snapshots. Use region filter to refine results.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_ebs_snapshots'
            }))
            snapshots = snapshots[:MAX_NODES]

        logger.info(f"[Module] Creating {len(snapshots)} EBS snapshot nodes (total available: {total_count})")

        # BATCH PROCESSING per evitare WebSocket overflow
        BATCH_SIZE = 50  # Invia 50 nodi + 50 edge alla volta
        nodes_batch = []
        edges_batch = []

        for i, snapshot in enumerate(snapshots):
            try:
                if isinstance(snapshot, str):
                    logger.warning(f"[Module] Skipping invalid snapshot format: {snapshot}")
                    continue

                snapshot_id = snapshot.get('SnapshotId', '')
                if not snapshot_id:
                    logger.warning(f"[Module] Skipping snapshot without ID: {snapshot}")
                    continue

                node = {
                    'id': f"ebs-snapshot-{snapshot_id}",
                    'type': 'aws-ebs-snapshot',
                    'label': snapshot_id,
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'snapshotId': snapshot_id,
                        'region': snapshot.get('Region', ''),
                        'volumeId': snapshot.get('VolumeId', ''),
                        'state': snapshot.get('State', ''),
                        'volumeSizeGiB': snapshot.get('VolumeSizeGiB', 0),
                        'encrypted': snapshot.get('Encrypted', False),
                        'ownerId': snapshot.get('OwnerId', ''),
                        'description': snapshot.get('Description', ''),
                        'startTime': snapshot.get('StartTime', ''),
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_ebs_snapshots',
                        'region': snapshot.get('Region', ''),
                    },
                    'level': 1,
                }

                edge = {
                    'id': f"edge-{self.current_session_id}-ebs-snapshot-{snapshot_id}",
                    'source': self.current_session_id,
                    'target': f"ebs-snapshot-{snapshot_id}",
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['nodes'].append(node)
                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                # Invia batch quando raggiungiamo BATCH_SIZE o siamo all'ultimo
                if len(nodes_batch) >= BATCH_SIZE or i == len(snapshots) - 1:
                    # Invia tutti i nodi in un unico messaggio
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    # Invia tutti gli edge in un unico messaggio
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))

                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(snapshots)})")

                    # Svuota batch
                    nodes_batch = []
                    edges_batch = []

                    # Piccolo delay per non saturare il WebSocket
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for snapshot {snapshot.get('SnapshotId', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(snapshots)} EBS snapshot nodes")


    async def _run_aws_download_ebs_snapshot(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS EBS snapshot download module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.exfiltration.ebs_download_snapshots import download_ebs_snapshot

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            snapshot_id = params.get('snapshot_id', None)
            out_dir = params.get('out_dir', None)

            await self._broadcast_module_output(execution_id, f"💾 Downloading EBS snapshot{f': {snapshot_id}' if snapshot_id else ''}...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.exfiltration.ebs_download_snapshots as ebs_dl_module
            original_console = ebs_dl_module.console
            ebs_dl_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: download_ebs_snapshot(manager, snapshot_id=snapshot_id, out_dir=out_dir)
                    )

                await self._broadcast_module_output(execution_id, f"\n✓ EBS snapshot download completed")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                ebs_dl_module.console = original_console

        except Exception as e:
            logger.error(f"EBS snapshot download failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_ecr_repositories(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS ECR repositories enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.ecr_repos import enumerate_ecr_repositories

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            region = params.get('region', None)

            # Handle region parameter
            original_regions = manager.current_session_data.get("regions", []).copy() if manager.current_session_data.get("regions") else None
            if region:
                manager.current_session_data["regions"] = [region]

            await self._broadcast_module_output(execution_id, f"🔍 Enumerating ECR repositories{f' in {region}' if region else ''}...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.ecr_repos as ecr_module
            original_console = ecr_module.console
            ecr_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(executor, enumerate_ecr_repositories, manager)

                # Create graph nodes
                repositories = manager.get_enumeration_data('ecr_repositories')
                if repositories and isinstance(repositories, list):
                    await self._create_ecr_repository_nodes(repositories, execution_id)

                await self._broadcast_module_output(execution_id, f"\n✓ ECR repositories enumeration completed")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                ecr_module.console = original_console
                # Restore original regions configuration
                if original_regions is not None:
                    manager.current_session_data["regions"] = original_regions
                elif region:
                    manager.current_session_data["regions"] = []

        except Exception as e:
            logger.error(f"ECR repositories enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _create_ecr_repository_nodes(self, repositories: list, execution_id: str) -> None:
        """Create graph nodes for ECR repositories."""
        import asyncio
        from datetime import datetime

        if not self.broadcast_callback:
            logger.warning("[Module] Cannot create ECR repository nodes - no broadcast callback")
            return

        total_count = len(repositories)
        MAX_NODES = 500  # Limite massimo nodi per prevenire UI freeze

        # Invia warning se ci sono più nodi del limite
        if total_count > MAX_NODES:
            logger.warning(f"[Module] {total_count} ECR repositories found, limiting to {MAX_NODES} nodes")
            await self._broadcast_module_output(
                execution_id,
                f"⚠️  Found {total_count} ECR repositories, showing first {MAX_NODES} to prevent UI overload"
            )
            await self.broadcast_callback(create_success_response('module.warning', {
                'message': f'Showing {MAX_NODES} of {total_count} ECR repositories. Use region filter to refine results.',
                'total': total_count,
                'shown': MAX_NODES,
                'module': 'enumerate_ecr_repositories'
            }))
            repositories = repositories[:MAX_NODES]

        logger.info(f"[Module] Creating {len(repositories)} ECR repository nodes (total available: {total_count})")

        # BATCH PROCESSING per evitare WebSocket overflow
        BATCH_SIZE = 50
        nodes_batch = []
        edges_batch = []

        for i, repo in enumerate(repositories):
            try:
                if isinstance(repo, str):
                    logger.warning(f"[Module] Skipping invalid repository format: {repo}")
                    continue

                repo_name = repo.get('RepositoryName', '')
                if not repo_name:
                    logger.warning(f"[Module] Skipping repository without name: {repo}")
                    continue

                images = repo.get('Images', [])
                image_count = len(images) if isinstance(images, list) else 0

                node = {
                    'id': f"ecr-{repo_name}",
                    'type': 'aws-ecr',
                    'label': repo_name,
                    'provider': 'aws',
                    'discoveredBy': [self.current_session_id],
                    'parentId': self.current_session_id,
                    'data': {
                        'repositoryName': repo_name,
                        'region': repo.get('Region', ''),
                        'repositoryUri': repo.get('RepositoryUri', ''),
                        'createdAt': repo.get('CreatedAt', ''),
                        'scanOnPush': repo.get('ScanOnPush', False),
                        'imageCount': image_count,
                    },
                    'metadata': {
                        'discoveredAt': datetime.now().isoformat(),
                        'moduleUsed': 'enumerate_ecr_repositories',
                        'region': repo.get('Region', ''),
                    },
                    'level': 1,
                }

                edge = {
                    'id': f"edge-{self.current_session_id}-ecr-{repo_name}",
                    'source': self.current_session_id,
                    'target': f"ecr-{repo_name}",
                    'label': 'discovered',
                    'type': 'owns',
                    'discoveredBy': [self.current_session_id],
                }

                self.graph_state['nodes'].append(node)
                self.graph_state['edges'].append(edge)
                nodes_batch.append(node)
                edges_batch.append(edge)

                # Invia batch quando raggiungiamo BATCH_SIZE o siamo all'ultimo
                if len(nodes_batch) >= BATCH_SIZE or i == len(repositories) - 1:
                    await self.broadcast_callback(create_success_response('graph.nodes.add', {'nodes': nodes_batch}))
                    await self.broadcast_callback(create_success_response('graph.edges.add', {'edges': edges_batch}))

                    logger.info(f"[Module] Sent batch of {len(nodes_batch)} nodes and {len(edges_batch)} edges ({i+1}/{len(repositories)})")

                    nodes_batch = []
                    edges_batch = []
                    await asyncio.sleep(0.05)

            except Exception as e:
                logger.error(f"[Module] Failed to create node/edge for repository {repo.get('RepositoryName', 'unknown')}: {e}", exc_info=True)

        logger.info(f"[Module] Created {len(repositories)} ECR repository nodes")


    async def _run_aws_get_ecr_credentials(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS ECR credentials retrieval module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.exfiltration.ecr_credentials import get_ecr_credentials

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            registry_id = params.get('registry_id', None)
            region = params.get('region', None)

            await self._broadcast_module_output(execution_id, f"🔑 Getting ECR credentials{f' for registry {registry_id}' if registry_id else ''}{f' in {region}' if region else ''}...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.exfiltration.ecr_credentials as ecr_cred_module
            original_console = ecr_cred_module.console
            ecr_cred_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: get_ecr_credentials(manager, registry_id=registry_id, region=region)
                    )

                await self._broadcast_module_output(execution_id, f"\n✓ ECR credentials retrieved")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                ecr_cred_module.console = original_console

        except Exception as e:
            logger.error(f"ECR credentials retrieval failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_mq(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS Amazon MQ enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.mq_enum import enumerate_mq_brokers

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            await self._broadcast_module_output(execution_id, "🔍 Enumerating Amazon MQ brokers...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.mq_enum as mq_module
            original_console = mq_module.console
            mq_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_mq_brokers(manager)
                    )

                # Get enumerated data and create graph nodes
                mq_brokers = manager.get_enumeration_data('mq_brokers')
                if mq_brokers:
                    await self._create_mq_nodes(mq_brokers)

                await self._broadcast_module_output(execution_id, f"\n✓ Amazon MQ enumeration complete")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                mq_module.console = original_console

        except Exception as e:
            logger.error(f"Amazon MQ enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_sns(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS SNS enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.sns_enum import enumerate_sns

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            max_topics = params.get('max_topics', 100)
            verbose = params.get('verbose', False)

            await self._broadcast_module_output(execution_id, f"🔔 Enumerating SNS topics (max {max_topics} per region)...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.sns_enum as sns_module
            original_console = sns_module.console
            sns_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_sns(manager, max_topics=max_topics, verbose=verbose)
                    )

                await self._broadcast_module_output(execution_id, f"\n✓ SNS enumeration complete")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                sns_module.console = original_console

        except Exception as e:
            logger.error(f"SNS enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_oidc_providers(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS OIDC providers enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.oidc_providers import enumerate_oidc_providers

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            await self._broadcast_module_output(execution_id, "🔍 Enumerating OIDC identity providers...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.oidc_providers as oidc_module
            original_console = oidc_module.console
            oidc_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_oidc_providers(manager)
                    )

                # Get enumerated data and create graph nodes
                oidc_providers = manager.get_enumeration_data('oidc_providers')
                if oidc_providers:
                    await self._create_oidc_nodes(oidc_providers)

                await self._broadcast_module_output(execution_id, f"\n✓ OIDC providers enumeration complete")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                oidc_module.console = original_console

        except Exception as e:
            logger.error(f"OIDC providers enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_ssm_parameters(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS SSM Parameter Store enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.ssm_parameters import enumerate_ssm_parameters

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            await self._broadcast_module_output(execution_id, "🔍 Enumerating SSM Parameter Store...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.ssm_parameters as ssm_module
            original_console = ssm_module.console
            ssm_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_ssm_parameters(manager)
                    )

                # Get enumerated data and create graph nodes
                ssm_params = manager.get_enumeration_data('ssm_parameters')
                if ssm_params:
                    await self._create_ssm_nodes(ssm_params)

                await self._broadcast_module_output(execution_id, f"\n✓ SSM Parameter Store enumeration complete")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                ssm_module.console = original_console

        except Exception as e:
            logger.error(f"SSM Parameter Store enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_launch_templates(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS EC2 Launch Templates enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.launch_templates import enumerate_launch_templates

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            await self._broadcast_module_output(execution_id, "🚀 Enumerating EC2 Launch Templates...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.launch_templates as lt_module
            original_console = lt_module.console
            lt_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_launch_templates(manager)
                    )

                # Get enumerated data and create graph nodes
                launch_templates = manager.get_enumeration_data('launch_templates')
                if launch_templates:
                    await self._create_launch_template_nodes(launch_templates)

                await self._broadcast_module_output(execution_id, f"\n✓ Launch Templates enumeration complete")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                lt_module.console = original_console

        except Exception as e:
            logger.error(f"Launch Templates enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_groundstation(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS Ground Station enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.groundstation_enum import enumerate_groundstation

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            await self._broadcast_module_output(execution_id, "🛰️  Enumerating AWS Ground Station resources...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.groundstation_enum as gs_module
            original_console = gs_module.console
            gs_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_groundstation(manager)
                    )

                # Get enumerated data and create graph nodes
                gs_data = manager.get_enumeration_data('groundstation')
                if gs_data:
                    await self._create_groundstation_nodes(gs_data)

                await self._broadcast_module_output(execution_id, f"\n✓ Ground Station enumeration complete")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                gs_module.console = original_console

        except Exception as e:
            logger.error(f"Ground Station enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))


    async def _run_aws_enumerate_elasticbeanstalk(self, execution_id: str, params: Dict[str, Any] = {}) -> None:
        """Execute AWS Elastic Beanstalk enumeration module."""
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from io import StringIO
        from src.clouds.aws.modules.enumeration.elasticbeanstalk_enum import enumerate_elasticbeanstalk

        try:
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                await self._broadcast_module_error(execution_id, "Session manager not initialized")
                return

            await self._broadcast_module_output(execution_id, "🪲 Enumerating Elastic Beanstalk...")

            output_buffer = StringIO()
            console = self.BroadcastConsole(
                self._broadcast_module_output,
                execution_id,
                file=output_buffer,
                width=120,
                force_terminal=False
            )

            import src.clouds.aws.modules.enumeration.elasticbeanstalk_enum as eb_module
            original_console = eb_module.console
            eb_module.console = console

            try:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    await loop.run_in_executor(
                        executor,
                        lambda: enumerate_elasticbeanstalk(manager)
                    )

                # Get enumerated data and create graph nodes
                eb_data = manager.get_enumeration_data('elasticbeanstalk')
                if eb_data:
                    await self._create_elasticbeanstalk_nodes(eb_data)

                await self._broadcast_module_output(execution_id, f"\n✓ Elastic Beanstalk enumeration complete")
                await self._broadcast_module_complete(execution_id, success=True)

            finally:
                eb_module.console = original_console

        except Exception as e:
            logger.error(f"Elastic Beanstalk enumeration failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

