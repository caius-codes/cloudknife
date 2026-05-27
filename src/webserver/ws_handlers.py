"""
WebSocket command handlers for CloudKnife operations.

This file acts as a lightweight coordinator that delegates to specialized handlers.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from .ws_messages import (
    WebSocketMessage,
    WebSocketResponse,
    MessageType,
    create_success_response,
    create_error_response,
)
from .session_importer import import_cli_sessions
from .handlers.session_handler import SessionHandler
from .handlers.credential_handler import CredentialHandler
from .handlers.graph_handler import GraphHandler
from .handlers.cloud_providers.aws_handler import AWSHandler
from .handlers.cloud_providers.gcp_handler import GCPHandler

logger = logging.getLogger(__name__)


class WebSocketCommandHandler:
    """Handles WebSocket commands from the web interface by delegating to specialized handlers."""

    def __init__(self, broadcast_callback=None):
        """Initialize the command handler and all specialized handlers."""
        # Initialize specialized handlers
        self.session_handler = SessionHandler(broadcast_callback)
        self.credential_handler = CredentialHandler(broadcast_callback)
        self.graph_handler = GraphHandler(broadcast_callback)
        self.aws_handler = AWSHandler(broadcast_callback)
        self.gcp_handler = GCPHandler(broadcast_callback)

        # Shared state management
        self.graph_state = self.session_handler.graph_state
        self.broadcast_callback = broadcast_callback

        # Share state between all handlers
        for handler in [self.credential_handler, self.graph_handler, self.aws_handler, self.gcp_handler]:
            handler.graph_state = self.graph_state
            handler.session_managers = self.session_handler.session_managers

        # Track current session (shared reference)
        self.current_session = None
        self.current_session_id = None
        self.current_cloud = None
        self.session_managers = self.session_handler.session_managers

    async def on_cli_session_created(self, session_name: str, cloud: str, session_id: str):
        """
        Callback when a session is created from CLI.
        Auto-switches to the new session if no current session is active.

        Args:
            session_name: Name of the created session
            cloud: Cloud provider (aws, gcp, azure)
            session_id: UUID of the session
        """
        logger.info(f"[SessionWatcher] New CLI session detected: {session_name} ({cloud})")

        # If no current session is active, auto-switch to this one
        if not self.current_session:
            logger.info(f"[SessionWatcher] Auto-switching to new session: {session_name}")

            try:
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
                    logger.warning(f"[SessionWatcher] Unsupported cloud provider: {cloud}")
                    return

                # Load session
                manager.create_or_load_session(session_name)

                # Update current session
                self.current_session = session_name
                self.current_session_id = session_id
                self.current_cloud = cloud
                self.session_managers[cloud] = manager

                logger.info(f"[SessionWatcher] Auto-switched to session: {session_name} (ID: {session_id})")

            except Exception as e:
                logger.error(f"[SessionWatcher] Error auto-switching to session: {e}", exc_info=True)

    async def import_cli_sessions_on_startup(self):
        """
        Import existing CLI sessions and enumeration data on server startup.

        This function scans the ~/.cloudknife/sessions directory and imports:
        - Session metadata
        - Graph nodes from enumeration data
        - Graph edges connecting sessions to resources

        Should be called once during server initialization.
        """
        logger.info("[SessionImporter] Starting CLI session import on server startup...")

        try:
            # Import AWS sessions (can extend to GCP/Azure later)
            imported = import_cli_sessions('aws')

            sessions = imported.get('sessions', [])
            nodes = imported.get('nodes', [])
            edges = imported.get('edges', [])

            logger.info(f"[SessionImporter] Loaded {len(sessions)} sessions, {len(nodes)} nodes, {len(edges)} edges")

            # Initialize session managers for each imported session
            sessions_base = Path.home() / '.cloudknife' / 'sessions'

            for session in sessions:
                cloud = session.get('cloud')
                session_name = session.get('name')
                session_id = session.get('id')

                if not cloud or not session_name:
                    continue

                # Create session manager if not exists
                if cloud not in self.session_managers:
                    if cloud == 'aws':
                        from src.clouds.aws.aws_session import AWSSessionManager
                        self.session_managers[cloud] = AWSSessionManager(str(sessions_base / 'aws'))
                    # Add GCP/Azure later

                # Load the session in the manager
                manager = self.session_managers[cloud]
                manager.create_or_load_session(session_name)

                logger.info(f"[SessionImporter] Loaded session manager for: {session_name}")

            # Add nodes and edges to graph state
            self.graph_state['nodes'].extend(nodes)
            self.graph_state['edges'].extend(edges)

            # Broadcast to connected clients (if any)
            if self.broadcast_callback:
                logger.info("[SessionImporter] Broadcasting imported data to connected clients...")

                # Broadcast nodes
                for node in nodes:
                    await self.broadcast_callback(
                        create_success_response(
                            'graph.node.add',
                            {'node': node}
                        )
                    )

                # Broadcast edges
                for edge in edges:
                    await self.broadcast_callback(
                        create_success_response(
                            'graph.edge.add',
                            {'edge': edge}
                        )
                    )

                logger.info("[SessionImporter] Broadcast complete")

            logger.info("[SessionImporter] CLI session import completed successfully")

        except Exception as e:
            logger.error(f"[SessionImporter] Error during CLI session import: {e}", exc_info=True)

    async def handle_message(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Route incoming message to appropriate handler.

        Args:
            message: Incoming WebSocket message

        Returns:
            WebSocketResponse with result
        """
        try:
            handler = self._get_handler(message.type)
            if not handler:
                return create_error_response(
                    message.type,
                    f"Unknown message type: {message.type}",
                    message.request_id
                )

            return await handler(message)

        except Exception as e:
            logger.error(f"Error handling message {message.type}: {e}", exc_info=True)
            return create_error_response(
                message.type,
                str(e),
                message.request_id
            )

    def _get_handler(self, message_type: str):
        """Get handler function for message type by delegating to specialized handlers."""
        handlers = {
            # Core handlers
            MessageType.PING: self._handle_ping,

            # Session handlers (wrapped to sync state)
            MessageType.SESSION_CREATE: self._handle_session_create,
            MessageType.SESSION_LIST: self.session_handler.handle_session_list,
            MessageType.SESSION_SWITCH: self._handle_session_switch,
            MessageType.SESSION_DELETE: self.session_handler.handle_session_delete,
            MessageType.SESSION_CLEAR_ALL: self.session_handler.handle_session_clear_all,

            # Credential handlers
            MessageType.CREDS_SET_KEYS: self.credential_handler.handle_creds_set_keys,
            MessageType.CREDS_WHOAMI: self.credential_handler.handle_creds_whoami,
            MessageType.SET_REGION: self.credential_handler.handle_set_region,
            MessageType.SET_PROJECT: self.credential_handler.handle_set_project,

            # Graph handlers
            MessageType.GRAPH_SYNC: self.graph_handler.handle_graph_sync,

            # Module execution (stays in main handler)
            MessageType.MODULE_RUN: self._handle_module_run,

            # AWS-specific handlers
            MessageType.ASSUME_ROLE: self.aws_handler._handle_assume_role,
        }
        return handlers.get(message_type)

    async def _handle_ping(self, message: WebSocketMessage) -> WebSocketResponse:
        """Respond to ping with pong."""
        return create_success_response(
            MessageType.PONG,
            {},
            message.request_id
        )

    async def _handle_session_create(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Wrapper for session creation that syncs state after creation.

        This ensures that when a session is created, the state is propagated
        from SessionHandler to WebSocketCommandHandler and all other handlers.
        """
        response = await self.session_handler.handle_session_create(message)

        if response.success:
            # Sync state from SessionHandler to main handler
            self.current_session = self.session_handler.current_session
            self.current_session_id = self.session_handler.current_session_id
            self.current_cloud = self.session_handler.current_cloud

            # Propagate to all other handlers
            self._sync_session_state()

            logger.info(f"[SessionCreate] State synced: session={self.current_session}, cloud={self.current_cloud}")

        return response

    async def _handle_session_switch(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Wrapper for session switching that syncs state after switch.

        This ensures that when a session is switched, the state is propagated
        from SessionHandler to WebSocketCommandHandler and all other handlers.
        """
        response = await self.session_handler.handle_session_switch(message)

        if response.success:
            # Sync state from SessionHandler to main handler
            self.current_session = self.session_handler.current_session
            self.current_session_id = self.session_handler.current_session_id
            self.current_cloud = self.session_handler.current_cloud

            # Propagate to all other handlers
            self._sync_session_state()

            logger.info(f"[SessionSwitch] State synced: session={self.current_session}, cloud={self.current_cloud}")

        return response

    # ==================== Module Execution ====================

    async def _handle_module_run(self, message: WebSocketMessage) -> WebSocketResponse:
        """Execute a CloudKnife module."""
        try:
            payload = message.payload
            module_id = payload.get('module')
            params = payload.get('params', {})

            if not module_id:
                return create_error_response(
                    message.type,
                    "Missing required field: module",
                    message.request_id
                )

            if not self.current_session or not self.current_cloud:
                return create_error_response(
                    message.type,
                    "No active session. Create or switch to a session first.",
                    message.request_id
                )

            # Generate execution ID
            execution_id = f"exec-{message.request_id}"

            # Start module execution in background
            asyncio.create_task(
                self._execute_module_async(
                    module_id,
                    params,
                    execution_id
                )
            )

            return create_success_response(
                message.type,
                {
                    'execution_id': execution_id,
                    'module': module_id,
                    'status': 'started',
                },
                message.request_id
            )

        except Exception as e:
            logger.error(f"Error running module: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)

    async def _execute_module_async(
        self,
        module_id: str,
        params: Dict[str, Any],
        execution_id: str
    ) -> None:
        """
        Execute module in background and stream output.

        Delegates to appropriate cloud handler for execution.
        """
        logger.info(f"[Module] Starting execution: {module_id} (execution_id: {execution_id})")
        try:
            # Update handlers with current session context
            self._sync_session_state()

            # Route to appropriate cloud handler
            if self.current_cloud == 'aws':
                # Strip aws_ prefix if present for backward compatibility
                module_name = module_id.replace('aws_', '') if module_id.startswith('aws_') else module_id

                # Delegate to AWS handler
                if module_name == 'enumerate_lambda':
                    await self.aws_handler._run_aws_enumerate_lambda(execution_id, params)
                elif module_name == 'describe_lambda_function':
                    await self.aws_handler._run_aws_describe_lambda(execution_id, params)
                elif module_name == 'enumerate_iam_roles':
                    await self.aws_handler._run_aws_enumerate_iam_roles(execution_id)
                elif module_name == 'enumerate_iam_users':
                    await self.aws_handler._run_aws_enumerate_iam_users(execution_id)
                elif module_name == 'enumerate_iam_groups':
                    await self.aws_handler._run_aws_enumerate_iam_groups(execution_id, params)
                elif module_name == 'bruteforce_permissions':
                    await self.aws_handler._run_aws_bruteforce_permissions(execution_id, params)
                elif module_name == 'privesc_paths':
                    await self.aws_handler._run_aws_privesc_paths(execution_id, params)
                elif module_name == 'enumerate_iam_policies':
                    await self.aws_handler._run_aws_enumerate_iam_policies(execution_id, params)
                elif module_name == 'describe_policy' or module_name == 'describe_policy_document':
                    await self.aws_handler._run_aws_describe_policy(execution_id, params)
                elif module_name == 'enumerate_secrets':
                    await self.aws_handler._run_aws_enumerate_secrets(execution_id, params)
                elif module_name == 'get_secret_value':
                    await self.aws_handler._run_aws_get_secret_value(execution_id, params)
                elif module_name == 'enumerate_s3_buckets':
                    await self.aws_handler._run_aws_enumerate_s3_buckets(execution_id, params)
                elif module_name == 'enumerate_s3_objects':
                    await self.aws_handler._run_aws_enumerate_s3_objects(execution_id, params)
                elif module_name == 'download_bucket' or module_name == 'download_s3_bucket':
                    await self.aws_handler._run_aws_download_s3_bucket(execution_id, params)
                elif module_name == 'download_object' or module_name == 'download_s3_object':
                    await self.aws_handler._run_aws_download_s3_object(execution_id, params)
                elif module_name == 'enumerate_ec2' or module_name == 'enumerate_ec2_instances':
                    await self.aws_handler._run_aws_enumerate_ec2(execution_id, params)
                elif module_name == 'get_ec2_userdata':
                    await self.aws_handler._run_aws_get_ec2_userdata(execution_id, params)
                # RDS & Database modules
                elif module_name == 'enumerate_rds' or module_name == 'enumerate_rds_instances':
                    await self.aws_handler._run_aws_enumerate_rds_instances(execution_id, params)
                elif module_name == 'enumerate_rds_snapshots':
                    await self.aws_handler._run_aws_enumerate_rds_snapshots(execution_id, params)
                elif module_name == 'enumerate_rds_public_snapshots':
                    await self.aws_handler._run_aws_enumerate_rds_public_snapshots(execution_id, params)
                elif module_name == 'rds_iam_token' or module_name == 'generate_rds_token':
                    await self.aws_handler._run_aws_generate_rds_token(execution_id, params)
                elif module_name == 'enumerate_dynamodb' or module_name == 'enumerate_dynamodb_tables':
                    await self.aws_handler._run_aws_enumerate_dynamodb_tables(execution_id, params)
                elif module_name == 'dynamodb_details' or module_name == 'describe_dynamodb_table':
                    await self.aws_handler._run_aws_describe_dynamodb_table(execution_id, params)
                elif module_name == 'dynamodb_scan' or module_name == 'exfiltrate_dynamodb_table':
                    await self.aws_handler._run_aws_exfiltrate_dynamodb_table(execution_id, params)
                # Storage & Container Registries modules
                elif module_name == 'enumerate_ebs_snapshots':
                    await self.aws_handler._run_aws_enumerate_ebs_snapshots(execution_id, params)
                elif module_name == 'download_ebs_snapshot':
                    await self.aws_handler._run_aws_download_ebs_snapshot(execution_id, params)
                elif module_name == 'enumerate_ecr' or module_name == 'enumerate_ecr_repositories':
                    await self.aws_handler._run_aws_enumerate_ecr_repositories(execution_id, params)
                elif module_name == 'ecr_credentials' or module_name == 'get_ecr_credentials':
                    await self.aws_handler._run_aws_get_ecr_credentials(execution_id, params)
                # Additional enumeration modules
                elif module_name == 'enumerate_mq':
                    await self.aws_handler._run_aws_enumerate_mq(execution_id, params)
                elif module_name == 'enumerate_sns':
                    await self.aws_handler._run_aws_enumerate_sns(execution_id, params)
                elif module_name == 'enumerate_oidc_providers':
                    await self.aws_handler._run_aws_enumerate_oidc_providers(execution_id, params)
                elif module_name == 'enumerate_ssm_parameters':
                    await self.aws_handler._run_aws_enumerate_ssm_parameters(execution_id, params)
                elif module_name == 'enumerate_launch_templates':
                    await self.aws_handler._run_aws_enumerate_launch_templates(execution_id, params)
                elif module_name == 'enumerate_groundstation':
                    await self.aws_handler._run_aws_enumerate_groundstation(execution_id, params)
                elif module_name == 'enumerate_elasticbeanstalk':
                    await self.aws_handler._run_aws_enumerate_elasticbeanstalk(execution_id, params)
                else:
                    await self._broadcast_module_error(
                        execution_id,
                        f"Unknown AWS module: {module_id}"
                    )
            elif self.current_cloud == 'gcp':
                # Strip gcp_ prefix if present for backward compatibility
                module_name = module_id.replace('gcp_', '') if module_id.startswith('gcp_') else module_id

                # Delegate to GCP handler
                if module_name == 'enumerate_compute':
                    await self.gcp_handler._run_gcp_enumerate_compute(execution_id, params)
                elif module_name == 'enumerate_storage':
                    await self.gcp_handler._run_gcp_enumerate_storage(execution_id, params)
                elif module_name == 'enumerate_iam':
                    await self.gcp_handler._run_gcp_enumerate_iam(execution_id, params)
                elif module_name == 'enumerate_secrets':
                    await self.gcp_handler._run_gcp_enumerate_secrets(execution_id, params)
                elif module_name == 'quick_enum':
                    await self.gcp_handler._run_gcp_quick_enum(execution_id, params)
                elif module_name == 'enumerate_artifact_repositories':
                    await self.gcp_handler._run_gcp_enumerate_artifact_repositories(execution_id, params)
                elif module_name == 'enumerate_artifact_packages':
                    await self.gcp_handler._run_gcp_enumerate_artifact_packages(execution_id, params)
                elif module_name == 'enumerate_artifact_versions':
                    await self.gcp_handler._run_gcp_enumerate_artifact_versions(execution_id, params)
                elif module_name == 'describe_role':
                    await self.gcp_handler._run_gcp_describe_role(execution_id, params)
                elif module_name == 'describe_service_account_iam_policy':
                    await self.gcp_handler._run_gcp_describe_service_account_iam_policy(execution_id, params)
                else:
                    await self._broadcast_module_error(
                        execution_id,
                        f"Unknown GCP module: {module_id}"
                    )
            elif self.current_cloud == 'azure':
                # TODO: Implement Azure handler delegation
                await self._broadcast_module_error(
                    execution_id,
                    f"Modules not yet implemented for Azure"
                )
            else:
                await self._broadcast_module_error(
                    execution_id,
                    f"Unknown cloud provider: {self.current_cloud}"
                )

        except Exception as e:
            logger.error(f"Module execution failed: {e}", exc_info=True)
            await self._broadcast_module_error(execution_id, str(e))

    def _sync_session_state(self):
        """Synchronize current session state across all handlers."""
        for handler in [self.session_handler, self.credential_handler, self.graph_handler, self.aws_handler, self.gcp_handler]:
            handler.current_session = self.current_session
            handler.current_session_id = self.current_session_id
            handler.current_cloud = self.current_cloud

    async def _broadcast_module_error(self, execution_id: str, error_message: str):
        """Broadcast a module execution error."""
        if self.broadcast_callback:
            await self.broadcast_callback(
                create_error_response(
                    'module.output',
                    error_message,
                    execution_id
                )
            )
