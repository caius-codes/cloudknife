"""
Credential management handler for CloudKnife WebSocket operations.

Handles credential configuration, identity verification, and region management
across cloud providers (AWS, GCP, Azure).
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from .base_handler import BaseHandler
from ..ws_messages import (
    WebSocketMessage,
    WebSocketResponse,
    create_success_response,
    create_error_response,
)

logger = logging.getLogger(__name__)


class CredentialHandler(BaseHandler):
    """Handles credential-related WebSocket commands."""

    async def handle_creds_set_keys(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Set cloud credentials (AWS keys, GCP service account, etc).

        Args:
            message: WebSocket message containing credential payload

        Returns:
            WebSocketResponse with success/error status and identity data
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

            if not self.current_session or self.current_cloud != cloud:
                return create_error_response(
                    message.type,
                    "No active session. Create or switch to a session first.",
                    message.request_id
                )

            # Handle AWS credentials
            if cloud == 'aws':
                access_key = payload.get('access_key')
                secret_key = payload.get('secret_key')
                session_token = payload.get('session_token')

                if not access_key or not secret_key:
                    return create_error_response(
                        message.type,
                        "Missing required AWS credentials: access_key, secret_key",
                        message.request_id
                    )

                # Get session manager
                manager = self.session_managers.get(self.current_cloud)
                if not manager:
                    return create_error_response(
                        message.type,
                        "Session manager not initialized",
                        message.request_id
                    )

                # Set credentials in session
                region = payload.get('region', 'us-east-1')

                # Check if credentials already exist
                had_credentials = bool(
                    manager.current_session_data.get("access_key") and
                    manager.current_session_data.get("secret_key")
                )

                # Force override with new credentials
                manager.current_session_data.update({
                    "access_key": access_key,
                    "secret_key": secret_key,
                    "session_token": session_token if session_token else None,
                    "region": region,
                    "credentials_updated_at": datetime.now().isoformat(),
                })
                manager.save_current_session()

                # Log credential update
                if had_credentials:
                    logger.warning(f"[SetKeys] Overriding existing credentials for session '{self.current_session}'")
                else:
                    logger.info(f"[SetKeys] Setting new credentials for session '{self.current_session}'")

                logger.info(f"[SetKeys] Set default region to: {region}")

                # Automatically call whoami to verify credentials and get identity
                try:
                    aws_sess = manager.get_boto3_session()
                    sts = aws_sess.client("sts")
                    identity = sts.get_caller_identity()

                    # Save identity to session data
                    manager.current_session_data["arn"] = identity["Arn"]
                    manager.current_session_data["user_id"] = identity["UserId"]
                    manager.current_session_data["account"] = identity["Account"]
                    manager.save_current_session()

                    # Prepare identity response
                    identity_data = {
                        'UserId': identity['UserId'],
                        'Account': identity['Account'],
                        'Arn': identity['Arn'],
                        'DefaultRegion': manager.default_region,
                        'ConfiguredRegions': list(manager.configured_regions) if manager.configured_regions else []
                    }

                    # Broadcast graph node UPDATE with identity information
                    if self.broadcast_callback:
                        # Update existing session node with identity (don't create a new one)
                        session_node = {
                            'id': self.current_session_id,  # Use UUID instead of name-based ID
                            'type': 'aws-session',
                            'label': self.current_session,
                            'provider': 'aws',
                            'discoveredBy': [self.current_session_id],
                            'parentId': None,
                            'data': {
                                'sessionName': self.current_session,
                                'sessionId': self.current_session_id,
                                'identity': identity_data,
                                'credentials': {
                                    'configured': True,
                                    'region': manager.default_region,
                                }
                            },
                            'metadata': {
                                'discoveredAt': datetime.now().isoformat(),
                                'moduleUsed': 'set_credentials',
                                'arn': identity['Arn'],
                                'account': identity['Account'],
                                'userId': identity['UserId'],
                            },
                            'level': 0,
                        }

                        # Broadcast UPDATE (not add) to all clients
                        asyncio.create_task(
                            self.broadcast_callback(
                                create_success_response(
                                    'graph.node.update',  # UPDATE instead of ADD
                                    {'node': session_node}
                                )
                            )
                        )

                    # Prepare success message
                    success_msg = 'AWS credentials updated successfully (overridden)' if had_credentials else 'AWS credentials set successfully'

                    return create_success_response(
                        message.type,
                        {
                            'message': success_msg,
                            'overridden': had_credentials,
                            'identity': identity_data,
                            'updated_at': manager.current_session_data.get('credentials_updated_at')
                        },
                        message.request_id
                    )

                except Exception as e:
                    # Credentials were saved but whoami failed
                    logger.error(f"Credentials saved but identity verification failed: {e}", exc_info=True)
                    return create_success_response(
                        message.type,
                        {
                            'message': 'Credentials saved but identity verification failed',
                            'error': str(e),
                            'warning': 'Check that credentials are valid and have sts:GetCallerIdentity permission'
                        },
                        message.request_id
                    )

            # Handle GCP credentials
            elif cloud == 'gcp':
                service_account_json = payload.get('service_account_json')

                if not service_account_json:
                    return create_error_response(
                        message.type,
                        "Missing required GCP credential: service_account_json",
                        message.request_id
                    )

                # TODO: Implement GCP credential setting
                return create_error_response(
                    message.type,
                    "GCP credential setting not yet implemented",
                    message.request_id
                )

            # Handle Azure credentials
            elif cloud == 'azure':
                # TODO: Implement Azure credential setting
                return create_error_response(
                    message.type,
                    "Azure credential setting not yet implemented",
                    message.request_id
                )

            else:
                return create_error_response(
                    message.type,
                    f"Unsupported cloud provider: {cloud}",
                    message.request_id
                )

        except Exception as e:
            logger.error(f"Error setting credentials: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)

    async def handle_creds_whoami(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Get current identity information.

        Args:
            message: WebSocket message requesting identity information

        Returns:
            WebSocketResponse with identity data (ARN, Account, UserId, Region)
        """
        try:
            if not self.current_session or not self.current_cloud:
                return create_error_response(
                    message.type,
                    "No active session",
                    message.request_id
                )

            if self.current_cloud == 'aws':
                # Get session manager and call whoami
                manager = self.session_managers.get(self.current_cloud)
                if not manager:
                    return create_error_response(
                        message.type,
                        "Session manager not initialized. Create or switch to a session first.",
                        message.request_id
                    )

                # Get boto3 session and call STS
                try:
                    aws_sess = manager.get_boto3_session()
                    sts = aws_sess.client("sts")
                    identity = sts.get_caller_identity()

                    # Save identity to session data
                    manager.current_session_data["arn"] = identity["Arn"]
                    manager.current_session_data["user_id"] = identity["UserId"]
                    manager.current_session_data["account"] = identity["Account"]
                    manager.save_current_session()

                    # Prepare identity response
                    identity_data = {
                        'UserId': identity['UserId'],
                        'Account': identity['Account'],
                        'Arn': identity['Arn'],
                        'DefaultRegion': manager.default_region,
                        'ConfiguredRegions': list(manager.configured_regions) if manager.configured_regions else []
                    }

                    # Broadcast graph node update with identity information
                    if self.broadcast_callback:
                        session_node = {
                            'id': self.current_session_id,
                            'type': 'aws-session',
                            'label': self.current_session,
                            'provider': 'aws',
                            'discoveredBy': [self.current_session_id],
                            'parentId': None,
                            'data': {
                                'sessionName': self.current_session,
                                'identity': identity_data,
                                'credentials': {
                                    'configured': True,
                                    'region': manager.default_region,
                                }
                            },
                            'metadata': {
                                'discoveredAt': datetime.now().isoformat(),
                                'moduleUsed': 'whoami',
                                'arn': identity['Arn'],
                                'account': identity['Account'],
                                'userId': identity['UserId'],
                            },
                            'level': 0,
                        }

                        # Broadcast to all clients
                        asyncio.create_task(
                            self.broadcast_callback(
                                create_success_response(
                                    'graph.node.add',
                                    {'node': session_node}
                                )
                            )
                        )

                    return create_success_response(
                        message.type,
                        {'identity': identity_data},
                        message.request_id
                    )

                except Exception as e:
                    logger.error(f"AWS STS error: {e}", exc_info=True)
                    return create_error_response(
                        message.type,
                        f"AWS Error: {str(e)}",
                        message.request_id
                    )

            else:
                return create_error_response(
                    message.type,
                    f"Whoami not yet implemented for {self.current_cloud}",
                    message.request_id
                )

        except Exception as e:
            logger.error(f"Error getting identity: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)

    async def handle_set_region(self, message: WebSocketMessage) -> WebSocketResponse:
        """
        Set default region for the current session.

        Args:
            message: WebSocket message containing region to set

        Returns:
            WebSocketResponse with updated region information
        """
        try:
            payload = message.payload
            region = payload.get('region')

            if not region:
                return create_error_response(
                    message.type,
                    "Missing required field: region",
                    message.request_id
                )

            if not self.current_session or not self.current_cloud:
                return create_error_response(
                    message.type,
                    "No active session. Create or switch to a session first.",
                    message.request_id
                )

            # Get session manager
            manager = self.session_managers.get(self.current_cloud)
            if not manager:
                return create_error_response(
                    message.type,
                    "Session manager not initialized",
                    message.request_id
                )

            # Update region in session data
            manager.current_session_data["region"] = region
            manager.save_current_session()

            logger.info(f"[SetRegion] Changed default region to: {region} for session: {self.current_session}")

            return create_success_response(
                message.type,
                {
                    'region': region,
                    'session': self.current_session,
                    'message': f'Default region set to {region}'
                },
                message.request_id
            )

        except Exception as e:
            logger.error(f"Set region failed: {e}", exc_info=True)
            return create_error_response(message.type, str(e), message.request_id)
