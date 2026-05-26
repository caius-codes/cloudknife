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

            logger.info(f"[SetKeys] Received request for cloud={cloud}")
            logger.info(f"[SetKeys] Current state: session={self.current_session}, cloud={self.current_cloud}")

            if not cloud:
                return create_error_response(
                    message.type,
                    "Missing required field: cloud",
                    message.request_id
                )

            if not self.current_session or self.current_cloud != cloud:
                logger.error(f"[SetKeys] Session mismatch: current_session={self.current_session}, current_cloud={self.current_cloud}, requested_cloud={cloud}")
                return create_error_response(
                    message.type,
                    f"No active {cloud.upper()} session. Current session: {self.current_session or 'None'}, Current cloud: {self.current_cloud or 'None'}. Create or switch to a {cloud.upper()} session first.",
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
                access_token = payload.get('access_token')
                project_id = payload.get('project_id')

                logger.info(f"[SetKeys GCP] service_account_json present: {bool(service_account_json)}")
                logger.info(f"[SetKeys GCP] access_token present: {bool(access_token)}")
                logger.info(f"[SetKeys GCP] project_id: {project_id}")

                # Must have either service account JSON or access token
                if not service_account_json and not access_token:
                    return create_error_response(
                        message.type,
                        "Missing required GCP credentials: provide either service_account_json or access_token",
                        message.request_id
                    )

                # Get or create GCP session manager
                if 'gcp' not in self.session_managers:
                    from pathlib import Path
                    from src.clouds.gcp.gcp_session import GCPSessionManager
                    sessions_base = Path.home() / '.cloudknife' / 'sessions'
                    self.session_managers['gcp'] = GCPSessionManager(str(sessions_base / 'gcp'))

                manager = self.session_managers['gcp']

                # Load current session
                manager.create_or_load_session(self.current_session)

                # Set credentials based on type
                success = False
                auth_method = None

                if service_account_json:
                    # Service Account JSON
                    import tempfile
                    import os
                    import json
                    import re

                    logger.info(f"[SetKeys GCP] Processing service account JSON")

                    # Validate JSON structure
                    if not isinstance(service_account_json, dict):
                        logger.error(f"[SetKeys GCP] service_account_json is not a dict: {type(service_account_json)}")
                        return create_error_response(
                            message.type,
                            f"Invalid service account JSON format: expected dict, got {type(service_account_json).__name__}",
                            message.request_id
                        )

                    # Check required fields
                    required_fields = ['type', 'private_key', 'client_email']
                    missing_fields = [f for f in required_fields if f not in service_account_json]
                    if missing_fields:
                        logger.error(f"[SetKeys GCP] Missing required fields: {missing_fields}")
                        return create_error_response(
                            message.type,
                            f"Invalid service account JSON: missing required fields: {', '.join(missing_fields)}",
                            message.request_id
                        )

                    # Ensure project_id is set to avoid interactive prompt in CLI module
                    # Priority: user-specified project_id > existing project_id in JSON > inferred from email
                    if not service_account_json.get('project_id'):
                        if project_id:
                            # User specified a project_id in the payload
                            logger.info(f"[SetKeys GCP] Using user-specified project_id: {project_id}")
                            service_account_json['project_id'] = project_id
                        else:
                            # Try to infer project_id from service account email
                            # Format: name@PROJECT-ID.iam.gserviceaccount.com
                            client_email = service_account_json.get('client_email', '')
                            pattern = r'^[^@]+@([^.]+)\.iam\.gserviceaccount\.com$'
                            match = re.match(pattern, client_email)

                            if match:
                                inferred_project = match.group(1)
                                logger.info(f"[SetKeys GCP] Inferred project_id from email: {inferred_project}")
                                service_account_json['project_id'] = inferred_project
                            else:
                                logger.warning(f"[SetKeys GCP] Could not infer project_id from email: {client_email}")
                    else:
                        logger.info(f"[SetKeys GCP] Using project_id from JSON: {service_account_json['project_id']}")

                    # Write JSON to permanent file in session directory (not temp file!)
                    # This allows the CLI to read credentials from the same session
                    from pathlib import Path
                    sessions_base = Path.home() / '.cloudknife' / 'sessions' / 'gcp'
                    sessions_base.mkdir(parents=True, exist_ok=True)

                    key_file_path = sessions_base / f"{self.current_session}_key.json"

                    try:
                        # Write service account JSON to permanent file
                        with open(key_file_path, 'w') as f:
                            json.dump(service_account_json, f, indent=2)

                        # Set restrictive permissions (only owner can read/write)
                        os.chmod(key_file_path, 0o600)

                        logger.info(f"[SetKeys GCP] Saved service account key to: {key_file_path}")
                        logger.info(f"[SetKeys GCP] Calling manager.set_service_account() with project_id: {service_account_json.get('project_id')}")

                        # Set service account (now with project_id, so no interactive prompt)
                        success = manager.set_service_account(str(key_file_path))
                        auth_method = 'service_account'

                        logger.info(f"[SetKeys GCP] set_service_account returned: {success}")
                    except Exception as e:
                        logger.error(f"[SetKeys GCP] Error writing/processing service account JSON: {e}", exc_info=True)
                        # Clean up key file if something went wrong
                        try:
                            if key_file_path.exists():
                                key_file_path.unlink()
                        except Exception:
                            pass
                        return create_error_response(
                            message.type,
                            f"Failed to process service account JSON: {str(e)}",
                            message.request_id
                        )

                elif access_token:
                    # Access Token
                    success = manager.set_access_token(
                        token=access_token,
                        project_id=project_id,
                        skip_tokeninfo=True
                    )
                    auth_method = 'access_token'

                if not success:
                    return create_error_response(
                        message.type,
                        "Failed to set GCP credentials",
                        message.request_id
                    )

                # Get identity info and verify credentials (similar to AWS whoami)
                project_id = manager.current_session_data.get('project_id')
                service_account_email = manager.current_session_data.get('service_account_email')

                identity_data = {
                    'auth_method': auth_method,
                    'project_id': project_id,
                    'service_account_email': service_account_email,
                }

                # Try to get token info to verify credentials and enrich identity data
                try:
                    token_info = manager.get_token_info()
                    if token_info and 'error' not in token_info:
                        # Add token info to identity data
                        identity_data['email'] = token_info.get('email', service_account_email)
                        identity_data['scopes'] = token_info.get('scope', '').split() if token_info.get('scope') else []
                        identity_data['expires_in'] = token_info.get('expires_in')

                        logger.info(f"[SetKeys GCP] Token verified. Email: {identity_data['email']}")
                    else:
                        logger.warning(f"[SetKeys GCP] Could not verify token: {token_info}")
                except Exception as e:
                    logger.warning(f"[SetKeys GCP] Failed to get token info: {e}")
                    # Continue anyway - credentials might still work

                # Broadcast graph node UPDATE with identity information
                if self.broadcast_callback:
                    session_node = {
                        'id': self.current_session_id,
                        'type': 'gcp-session',
                        'label': self.current_session,
                        'provider': 'gcp',
                        'discoveredBy': [self.current_session_id],
                        'parentId': None,
                        'data': {
                            'sessionName': self.current_session,
                            'sessionId': self.current_session_id,
                            'identity': identity_data,
                            'credentials': {
                                'configured': True,
                                'auth_method': auth_method,
                            }
                        },
                        'metadata': {
                            'discoveredAt': datetime.now().isoformat(),
                            'moduleUsed': 'set_credentials',
                            'project_id': project_id,
                            'service_account_email': service_account_email,
                            'auth_method': auth_method,
                        },
                        'level': 0,
                    }

                    # Broadcast UPDATE to all clients
                    asyncio.create_task(
                        self.broadcast_callback(
                            create_success_response(
                                'graph.node.update',
                                {'node': session_node}
                            )
                        )
                    )

                return create_success_response(
                    message.type,
                    {
                        'message': 'GCP credentials configured successfully',
                        'auth_method': auth_method,
                        'project_id': project_id,
                    },
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

            elif self.current_cloud == 'gcp':
                # Get session manager
                manager = self.session_managers.get(self.current_cloud)
                if not manager:
                    return create_error_response(
                        message.type,
                        "Session manager not initialized. Create or switch to a session first.",
                        message.request_id
                    )

                try:
                    # Get identity info from session data
                    auth_method = manager.current_session_data.get('auth_method')
                    project_id = manager.current_session_data.get('project_id')
                    service_account_email = manager.current_session_data.get('service_account_email')

                    if not auth_method:
                        return create_error_response(
                            message.type,
                            "No credentials configured",
                            message.request_id
                        )

                    identity_data = {
                        'auth_method': auth_method,
                        'project_id': project_id,
                        'service_account_email': service_account_email,
                    }

                    return create_success_response(
                        message.type,
                        {'identity': identity_data},
                        message.request_id
                    )

                except Exception as e:
                    logger.error(f"GCP identity error: {e}", exc_info=True)
                    return create_error_response(
                        message.type,
                        f"GCP Error: {str(e)}",
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
