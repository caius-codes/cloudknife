"""
Azure-specific WebSocket handlers.
Handles all Azure session management and authentication methods.
"""

import asyncio
import logging
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from ..base_handler import BaseHandler
from ...ws_messages import (
    WebSocketMessage,
    WebSocketResponse,
    create_success_response,
    create_error_response,
)

logger = logging.getLogger(__name__)


class AzureHandler(BaseHandler):
    """
    Handler for Azure-specific WebSocket operations.

    Handles:
    - Session management (create, list, switch, delete)
    - Multiple authentication methods (service principal, interactive, device code, password, tokens, managed identity, Azure CLI)
    - User info retrieval
    - Subscription management
    """

    # ==================== Session Management ====================

    async def _run_azure_list_sessions(self, execution_id: str, params: Dict[str, Any]) -> None:
        """List all Azure sessions."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    WebSocketResponse(
                        type="azure_session_list",
                        success=False,
                        error="No Azure session manager available"
                    )
                )
                return

            sessions = manager.list_sessions()
            await self._send_response(
                execution_id,
                WebSocketResponse(
                    type="azure_session_list",
                    success=True,
                    data={"sessions": sessions}
                )
            )

        except Exception as e:
            logger.error(f"Error listing Azure sessions: {e}", exc_info=True)
            await self._send_response(
                execution_id,
                WebSocketResponse(
                    type="azure_session_list",
                    success=False,
                    error=str(e)
                )
            )

    async def _run_azure_create_session(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Create or load an Azure session."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    WebSocketResponse(
                        type="azure_session_created",
                        success=False,
                        error="No Azure session manager available"
                    )
                )
                return

            session_name = params.get('name', 'azure-default')
            manager.create_or_load_session(session_name)

            # Clear credential cache for new/switched session
            manager.clear_credential_cache()

            # Get session data
            session_data = manager.current_session_data or {}

            await self._send_response(
                execution_id,
                WebSocketResponse(
                    type="azure_session_created",
                    success=True,
                    data={
                        "session_name": session_name,
                        "session_id": manager.session_id,
                        "tenant_id": session_data.get("tenant_id"),
                        "subscription_id": session_data.get("subscription_id"),
                        "subscription_name": session_data.get("subscription_name"),
                        "account_name": session_data.get("account_name"),
                        "auth_method": session_data.get("auth_method")
                    }
                )
            )

        except Exception as e:
            logger.error(f"Error creating Azure session: {e}", exc_info=True)
            await self._send_response(
                execution_id,
                WebSocketResponse(
                    type="azure_session_created",
                    success=False,
                    error=str(e)
                )
            )

    async def _run_azure_delete_session(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Delete an Azure session."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    WebSocketResponse(
                        type="azure_session_deleted",
                        success=False,
                        error="No Azure session manager available"
                    )
                )
                return

            session_name = params.get('name')
            if not session_name:
                await self._send_response(
                    execution_id,
                    WebSocketResponse(
                        type="azure_session_deleted",
                        success=False,
                        error="Session name is required"
                    )
                )
                return

            deleted = manager.delete_session(session_name)

            await self._send_response(
                execution_id,
                WebSocketResponse(
                    type="azure_session_deleted",
                    success=deleted,
                    data={"session_name": session_name} if deleted else None,
                    error=None if deleted else "Session could not be deleted"
                )
            )

        except Exception as e:
            logger.error(f"Error deleting Azure session: {e}", exc_info=True)
            await self._send_response(
                execution_id,
                WebSocketResponse(
                    type="azure_session_deleted",
                    success=False,
                    error=str(e)
                )
            )

    # ==================== Authentication Methods ====================

    async def _run_azure_auth_az_cli(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Authenticate using Azure CLI (uses existing az login credentials)."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            # Check if Azure CLI is installed
            import shutil
            if not shutil.which("az"):
                await self._send_response(
                    execution_id,
                    create_error_response("Azure CLI (az) not found. Please install it first: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
                )
                return

            # Set auth method to use AzureCliCredential
            manager.current_session_data["auth_method"] = "az_cli"
            manager.save_current_session()

            # Test credential by getting account info from Azure CLI
            try:
                manager.azure_sync_from_current_account()
            except Exception as e:
                await self._send_response(
                    execution_id,
                    create_error_response(f"Failed to sync from Azure CLI. Make sure you're logged in with 'az login': {str(e)}")
                )
                return

            # Sync user info from Graph API
            user_info_retrieved = manager.sync_user_info_from_graph()

            await self._send_response(
                execution_id,
                create_success_response({
                    "message": "Azure CLI authentication successful",
                    "tenant_id": manager.current_session_data.get("tenant_id"),
                    "subscription_id": manager.current_session_data.get("subscription_id"),
                    "subscription_name": manager.current_session_data.get("subscription_name"),
                    "account_name": manager.current_session_data.get("account_name"),
                    "user_info_retrieved": user_info_retrieved
                })
            )

        except Exception as e:
            logger.error(f"Error in Azure CLI auth: {e}", exc_info=True)
            await self._send_response(execution_id, create_error_response(str(e)))

    async def _run_azure_auth_interactive(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Authenticate using interactive browser login."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            tenant_id = params.get('tenant_id', '')

            # Store auth method in session
            manager.current_session_data["auth_method"] = "interactive"
            if tenant_id:
                manager.current_session_data["tenant_id"] = tenant_id
            manager.save_current_session()

            # Get credential (this will trigger browser-based login)
            credential = manager.get_credential("graph")
            if not credential:
                await self._send_response(
                    execution_id,
                    create_error_response("Failed to create credential")
                )
                return

            # Get a token to test authentication
            token = credential.get_token("https://graph.microsoft.com/.default")

            # Extract tenant ID from token if not provided
            if not manager.current_session_data.get("tenant_id"):
                extracted_tenant = manager.extract_tenant_from_token()
                if extracted_tenant:
                    manager.current_session_data["tenant_id"] = extracted_tenant
                    manager.save_current_session()

            # Sync user info from Graph API
            user_info_retrieved = manager.sync_user_info_from_graph()

            # Sync subscriptions from SDK
            subscriptions_retrieved = manager.sync_subscriptions_from_sdk()

            await self._send_response(
                execution_id,
                create_success_response({
                    "message": "Interactive browser authentication successful",
                    "tenant_id": manager.current_session_data.get("tenant_id"),
                    "user_info_retrieved": user_info_retrieved,
                    "subscriptions_retrieved": subscriptions_retrieved,
                    "subscription_id": manager.current_session_data.get("subscription_id"),
                    "subscription_name": manager.current_session_data.get("subscription_name"),
                    "account_name": manager.current_session_data.get("account_name")
                })
            )

        except Exception as e:
            error_str = str(e)

            # Check if error is MFA-related
            is_mfa_error = any(indicator in error_str for indicator in [
                "AADSTS50076", "AADSTS50079", "multi-factor", "MFA", "authentication_required"
            ])

            if is_mfa_error:
                logger.error(f"MFA error in interactive auth: {e}", exc_info=True)
                await self._send_response(
                    execution_id,
                    create_error_response(f"Authentication failed: MFA required. Details: {error_str}")
                )
            else:
                logger.error(f"Error in interactive auth: {e}", exc_info=True)
                await self._send_response(execution_id, create_error_response(str(e)))

    async def _run_azure_auth_service_principal(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Authenticate using Service Principal (Client ID + Secret)."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            tenant_id = params.get('tenant_id')
            client_id = params.get('client_id')
            client_secret = params.get('client_secret')

            if not tenant_id or not client_id or not client_secret:
                await self._send_response(
                    execution_id,
                    create_error_response("tenant_id, client_id, and client_secret are required")
                )
                return

            # Store credentials in session
            manager.current_session_data["auth_method"] = "service_principal"
            manager.current_session_data["tenant_id"] = tenant_id
            manager.current_session_data["client_id"] = client_id
            manager.current_session_data["client_secret"] = client_secret
            manager.save_current_session()

            # Try to sync user info (may fail if SP doesn't have Graph permissions)
            user_info_retrieved = manager.sync_user_info_from_graph()

            # Sync subscriptions from SDK
            subscriptions_retrieved = manager.sync_subscriptions_from_sdk()

            await self._send_response(
                execution_id,
                create_success_response({
                    "message": "Service principal configured successfully",
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "user_info_retrieved": user_info_retrieved,
                    "subscriptions_retrieved": subscriptions_retrieved,
                    "subscription_id": manager.current_session_data.get("subscription_id"),
                    "subscription_name": manager.current_session_data.get("subscription_name")
                })
            )

        except Exception as e:
            logger.error(f"Error in service principal auth: {e}", exc_info=True)
            await self._send_response(execution_id, create_error_response(str(e)))

    async def _run_azure_auth_device_code(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Authenticate using device code flow."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            tenant_id = params.get('tenant_id', '')

            # Store auth method in session
            manager.current_session_data["auth_method"] = "device_code"
            if tenant_id:
                manager.current_session_data["tenant_id"] = tenant_id
            manager.save_current_session()

            # Get credential (this will trigger device code flow)
            credential = manager.get_credential("graph")
            if not credential:
                await self._send_response(
                    execution_id,
                    create_error_response("Failed to create credential")
                )
                return

            # Get a token to test authentication
            token = credential.get_token("https://graph.microsoft.com/.default")

            # Extract tenant ID from token if not provided
            if not manager.current_session_data.get("tenant_id"):
                extracted_tenant = manager.extract_tenant_from_token()
                if extracted_tenant:
                    manager.current_session_data["tenant_id"] = extracted_tenant
                    manager.save_current_session()

            # Sync user info from Graph API
            user_info_retrieved = manager.sync_user_info_from_graph()

            # Sync subscriptions from SDK
            subscriptions_retrieved = manager.sync_subscriptions_from_sdk()

            await self._send_response(
                execution_id,
                create_success_response({
                    "message": "Device code authentication successful",
                    "tenant_id": manager.current_session_data.get("tenant_id"),
                    "user_info_retrieved": user_info_retrieved,
                    "subscriptions_retrieved": subscriptions_retrieved,
                    "subscription_id": manager.current_session_data.get("subscription_id"),
                    "subscription_name": manager.current_session_data.get("subscription_name"),
                    "account_name": manager.current_session_data.get("account_name")
                })
            )

        except Exception as e:
            logger.error(f"Error in device code auth: {e}", exc_info=True)
            await self._send_response(execution_id, create_error_response(str(e)))

    async def _run_azure_auth_password(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Authenticate using username/password (ROPC flow)."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            username = params.get('username')
            password = params.get('password')
            tenant_id = params.get('tenant_id', '')

            if not username or not password:
                await self._send_response(
                    execution_id,
                    create_error_response("username and password are required")
                )
                return

            # Use the session manager's set_password_auth method
            success = manager.set_password_auth(username, password, tenant_id if tenant_id else None)

            if success:
                await self._send_response(
                    execution_id,
                    create_success_response({
                        "message": "Password authentication configured successfully",
                        "username": username,
                        "tenant_id": manager.current_session_data.get("tenant_id"),
                        "account_name": manager.current_session_data.get("account_name"),
                        "subscription_id": manager.current_session_data.get("subscription_id"),
                        "subscription_name": manager.current_session_data.get("subscription_name")
                    })
                )
            else:
                await self._send_response(
                    execution_id,
                    create_error_response("Password authentication failed. Check credentials or ensure ROPC is enabled.")
                )

        except Exception as e:
            logger.error(f"Error in password auth: {e}", exc_info=True)
            await self._send_response(execution_id, create_error_response(str(e)))

    async def _run_azure_auth_access_token(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Authenticate using an access token (stolen/SSRF)."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            access_token = params.get('access_token')
            if not access_token:
                await self._send_response(
                    execution_id,
                    create_error_response("access_token is required")
                )
                return

            # Decode JWT to extract metadata
            import base64
            import time

            claims = {}
            try:
                parts = access_token.split(".")
                if len(parts) == 3:
                    payload = parts[1]
                    payload += "=" * (4 - len(payload) % 4)
                    claims = json.loads(base64.urlsafe_b64decode(payload))
            except Exception:
                pass

            # Detect audience → determine which resource slot to populate
            aud = claims.get("aud", "")
            AUDIENCE_MAP = {
                "https://graph.microsoft.com": ("graph", "graph_access_token"),
                "https://graph.windows.net": ("graph", "graph_access_token"),
                "https://management.azure.com/": ("management", "management_access_token"),
                "https://management.azure.com": ("management", "management_access_token"),
                "https://management.core.windows.net/": ("management", "management_access_token"),
                "https://storage.azure.com/": ("storage", "storage_access_token"),
                "https://vault.azure.net": ("vault", "vault_access_token"),
                "https://api.spaces.skype.com": ("teams", "teams_access_token"),
                "https://manage.office.com": ("office", "office_access_token"),
                "https://outlook.office365.com": ("outlook", "outlook_access_token"),
            }
            scope_name, token_key = AUDIENCE_MAP.get(aud, ("unknown", "unknown_access_token"))

            # Extract expiry from JWT exp claim
            jwt_expires_at = None
            if claims.get("exp"):
                try:
                    jwt_expires_at = int(claims["exp"])
                except (ValueError, TypeError):
                    pass

            # Store token in session
            manager.current_session_data["auth_method"] = "access_token"

            # Only set generic access_token if we don't know the audience (for backwards compatibility)
            if scope_name == "unknown":
                manager.current_session_data["access_token"] = access_token
                if jwt_expires_at:
                    manager.current_session_data["token_expires_at"] = jwt_expires_at

            # Always store in the specific slot
            manager.current_session_data[token_key] = access_token
            if jwt_expires_at:
                manager.current_session_data[f"{scope_name}_token_expires_at"] = jwt_expires_at

            # Populate session metadata from JWT claims
            upn = claims.get("upn") or claims.get("unique_name") or claims.get("email")
            if claims.get("tid") and not manager.current_session_data.get("tenant_id"):
                manager.current_session_data["tenant_id"] = claims["tid"]
            if upn and not manager.current_session_data.get("account_name"):
                manager.current_session_data["account_name"] = upn
            if claims.get("oid") and not manager.current_session_data.get("user_id"):
                manager.current_session_data["user_id"] = claims["oid"]

            manager.save_current_session()

            # Try to sync user info from Graph if we have a Graph token
            user_info_retrieved = False
            if scope_name == "graph":
                user_info_retrieved = manager.sync_user_info_from_graph()

            # Calculate if token is expired
            is_expired = False
            remaining_mins = 0
            if jwt_expires_at:
                is_expired = time.time() > jwt_expires_at
                remaining_mins = max(0, int((jwt_expires_at - time.time()) / 60))

            await self._send_response(
                execution_id,
                create_success_response({
                    "message": f"Token stored in slot: {token_key}",
                    "scope": scope_name,
                    "audience": aud,
                    "tenant_id": claims.get("tid"),
                    "user": upn,
                    "object_id": claims.get("oid"),
                    "is_expired": is_expired,
                    "remaining_minutes": remaining_mins,
                    "user_info_retrieved": user_info_retrieved,
                    "warning": "This token cannot be refreshed automatically" if not is_expired else "Token is expired"
                })
            )

        except Exception as e:
            logger.error(f"Error in access token auth: {e}", exc_info=True)
            await self._send_response(execution_id, create_error_response(str(e)))

    async def _run_azure_auth_managed_identity(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Authenticate using Managed Identity."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            client_id = params.get('client_id', '')

            # Store auth method in session
            manager.current_session_data["auth_method"] = "managed_identity"
            if client_id:
                manager.current_session_data["client_id"] = client_id
            manager.save_current_session()

            # Test credential by getting token
            credential = manager.get_credential("management")
            if not credential:
                await self._send_response(
                    execution_id,
                    create_error_response("Failed to create credential")
                )
                return

            # Get a token to test authentication
            token = credential.get_token("https://management.azure.com/.default")

            # Try to retrieve user information
            user_info_retrieved = manager.sync_user_info_from_graph()

            await self._send_response(
                execution_id,
                create_success_response({
                    "message": "Managed identity authentication successful",
                    "client_id": client_id if client_id else "system-assigned",
                    "user_info_retrieved": user_info_retrieved,
                    "note": "Managed identity may lack Graph API permissions" if not user_info_retrieved else None
                })
            )

        except Exception as e:
            logger.error(f"Error in managed identity auth: {e}", exc_info=True)
            await self._send_response(
                execution_id,
                create_error_response(f"Managed identity authentication failed: {str(e)}. Ensure this is running in an Azure VM/container with managed identity enabled.")
            )

    # ==================== User Info ====================

    async def _run_azure_whoami(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Get current user information."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            data = manager.current_session_data or {}

            # Collect user information
            user_info = {
                "session_id": manager.session_id,
                "session_name": manager.current_session,
                "auth_method": data.get("auth_method"),
                "tenant_id": data.get("tenant_id"),
                "subscription_id": data.get("subscription_id"),
                "subscription_name": data.get("subscription_name"),
                "account_name": data.get("account_name"),
                "user_id": data.get("user_id"),
                "user_display_name": data.get("user_display_name"),
                "user_principal_name": data.get("user_principal_name"),
                "user_job_title": data.get("user_job_title"),
                "tokens": []
            }

            # Collect token information
            import base64
            import time

            for scope_name in ["graph", "management", "storage", "vault", "teams", "office", "outlook", "unknown"]:
                token_key = f"{scope_name}_access_token"
                token = data.get(token_key)

                if token:
                    try:
                        parts = token.split(".")
                        if len(parts) == 3:
                            payload = parts[1]
                            payload += "=" * (4 - len(payload) % 4)
                            claims = json.loads(base64.urlsafe_b64decode(payload))

                            aud = claims.get("aud", "unknown")
                            exp = claims.get("exp")

                            is_expired = False
                            if exp:
                                is_expired = time.time() > exp

                            user_info["tokens"].append({
                                "scope": scope_name,
                                "audience": aud,
                                "is_expired": is_expired,
                                "expires_at": exp
                            })
                    except Exception:
                        pass

            await self._send_response(
                execution_id,
                create_success_response(user_info)
            )

        except Exception as e:
            logger.error(f"Error getting user info: {e}", exc_info=True)
            await self._send_response(execution_id, create_error_response(str(e)))

    # ==================== Subscription Management ====================

    async def _run_azure_set_subscription(self, execution_id: str, params: Dict[str, Any]) -> None:
        """Set the active subscription."""
        try:
            manager = self._get_or_create_azure_manager()
            if not manager:
                await self._send_response(
                    execution_id,
                    create_error_response("No Azure session manager available")
                )
                return

            subscription_id = params.get('subscription_id')
            subscription_name = params.get('subscription_name')

            if not subscription_id:
                await self._send_response(
                    execution_id,
                    create_error_response("subscription_id is required")
                )
                return

            # Validate subscription_id format (GUID)
            import re
            if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', subscription_id, re.IGNORECASE):
                await self._send_response(
                    execution_id,
                    create_error_response(f"Invalid subscription ID format: {subscription_id}")
                )
                return

            # Set subscription in session
            manager.current_session_data["subscription_id"] = subscription_id
            if subscription_name:
                manager.current_session_data["subscription_name"] = subscription_name

            manager.save_current_session()

            await self._send_response(
                execution_id,
                create_success_response({
                    "message": "Subscription set successfully",
                    "subscription_id": subscription_id,
                    "subscription_name": subscription_name
                })
            )

        except Exception as e:
            logger.error(f"Error setting subscription: {e}", exc_info=True)
            await self._send_response(execution_id, create_error_response(str(e)))

    # ==================== Helper Methods ====================

    def _get_or_create_azure_manager(self):
        """Get or create Azure session manager."""
        # Import here to avoid circular imports
        from src.clouds.azure.azure_session import AzureSessionManager

        if not hasattr(self, '_azure_manager'):
            self._azure_manager = AzureSessionManager()
        return self._azure_manager

    async def _send_response(self, execution_id: str, response: WebSocketResponse):
        """Send a WebSocket response."""
        await self.ws_manager.send_message(
            self.websocket,
            WebSocketMessage(
                type=response.type,
                execution_id=execution_id,
                data=response.data if response.success else None,
                error=response.error,
                success=response.success
            )
        )
