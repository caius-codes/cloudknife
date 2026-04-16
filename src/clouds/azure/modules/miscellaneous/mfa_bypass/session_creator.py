"""
Automatic CloudKnife session creation for MFA bypasses.

Based on FindMeAccess by Ryan McFarland (MIT License)
https://github.com/absolomb/FindMeAccess

This module creates CloudKnife sessions for each successful MFA bypass,
allowing users to immediately use the obtained tokens.
"""

import base64
import json
from typing import List
from datetime import datetime, timedelta

from rich.console import Console

from ....azure_session import AzureSessionManager
from .audit import BypassResult

console = Console()


def _detect_audience_from_resource(resource_url: str) -> tuple[str, str]:
    """
    Map resource URL to CloudKnife token slot.

    Args:
        resource_url: Resource URL (audience)

    Returns:
        Tuple of (scope_name, token_key) for session storage
    """
    AUDIENCE_MAP = {
        "https://graph.microsoft.com": ("graph", "graph_access_token"),
        "https://graph.windows.net": ("graph", "graph_access_token"),  # Legacy Azure AD Graph
        "https://management.azure.com": ("management", "management_access_token"),
        "https://management.core.windows.net": ("management", "management_access_token"),
        "https://vault.azure.net": ("vault", "vault_access_token"),
        "https://api.spaces.skype.com": ("teams", "teams_access_token"),
        "https://manage.office.com": ("office", "office_access_token"),
        "https://outlook.office365.com": ("outlook", "outlook_access_token"),
        "https://storage.azure.com": ("storage", "storage_access_token"),
    }

    # Try exact match
    for audience, (scope, key) in AUDIENCE_MAP.items():
        if resource_url.startswith(audience):
            return (scope, key)

    # Default to generic access_token
    return ("unknown", "access_token")


def _decode_token_claims(access_token: str) -> dict:
    """
    Decode JWT claims without verification.

    Args:
        access_token: JWT access token

    Returns:
        Dictionary of decoded claims, or empty dict if decoding fails
    """
    try:
        parts = access_token.split(".")
        if len(parts) == 3:
            payload = parts[1]
            # Add padding if needed
            payload += "=" * (4 - len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            return claims
    except Exception:
        pass

    return {}


def create_bypass_sessions(
    session_mgr: AzureSessionManager,
    bypass_results: List[BypassResult],
    base_session_name: str = "mfa-bypass"
) -> List[str]:
    """
    Create CloudKnife sessions for each MFA bypass.

    Deduplicates bypasses by resource URL - if multiple bypasses are found
    for the same resource (e.g., different user agents), only one session
    is created per resource.

    Session naming format: {email-slug}-{client}-{resource}
    Example: pippo@pluto.com → pippo-pluto-com-microsoft-office-azure-management-api

    Args:
        session_mgr: Azure session manager
        bypass_results: List of successful bypasses
        base_session_name: Fallback name if email not found in token (default: "mfa-bypass")

    Returns:
        List of created session names
    """
    if not bypass_results:
        return []

    # Deduplicate bypasses by resource URL
    # Keep only the first bypass for each unique resource
    unique_bypasses = {}
    for bypass in bypass_results:
        if bypass.resource_url not in unique_bypasses:
            unique_bypasses[bypass.resource_url] = bypass

    console.print(f"\n[dim]Found {len(bypass_results)} bypass(es), creating {len(unique_bypasses)} unique session(s) (deduplicated by resource)[/dim]\n")

    created_sessions = []

    for i, bypass in enumerate(unique_bypasses.values(), 1):
        # Decode token for metadata (needed for session name)
        claims = _decode_token_claims(bypass.access_token)
        tenant_id = claims.get("tid")
        upn = claims.get("upn") or claims.get("unique_name") or claims.get("email")
        oid = claims.get("oid")

        # Generate session name
        # Format: {email-slug}-{client}-{resource}
        # Example: pippo@pluto.com → pippo-pluto-microsoft-office-azure-management-api
        import re

        # Create email slug (email prefix before @, sanitized)
        if upn:
            # Extract email and sanitize: pippo@pluto.com → pippo-pluto
            email_slug = re.sub(r'[^a-z0-9\-_]', '-', upn.lower())[:30]
        else:
            # Fallback to base_session_name if no email found
            email_slug = base_session_name

        # Sanitize client and resource names
        client_slug = re.sub(r'[^a-z0-9\-_]', '-', bypass.client_name.lower())[:20]
        resource_slug = re.sub(r'[^a-z0-9\-_]', '-', bypass.resource_name.lower())[:20]

        session_name = f"{email_slug}-{client_slug}-{resource_slug}"

        # Make unique if needed
        existing = session_mgr.list_sessions()
        existing_names = {s["name"] for s in existing}
        if session_name in existing_names:
            session_name = f"{session_name}-{i}"

        # Create new session
        session_mgr.create_or_load_session(session_name)

        # Detect token slot
        scope_name, token_key = _detect_audience_from_resource(bypass.resource_url)

        # Calculate token expiry
        expires_at = None
        if claims.get("exp"):
            try:
                expires_at = int(claims["exp"])
            except (ValueError, TypeError):
                pass

        # If no exp in token, use expires_in from response
        if not expires_at and bypass.expires_in:
            expires_at = int(datetime.now().timestamp()) + bypass.expires_in

        # Store token and metadata
        session_mgr.current_session_data.update({
            "auth_method": "mfa_bypass",
            "mfa_bypass_client": bypass.client_name,
            "mfa_bypass_resource": bypass.resource_name,
            token_key: bypass.access_token,
        })

        # Store expiry
        if expires_at:
            session_mgr.current_session_data[f"{scope_name}_token_expires_at"] = expires_at

        # Store refresh token if available
        if bypass.refresh_token:
            session_mgr.current_session_data[f"{scope_name}_refresh_token"] = bypass.refresh_token

        # Store tenant/user metadata
        if tenant_id:
            session_mgr.current_session_data["tenant_id"] = tenant_id
        if upn:
            session_mgr.current_session_data["account_name"] = upn
        if oid:
            session_mgr.current_session_data["user_id"] = oid

        # If this is a management token, try to get subscription info
        if scope_name == "management" and bypass.access_token:
            try:
                import requests
                headers = {
                    "Authorization": f"Bearer {bypass.access_token}",
                    "Content-Type": "application/json"
                }
                response = requests.get(
                    "https://management.azure.com/subscriptions?api-version=2020-01-01",
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    subscriptions = response.json().get("value", [])
                    if subscriptions:
                        # Use the first subscription
                        first_sub = subscriptions[0]
                        session_mgr.current_session_data["subscription_id"] = first_sub.get("subscriptionId")
                        session_mgr.current_session_data["subscription_name"] = first_sub.get("displayName")
                        console.print(f"    [dim]Auto-configured subscription: {first_sub.get('displayName')}[/dim]")
            except Exception:
                # Silently ignore - subscription can be set manually later
                pass

        # Save session
        session_mgr.save_current_session()

        created_sessions.append(session_name)

        console.print(
            f"  [green]✓[/green] Created session: [cyan]{session_name}[/cyan] "
            f"([dim]{bypass.client_name} → {bypass.resource_name}[/dim])"
        )

    return created_sessions
