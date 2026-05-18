"""
Azure AD Graph API (LEGACY) Permission Bruteforce Module.

⚠️  DEPRECATED API - Azure AD Graph API was retired in June 2023.
    This module is for compatibility with legacy tokens (graph.windows.net).
    Use Microsoft Graph API (graph.microsoft.com) whenever possible.

Enumerates Azure AD Graph API permissions by making actual API calls.
Similar to the Microsoft Graph bruteforce but uses legacy endpoints.

Usage:
    enumerate_bruteforce_aad_permissions         # Fast mode (default) - key permissions
    enumerate_bruteforce_aad_permissions full    # Full mode - all permissions
"""

import base64
import json
import time
from typing import Dict, List, Any, Optional, Tuple

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from ...azure_session import AzureSessionManager

console = Console()


# =============================================================================
# Azure AD Graph API Permission Mappings
# Format: "permission_name": ("method", "url_template", optional_data)
# {tenant} will be replaced with actual tenant ID
# =============================================================================

# Fast mode: ~25 key permissions covering main categories
FAST_PERMISSIONS_MAPPING: Dict[str, Tuple[str, str, Optional[Dict]]] = {
    # ========== Directory & Users ==========
    "Directory.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/users?api-version=1.6&$top=1",
        None
    ),
    "Directory.ReadWrite.All": (
        "POST",
        "https://graph.windows.net/{tenant}/users?api-version=1.6",
        {"accountEnabled": True, "displayName": "test"}
    ),
    "User.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/users?api-version=1.6&$top=1",
        None
    ),
    "User.ReadWrite.All": (
        "PATCH",
        "https://graph.windows.net/{tenant}/users/00000000-0000-0000-0000-000000000000?api-version=1.6",
        {"displayName": "test"}
    ),

    # ========== Groups ==========
    "Group.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/groups?api-version=1.6&$top=1",
        None
    ),
    "Group.ReadWrite.All": (
        "POST",
        "https://graph.windows.net/{tenant}/groups?api-version=1.6",
        {"displayName": "test", "mailEnabled": False, "securityEnabled": True}
    ),

    # ========== Applications & Service Principals ==========
    "Application.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/applications?api-version=1.6&$top=1",
        None
    ),
    "Application.ReadWrite.All": (
        "POST",
        "https://graph.windows.net/{tenant}/applications?api-version=1.6",
        {"displayName": "test"}
    ),
    "ServicePrincipal.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/servicePrincipals?api-version=1.6&$top=1",
        None
    ),
    "ServicePrincipal.ReadWrite.All": (
        "POST",
        "https://graph.windows.net/{tenant}/servicePrincipals?api-version=1.6",
        {"appId": "00000000-0000-0000-0000-000000000000"}
    ),

    # ========== Domains ==========
    "Domain.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/domains?api-version=1.6",
        None
    ),
    "Domain.ReadWrite.All": (
        "POST",
        "https://graph.windows.net/{tenant}/domains?api-version=1.6",
        {"name": "test.example.com"}
    ),

    # ========== Roles & Role Assignments ==========
    "RoleManagement.Read.Directory": (
        "GET",
        "https://graph.windows.net/{tenant}/directoryRoles?api-version=1.6&$top=1",
        None
    ),
    "RoleManagement.ReadWrite.Directory": (
        "POST",
        "https://graph.windows.net/{tenant}/directoryRoles?api-version=1.6",
        {"roleTemplateId": "00000000-0000-0000-0000-000000000000"}
    ),

    # ========== OAuth2 Permissions ==========
    "OAuth2PermissionGrant.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/oauth2PermissionGrants?api-version=1.6&$top=1",
        None
    ),

    # ========== Tenant Info ==========
    "Organization.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/tenantDetails?api-version=1.6",
        None
    ),
    "Organization.ReadWrite.All": (
        "PATCH",
        "https://graph.windows.net/{tenant}/tenantDetails?api-version=1.6",
        {"displayName": "test"}
    ),

    # ========== Contacts ==========
    "Contacts.Read": (
        "GET",
        "https://graph.windows.net/{tenant}/contacts?api-version=1.6&$top=1",
        None
    ),
    "Contacts.ReadWrite": (
        "POST",
        "https://graph.windows.net/{tenant}/contacts?api-version=1.6",
        {"displayName": "test"}
    ),

    # ========== Devices ==========
    "Device.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/devices?api-version=1.6&$top=1",
        None
    ),
    "Device.ReadWrite.All": (
        "POST",
        "https://graph.windows.net/{tenant}/devices?api-version=1.6",
        {"displayName": "test", "accountEnabled": True}
    ),
}

# Full mode: extended permission set
FULL_PERMISSIONS_MAPPING: Dict[str, Tuple[str, str, Optional[Dict]]] = {
    **FAST_PERMISSIONS_MAPPING,  # Include fast permissions

    # Additional permissions for full mode
    "Directory.AccessAsUser.All": (
        "GET",
        "https://graph.windows.net/{tenant}/me?api-version=1.6",
        None
    ),
    "User.ReadBasic.All": (
        "GET",
        "https://graph.windows.net/{tenant}/users?api-version=1.6&$select=displayName,userPrincipalName&$top=1",
        None
    ),
    "GroupMember.Read.All": (
        "GET",
        "https://graph.windows.net/{tenant}/groups?api-version=1.6&$top=1",
        None
    ),
    "GroupMember.ReadWrite.All": (
        "POST",
        "https://graph.windows.net/{tenant}/groups/00000000-0000-0000-0000-000000000000/$links/members?api-version=1.6",
        {"url": "https://graph.windows.net/{tenant}/users/00000000-0000-0000-0000-000000000000"}
    ),
}


# Permission categories for display
PERMISSION_CATEGORIES = {
    # Directory & Users
    "Directory.Read.All": "Directory & Users",
    "Directory.ReadWrite.All": "Directory & Users",
    "Directory.AccessAsUser.All": "Directory & Users",
    "User.Read.All": "Directory & Users",
    "User.ReadWrite.All": "Directory & Users",
    "User.ReadBasic.All": "Directory & Users",

    # Groups
    "Group.Read.All": "Groups",
    "Group.ReadWrite.All": "Groups",
    "GroupMember.Read.All": "Groups",
    "GroupMember.ReadWrite.All": "Groups",

    # Applications & Service Principals
    "Application.Read.All": "Applications",
    "Application.ReadWrite.All": "Applications",
    "ServicePrincipal.Read.All": "Applications",
    "ServicePrincipal.ReadWrite.All": "Applications",

    # Domains
    "Domain.Read.All": "Domains",
    "Domain.ReadWrite.All": "Domains",

    # Roles
    "RoleManagement.Read.Directory": "Roles",
    "RoleManagement.ReadWrite.Directory": "Roles",

    # OAuth & Permissions
    "OAuth2PermissionGrant.Read.All": "OAuth & Permissions",

    # Organization
    "Organization.Read.All": "Organization",
    "Organization.ReadWrite.All": "Organization",

    # Contacts
    "Contacts.Read": "Contacts",
    "Contacts.ReadWrite": "Contacts",

    # Devices
    "Device.Read.All": "Devices",
    "Device.ReadWrite.All": "Devices",
}


# Dangerous permissions that enable privilege escalation
DANGEROUS_PERMISSIONS = {
    "Directory.ReadWrite.All": "Can create/modify/delete any directory object (users, groups, apps)",
    "User.ReadWrite.All": "Can create/modify/delete users and reset passwords",
    "Group.ReadWrite.All": "Can add users to privileged groups",
    "Application.ReadWrite.All": "Can create applications and grant them permissions",
    "ServicePrincipal.ReadWrite.All": "Can create service principals with permissions",
    "RoleManagement.ReadWrite.Directory": "Can assign directory roles (Global Admin, etc.)",
    "Domain.ReadWrite.All": "Can add/remove domains",
    "Organization.ReadWrite.All": "Can modify tenant settings",
}


def _decode_token_scopes(access_token: str) -> Dict[str, List[str]]:
    """
    Decode JWT token and extract scopes/roles.

    Args:
        access_token: JWT access token

    Returns:
        Dict with 'delegated' and 'application' scope lists
    """
    try:
        parts = access_token.split('.')
        if len(parts) != 3:
            return {"delegated": [], "application": []}

        payload = parts[1]
        payload += '=' * (4 - len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))

        delegated_scopes = []
        if 'scp' in claims:
            delegated_scopes = claims['scp'].split(' ')

        application_scopes = []
        if 'roles' in claims:
            application_scopes = claims['roles']

        return {
            "delegated": delegated_scopes,
            "application": application_scopes
        }
    except Exception:
        return {"delegated": [], "application": []}


def _test_aad_permission(
    access_token: str,
    tenant_id: str,
    permission: str,
    method: str,
    url_template: str,
    data: Optional[Dict] = None,
    retry_count: int = 0,
    timeout: int = 10
) -> Tuple[str, str, str]:
    """
    Test a single Azure AD Graph API permission by making an actual API call.

    Args:
        access_token: Valid Azure AD Graph API access token
        tenant_id: Azure AD tenant ID
        permission: Permission name (e.g., "User.Read.All")
        method: HTTP method (GET, POST, PATCH, DELETE)
        url_template: Azure AD Graph API endpoint URL template
        data: Optional JSON data for POST/PATCH
        retry_count: Number of retries for rate limiting (internal)
        timeout: Request timeout in seconds (default: 10)

    Returns:
        Tuple of (permission, status, error_message)
        status: "ALLOWED", "DENIED", "ERROR", "SKIPPED"
    """
    # Replace {tenant} placeholder
    url = url_template.replace("{tenant}", tenant_id)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=timeout)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=timeout)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, json=data, timeout=timeout)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=timeout)
        else:
            return (permission, "ERROR", f"Unsupported method: {method}")

        # Success - permission is granted
        if response.status_code in [200, 201, 204]:
            return (permission, "ALLOWED", "")

        # 404 Not Found - permission OK, resource doesn't exist
        elif response.status_code == 404:
            return (permission, "ALLOWED", "Resource not found (permission OK)")

        # 403 Forbidden - permission denied
        elif response.status_code == 403:
            try:
                error_data = response.json()
                error_msg = error_data.get("odata.error", {}).get("message", {}).get("value", "Forbidden")

                if any(x in error_msg.lower() for x in [
                    "insufficient privileges",
                    "access denied",
                    "authorization_requestdenied",
                    "forbidden",
                    "does not have permission"
                ]):
                    return (permission, "DENIED", error_msg[:100])
                else:
                    return (permission, "DENIED", error_msg[:100])
            except:
                return (permission, "DENIED", "Forbidden")

        # 401 Unauthorized - token issue
        elif response.status_code == 401:
            return (permission, "ERROR", "Token expired or invalid")

        # 400 Bad Request - might be permission issue or malformed request
        elif response.status_code == 400:
            try:
                error_data = response.json()
                error_msg = error_data.get("odata.error", {}).get("message", {}).get("value", "Bad Request")

                if "invalid" in error_msg.lower() or "required property" in error_msg.lower():
                    return (permission, "ALLOWED", "Bad request but permission seems OK")
                else:
                    return (permission, "DENIED", error_msg[:100])
            except:
                return (permission, "DENIED", "Bad Request")

        # 429 Rate Limited - retry with limit
        elif response.status_code == 429:
            if retry_count >= 2:
                return (permission, "ERROR", "Rate limit exceeded (max retries)")

            retry_after = int(response.headers.get("Retry-After", 5))
            console.print(f"[yellow]Rate limited on {permission}. Waiting {retry_after}s before retry {retry_count + 1}/2...[/yellow]")
            time.sleep(retry_after)
            return _test_aad_permission(access_token, tenant_id, permission, method, url_template, data, retry_count + 1, timeout)

        # Other errors
        else:
            return (permission, "ERROR", f"HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        console.print(f"\n[yellow]⏱️  Timeout ({timeout}s) testing {permission}[/yellow]")

        choice = Prompt.ask(
            "[cyan]Choose action[/cyan]",
            choices=["retry", "skip"],
            default="skip"
        ).lower()

        if choice == "retry":
            console.print(f"[cyan]Retrying with 30s timeout...[/cyan]")
            return _test_aad_permission(access_token, tenant_id, permission, method, url_template, data, retry_count, timeout=30)
        else:
            return (permission, "SKIPPED", f"Skipped due to timeout ({timeout}s)")

    except requests.exceptions.RequestException as e:
        return (permission, "ERROR", str(e)[:100])
    except Exception as e:
        return (permission, "ERROR", str(e)[:100])


def enumerate_bruteforce_aad_permissions(
    session_mgr: AzureSessionManager,
    mode: str = "fast"
) -> Optional[Dict[str, Any]]:
    """
    Enumerate Azure AD Graph API (LEGACY) permissions by making actual API calls.

    ⚠️  Uses deprecated graph.windows.net API (retired June 2023).
        Use Microsoft Graph (graph.microsoft.com) whenever possible.

    Args:
        session_mgr: Azure session manager
        mode: Testing mode - "fast" (~25 perms) or "full" (~30 perms)

    Returns:
        Dict with enumeration results or None on error
    """
    console.print("[bold yellow]⚠️  Azure AD Graph API (Legacy)[/bold yellow]")
    console.print("[dim]Using deprecated graph.windows.net endpoint (retired June 2023)[/dim]")
    console.print("[dim]Consider using Microsoft Graph (graph.microsoft.com) instead[/dim]\n")

    # Get Azure AD Graph API access token
    # We need to check for tokens with audience graph.windows.net
    access_token = None

    # Check if we have a stored token with graph.windows.net audience
    stored_token = session_mgr.current_session_data.get("graph_access_token")
    if stored_token:
        try:
            parts = stored_token.split(".")
            if len(parts) == 3:
                payload = parts[1]
                payload += "=" * (4 - len(payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload))

                aud = claims.get("aud", "")
                if aud == "https://graph.windows.net":
                    console.print("[green]✓ Found Azure AD Graph API token (graph.windows.net)[/green]")
                    access_token = stored_token
                else:
                    console.print(f"[yellow]Token has wrong audience: {aud}[/yellow]")
                    console.print("[yellow]Expected: https://graph.windows.net[/yellow]")
        except Exception:
            pass

    if not access_token:
        console.print("[red]No Azure AD Graph API token available.[/red]")
        console.print("[cyan]Get a token with audience 'https://graph.windows.net' and use:[/cyan]")
        console.print("  set_token /path/to/aad_graph_token.txt")
        return None

    # Get tenant ID from token or session
    tenant_id = session_mgr.current_session_data.get("tenant_id")
    if not tenant_id:
        # Try to extract from token
        try:
            parts = access_token.split(".")
            if len(parts) == 3:
                payload = parts[1]
                payload += "=" * (4 - len(payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload))
                tenant_id = claims.get("tid")
        except Exception:
            pass

    if not tenant_id:
        console.print("[red]Could not determine tenant ID.[/red]")
        console.print("[yellow]Set tenant ID in session or extract from token.[/yellow]")
        return None

    console.print(f"[dim]Using tenant ID: {tenant_id}[/dim]")

    # Validate and select permissions mapping
    mode = mode.lower()
    if mode == "full":
        permissions_mapping = FULL_PERMISSIONS_MAPPING
    elif mode == "fast":
        permissions_mapping = FAST_PERMISSIONS_MAPPING
    else:
        console.print(f"[yellow]Unknown mode '{mode}'. Using 'fast' mode.[/yellow]")
        mode = "fast"
        permissions_mapping = FAST_PERMISSIONS_MAPPING

    total_permissions = len(permissions_mapping)

    console.print(f"\n[bold blue]🔍 Azure AD Graph API Permission Bruteforce ({mode} mode)[/bold blue]")
    console.print(f"[dim]Total permissions to test: {total_permissions}[/dim]\n")

    # Decode token to show declared scopes
    token_scopes = _decode_token_scopes(access_token)
    if token_scopes["delegated"] or token_scopes["application"]:
        console.print("[cyan]Token declared scopes:[/cyan]")
        if token_scopes["delegated"]:
            console.print(f"  [dim]Delegated: {', '.join(token_scopes['delegated'])}[/dim]")
        if token_scopes["application"]:
            console.print(f"  [dim]Application: {', '.join(token_scopes['application'])}[/dim]")
        console.print()

    # Test permissions
    granted_permissions: List[str] = []
    denied_permissions: List[str] = []
    error_permissions: List[str] = []
    skipped_permissions: List[str] = []

    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} permissions"),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Testing permissions...",
            total=total_permissions
        )

        permission_list = list(permissions_mapping.items())
        for idx, (permission, (method, url_template, data)) in enumerate(permission_list):
            progress.update(task, description=f"[cyan]Testing {permission}")

            perm_name, status, error_msg = _test_aad_permission(
                access_token, tenant_id, permission, method, url_template, data
            )

            if status == "ALLOWED":
                granted_permissions.append(permission)
            elif status == "DENIED":
                denied_permissions.append(permission)
            elif status == "SKIPPED":
                skipped_permissions.append(permission)
            else:  # ERROR
                error_permissions.append(permission)

            progress.advance(task)

            # Add small delay between requests
            if idx < len(permission_list) - 1:
                time.sleep(0.3)

    console.print(f"[dim]  → Found {len(granted_permissions)} granted permissions[/dim]")
    console.print(f"[dim]  → Found {len(denied_permissions)} denied permissions[/dim]")
    console.print(f"[dim]  → Found {len(error_permissions)} errors[/dim]")
    console.print(f"[dim]  → Found {len(skipped_permissions)} skipped[/dim]\n")

    # Debug: Show first error if all requests failed
    if len(error_permissions) == total_permissions:
        console.print("[bold red]⚠️  All requests resulted in errors![/bold red]")
        console.print("[yellow]This usually means the token is invalid, expired, or has the wrong audience.[/yellow]")
        console.print()

    # Organize results by category
    results_by_category: Dict[str, Dict[str, Any]] = {}
    dangerous_found = []

    for permission in granted_permissions:
        category = PERMISSION_CATEGORIES.get(permission, "Other")

        if category not in results_by_category:
            results_by_category[category] = {"granted": [], "denied": [], "total": 0}

        results_by_category[category]["granted"].append(permission)

        if permission in DANGEROUS_PERMISSIONS:
            dangerous_found.append(permission)

    for permission in denied_permissions:
        category = PERMISSION_CATEGORIES.get(permission, "Other")

        if category not in results_by_category:
            results_by_category[category] = {"granted": [], "denied": [], "total": 0}

        results_by_category[category]["denied"].append(permission)

    # Calculate totals
    for category in results_by_category:
        results_by_category[category]["total"] = (
            len(results_by_category[category]["granted"]) +
            len(results_by_category[category]["denied"])
        )

    # Save results
    enumeration_results = {
        "mode": mode,
        "api": "Azure AD Graph (Legacy)",
        "endpoint": "graph.windows.net",
        "total_tested": total_permissions,
        "total_granted": len(granted_permissions),
        "total_denied": len(denied_permissions),
        "total_errors": len(error_permissions),
        "total_skipped": len(skipped_permissions),
        "granted_permissions": granted_permissions,
        "denied_permissions": denied_permissions,
        "error_permissions": error_permissions,
        "skipped_permissions": skipped_permissions,
        "dangerous_found": dangerous_found,
        "by_category": results_by_category,
        "token_declared_scopes": token_scopes,
    }

    session_mgr.save_enumeration_data("aad_graph_legacy_bruteforce", enumeration_results)

    # Display results
    _display_results(
        enumeration_results,
        results_by_category,
        granted_permissions,
        dangerous_found,
        total_permissions,
        skipped_permissions
    )

    return enumeration_results


def _display_results(
    enumeration_results: Dict[str, Any],
    results_by_category: Dict[str, Dict[str, Any]],
    granted_permissions: List[str],
    dangerous_found: List[str],
    total_permissions: int,
    skipped_permissions: List[str]
):
    """Display enumeration results in a formatted table."""

    # Summary table
    console.print("[bold blue]📊 Permission Summary[/bold blue]\n")

    summary_table = Table()
    summary_table.add_column("Category", style="cyan", no_wrap=True)
    summary_table.add_column("Total", style="white", justify="right")
    summary_table.add_column("Granted", style="green", justify="right")
    summary_table.add_column("Denied", style="red", justify="right")
    summary_table.add_column("Rate", style="yellow", justify="right")

    # Sort categories alphabetically
    for category in sorted(results_by_category.keys()):
        cat_data = results_by_category[category]
        total = cat_data["total"]
        granted = len(cat_data["granted"])
        denied = len(cat_data["denied"])
        rate = f"{(granted / total * 100):.0f}%" if total > 0 else "0%"

        summary_table.add_row(
            category,
            str(total),
            str(granted),
            str(denied),
            rate
        )

    # Add total row
    total_granted = enumeration_results["total_granted"]
    total_denied = enumeration_results["total_denied"]
    total_rate = f"{(total_granted / total_permissions * 100):.0f}%" if total_permissions > 0 else "0%"

    summary_table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{total_permissions}[/bold]",
        f"[bold green]{total_granted}[/bold green]",
        f"[bold red]{total_denied}[/bold red]",
        f"[bold]{total_rate}[/bold]"
    )

    console.print(summary_table)
    console.print()

    # Debug: Warn if no permissions found at all
    if total_granted == 0 and total_denied == 0:
        console.print("[bold yellow]⚠️  No results found![/bold yellow]")
        console.print("[dim]Possible causes:[/dim]")
        console.print("  - Token is invalid or expired")
        console.print("  - Token has wrong audience (should be https://graph.windows.net)")
        console.print("  - Azure AD Graph API is disabled in tenant (retired June 2023)")
        console.print()
        console.print("[cyan]Try running 'whoami' to check token validity[/cyan]")
        console.print()

    # Dangerous permissions found
    if dangerous_found:
        console.print(f"[bold red]⚠️  DANGEROUS PERMISSIONS FOUND ({len(dangerous_found)}):[/bold red]")
        for perm in sorted(dangerous_found):
            description = DANGEROUS_PERMISSIONS.get(perm, "")
            console.print(f"  [red]🔥[/red] {perm}")
            if description:
                console.print(f"     [dim]{description}[/dim]")
        console.print()

    # List granted permissions by category
    if granted_permissions:
        console.print("[bold green]✓ Granted Permissions by Category:[/bold green]\n")

        for category in sorted(results_by_category.keys()):
            cat_granted = results_by_category[category]["granted"]
            if cat_granted:
                console.print(f"[cyan]{category}:[/cyan]")
                for perm in sorted(cat_granted):
                    dangerous_marker = " [red]🔥[/red]" if perm in DANGEROUS_PERMISSIONS else ""
                    console.print(f"  • {perm}{dangerous_marker}")
                console.print()

    # Skipped permissions
    if skipped_permissions:
        console.print(f"[yellow]⏭️  Skipped {len(skipped_permissions)} permission(s) due to timeouts[/yellow]")
        console.print()

    console.print("[dim]Results saved in session as 'aad_graph_legacy_bruteforce'[/dim]")
