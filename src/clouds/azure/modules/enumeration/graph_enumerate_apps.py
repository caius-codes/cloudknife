# src/clouds/azure/modules/enumeration/graph_enumerate_apps.py

import json
from typing import List, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...azure_session import AzureSessionManager
from ...utils.graph_helpers import (
    paginated_graph_request,
    check_token_scopes
)

console = Console()

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"

# High-risk permissions to highlight
HIGH_RISK_PERMISSIONS = {
    "Mail.ReadWrite.All",
    "Mail.Send",
    "Directory.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
}


def enumerate_apps(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate app registrations and service principals using Graph API.

    Workflow:
    1. Choose between app registrations or service principals
    2. Display apps with their permissions
    3. Highlight high-risk permissions

    Requires: Application.Read.All
    """
    console.print("[cyan]Microsoft Graph - App Registrations & Service Principals[/cyan]")

    # Get access token
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]No Graph API access token available. Please authenticate first.[/red]")
        return

    # Check token scopes
    check_token_scopes(access_token, ["Application.Read.All"])

    # Ask what to enumerate
    console.print("\n[cyan]What would you like to enumerate?[/cyan]")
    console.print("  [1] App Registrations")
    console.print("  [2] Service Principals")

    choice = Prompt.ask("[cyan]Choose", choices=["1", "2"], default="1")

    if choice == "1":
        _enumerate_app_registrations(access_token, session_mgr)
    else:
        _enumerate_service_principals(access_token, session_mgr)


def _enumerate_app_registrations(access_token: str, session_mgr: AzureSessionManager) -> None:
    """Enumerate app registrations."""
    console.print("\n[cyan]Fetching app registrations...[/cyan]")

    url = f"{GRAPH_ENDPOINT}/applications"
    url += "?$select=id,appId,displayName,createdDateTime,signInAudience,requiredResourceAccess"

    apps = paginated_graph_request(access_token, url, limit=200)

    # apps is None if there was an API error (403, 404, etc.)
    # apps is [] if the API succeeded but returned no apps
    if apps is None:
        console.print("[red]Failed to fetch app registrations due to an error (see above).[/red]")
        return

    if not apps:
        console.print("[yellow]No app registrations found in this tenant.[/yellow]")
        console.print("[dim]This tenant has no registered applications.[/dim]")
        return

    console.print(f"[green]Found {len(apps)} app registration(s).[/green]")

    # Save to session data
    session_mgr.save_enumeration_data("app_registrations", apps)

    # Display
    _display_app_registrations(apps)

    # Offer to export to JSON
    from prompt_toolkit import prompt
    from rich.prompt import Confirm
    if Confirm.ask("\n[cyan]Export to JSON file?[/cyan]", default=False):
        _export_apps_to_json(apps, "app_registrations", session_mgr)


def _enumerate_service_principals(access_token: str, session_mgr: AzureSessionManager) -> None:
    """Enumerate service principals."""
    console.print("\n[cyan]Fetching service principals...[/cyan]")

    url = f"{GRAPH_ENDPOINT}/servicePrincipals"
    url += "?$select=id,appId,displayName,createdDateTime,servicePrincipalType,appRoles"

    sps = paginated_graph_request(access_token, url, limit=200)

    # sps is None if there was an API error (403, 404, etc.)
    # sps is [] if the API succeeded but returned no service principals
    if sps is None:
        console.print("[red]Failed to fetch service principals due to an error (see above).[/red]")
        return

    if not sps:
        console.print("[yellow]No service principals found in this tenant.[/yellow]")
        console.print("[dim]This tenant has no service principals.[/dim]")
        return

    console.print(f"[green]Found {len(sps)} service principal(s).[/green]")

    # Save to session data
    session_mgr.save_enumeration_data("service_principals", sps)

    # Display
    _display_service_principals(sps)

    # Offer to export to JSON
    from rich.prompt import Confirm
    if Confirm.ask("\n[cyan]Export to JSON file?[/cyan]", default=False):
        _export_apps_to_json(sps, "service_principals", session_mgr)


def _display_app_registrations(apps: List[Dict[str, Any]]) -> None:
    """Display app registrations in a table."""
    # Limit display to first 50 apps
    display_limit = 50
    apps_to_display = apps[:display_limit]

    table = Table(title=f"App Registrations (showing {len(apps_to_display)} of {len(apps)})")
    table.add_column("Display Name", style="cyan", overflow="fold", max_width=35)
    table.add_column("App ID", style="blue", overflow="fold")
    table.add_column("Created", style="yellow", max_width=18)
    table.add_column("Sign-In Audience", style="magenta", overflow="fold")
    table.add_column("API Permissions", style="green", overflow="fold", max_width=40)

    for app in apps_to_display:
        display_name = app.get("displayName", "")
        app_id = app.get("appId", "")

        # Parse created date
        created_str = app.get("createdDateTime", "")
        if created_str:
            try:
                created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                created = created_dt.strftime("%Y-%m-%d")
            except:
                created = created_str[:10]
        else:
            created = ""

        sign_in_audience = app.get("signInAudience", "")

        # Parse API permissions
        permissions_str = _parse_required_resource_access(app.get("requiredResourceAccess", []))

        table.add_row(display_name, app_id, created, sign_in_audience, permissions_str)

    console.print(table)

    if len(apps) > display_limit:
        console.print(f"[dim]... and {len(apps) - display_limit} more app(s)[/dim]")


def _display_service_principals(sps: List[Dict[str, Any]]) -> None:
    """Display service principals in a table."""
    # Limit display to first 50
    display_limit = 50
    sps_to_display = sps[:display_limit]

    table = Table(title=f"Service Principals (showing {len(sps_to_display)} of {len(sps)})")
    table.add_column("Display Name", style="cyan", overflow="fold", max_width=40)
    table.add_column("App ID", style="blue", overflow="fold")
    table.add_column("Created", style="yellow", max_width=18)
    table.add_column("Type", style="magenta")

    for sp in sps_to_display:
        display_name = sp.get("displayName", "")
        app_id = sp.get("appId", "")

        # Parse created date
        created_str = sp.get("createdDateTime", "")
        if created_str:
            try:
                created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                created = created_dt.strftime("%Y-%m-%d")
            except:
                created = created_str[:10]
        else:
            created = ""

        sp_type = sp.get("servicePrincipalType", "")

        table.add_row(display_name, app_id, created, sp_type)

    console.print(table)

    if len(sps) > display_limit:
        console.print(f"[dim]... and {len(sps) - display_limit} more service principal(s)[/dim]")


def _parse_required_resource_access(required_resource_access: List[Dict[str, Any]]) -> str:
    """
    Parse requiredResourceAccess to extract permission names.

    This is a simplified parser - it extracts permission IDs but doesn't resolve names.
    Full resolution would require querying servicePrincipals to map IDs to names.
    """
    if not required_resource_access:
        return ""

    all_permissions = []
    high_risk_found = []

    for resource in required_resource_access:
        resource_app_id = resource.get("resourceAppId", "")
        resource_access = resource.get("resourceAccess", [])

        for access in resource_access:
            permission_id = access.get("id", "")
            permission_type = access.get("type", "")  # Scope (delegated) or Role (application)

            # We can't resolve names without additional API calls
            # So we'll just show the count and type
            all_permissions.append(f"{permission_type}:{permission_id[:8]}")

    if not all_permissions:
        return ""

    # Show first few permissions
    if len(all_permissions) <= 3:
        return ", ".join(all_permissions)
    else:
        return f"{', '.join(all_permissions[:3])}, ... (+{len(all_permissions) - 3} more)"


def _export_apps_to_json(apps: List[Dict[str, Any]], prefix: str, session_mgr: AzureSessionManager) -> None:
    """Export apps to JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.json"

    exfil_dir = session_mgr.get_exfil_dir("apps")
    file_path = exfil_dir / filename

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(apps, f, indent=2, ensure_ascii=False)

        console.print(f"[green]Exported {len(apps)} app(s) to:[/green] {file_path}")

    except Exception as e:
        console.print(f"[red]Failed to export: {e}[/red]")
