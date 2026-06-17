"""
Enumerate objects owned by a user (similar to Get-MgUserOwnedObject in PowerShell).

This module retrieves all directory objects owned by a specific user,
including applications, service principals, groups, and devices.

Equivalent PowerShell command:
    Get-MgUserOwnedObject -UserId <user-id>

API Endpoint:
    GET https://graph.microsoft.com/v1.0/users/{id}/ownedObjects

Works with all authentication methods that provide a Graph API token:
- service_principal (if granted Directory.Read.All or similar)
- interactive/device_code/password (with user consent)
- az_cli (extracts token from Azure CLI)
- access_token/refresh_token (if Graph API token available)
- get_graph_token (automatic or ROPC)
"""

from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from src.clouds.azure.utils.graph_helpers import paginated_graph_request

if TYPE_CHECKING:
    from src.clouds.azure.azure_session import AzureSessionManager

console = Console()


def enumerate_user_owned_objects(session_mgr: "AzureSessionManager") -> None:
    """
    Enumerate all directory objects owned by a user.

    Similar to PowerShell's Get-MgUserOwnedObject.
    Retrieves applications, service principals, groups, and devices owned by the user.

    Args:
        session_mgr: Azure session manager instance
    """
    console.print("\n[bold cyan]🔍 Enumerate User Owned Objects[/bold cyan]")
    console.print("[dim]Similar to PowerShell's Get-MgUserOwnedObject[/dim]\n")

    # Get Graph API access token
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print(
            "[red]No Graph API token available.[/red]\n"
            "[yellow]Run 'get_graph_token' to obtain a Graph API token.[/yellow]"
        )
        return

    # Prompt for user ID or UPN
    console.print("[cyan]Enter user identifier:[/cyan]")
    console.print("  - User Principal Name (UPN): user@domain.com")
    console.print("  - Object ID (GUID): 12345678-1234-1234-1234-123456789abc")
    console.print("  - Or type 'me' for current user\n")

    user_id = Prompt.ask("[cyan]User ID/UPN[/cyan]", default="me").strip()

    if not user_id:
        console.print("[red]User ID is required.[/red]")
        return

    # Build API URL - special case for 'me'
    if user_id.lower() == "me":
        url = "https://graph.microsoft.com/v1.0/me/ownedObjects"
    else:
        url = f"https://graph.microsoft.com/v1.0/users/{user_id}/ownedObjects"

    console.print(f"\n[dim]Fetching owned objects for user: {user_id}...[/dim]\n")

    # Fetch all pages
    owned_objects = paginated_graph_request(access_token, url)

    if owned_objects is None:
        console.print("[red]Failed to retrieve owned objects.[/red]")
        console.print("[yellow]Ensure you have sufficient permissions (Directory.Read.All or User.Read.All).[/yellow]")
        return

    if not owned_objects:
        console.print(f"[yellow]No owned objects found for user: {user_id}[/yellow]")
        return

    # Categorize owned objects by type
    applications = []
    service_principals = []
    groups = []
    devices = []
    other = []

    for obj in owned_objects:
        odata_type = obj.get("@odata.type", "")

        if "#microsoft.graph.application" in odata_type:
            applications.append(obj)
        elif "#microsoft.graph.servicePrincipal" in odata_type:
            service_principals.append(obj)
        elif "#microsoft.graph.group" in odata_type:
            groups.append(obj)
        elif "#microsoft.graph.device" in odata_type:
            devices.append(obj)
        else:
            other.append(obj)

    # Display results
    console.print(f"[bold green]✓ Found {len(owned_objects)} owned objects for user: {user_id}[/bold green]\n")

    # --- Applications ---
    if applications:
        console.print(f"[bold blue]📱 Applications ({len(applications)})[/bold blue]")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Display Name", style="cyan", no_wrap=False)
        table.add_column("App ID (Client ID)", style="yellow", no_wrap=False)
        table.add_column("Sign-In Audience", no_wrap=False)
        table.add_column("Object ID", style="dim", no_wrap=False)

        for app in applications:
            display_name = app.get("displayName", "N/A")
            app_id = app.get("appId", "N/A")
            sign_in_audience = app.get("signInAudience", "N/A")
            obj_id = app.get("id", "N/A")

            table.add_row(display_name, app_id, sign_in_audience, obj_id)

        console.print(table)
        console.print()

    # --- Service Principals ---
    if service_principals:
        console.print(f"[bold magenta]🔐 Service Principals ({len(service_principals)})[/bold magenta]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Display Name", style="magenta", no_wrap=False)
        table.add_column("App ID", style="yellow", no_wrap=False)
        table.add_column("Service Principal Type", no_wrap=False)
        table.add_column("Object ID", style="dim", no_wrap=False)

        for sp in service_principals:
            display_name = sp.get("displayName", "N/A")
            app_id = sp.get("appId", "N/A")
            sp_type = sp.get("servicePrincipalType", "N/A")
            obj_id = sp.get("id", "N/A")

            table.add_row(display_name, app_id, sp_type, obj_id)

        console.print(table)
        console.print()

    # --- Groups ---
    if groups:
        console.print(f"[bold green]👥 Groups ({len(groups)})[/bold green]")
        table = Table(show_header=True, header_style="bold green")
        table.add_column("Display Name", style="green", no_wrap=False)
        table.add_column("Mail", style="dim", no_wrap=False)
        table.add_column("Group Type", no_wrap=False)
        table.add_column("Object ID", style="dim", no_wrap=False)

        for group in groups:
            display_name = group.get("displayName", "N/A")
            mail = group.get("mail", "N/A")
            group_types = group.get("groupTypes", [])
            security_enabled = group.get("securityEnabled", False)
            mail_enabled = group.get("mailEnabled", False)
            obj_id = group.get("id", "N/A")

            # Determine group type
            if "Unified" in group_types:
                group_type = "[cyan]Microsoft 365[/cyan]"
            elif security_enabled and not mail_enabled:
                group_type = "[yellow]Security[/yellow]"
            elif mail_enabled and not security_enabled:
                group_type = "[blue]Distribution[/blue]"
            elif security_enabled and mail_enabled:
                group_type = "[green]Mail-enabled Security[/green]"
            else:
                group_type = "Unknown"

            table.add_row(display_name, mail, group_type, obj_id)

        console.print(table)
        console.print()

    # --- Devices ---
    if devices:
        console.print(f"[bold yellow]💻 Devices ({len(devices)})[/bold yellow]")
        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Display Name", style="yellow", no_wrap=False)
        table.add_column("Operating System", no_wrap=False)
        table.add_column("Device ID", style="dim", no_wrap=False)
        table.add_column("Object ID", style="dim", no_wrap=False)

        for device in devices:
            display_name = device.get("displayName", "N/A")
            os = device.get("operatingSystem", "N/A")
            device_id = device.get("deviceId", "N/A")
            obj_id = device.get("id", "N/A")

            table.add_row(display_name, os, device_id, obj_id)

        console.print(table)
        console.print()

    # --- Other ---
    if other:
        console.print(f"[bold dim]Other Owned Objects ({len(other)})[/bold dim]")
        for item in other:
            console.print(f"  - {item.get('@odata.type', 'Unknown')}: {item.get('displayName', 'N/A')}")
        console.print()

    # Save to session data
    enumeration_data = {
        "user_id": user_id,
        "total_objects": len(owned_objects),
        "applications": applications,
        "service_principals": service_principals,
        "groups": groups,
        "devices": devices,
        "other": other,
    }

    session_mgr.save_enumeration_data("user_owned_objects", enumeration_data)

    console.print(f"[dim]Saved as 'user_owned_objects' in enumeration data[/dim]")

    # Show privilege escalation opportunities if any
    if applications or service_principals:
        console.print(f"\n[cyan]💡 Privilege Escalation Opportunities:[/cyan]")
        if applications:
            console.print(f"  - User owns {len(applications)} application(s)")
            console.print(f"    → Can create credentials for these apps (persistence)")
        if service_principals:
            console.print(f"  - User owns {len(service_principals)} service principal(s)")
            console.print(f"    → Can create credentials for these SPs (persistence)")

    console.print(f"\n[cyan]💡 Next steps:[/cyan]")
    console.print(f"  - Use 'enumerate_apps' to see all app registrations and their permissions")
    console.print(f"  - Check if owned apps have high-privilege API permissions")
