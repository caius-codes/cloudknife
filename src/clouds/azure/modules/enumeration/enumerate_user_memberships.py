"""
Enumerate user group memberships (similar to Get-MgUserMemberOf in PowerShell).

This module retrieves all groups, directory roles, and administrative units
that a user is a member of using the Microsoft Graph API.

Equivalent PowerShell command:
    Get-MgUserMemberOf -UserId <user-id>

API Endpoint:
    GET https://graph.microsoft.com/v1.0/users/{id}/memberOf

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


def enumerate_user_memberships(session_mgr: "AzureSessionManager") -> None:
    """
    Enumerate all groups and directory roles a user is a member of.

    Similar to PowerShell's Get-MgUserMemberOf.
    Retrieves security groups, Microsoft 365 groups, distribution lists,
    directory roles, and administrative units.

    Args:
        session_mgr: Azure session manager instance
    """
    console.print("\n[bold cyan]🔍 Enumerate User Group Memberships[/bold cyan]")
    console.print("[dim]Similar to PowerShell's Get-MgUserMemberOf[/dim]\n")

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
        url = "https://graph.microsoft.com/v1.0/me/memberOf"
    else:
        url = f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf"

    console.print(f"\n[dim]Fetching memberships for user: {user_id}...[/dim]\n")

    # Fetch all pages
    memberships = paginated_graph_request(access_token, url)

    if memberships is None:
        console.print("[red]Failed to retrieve user memberships.[/red]")
        console.print("[yellow]Ensure you have sufficient permissions (Directory.Read.All or User.Read.All).[/yellow]")
        return

    if not memberships:
        console.print(f"[yellow]No memberships found for user: {user_id}[/yellow]")
        return

    # Categorize memberships by type
    groups = []
    directory_roles = []
    admin_units = []
    other = []

    for item in memberships:
        odata_type = item.get("@odata.type", "")

        if "#microsoft.graph.group" in odata_type:
            groups.append(item)
        elif "#microsoft.graph.directoryRole" in odata_type:
            directory_roles.append(item)
        elif "#microsoft.graph.administrativeUnit" in odata_type:
            admin_units.append(item)
        else:
            other.append(item)

    # Display results
    console.print(f"[bold green]✓ Found {len(memberships)} memberships for user: {user_id}[/bold green]\n")

    # --- Groups ---
    if groups:
        console.print(f"[bold blue]📁 Groups ({len(groups)})[/bold blue]")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Display Name", style="cyan", no_wrap=False)
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

    # --- Directory Roles ---
    if directory_roles:
        console.print(f"[bold magenta]👑 Directory Roles ({len(directory_roles)})[/bold magenta]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Role Name", style="magenta", no_wrap=False)
        table.add_column("Description", style="dim", no_wrap=False)
        table.add_column("Object ID", style="dim", no_wrap=False)

        for role in directory_roles:
            role_name = role.get("displayName", "N/A")
            description = role.get("description", "N/A")
            obj_id = role.get("id", "N/A")

            table.add_row(role_name, description, obj_id)

        console.print(table)
        console.print()

    # --- Administrative Units ---
    if admin_units:
        console.print(f"[bold yellow]🏢 Administrative Units ({len(admin_units)})[/bold yellow]")
        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Display Name", style="yellow", no_wrap=False)
        table.add_column("Description", style="dim", no_wrap=False)
        table.add_column("Object ID", style="dim", no_wrap=False)

        for unit in admin_units:
            display_name = unit.get("displayName", "N/A")
            description = unit.get("description", "N/A")
            obj_id = unit.get("id", "N/A")

            table.add_row(display_name, description, obj_id)

        console.print(table)
        console.print()

    # --- Other ---
    if other:
        console.print(f"[bold dim]Other Memberships ({len(other)})[/bold dim]")
        for item in other:
            console.print(f"  - {item.get('@odata.type', 'Unknown')}: {item.get('displayName', 'N/A')}")
        console.print()

    # Save to session data
    enumeration_data = {
        "user_id": user_id,
        "total_memberships": len(memberships),
        "groups": groups,
        "directory_roles": directory_roles,
        "administrative_units": admin_units,
        "other": other,
    }

    session_mgr.save_enumeration_data("user_memberships", enumeration_data)

    console.print(f"[dim]Saved as 'user_memberships' in enumeration data[/dim]")
    console.print(f"\n[cyan]💡 Next steps:[/cyan]")
    console.print(f"  - Use 'enumerate_group_members <group-id>' to see who else is in a group")
    console.print(f"  - Check if user has privileged role assignments")
