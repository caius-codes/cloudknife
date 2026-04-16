# src/clouds/azure/modules/enumeration/enum_administrative_unit_scoped_members.py

from typing import Any, Dict, List
import requests

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...azure_session import AzureSessionManager

console = Console()


def _get_role_description(role_id: str, access_token: str) -> str:
    """
    Retrieves a role's description via Microsoft Graph API.

    Args:
        role_id: Role ID to query
        access_token: Bearer token for authentication

    Returns:
        Role description or "N/A" if not available
    """
    if not role_id or role_id == "N/A":
        return "N/A"

    uri = f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(uri, headers=headers, timeout=30)
        response.raise_for_status()

        role_data = response.json()
        description = role_data.get("description", "N/A")
        return description if description else "N/A"

    except (requests.exceptions.RequestException, Exception):
        # On error, return N/A without blocking execution
        return "N/A"


def enumerate_administrative_unit_scoped_members(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate members with scoped roles within a specific administrative unit via Microsoft Graph API.

    Uses Azure SDK credentials with direct REST API calls for Graph API.
    Implements automatic pagination for large member lists.
    """

    # Get access token for Graph API
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    # Request administrative unit ID
    admin_unit_id = Prompt.ask("[cyan]Administrative Unit ID[/cyan]").strip()

    if not admin_unit_id:
        console.print("[red]Administrative Unit ID cannot be empty.[/red]")
        return

    # Implement pagination
    all_members: List[Dict[str, Any]] = []
    next_link = f"https://graph.microsoft.com/v1.0/directory/administrativeUnits/{admin_unit_id}/scopedRoleMembers"
    page = 1

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    while next_link:
        console.print(f"[dim]Fetching scoped role members (page {page})...[/dim]")

        try:
            response = requests.get(next_link, headers=headers, timeout=60)
            response.raise_for_status()

            data = response.json()
            page_members = data.get("value", [])
            all_members.extend(page_members)

            console.print(f"[dim]Page {page}: {len(page_members)} scoped role members[/dim]")

            # Check for next page
            next_link = data.get("@odata.nextLink")
            page += 1

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                console.print("[red]Authentication failed. Token may be expired.[/red]")
                console.print("[yellow]Try re-authenticating with one of the login commands.[/yellow]")
            elif e.response.status_code == 403:
                console.print("[red]Permission denied. Insufficient privileges to list scoped role members.[/red]")
            elif e.response.status_code == 404:
                console.print(f"[red]Administrative unit not found: {admin_unit_id}[/red]")
            else:
                console.print(f"[red]HTTP {e.response.status_code} error on page {page}[/red]")
                console.print(f"[dim]{e}[/dim]")
            break

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error on page {page}: {e}[/red]")
            break

        except Exception as e:
            console.print(f"[red]Error parsing response on page {page}: {e}[/red]")
            break

    console.print(f"[green]Total scoped role members retrieved: {len(all_members)}[/green]")
    members = all_members

    if not members:
        console.print(f"[yellow]No scoped role members found for administrative unit {admin_unit_id}.[/yellow]")
        return

    # Save enumeration data
    session_mgr.save_enumeration_data(f"admin_unit_scoped_members_{admin_unit_id}", members)

    # Cache role descriptions to avoid N+1 API calls
    # Step 1: Collect unique role IDs
    unique_role_ids = set()
    for member in members:
        role_id = member.get("roleId")
        if role_id and role_id != "N/A":
            unique_role_ids.add(role_id)

    # Step 2: Batch fetch role descriptions for unique IDs
    role_cache = {}
    if unique_role_ids:
        console.print(f"[dim]Fetching {len(unique_role_ids)} unique role descriptions...[/dim]")
        for role_id in unique_role_ids:
            role_cache[role_id] = _get_role_description(role_id, access_token)

    # Create results table
    table = Table(title=f"Scoped Role Members - Administrative Unit: {admin_unit_id}")
    table.add_column("Role ID", style="cyan")
    table.add_column("Role Description", style="magenta")
    table.add_column("Member Display Name", style="green")
    table.add_column("Member ID", style="yellow")
    table.add_column("Assignment ID", style="dim")

    # Step 3: Use cached descriptions when building table
    for member in members:
        role_id = member.get("roleId", "N/A")
        assignment_id = member.get("id", "N/A")

        # Use cached role description instead of calling API
        role_description = role_cache.get(role_id, "N/A")

        # roleMemberInfo may contain member information
        role_member_info = member.get("roleMemberInfo", {})
        member_display_name = role_member_info.get("displayName", "N/A")
        member_id = role_member_info.get("id", "N/A")

        table.add_row(
            role_id,
            role_description,
            member_display_name,
            member_id,
            assignment_id,
        )

    console.print(table)
    console.print(f"[green]Total: {len(members)} scoped role member(s)[/green]")
