# src/clouds/azure/modules/enumeration/enum_administrative_unit_members.py

from typing import Any, Dict, List
import requests

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_administrative_unit_members(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate direct members of a specific administrative unit via Microsoft Graph API.

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
    next_link = f"https://graph.microsoft.com/v1.0/directory/administrativeUnits/{admin_unit_id}/members"
    page = 1

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    while next_link:
        console.print(f"[dim]Fetching members (page {page})...[/dim]")

        try:
            response = requests.get(next_link, headers=headers, timeout=60)
            response.raise_for_status()

            data = response.json()
            page_members = data.get("value", [])
            all_members.extend(page_members)

            console.print(f"[dim]Page {page}: {len(page_members)} members[/dim]")

            # Check for next page
            next_link = data.get("@odata.nextLink")
            page += 1

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                console.print("[red]Authentication failed. Token may be expired.[/red]")
                console.print("[yellow]Try re-authenticating with one of the login commands.[/yellow]")
            elif e.response.status_code == 403:
                console.print("[red]Permission denied. Insufficient privileges to list administrative unit members.[/red]")
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

    console.print(f"[green]Total members retrieved: {len(all_members)}[/green]")
    members = all_members

    if not members:
        console.print(f"[yellow]No members found for administrative unit {admin_unit_id}.[/yellow]")
        return

    # Save enumeration data
    session_mgr.save_enumeration_data(f"admin_unit_members_{admin_unit_id}", members)

    # Create results table
    table = Table(title=f"Members - Administrative Unit: {admin_unit_id}")
    table.add_column("Display Name", style="green")
    table.add_column("User Principal Name", style="cyan")
    table.add_column("Object Type", style="yellow")
    table.add_column("Object ID", style="dim")

    for member in members:
        display_name = member.get("displayName", "N/A")
        user_principal_name = member.get("userPrincipalName", "N/A")
        object_type = member.get("@odata.type", "N/A")
        object_id = member.get("id", "N/A")

        # Clean up type for better readability
        if object_type.startswith("#microsoft.graph."):
            object_type = object_type.replace("#microsoft.graph.", "")

        table.add_row(
            display_name,
            user_principal_name,
            object_type,
            object_id,
        )

    console.print(table)
    console.print(f"[green]Total: {len(members)} member(s)[/green]")
