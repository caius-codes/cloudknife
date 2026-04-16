# src/clouds/azure/modules/enumeration/enum_groups.py

from typing import Any, Dict, List
import requests

from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_groups(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate all visible Entra ID groups via Microsoft Graph API.

    Uses Azure SDK credentials with direct REST API calls for Graph API.
    Implements automatic pagination for large group lists.
    """

    # Get access token for Graph API
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    console.print("[cyan]Enumerating Entra ID groups via Microsoft Graph API...[/cyan]")

    # Implement pagination
    all_groups: List[Dict[str, Any]] = []
    next_link = "https://graph.microsoft.com/v1.0/groups"
    page = 1

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    while next_link:
        console.print(f"[dim]Fetching groups (page {page})...[/dim]")

        try:
            response = requests.get(next_link, headers=headers, timeout=60)
            response.raise_for_status()

            data = response.json()
            page_groups = data.get("value", [])
            all_groups.extend(page_groups)

            console.print(f"[dim]Page {page}: {len(page_groups)} groups[/dim]")

            # Check for next page
            next_link = data.get("@odata.nextLink")
            page += 1

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                console.print("[red]Authentication failed. Token may be expired.[/red]")
            elif e.response.status_code == 403:
                console.print("[red]Permission denied. Insufficient privileges to list groups.[/red]")
            else:
                console.print(f"[red]HTTP {e.response.status_code} error on page {page}[/red]")
            break

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error on page {page}: {e}[/red]")
            break

    if not all_groups:
        console.print("[yellow]No groups found.[/yellow]")
        return

    console.print(f"[green]Total groups retrieved: {len(all_groups)}[/green]")

    # Save in session
    session_mgr.save_enumeration_data("groups", all_groups)

    # Display results
    table = Table(
        title=f"Entra ID Groups ({len(all_groups)} found)",
        show_lines=False,
    )
    table.add_column("Name", style="cyan")
    table.add_column("Mail", style="magenta")
    table.add_column("Description", style="green", overflow="fold", no_wrap=False)

    for g in all_groups:
        name = g.get("displayName") or ""
        mail = g.get("mail") or ""
        desc = g.get("description") or ""
        table.add_row(name, mail, desc)

    console.print(table)
    console.print("[dim]Saved as 'groups' in this session's enumeration data.[/dim]")
    console.print(f"[green]Enumerated {len(all_groups)} group(s).[/green]")
