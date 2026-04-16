# src/clouds/azure/modules/enumeration/enum_administrative_units.py

from typing import Any, Dict, List
import requests

from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_administrative_units(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate all visible Entra ID Administrative Units via Microsoft Graph API.

    Uses Azure SDK credentials with direct REST API calls for Graph API.
    Implements automatic pagination for large lists.
    """

    # Get access token for Graph API
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    console.print(
        "[cyan]Enumerating Entra ID Administrative Units via Microsoft Graph API...[/cyan]"
    )

    # Implement pagination
    all_admin_units: List[Dict[str, Any]] = []
    next_link = "https://graph.microsoft.com/v1.0/directory/administrativeUnits"
    page = 1

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    while next_link:
        console.print(f"[dim]Fetching administrative units (page {page})...[/dim]")

        try:
            response = requests.get(next_link, headers=headers, timeout=60)
            response.raise_for_status()

            data = response.json()
            page_admin_units = data.get("value", [])
            all_admin_units.extend(page_admin_units)

            console.print(f"[dim]Page {page}: {len(page_admin_units)} administrative units[/dim]")

            # Check for next page
            next_link = data.get("@odata.nextLink")
            page += 1

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                console.print("[red]Authentication failed. Token may be expired.[/red]")
                console.print("[yellow]Try re-authenticating with one of the login commands.[/yellow]")
            elif e.response.status_code == 403:
                console.print("[red]Permission denied. Insufficient privileges to list administrative units.[/red]")
            elif e.response.status_code == 404:
                console.print("[red]Resource not found. Administrative units endpoint may not be available.[/red]")
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

    console.print(f"[green]Total administrative units retrieved: {len(all_admin_units)}[/green]")
    admin_units = all_admin_units

    if not admin_units:
        console.print("[yellow]No Administrative Units found.[/yellow]")
        return

    # Save in session
    session_mgr.save_enumeration_data("administrative_units", admin_units)

    table = Table(
        title="Entra ID Administrative Units",
        show_lines=False,
    )
    table.add_column("Display Name", style="cyan")
    table.add_column("Description", style="green", overflow="fold", no_wrap=False)
    table.add_column("Visibility", style="magenta")
    table.add_column("Membership Type", style="yellow")
    table.add_column("ID", style="dim")

    for au in admin_units:
        display_name = au.get("displayName") or ""
        description = au.get("description") or ""
        visibility = au.get("visibility") or "N/A"
        membership_type = au.get("membershipType") or "N/A"
        au_id = au.get("id") or ""

        table.add_row(display_name, description, visibility, membership_type, au_id)

    console.print(table)
    console.print(
        f"[bold green]Total:[/bold green] {len(admin_units)} Administrative Unit(s)"
    )
    console.print(
        "[dim]Saved as 'administrative_units' in this session's enumeration data.[/dim]"
    )
