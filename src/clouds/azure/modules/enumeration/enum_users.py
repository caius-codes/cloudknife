# src/clouds/azure/modules/enumeration/enum_users.py

from typing import Any, Dict, List
import requests

from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def enumerate_users(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate all visible Entra ID users via Microsoft Graph API.

    Uses Azure SDK credentials with direct REST API calls for Graph API.
    Implements automatic pagination for large user lists.
    """

    # Get access token for Graph API
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    console.print("[cyan]Enumerating Entra ID users via Microsoft Graph API...[/cyan]")

    # Implement pagination
    all_users: List[Dict[str, Any]] = []
    next_link = "https://graph.microsoft.com/v1.0/users"
    page = 1

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    while next_link:
        console.print(f"[dim]Fetching users (page {page})...[/dim]")

        try:
            response = requests.get(next_link, headers=headers, timeout=60)
            response.raise_for_status()

            data = response.json()
            page_users = data.get("value", [])
            all_users.extend(page_users)

            console.print(f"[dim]Page {page}: {len(page_users)} users[/dim]")

            # Check for next page
            next_link = data.get("@odata.nextLink")
            page += 1

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                console.print("[red]Authentication failed. Token may be expired.[/red]")
                console.print("[yellow]Try re-authenticating with one of the login commands.[/yellow]")
            elif e.response.status_code == 403:
                console.print("[red]Permission denied. Insufficient privileges to list users.[/red]")
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

    if not all_users:
        console.print("[yellow]No users found.[/yellow]")
        return

    console.print(f"[green]Total users retrieved: {len(all_users)}[/green]")

    # Save in session
    session_mgr.save_enumeration_data("users", all_users)

    # Display results
    table = Table(
        title=f"Entra ID Users ({len(all_users)} found)",
        show_lines=False,
    )
    table.add_column("DisplayName", style="cyan")
    table.add_column("UserPrincipalName", style="magenta")
    table.add_column("Job Title", style="green")

    for u in all_users:
        display_name = u.get("displayName") or ""
        upn = u.get("userPrincipalName") or ""
        job = u.get("jobTitle") or ""

        table.add_row(display_name, upn, job)

    console.print(table)
    console.print("[dim]Saved as 'users' in this session's enumeration data.[/dim]")
    console.print(f"[green]Enumerated {len(all_users)} user(s).[/green]")
