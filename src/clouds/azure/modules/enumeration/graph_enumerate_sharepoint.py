# src/clouds/azure/modules/enumeration/graph_enumerate_sharepoint.py

from typing import List, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...azure_session import AzureSessionManager
from ...utils.graph_helpers import (
    paginated_graph_request,
    graph_api_call,
    check_token_scopes
)

console = Console()

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"


def enumerate_sharepoint(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate SharePoint sites and document libraries using Graph API.

    Workflow:
    1. List followed sites and search all accessible sites
    2. Optionally enumerate document libraries for a selected site

    Requires: Sites.Read.All
    """
    console.print("[cyan]Microsoft Graph - SharePoint Sites Enumeration[/cyan]")

    # Get access token
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]No Graph API access token available. Please authenticate first.[/red]")
        return

    # Check token scopes
    check_token_scopes(access_token, ["Sites.Read.All"])

    # Step 1: List followed sites
    console.print("\n[cyan]Fetching followed sites...[/cyan]")
    followed_sites = _list_followed_sites(access_token)

    if followed_sites:
        console.print(f"[green]Found {len(followed_sites)} followed site(s).[/green]")
        _display_sites(followed_sites, "Followed Sites")
    else:
        console.print("[yellow]No followed sites found.[/yellow]")

    # Step 2: Search all sites
    if Confirm.ask("\n[cyan]Search for all accessible sites?[/cyan]", default=True):
        console.print("[cyan]Searching all sites (this may take a moment)...[/cyan]")
        all_sites = _search_all_sites(access_token, session_mgr)

        # all_sites is None if there was an API error (403, 404, etc.)
        # all_sites is [] if the API succeeded but returned no sites
        if all_sites is None:
            console.print("[red]Failed to search sites due to an error (see above).[/red]")
            return

        if all_sites:
            console.print(f"[green]Found {len(all_sites)} accessible site(s).[/green]")
            _display_sites(all_sites, "All Accessible Sites")
        else:
            console.print("[yellow]No SharePoint sites found.[/yellow]")
            console.print("[dim]This user has no accessible SharePoint sites.[/dim]")
            return
    else:
        all_sites = followed_sites

    if not all_sites:
        return

    # Step 3: Enumerate document libraries for a site
    if Confirm.ask("\n[cyan]Enumerate document libraries for a site?[/cyan]", default=False):
        site_id = Prompt.ask("\n[cyan]Enter Site ID").strip()

        selected_site = None
        for site in all_sites:
            if site.get("id") == site_id:
                selected_site = site
                break

        if not selected_site:
            console.print(f"[yellow]Site with ID '{site_id}' not found in list. Trying anyway...[/yellow]")
            selected_site = {"id": site_id, "displayName": "Unknown Site"}

        site_name = selected_site.get("displayName", "Unknown")
        console.print(f"\n[cyan]Enumerating document libraries in site:[/cyan] {site_name}")

        drives = _list_site_drives(access_token, site_id, site_name, session_mgr)

        if drives:
            console.print(f"[green]Found {len(drives)} document library/libraries.[/green]")
            _display_drives(drives, site_name)
        else:
            console.print(f"[yellow]No document libraries found in {site_name}.[/yellow]")


def _list_followed_sites(access_token: str) -> List[Dict[str, Any]]:
    """List sites the user follows."""
    url = f"{GRAPH_ENDPOINT}/me/followedSites"

    sites = paginated_graph_request(access_token, url)
    return sites


def _search_all_sites(access_token: str, session_mgr: AzureSessionManager) -> List[Dict[str, Any]]:
    """Search for all accessible sites."""
    url = f"{GRAPH_ENDPOINT}/sites?search=*"

    sites = paginated_graph_request(access_token, url, limit=200)  # Limit to 200 sites

    # Save to session data
    if sites:
        session_mgr.save_enumeration_data("sharepoint_sites", sites)

    return sites


def _display_sites(sites: List[Dict[str, Any]], title: str) -> None:
    """Display sites in a table."""
    # Limit display to first 50 sites
    display_limit = 50
    sites_to_display = sites[:display_limit]

    table = Table(title=f"{title} (showing {len(sites_to_display)} of {len(sites)})")
    table.add_column("Display Name", style="cyan", overflow="fold", max_width=35)
    table.add_column("ID", style="dim", overflow="fold")
    table.add_column("Web URL", style="blue", overflow="fold", max_width=50)
    table.add_column("Last Modified", style="yellow", max_width=18)

    for site in sites_to_display:
        display_name = site.get("displayName", site.get("name", ""))
        site_id = site.get("id", "")
        web_url = site.get("webUrl", "")

        # Parse last modified date
        last_modified_str = site.get("lastModifiedDateTime", "")
        if last_modified_str:
            try:
                last_modified_dt = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00'))
                last_modified = last_modified_dt.strftime("%Y-%m-%d %H:%M")
            except:
                last_modified = last_modified_str[:16]
        else:
            last_modified = ""

        table.add_row(display_name, site_id, web_url, last_modified)

    console.print(table)

    if len(sites) > display_limit:
        console.print(f"[dim]... and {len(sites) - display_limit} more site(s)[/dim]")


def _list_site_drives(
    access_token: str,
    site_id: str,
    site_name: str,
    session_mgr: AzureSessionManager
) -> List[Dict[str, Any]]:
    """List document libraries (drives) in a site."""
    url = f"{GRAPH_ENDPOINT}/sites/{site_id}/drives"

    drives = paginated_graph_request(access_token, url)

    # Save to session data
    if drives:
        session_mgr.save_enumeration_data(f"sharepoint_{site_id}_drives", drives)

    return drives


def _display_drives(drives: List[Dict[str, Any]], site_name: str) -> None:
    """Display document libraries in a table."""
    table = Table(title=f"Document Libraries in {site_name} ({len(drives)} found)")
    table.add_column("Name", style="cyan", overflow="fold", max_width=40)
    table.add_column("ID", style="dim", overflow="fold")
    table.add_column("Drive Type", style="magenta")
    table.add_column("Owner", style="green", overflow="fold", max_width=30)

    for drive in drives:
        name = drive.get("name", "")
        drive_id = drive.get("id", "")
        drive_type = drive.get("driveType", "")

        # Extract owner
        owner_data = drive.get("owner", {})
        owner_user = owner_data.get("user", {}) if owner_data else {}
        owner_name = owner_user.get("displayName", "") if owner_user else ""

        table.add_row(name, drive_id, drive_type, owner_name)

    console.print(table)
