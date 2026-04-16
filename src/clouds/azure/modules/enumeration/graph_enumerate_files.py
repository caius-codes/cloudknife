# src/clouds/azure/modules/enumeration/graph_enumerate_files.py

import os
import json
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...azure_session import AzureSessionManager
from ...utils.graph_helpers import (
    paginated_graph_request,
    graph_api_call,
    check_token_scopes,
    format_file_size,
    download_file_stream
)

console = Console()

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"


def enumerate_files(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate files in OneDrive and SharePoint using Graph API.

    Workflow:
    1. List all drives (OneDrive + SharePoint)
    2. Select a drive and enumerate files
    3. Optional: Recursively enumerate folders
    4. Optional: Download individual files

    Requires: Files.Read.All
    """
    console.print("[cyan]Microsoft Graph - Files Enumeration[/cyan]")

    # Get access token
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]No Graph API access token available. Please authenticate first.[/red]")
        return

    # Check token scopes
    check_token_scopes(access_token, ["Files.Read.All"])

    # Choose mode
    console.print("\n[dim]Select enumeration mode:[/dim]")
    console.print("  [bold]1[/bold]  Search by keyword  [dim](like GraphRunner Invoke-SearchSharePointAndOneDrive — works even without direct drive access)[/dim]")
    console.print("  [bold]2[/bold]  Browse drives       [dim](enumerate drive root and navigate folders)[/dim]")
    mode = Prompt.ask("Mode", choices=["1", "2"], default="1")

    if mode == "1":
        _search_files(access_token, session_mgr)
        return

    # Step 1: List drives
    console.print("\n[cyan]Fetching drives...[/cyan]")
    drives = _list_drives(access_token, session_mgr)

    # drives is None if there was an API error (403, 404, etc.)
    # drives is [] if the API succeeded but returned no drives
    if drives is None:
        console.print("[red]Failed to fetch drives due to an error (see above).[/red]")
        return

    if not drives:
        console.print("[yellow]No drives found.[/yellow]")
        console.print("[dim]This user has no OneDrive or accessible drives.[/dim]")
        return

    console.print(f"[green]Found {len(drives)} drive(s).[/green]")
    _display_drives(drives)

    # Step 2: Select drive and enumerate files
    drive_id = Prompt.ask("\n[cyan]Enter Drive ID to enumerate").strip()

    selected_drive = None
    for drive in drives:
        if drive.get("id") == drive_id:
            selected_drive = drive
            break

    if not selected_drive:
        console.print(f"[yellow]Drive with ID '{drive_id}' not found in list. Trying anyway...[/yellow]")
        selected_drive = {"id": drive_id, "name": "Unknown Drive"}

    drive_name = selected_drive.get("name", "Unknown")
    console.print(f"\n[cyan]Enumerating root of drive:[/cyan] {drive_name}")

    # Step 2: Always enumerate root first and show it
    current_items = _enumerate_drive_root(access_token, drive_id, drive_name, session_mgr)

    if not current_items:
        console.print(f"[yellow]No items found in {drive_name}.[/yellow]")
        return

    console.print(f"[green]Found {len(current_items)} item(s) at root.[/green]")
    _display_items(current_items, drive_name)

    # Step 3: Offer folder navigation or full recursive enumeration
    all_enumerated = list(current_items)

    folders = [i for i in current_items if i.get("folder")]
    while folders:
        console.print(f"\n[dim]{len(folders)} folder(s) found in current listing.[/dim]")
        console.print("  [bold]1[/bold]  Navigate into a folder")
        console.print("  [bold]2[/bold]  Enumerate ALL folders recursively")
        console.print("  [bold]3[/bold]  Continue (skip folder enumeration)")
        nav_choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="3")

        if nav_choice == "3":
            break

        if nav_choice == "2":
            console.print("[dim]Starting recursive enumeration from current listing...[/dim]")
            for folder in folders:
                folder_id = folder.get("id")
                folder_name = folder.get("name", "Unknown")
                console.print(f"[dim]Enumerating folder: {folder_name}...[/dim]")
                sub_items = _enumerate_folder_recursive(access_token, drive_id, folder_id)
                all_enumerated.extend(sub_items)
            session_mgr.save_enumeration_data(f"drive_{drive_id}_all", all_enumerated)
            console.print(f"[green]Total items after recursive enumeration: {len(all_enumerated)}[/green]")
            _display_items(all_enumerated, drive_name)
            break

        # nav_choice == "1": navigate into a specific folder
        folder_table = Table(show_header=True)
        folder_table.add_column("#", style="dim")
        folder_table.add_column("Folder Name", style="cyan")
        folder_table.add_column("ID", style="dim")
        for idx, f in enumerate(folders, 1):
            folder_table.add_row(str(idx), f.get("name", ""), f.get("id", ""))
        console.print(folder_table)

        choices = [str(i) for i in range(1, len(folders) + 1)]
        pick = Prompt.ask("[cyan]Select folder number[/cyan]", choices=choices)
        selected_folder = folders[int(pick) - 1]
        folder_id = selected_folder.get("id")
        folder_name = selected_folder.get("name", "Unknown")

        console.print(f"\n[cyan]Enumerating folder:[/cyan] {folder_name}")
        sub_items = _enumerate_folder_recursive(access_token, drive_id, folder_id, depth=0)

        if not sub_items:
            console.print(f"[yellow]No items found in {folder_name}.[/yellow]")
            folders = []
            break

        all_enumerated.extend(sub_items)
        console.print(f"[green]Found {len(sub_items)} item(s) in {folder_name}.[/green]")
        _display_items(sub_items, folder_name)

        # Update folders to subfolders of current selection for further navigation
        folders = [i for i in sub_items if i.get("folder")]

    # Step 4: Optional file download
    downloadable = [i for i in all_enumerated if i.get("file")]
    if downloadable:
        if Confirm.ask("\n[cyan]Download a file?[/cyan]", default=False):
            _handle_file_download(access_token, drive_id, all_enumerated, session_mgr)
    else:
        console.print("[dim]No files enumerated yet — navigate into folders to find files.[/dim]")


def _search_files(access_token: str, session_mgr: AzureSessionManager) -> None:
    """
    Search for files across all SharePoint sites and OneDrive using the Microsoft
    Search API — replicating GraphRunner's Invoke-SearchSharePointAndOneDrive.

    Uses POST /v1.0/search/query with entityTypes: ["driveItem"].
    Works even when direct drive enumeration is blocked by permissions.

    Requires: Files.Read.All (or Files.ReadWrite.All)
    """
    search_term = Prompt.ask("[cyan]Search term (e.g. password, secret, config)[/cyan]").strip()
    if not search_term:
        console.print("[red]Search term cannot be empty.[/red]")
        return

    page_size = 25
    from_offset = 0
    all_hits: List[Dict[str, Any]] = []

    console.print(f"\n[cyan]Searching SharePoint + OneDrive for:[/cyan] {search_term}")

    while True:
        body = {
            "requests": [
                {
                    "entityTypes": ["driveItem"],
                    "query": {"queryString": search_term},
                    "from": from_offset,
                    "size": page_size,
                    "fields": [
                        "id", "name", "parentReference", "webUrl",
                        "lastModifiedDateTime", "size", "file", "folder",
                        "createdBy", "lastModifiedBy"
                    ],
                }
            ]
        }

        try:
            response = requests.post(
                f"{GRAPH_ENDPOINT}/search/query",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=30,
            )

            if response.status_code == 403:
                console.print("[red]Permission denied. Ensure the token has Files.Read.All scope.[/red]")
                return
            if response.status_code == 401:
                console.print("[red]Token expired or invalid.[/red]")
                return
            if response.status_code != 200:
                console.print(f"[red]Search API error {response.status_code}: {response.text[:200]}[/red]")
                return

            data = response.json()
            value = data.get("value", [])
            if not value:
                break

            hits_container = value[0].get("hitsContainers", [])
            if not hits_container:
                break

            container = hits_container[0]
            hits = container.get("hits", [])
            total = container.get("total", 0)
            more_results = container.get("moreResultsAvailable", False)

            if from_offset == 0:
                console.print(f"[green]Total results: {total}[/green]")

            for hit in hits:
                resource = hit.get("resource", {})
                all_hits.append(resource)

            console.print(f"[dim]Fetched {len(all_hits)}/{total} results...[/dim]")

            if not more_results or len(all_hits) >= total:
                break

            from_offset += page_size

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Search request failed: {e}[/red]")
            return

    if not all_hits:
        console.print(f"[yellow]No results found for '{search_term}'.[/yellow]")
        return

    console.print(f"[green]Found {len(all_hits)} result(s) for '{search_term}'.[/green]")

    # Save to session
    session_mgr.save_enumeration_data(
        f"search_{search_term.replace(' ', '_').lower()[:30]}",
        all_hits
    )

    # Display results
    display_limit = 50
    to_display = all_hits[:display_limit]

    table = Table(title=f"Search results: '{search_term}' ({len(all_hits)} found)")
    table.add_column("Name", style="cyan", overflow="fold", max_width=40)
    table.add_column("Type", style="magenta", justify="center")
    table.add_column("Size", style="yellow", justify="right")
    table.add_column("Last Modified", style="green", max_width=18)
    table.add_column("Location (webUrl)", style="dim", overflow="fold", max_width=50)

    for item in to_display:
        name = item.get("name", "")
        web_url = item.get("webUrl", "")

        # Search API returns "file": {} (empty dict) for files — use key presence, not truthiness
        is_file = "file" in item
        is_folder = "folder" in item
        if is_file:
            item_type = "File"
            size = format_file_size(item.get("size", 0))
        elif is_folder:
            item_type = "Folder"
            size = ""
        else:
            # Fallback: items without file/folder facet are typically files
            item_type = "File"
            size = format_file_size(item.get("size", 0)) if item.get("size") else ""

        last_mod_str = item.get("lastModifiedDateTime", "")
        try:
            last_mod = datetime.fromisoformat(last_mod_str.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M") if last_mod_str else ""
        except Exception:
            last_mod = last_mod_str[:16]

        table.add_row(name, item_type, size, last_mod, web_url)

    console.print(table)

    if len(all_hits) > display_limit:
        console.print(f"[dim]... and {len(all_hits) - display_limit} more result(s)[/dim]")

    # Offer download — exclude folders (can't download), offer all files including those without "file" facet
    downloadable = [h for h in all_hits if "folder" not in h]
    if downloadable and Confirm.ask("\n[cyan]Download a file from results?[/cyan]", default=False):
        _handle_search_download(access_token, downloadable, session_mgr)


def _handle_search_download(access_token: str, files: List[Dict[str, Any]], session_mgr: AzureSessionManager) -> None:
    """Download a file from search results."""
    console.print("\n[cyan]Files available for download:[/cyan]")
    table = Table(show_header=True)
    table.add_column("#", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Size", style="yellow")
    table.add_column("Location", style="dim", overflow="fold", max_width=50)

    for idx, f in enumerate(files[:50], 1):
        table.add_row(
            str(idx),
            f.get("name", ""),
            format_file_size(f.get("size", 0)),
            f.get("webUrl", ""),
        )
    console.print(table)

    choices = [str(i) for i in range(1, min(len(files), 50) + 1)]
    pick = Prompt.ask("[cyan]Select file number[/cyan]", choices=choices)
    selected = files[int(pick) - 1]

    # Build download URL from parentReference + id
    parent_ref = selected.get("parentReference", {})
    drive_id = parent_ref.get("driveId", "")
    item_id = selected.get("id", "")
    file_name = selected.get("name", "download_file")
    size_bytes = selected.get("size", 0)

    if not drive_id or not item_id:
        console.print("[red]Cannot determine download URL — missing driveId or item ID.[/red]")
        console.print(f"[dim]webUrl: {selected.get('webUrl', '')}[/dim]")
        return

    console.print(f"[cyan]File:[/cyan] {file_name}")
    console.print(f"[cyan]Size:[/cyan] {format_file_size(size_bytes)}")

    if size_bytes > 100 * 1024 * 1024:
        console.print(f"[yellow]Warning: Large file ({format_file_size(size_bytes)})[/yellow]")
        if not Confirm.ask("[cyan]Continue?[/cyan]", default=False):
            return

    exfil_dir = session_mgr.get_exfil_dir("files")
    default_path = str(exfil_dir / file_name)
    dest_path = Prompt.ask("[cyan]Save to[/cyan]", default=default_path).strip()

    download_url = f"{GRAPH_ENDPOINT}/drives/{drive_id}/items/{item_id}/content"
    success = download_file_stream(access_token, download_url, dest_path, show_progress=True)

    if success:
        console.print("[green]File downloaded successfully![/green]")
    else:
        console.print("[red]Download failed.[/red]")


def _list_drives(access_token: str, session_mgr: AzureSessionManager) -> List[Dict[str, Any]]:
    """
    List all accessible drives:
    1. Personal OneDrive via /me/drives
    2. SharePoint document library drives via /sites?search=* → /sites/{id}/drives
    """
    import requests

    headers = {"Authorization": f"Bearer {access_token}"}
    all_drives: List[Dict[str, Any]] = []
    seen_ids: set = set()

    # --- Personal OneDrive ---
    personal = paginated_graph_request(access_token, f"{GRAPH_ENDPOINT}/me/drives")
    for d in personal:
        did = d.get("id", "")
        if did and did not in seen_ids:
            seen_ids.add(did)
            d.setdefault("_source", "OneDrive")
            all_drives.append(d)

    # --- SharePoint site drives ---
    console.print("[dim]Searching SharePoint sites for document libraries...[/dim]")
    try:
        resp = requests.get(
            f"{GRAPH_ENDPOINT}/sites?search=*&$top=50&$select=id,displayName,webUrl",
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 200:
            sites = resp.json().get("value", [])
            for site in sites:
                site_id = site.get("id", "")
                site_name = site.get("displayName") or site.get("webUrl", "")
                if not site_id:
                    continue
                try:
                    site_resp = requests.get(
                        f"{GRAPH_ENDPOINT}/sites/{site_id}/drives?$select=id,name,driveType,owner",
                        headers=headers,
                        timeout=20,
                    )
                    if site_resp.status_code == 200:
                        for d in site_resp.json().get("value", []):
                            did = d.get("id", "")
                            if did and did not in seen_ids:
                                seen_ids.add(did)
                                d["_source"] = f"SharePoint: {site_name}"
                                all_drives.append(d)
                except Exception:
                    pass
        elif resp.status_code == 403:
            console.print("[dim]No Sites.Read.All permission — SharePoint drives skipped.[/dim]")
    except Exception as e:
        console.print(f"[dim]SharePoint search skipped: {e}[/dim]")

    if all_drives:
        session_mgr.save_enumeration_data("drives", all_drives)

    return all_drives


def _display_drives(drives: List[Dict[str, Any]]) -> None:
    """Display drives in a table."""
    table = Table(title=f"Drives ({len(drives)} found)")
    table.add_column("Name", style="cyan", overflow="fold", max_width=30)
    table.add_column("ID", style="dim", overflow="fold")
    table.add_column("Type", style="magenta")
    table.add_column("Source", style="yellow", overflow="fold", max_width=35)
    table.add_column("Owner", style="green", overflow="fold", max_width=25)

    for drive in drives:
        name = drive.get("name", "")
        drive_id = drive.get("id", "")
        drive_type = drive.get("driveType", "")
        source = drive.get("_source", "")

        owner_data = drive.get("owner", {})
        owner_user = owner_data.get("user", {}) if owner_data else {}
        owner_name = owner_user.get("displayName", "") if owner_user else ""

        table.add_row(name, drive_id, drive_type, source, owner_name)

    console.print(table)


def _enumerate_drive_root(
    access_token: str,
    drive_id: str,
    drive_name: str,
    session_mgr: AzureSessionManager
) -> List[Dict[str, Any]]:
    """Enumerate root folder of a drive (non-recursive)."""
    url = f"{GRAPH_ENDPOINT}/drives/{drive_id}/root/children"
    url += "?$select=id,name,size,file,folder,lastModifiedDateTime,webUrl"

    items = paginated_graph_request(access_token, url, limit=500)

    # Save to session data
    if items:
        session_mgr.save_enumeration_data(f"drive_{drive_id}_root", items)

    return items


def _enumerate_drive_recursive(
    access_token: str,
    drive_id: str,
    drive_name: str,
    session_mgr: AzureSessionManager
) -> List[Dict[str, Any]]:
    """Recursively enumerate all folders in a drive."""
    all_items = []

    console.print("[dim]Starting recursive enumeration...[/dim]")

    # Start with root
    root_items = _enumerate_drive_root(access_token, drive_id, drive_name, session_mgr)
    all_items.extend(root_items)

    # Find folders and enumerate them recursively
    folders = [item for item in root_items if item.get("folder")]

    for folder in folders:
        folder_id = folder.get("id")
        folder_name = folder.get("name", "Unknown")

        console.print(f"[dim]Enumerating folder: {folder_name}...[/dim]")

        folder_items = _enumerate_folder_recursive(access_token, drive_id, folder_id)
        all_items.extend(folder_items)

    # Save to session data
    if all_items:
        session_mgr.save_enumeration_data(f"drive_{drive_id}_all", all_items)

    return all_items


def _enumerate_folder_recursive(
    access_token: str,
    drive_id: str,
    folder_id: str,
    depth: int = 0
) -> List[Dict[str, Any]]:
    """Recursively enumerate a folder (depth-first)."""
    if depth > 10:  # Prevent infinite recursion
        return []

    url = f"{GRAPH_ENDPOINT}/drives/{drive_id}/items/{folder_id}/children"
    url += "?$select=id,name,size,file,folder,lastModifiedDateTime,webUrl"

    items = paginated_graph_request(access_token, url, limit=500)

    all_items = list(items) if items else []

    # Recurse into subfolders
    folders = [item for item in items if item.get("folder")]
    for folder in folders:
        sub_folder_id = folder.get("id")
        subfolder_items = _enumerate_folder_recursive(access_token, drive_id, sub_folder_id, depth + 1)
        all_items.extend(subfolder_items)

    return all_items


def _display_items(items: List[Dict[str, Any]], drive_name: str) -> None:
    """Display files and folders in a table."""
    # Limit display to first 50 items
    display_limit = 50
    items_to_display = items[:display_limit]

    table = Table(title=f"Items in {drive_name} (showing {len(items_to_display)} of {len(items)})")
    table.add_column("Name", style="cyan", overflow="fold", max_width=40)
    table.add_column("Type", style="magenta", justify="center")
    table.add_column("Size", style="yellow", justify="right")
    table.add_column("Last Modified", style="green", max_width=18)
    table.add_column("ID", style="dim", overflow="fold")

    for item in items_to_display:
        name = item.get("name", "")
        item_id = item.get("id", "")

        # Determine type
        if item.get("folder"):
            item_type = "📁 Folder"
            size = ""
        elif item.get("file"):
            item_type = "📄 File"
            size_bytes = item.get("size", 0)
            size = format_file_size(size_bytes)
        else:
            item_type = "Unknown"
            size = ""

        # Parse last modified
        last_modified_str = item.get("lastModifiedDateTime", "")
        if last_modified_str:
            try:
                last_modified_dt = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00'))
                last_modified = last_modified_dt.strftime("%Y-%m-%d %H:%M")
            except:
                last_modified = last_modified_str[:16]
        else:
            last_modified = ""

        table.add_row(name, item_type, size, last_modified, item_id)

    console.print(table)

    if len(items) > display_limit:
        console.print(f"[dim]... and {len(items) - display_limit} more item(s)[/dim]")


def _handle_file_download(
    access_token: str,
    drive_id: str,
    items: List[Dict[str, Any]],
    session_mgr: AzureSessionManager
) -> None:
    """Handle file download workflow."""
    item_id = Prompt.ask("\n[cyan]Enter Item ID to download").strip()

    # Find item
    selected_item = None
    for item in items:
        if item.get("id") == item_id:
            selected_item = item
            break

    if not selected_item:
        console.print(f"[yellow]Item with ID '{item_id}' not found in list. Trying anyway...[/yellow]")
        selected_item = {"id": item_id, "name": "download_file"}

    # Check if it's a file
    if not selected_item.get("file"):
        console.print("[red]The selected item is not a file. Cannot download folders directly.[/red]")
        return

    file_name = selected_item.get("name", "download_file")
    size_bytes = selected_item.get("size", 0)

    console.print(f"[cyan]File:[/cyan] {file_name}")
    console.print(f"[cyan]Size:[/cyan] {format_file_size(size_bytes)}")

    # Confirm download
    if size_bytes > 100 * 1024 * 1024:  # 100MB
        console.print(f"[yellow]Warning: Large file ({format_file_size(size_bytes)})[/yellow]")
        if not Confirm.ask("[cyan]Continue with download?[/cyan]", default=False):
            return

    # Specify download location
    exfil_dir = session_mgr.get_exfil_dir("files")
    default_path = str(exfil_dir / file_name)
    dest_path = Prompt.ask("[cyan]Save to", default=default_path).strip()

    # Build download URL
    download_url = f"{GRAPH_ENDPOINT}/drives/{drive_id}/items/{item_id}/content"

    # Download
    console.print(f"\n[cyan]Downloading...[/cyan]")
    success = download_file_stream(access_token, download_url, dest_path, show_progress=True)

    if success:
        console.print(f"\n[green]File downloaded successfully![/green]")
    else:
        console.print(f"\n[red]File download failed.[/red]")
