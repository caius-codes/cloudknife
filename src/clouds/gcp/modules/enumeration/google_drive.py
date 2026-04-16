"""
GCP Google Drive Enumeration for Cloud Knife.

Enumerates files, folders, and permissions from Google Drive API.
Useful for:
- Finding sensitive files in Drive
- Discovering overly permissive sharing
- Mapping accessible resources
- Identifying orphaned or shared files

Supports authentication via:
- Service Account JSON key file (with domain-wide delegation)
- Application Default Credentials (ADC)
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import io

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()


def enumerate_drive_files(
    session_mgr: "GCPSessionManager",
    query: str = None,
    max_results: int = 1000,
    show_shared: bool = False,
    show_permissions: bool = False,
) -> List[Dict[str, Any]]:
    """
    Enumerate files from Google Drive.

    Args:
        session_mgr: GCP session manager with valid credentials
        query: Drive query filter (e.g., "name contains 'secret'")
        max_results: Maximum number of files to return
        show_shared: Show only shared files
        show_permissions: Include detailed permissions for each file

    Returns:
        List of file dictionaries with metadata
    """
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError

    # Request Drive API scopes (read-only access)
    drive_scopes = [
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/drive.metadata.readonly",
    ]
    credentials = session_mgr.get_credentials(scopes=drive_scopes)
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    console.print("[bold]Enumerating Google Drive files...[/bold]")
    if query:
        console.print(f"[dim]Query filter: {query}[/dim]")

    try:
        # Build Drive API service
        service = build('drive', 'v3', credentials=credentials)

        # Build query
        drive_query = _build_drive_query(query, show_shared)

        # Fields to retrieve
        fields = "nextPageToken, files(id, name, mimeType, size, createdTime, modifiedTime, owners, shared, sharingUser, permissions, webViewLink)"

        all_files: List[Dict[str, Any]] = []
        page_token = None
        page_count = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Fetching files...", total=None)

            while True:
                try:
                    results = service.files().list(
                        q=drive_query,
                        pageSize=100,
                        pageToken=page_token,
                        fields=fields,
                        supportsAllDrives=True,
                        includeItemsFromAllDrives=True,
                    ).execute()

                    files = results.get('files', [])
                    page_count += 1

                    for file_item in files:
                        file_data = _parse_file_data(file_item, show_permissions)
                        all_files.append(file_data)

                        if len(all_files) >= max_results:
                            break

                    progress.update(task, description=f"Fetched {len(all_files)} files (page {page_count})...")

                    if len(all_files) >= max_results:
                        console.print(f"[yellow]Reached max results limit ({max_results})[/yellow]")
                        break

                    page_token = results.get('nextPageToken')
                    if not page_token:
                        break

                except HttpError as error:
                    console.print(f"[red]API error: {error}[/red]")
                    break

    except Exception as e:
        console.print(f"[red]Error accessing Drive API: {str(e)}[/red]")
        return []

    # Save enumeration results
    session_mgr.save_enumeration_data("drive_files", all_files)

    # Display results
    _display_files_table(all_files, show_permissions)

    # Display sensitive file warnings
    _analyze_sensitive_files(all_files)

    # Ask user if they want to download the files
    if all_files:
        if Confirm.ask(f"\n[cyan]Download {len(all_files)} file(s)?[/cyan]", default=False):
            output_dir = Prompt.ask("[cyan]Output directory[/cyan]", default="./drive_downloads")
            download_files_batch(session_mgr, all_files, output_dir)

    return all_files


def search_drive_files(
    session_mgr: "GCPSessionManager",
    keywords: List[str] = None,
    file_types: List[str] = None,
    owner: str = None,
) -> List[Dict[str, Any]]:
    """
    Search for specific files in Google Drive.

    Args:
        session_mgr: GCP session manager
        keywords: Keywords to search in file names (e.g., ['password', 'secret', 'key'])
        file_types: File MIME types to filter (e.g., ['application/pdf', 'text/plain'])
        owner: Filter by owner email

    Returns:
        List of matching files
    """
    query_parts = []

    if keywords:
        # Search in name
        keyword_queries = [f"name contains '{kw}'" for kw in keywords]
        query_parts.append(f"({' or '.join(keyword_queries)})")

    if file_types:
        type_queries = [f"mimeType = '{ft}'" for ft in file_types]
        query_parts.append(f"({' or '.join(type_queries)})")

    if owner:
        query_parts.append(f"'{owner}' in owners")

    query = " and ".join(query_parts) if query_parts else None

    console.print(f"[cyan]Searching Drive with query: {query}[/cyan]")

    return enumerate_drive_files(session_mgr, query=query, show_permissions=True)


def list_shared_files(
    session_mgr: "GCPSessionManager",
    publicly_shared: bool = False,
) -> List[Dict[str, Any]]:
    """
    List files shared with others or publicly.

    Args:
        session_mgr: GCP session manager
        publicly_shared: Show only publicly accessible files

    Returns:
        List of shared files
    """
    if publicly_shared:
        console.print("[bold yellow]Listing publicly shared files (SECURITY RISK!)...[/bold yellow]")
        query = "visibility = 'anyoneWithLink' or visibility = 'anyoneCanFind'"
    else:
        console.print("[bold]Listing shared files...[/bold]")
        query = "sharedWithMe = true or visibility != 'limited'"

    return enumerate_drive_files(session_mgr, query=query, show_shared=True, show_permissions=True)


def describe_file_permissions(
    session_mgr: "GCPSessionManager",
    file_id: str = None,
) -> Dict[str, Any]:
    """
    Get detailed permissions for a specific file.

    Args:
        session_mgr: GCP session manager
        file_id: Google Drive file ID

    Returns:
        Dictionary with file details and permissions
    """
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError

    # Request Drive API scopes
    drive_scopes = [
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/drive.metadata.readonly",
    ]
    credentials = session_mgr.get_credentials(scopes=drive_scopes)
    if not credentials:
        console.print("[red]No credentials configured.[/red]")
        return {}

    if not file_id:
        file_id = Prompt.ask("[cyan]Enter file ID[/cyan]")

    if not file_id:
        console.print("[red]File ID is required.[/red]")
        return {}

    try:
        service = build('drive', 'v3', credentials=credentials)

        # Get file metadata
        file = service.files().get(
            fileId=file_id,
            fields="id, name, mimeType, size, createdTime, modifiedTime, owners, shared, webViewLink, permissions",
            supportsAllDrives=True,
        ).execute()

        console.print(f"\n[bold blue]File: {file.get('name')}[/bold blue]")
        console.print(f"[dim]ID: {file_id}[/dim]")
        console.print(f"[dim]Type: {file.get('mimeType')}[/dim]")
        console.print(f"[dim]Size: {_format_size(file.get('size', 0))}[/dim]")
        console.print(f"[dim]Link: {file.get('webViewLink', 'N/A')}[/dim]")

        # Display permissions
        permissions = file.get('permissions', [])
        if permissions:
            console.print(f"\n[bold]Permissions ({len(permissions)}):[/bold]")

            perm_table = Table(show_header=True, expand=True)
            perm_table.add_column("Type", style="cyan")
            perm_table.add_column("Email/Domain", style="green")
            perm_table.add_column("Role", style="yellow")
            perm_table.add_column("Inherited", style="dim")

            for perm in permissions:
                perm_type = perm.get('type', 'unknown')
                email_or_domain = perm.get('emailAddress') or perm.get('domain', '-')
                role = perm.get('role', 'unknown')
                inherited = "Yes" if perm.get('permissionDetails', [{}])[0].get('inherited') else "No"

                # Highlight risky permissions
                if perm_type == 'anyone':
                    email_or_domain = f"[bold red]{email_or_domain}[/bold red]"
                    role = f"[bold red]{role}[/bold red]"

                perm_table.add_row(perm_type, email_or_domain, role, inherited)

            console.print(perm_table)
        else:
            console.print("[dim]No permissions found.[/dim]")

        return file

    except HttpError as error:
        console.print(f"[red]API error: {error}[/red]")
        return {}


def _build_drive_query(custom_query: Optional[str], shared_only: bool) -> str:
    """Build Drive API query string."""
    query_parts = []

    if custom_query:
        query_parts.append(custom_query)

    if shared_only:
        query_parts.append("sharedWithMe = true")

    # Exclude trashed files
    query_parts.append("trashed = false")

    return " and ".join(query_parts) if query_parts else "trashed = false"


def _parse_file_data(file_item: Dict[str, Any], include_permissions: bool) -> Dict[str, Any]:
    """Parse Drive API file response."""
    file_data = {
        "id": file_item.get('id'),
        "name": file_item.get('name'),
        "mimeType": file_item.get('mimeType'),
        "size": int(file_item.get('size', 0)),
        "size_formatted": _format_size(file_item.get('size', 0)),
        "created": file_item.get('createdTime'),
        "modified": file_item.get('modifiedTime'),
        "shared": file_item.get('shared', False),
        "web_link": file_item.get('webViewLink'),
        "owners": [owner.get('emailAddress', 'Unknown') for owner in file_item.get('owners', [])],
    }

    if include_permissions:
        file_data["permissions"] = file_item.get('permissions', [])
        file_data["permission_count"] = len(file_item.get('permissions', []))

        # Check for public access
        permissions = file_item.get('permissions', [])
        file_data["is_public"] = any(p.get('type') == 'anyone' for p in permissions)

    return file_data


def _format_size(size_bytes) -> str:
    """Format file size in human-readable format."""
    try:
        size = int(size_bytes)
    except (ValueError, TypeError):
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _display_files_table(files: List[Dict[str, Any]], show_permissions: bool) -> None:
    """Display files in a Rich table."""
    if not files:
        console.print("[yellow]No files found.[/yellow]")
        return

    table = Table(title=f"Google Drive Files ({len(files)} found)", expand=True)
    table.add_column("File ID", style="dim", no_wrap=True, width=20)
    table.add_column("Name", style="green", no_wrap=False)
    table.add_column("Type", style="dim")
    table.add_column("Size", justify="right")
    table.add_column("Shared", style="yellow")
    table.add_column("Owner", style="cyan", no_wrap=False)

    if show_permissions:
        table.add_column("Permissions", justify="right", style="cyan")
        table.add_column("Public", style="red")

    for file in files[:100]:  # Limit display to 100
        shared = "Yes" if file.get('shared') else "No"
        # Handle empty owners list
        owners = file.get('owners', [])
        owner = owners[0] if owners else 'Unknown'

        # Truncate file ID for display (keep first 15 chars)
        file_id_display = file['id'][:15] + "..." if len(file['id']) > 15 else file['id']

        row = [
            file_id_display,
            file['name'],
            file.get('mimeType', 'unknown').split('.')[-1],
            file['size_formatted'],
            shared,
            owner,
        ]

        if show_permissions:
            perm_count = file.get('permission_count', 0)
            is_public = file.get('is_public', False)

            row.append(str(perm_count))
            row.append("[bold red]YES[/bold red]" if is_public else "No")

        table.add_row(*row)

    console.print(table)

    if len(files) > 100:
        console.print(f"\n[dim]... and {len(files) - 100} more files (showing first 100)[/dim]")

    # Print file IDs for easy copying (first 20 files)
    if files:
        console.print(f"\n[bold cyan]File IDs (for download_drive_file command):[/bold cyan]")
        for i, file in enumerate(files[:20], 1):
            console.print(f"  [dim]{i}.[/dim] [green]{file['name']}[/green]")
            console.print(f"     [yellow]{file['id']}[/yellow]")

        if len(files) > 20:
            console.print(f"\n[dim]... and {len(files) - 20} more files (use 'download_drive_files' to download all)[/dim]")


def _analyze_sensitive_files(files: List[Dict[str, Any]]) -> None:
    """Analyze files for potential security issues."""
    if not files:
        return

    # Check for publicly shared files
    public_files = [f for f in files if f.get('is_public')]
    if public_files:
        console.print(f"\n[bold red]WARNING: {len(public_files)} publicly accessible file(s) found![/bold red]")

    # Check for sensitive keywords in filenames
    sensitive_keywords = ['password', 'secret', 'key', 'token', 'credential', 'private', 'confidential', 'api', 'backup', 'dump']
    sensitive_files = []

    for file in files:
        name_lower = file['name'].lower()
        for keyword in sensitive_keywords:
            if keyword in name_lower:
                sensitive_files.append((file, keyword))
                break

    if sensitive_files:
        console.print(f"\n[bold yellow]Found {len(sensitive_files)} file(s) with sensitive keywords:[/bold yellow]")
        for file, keyword in sensitive_files[:10]:
            shared_indicator = " [red](SHARED)[/red]" if file.get('shared') else ""
            public_indicator = " [bold red](PUBLIC!)[/bold red]" if file.get('is_public') else ""
            console.print(f"  • {file['name']} [dim](contains '{keyword}'){shared_indicator}{public_indicator}[/dim]")

        if len(sensitive_files) > 10:
            console.print(f"  [dim]... and {len(sensitive_files) - 10} more[/dim]")


def download_file(
    session_mgr: "GCPSessionManager",
    file_id: str,
    output_path: str,
    file_name: str = None,
) -> bool:
    """
    Download a single file from Google Drive.

    Args:
        session_mgr: GCP session manager with valid credentials
        file_id: Google Drive file ID
        output_path: Directory where to save the file
        file_name: Optional custom filename (otherwise uses Drive filename)

    Returns:
        True if download succeeded, False otherwise
    """
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    from googleapiclient.http import MediaIoBaseDownload

    # Request Drive API scopes
    drive_scopes = [
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/drive.metadata.readonly",
    ]
    credentials = session_mgr.get_credentials(scopes=drive_scopes)
    if not credentials:
        console.print("[red]No credentials configured.[/red]")
        return False

    try:
        service = build('drive', 'v3', credentials=credentials)

        # Always get file metadata to determine mime type
        file_metadata = service.files().get(
            fileId=file_id,
            fields="name, mimeType",
            supportsAllDrives=True,
        ).execute()

        # Use provided filename or get from metadata
        if not file_name:
            file_name = file_metadata.get('name', f'file_{file_id}')

        mime_type = file_metadata.get('mimeType', '')

        # Create output directory
        output_dir = Path(output_path).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        # Full file path
        file_path = output_dir / file_name

        # Handle Google Workspace files (Docs, Sheets, Slides) - export as PDF
        if mime_type.startswith('application/vnd.google-apps'):
            console.print(f"[yellow]Google Workspace file detected: {mime_type}[/yellow]")
            console.print(f"[dim]Exporting as PDF...[/dim]")

            # Export as PDF
            request = service.files().export_media(
                fileId=file_id,
                mimeType='application/pdf'
            )
            # Update filename extension
            file_path = file_path.with_suffix('.pdf')
        else:
            # Regular file download
            request = service.files().get_media(
                fileId=file_id,
                supportsAllDrives=True,
            )

        # Download file with progress
        fh = io.FileIO(str(file_path), 'wb')
        downloader = MediaIoBaseDownload(fh, request)

        done = False
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"Downloading {file_name}...", total=100)

            while not done:
                status, done = downloader.next_chunk()
                if status:
                    progress.update(task, completed=int(status.progress() * 100))

        console.print(f"[green]✓ Downloaded: {file_path}[/green]")
        return True

    except HttpError as error:
        console.print(f"[red]API error downloading {file_name}: {error}[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Error downloading {file_name}: {str(e)}[/red]")
        return False


def download_files_batch(
    session_mgr: "GCPSessionManager",
    files: List[Dict[str, Any]],
    output_dir: str = "./drive_downloads",
    max_workers: int = 5,
) -> Dict[str, Any]:
    """
    Download multiple files from Google Drive in parallel.

    Args:
        session_mgr: GCP session manager with valid credentials
        files: List of file dictionaries (from enumerate_drive_files)
        output_dir: Directory where to save files
        max_workers: Number of parallel downloads (default 5)

    Returns:
        Dictionary with download statistics
    """
    if not files:
        console.print("[yellow]No files to download.[/yellow]")
        return {"success": 0, "failed": 0, "total": 0}

    console.print(f"\n[bold]Downloading {len(files)} file(s) to: {output_dir}[/bold]")

    # Create output directory
    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    success_count = 0
    failed_count = 0
    failed_files = []

    # Download files in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {
            executor.submit(
                download_file,
                session_mgr,
                file['id'],
                output_dir,
                file['name']
            ): file
            for file in files
        }

        for future in as_completed(future_to_file):
            file = future_to_file[future]
            try:
                result = future.result()
                if result:
                    success_count += 1
                else:
                    failed_count += 1
                    failed_files.append(file['name'])
            except Exception as e:
                console.print(f"[red]Error downloading {file['name']}: {str(e)}[/red]")
                failed_count += 1
                failed_files.append(file['name'])

    # Summary
    console.print(f"\n[bold green]Download complete![/bold green]")
    console.print(f"[green]✓ Success: {success_count}[/green]")
    if failed_count > 0:
        console.print(f"[red]✗ Failed: {failed_count}[/red]")
        if failed_files:
            console.print("[dim]Failed files:[/dim]")
            for name in failed_files[:10]:
                console.print(f"  [dim]• {name}[/dim]")
            if len(failed_files) > 10:
                console.print(f"  [dim]... and {len(failed_files) - 10} more[/dim]")

    console.print(f"[cyan]Files saved to: {output_path}[/cyan]")

    return {
        "success": success_count,
        "failed": failed_count,
        "total": len(files),
        "output_dir": str(output_path),
        "failed_files": failed_files,
    }
