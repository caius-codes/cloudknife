from typing import Optional, List, Dict, Any
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...aws_session import AWSSessionManager

console = Console()


def _format_size(size_bytes: int) -> str:
    """Format bytes to human readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def _list_object_versions(s3_client, bucket: str, key: str) -> List[Dict[str, Any]]:
    """List all versions of a specific object."""
    versions = []

    try:
        paginator = s3_client.get_paginator("list_object_versions")

        for page in paginator.paginate(Bucket=bucket, Prefix=key):
            # Get versions
            for obj in page.get("Versions", []):
                if obj["Key"] == key:  # Exact match only
                    versions.append({
                        "VersionId": obj.get("VersionId", "null"),
                        "IsLatest": obj.get("IsLatest", False),
                        "LastModified": str(obj["LastModified"])[:19],
                        "Size": obj["Size"],
                        "IsDeleteMarker": False,
                    })

            # Get delete markers
            for marker in page.get("DeleteMarkers", []):
                if marker["Key"] == key:
                    versions.append({
                        "VersionId": marker.get("VersionId", "null"),
                        "IsLatest": marker.get("IsLatest", False),
                        "LastModified": str(marker["LastModified"])[:19],
                        "Size": 0,
                        "IsDeleteMarker": True,
                    })

    except Exception:
        # Versioning not enabled or no permission
        pass

    # Sort by LastModified descending (newest first)
    versions.sort(key=lambda x: x["LastModified"], reverse=True)
    return versions


def s3_download_object(session_mgr: AWSSessionManager, bucket: Optional[str] = None, key: Optional[str] = None,
                       dest: Optional[str] = None, version_id: Optional[str] = None):
    """
    Download a single S3 object to local filesystem.
    If the object has multiple versions, shows all versions and asks which one to download.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    if not bucket:
        bucket = Prompt.ask("[cyan]S3 bucket name[/cyan]")
    if not key:
        key = Prompt.ask("[cyan]Object key (full path inside bucket)[/cyan]")

    aws_sess = session_mgr.get_boto3_session()
    s3 = aws_sess.client("s3")

    # Check for multiple versions
    selected_version_id = version_id
    versions = _list_object_versions(s3, bucket, key)

    # Filter out delete markers for download (can't download a delete marker)
    downloadable_versions = [v for v in versions if not v["IsDeleteMarker"]]

    if len(downloadable_versions) > 1 and not version_id:
        console.print(f"\n[bold blue]📦 Object has {len(downloadable_versions)} versions available[/bold blue]\n")

        table = Table(title=f"Versions of {key}")
        table.add_column("#", style="bold", justify="right")
        table.add_column("Version ID", style="cyan", no_wrap=False)
        table.add_column("Last Modified")
        table.add_column("Size", justify="right")
        table.add_column("Status", style="dim")

        for idx, ver in enumerate(downloadable_versions, 1):
            status = "[green]Latest[/green]" if ver["IsLatest"] else ""
            table.add_row(
                str(idx),
                ver["VersionId"],
                ver["LastModified"],
                _format_size(ver["Size"]),
                status,
            )

        console.print(table)
        console.print()

        # Ask user to select version
        choice = Prompt.ask(
            "[cyan]Select version number to download (1 = latest)[/cyan]",
            default="1"
        )

        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(downloadable_versions):
                selected_version_id = downloadable_versions[choice_idx]["VersionId"]
                if selected_version_id == "null":
                    selected_version_id = None  # null means no versioning
            else:
                console.print("[red]Invalid selection. Aborting.[/red]")
                return
        except ValueError:
            console.print("[red]Invalid input. Aborting.[/red]")
            return

    elif len(downloadable_versions) == 1:
        # Only one version, use it
        selected_version_id = downloadable_versions[0]["VersionId"]
        if selected_version_id == "null":
            selected_version_id = None

    elif len(downloadable_versions) == 0 and len(versions) > 0:
        # All versions are delete markers
        console.print("[red]Object has been deleted (only delete markers exist).[/red]")
        return

    # Ask for destination
    if not dest:
        exfil_dir = session_mgr.get_exfil_dir("s3")
        filename = key.split("/")[-1] or "downloaded_object"
        if selected_version_id and selected_version_id != "null":
            # Add version hint to filename
            filename = f"{filename}.v{selected_version_id[:8]}"
        default_path = str(exfil_dir / bucket / filename)
        dest = Prompt.ask("[cyan]Local destination path[/cyan]", default=default_path)

    dest_path = Path(dest).expanduser().resolve()
    console.print(
        f"\n[bold yellow]⚠️ Downloading S3 object to local disk may involve sensitive data.[/bold yellow]"
    )
    console.print(f"Bucket:  [cyan]{bucket}[/cyan]")
    console.print(f"Key:     [cyan]{key}[/cyan]")
    if selected_version_id:
        console.print(f"Version: [cyan]{selected_version_id}[/cyan]")
    else:
        console.print(f"Version: [dim]latest (no versioning)[/dim]")
    console.print(f"Local:   [cyan]{dest_path}[/cyan]")

    if not Confirm.ask("Proceed with download?"):
        console.print("[yellow]Aborted S3 object download.[/yellow]")
        return

    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Prepare download args
        extra_args = {}
        if selected_version_id:
            extra_args["VersionId"] = selected_version_id

        with dest_path.open("wb") as f:
            if extra_args:
                s3.download_fileobj(bucket, key, f, ExtraArgs=extra_args)
            else:
                s3.download_fileobj(bucket, key, f)

    except Exception as e:
        console.print(f"[red]Failed to download object: {str(e)}[/red]")
        console.print("[yellow]Ensure s3:GetObject permission and correct bucket/key.[/yellow]")
        return

    console.print(f"[green]✓ Object downloaded successfully to {dest_path}[/green]")
