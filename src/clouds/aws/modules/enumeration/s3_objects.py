from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager

console = Console()


def _check_versioning_status(s3_client, bucket: str) -> str:
    """Check if bucket versioning is enabled."""
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket)
        return response.get("Status", "Disabled")
    except Exception:
        return "Unknown"


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


def enumerate_s3_objects(session_mgr: AWSSessionManager, bucket: Optional[str] = None, prefix: Optional[str] = None) -> None:
    """
    Recursively list objects in a specific bucket (optionally under a prefix).
    Shows ALL versions of each object including delete markers.
    Indicates which version is latest (IsLatest=True) and highlights deleted objects.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    if not bucket:
        bucket = Prompt.ask("[cyan]S3 bucket name[/cyan]")
    if prefix is None:
        prefix = Prompt.ask("[cyan]Prefix (optional, empty for full bucket)[/cyan]", default="").strip() or None

    console.print(
        f"[bold blue]🔍 Enumerating objects in bucket '{bucket}'"
        f"{' with prefix ' + prefix if prefix else ''}...[/bold blue]"
    )

    aws_sess = session_mgr.get_boto3_session()
    s3 = aws_sess.client("s3")

    # Check versioning status
    versioning_status = _check_versioning_status(s3, bucket)
    if versioning_status == "Enabled":
        console.print(f"[dim]Bucket versioning: [green]Enabled[/green][/dim]")
    elif versioning_status == "Suspended":
        console.print(f"[dim]Bucket versioning: [yellow]Suspended[/yellow][/dim]")
    else:
        console.print(f"[dim]Bucket versioning: [dim]Disabled[/dim][/dim]")

    objects: List[Dict[str, Any]] = []
    unique_keys = set()  # Track unique keys for statistics

    try:
        # Use list_object_versions to get ALL versions and delete markers
        paginator = s3.get_paginator("list_object_versions")
        paginate_kwargs: Dict[str, Any] = {"Bucket": bucket}
        if prefix:
            paginate_kwargs["Prefix"] = prefix

        for page in paginator.paginate(**paginate_kwargs):
            # Process ALL versions (not just latest)
            for obj in page.get("Versions", []):
                key = obj["Key"]
                unique_keys.add(key)
                objects.append(
                    {
                        "Key": key,
                        "Size": obj["Size"],
                        "LastModified": str(obj["LastModified"])[:19],
                        "StorageClass": obj.get("StorageClass", "STANDARD"),
                        "VersionId": obj.get("VersionId", "null"),
                        "IsLatest": obj.get("IsLatest", False),
                        "IsDeleteMarker": False,
                    }
                )

            # Process delete markers
            for marker in page.get("DeleteMarkers", []):
                key = marker["Key"]
                unique_keys.add(key)
                objects.append(
                    {
                        "Key": key,
                        "Size": 0,  # Delete markers have no size
                        "LastModified": str(marker["LastModified"])[:19],
                        "StorageClass": "DELETE_MARKER",
                        "VersionId": marker.get("VersionId", "null"),
                        "IsLatest": marker.get("IsLatest", False),
                        "IsDeleteMarker": True,
                    }
                )

    except Exception as e:
        # Fallback to list_objects_v2 if versioning not supported or permission denied
        console.print(f"[dim]Falling back to non-versioned listing...[/dim]")
        try:
            paginator = s3.get_paginator("list_objects_v2")
            paginate_kwargs = {"Bucket": bucket}
            if prefix:
                paginate_kwargs["Prefix"] = prefix

            for page in paginator.paginate(**paginate_kwargs):
                for obj in page.get("Contents", []):
                    unique_keys.add(obj["Key"])
                    objects.append(
                        {
                            "Key": obj["Key"],
                            "Size": obj["Size"],
                            "LastModified": str(obj["LastModified"])[:19],
                            "StorageClass": obj.get("StorageClass", "STANDARD"),
                            "VersionId": "N/A",
                            "IsLatest": True,
                            "IsDeleteMarker": False,
                        }
                    )
        except Exception as e2:
            console.print(f"[red]Failed to list objects: {str(e2)}[/red]")
            console.print("[yellow]Ensure s3:ListBucket permission on the target bucket.[/yellow]")
            return

    # Sort objects: by Key, then by LastModified descending (newest first)
    objects.sort(key=lambda x: (x["Key"], x["LastModified"]), reverse=False)
    # Reverse LastModified within each key to show newest first
    from itertools import groupby
    sorted_objects = []
    for key, group in groupby(objects, key=lambda x: x["Key"]):
        group_list = list(group)
        group_list.sort(key=lambda x: x["LastModified"], reverse=True)
        sorted_objects.extend(group_list)
    objects = sorted_objects

    key_name = f"s3_objects_{bucket}"
    session_mgr.save_enumeration_data(key_name, objects)

    if not objects:
        console.print("[yellow]No objects found in this bucket/prefix.[/yellow]")
        return

    # Statistics
    total_versions = len(objects)
    total_unique_keys = len(unique_keys)
    total_delete_markers = sum(1 for o in objects if o["IsDeleteMarker"])

    table = Table(title=f"S3 Objects in {bucket} (Keys: {total_unique_keys}, Versions: {total_versions}, Delete Markers: {total_delete_markers})")
    table.add_column("Key", style="cyan", no_wrap=False, max_width=50)
    table.add_column("Size", justify="right")
    table.add_column("LastModified")
    table.add_column("Status", justify="center")
    table.add_column("VersionId", style="dim", no_wrap=False)
    table.add_column("StorageClass", style="dim")

    for o in objects[:500]:  # protezione output: primi 500
        # Determine status
        if o["IsDeleteMarker"]:
            status = "[red]🗑️ DELETED[/red]" if o["IsLatest"] else "[dim red]🗑️ deleted[/dim red]"
        elif o["IsLatest"]:
            status = "[green]✓ Latest[/green]"
        else:
            status = "[dim]old version[/dim]"

        row = [
            o["Key"],
            _format_size(o["Size"]) if not o["IsDeleteMarker"] else "[dim]—[/dim]",
            o["LastModified"],
            status,
            o["VersionId"],
            o["StorageClass"],
        ]
        table.add_row(*row)

    console.print(table)
    if len(objects) > 500:
        console.print(f"[yellow]Output truncated to first 500 versions (total: {len(objects)}).[/yellow]")

    # Summary
    console.print(f"\n[dim]Summary:[/dim]")
    console.print(f"  [cyan]Unique keys:[/cyan] {total_unique_keys}")
    console.print(f"  [cyan]Total versions:[/cyan] {total_versions}")
    if total_delete_markers > 0:
        console.print(f"  [red]Delete markers:[/red] {total_delete_markers}")

    console.print(
        f"\n[green]Object list stored under key '{key_name}' in session data.[/green]"
    )
