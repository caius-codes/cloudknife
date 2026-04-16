from typing import Optional, Dict, Any, List
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm

from ...aws_session import AWSSessionManager

console = Console()


def s3_download_bucket(session_mgr: AWSSessionManager, bucket: Optional[str] = None,
                       prefix: Optional[str] = None, dest_dir: Optional[str] = None,
                       include_versions: bool = False):
    """
    Recursively download all objects from a bucket (optionally a prefix) to a local directory.

    Args:
        session_mgr: AWS session manager
        bucket: S3 bucket name
        prefix: Optional prefix to filter objects
        dest_dir: Local destination directory
        include_versions: If True, download ALL versions of each object. If False, only latest.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    if not bucket:
        bucket = Prompt.ask("[cyan]S3 bucket name[/cyan]")
    if prefix is None:
        prefix = Prompt.ask("[cyan]Prefix (optional, empty for full bucket)[/cyan]", default="").strip() or None
    if not dest_dir:
        dest_dir = Prompt.ask("[cyan]Local destination directory[/cyan]", default=f"s3_{bucket}")

    # Ask about versioning if not specified
    if not include_versions:
        version_choice = Prompt.ask(
            "[cyan]Download mode[/cyan]",
            choices=["latest", "all"],
            default="latest"
        )
        include_versions = (version_choice == "all")

    dest_root = Path(dest_dir).expanduser().resolve()

    console.print(
        "[bold yellow]⚠️ Recursive S3 download may exfiltrate large volumes of data.[/bold yellow]"
    )
    console.print(f"Bucket: [cyan]{bucket}[/cyan]")
    console.print(f"Prefix: [cyan]{prefix or '(none, full bucket)'}[/cyan]")
    console.print(f"Mode: [cyan]{'All versions' if include_versions else 'Latest only'}[/cyan]")
    console.print(f"Local dir: [cyan]{dest_root}[/cyan]")

    if not Confirm.ask("Proceed with recursive download?"):
        console.print("[yellow]Aborted S3 bucket download.[/yellow]")
        return

    aws_sess = session_mgr.get_boto3_session()
    s3 = aws_sess.client("s3")

    # First enumerate objects
    console.print("[blue]Listing objects to download...[/blue]")
    objects: List[Dict[str, Any]] = []

    try:
        if include_versions:
            # Use list_object_versions to get ALL versions
            paginator = s3.get_paginator("list_object_versions")
            paginate_kwargs: Dict[str, Any] = {"Bucket": bucket}
            if prefix:
                paginate_kwargs["Prefix"] = prefix

            for page in paginator.paginate(**paginate_kwargs):
                # Get all versions (not delete markers)
                for obj in page.get("Versions", []):
                    objects.append({
                        "Key": obj["Key"],
                        "VersionId": obj.get("VersionId"),
                        "IsLatest": obj.get("IsLatest", False),
                        "Size": obj.get("Size", 0),
                        "LastModified": obj.get("LastModified"),
                    })
        else:
            # Use list_objects_v2 to get only latest versions
            paginator = s3.get_paginator("list_objects_v2")
            paginate_kwargs = {"Bucket": bucket}
            if prefix:
                paginate_kwargs["Prefix"] = prefix

            for page in paginator.paginate(**paginate_kwargs):
                for obj in page.get("Contents", []):
                    objects.append({
                        "Key": obj["Key"],
                        "VersionId": None,  # No versioning in list_objects_v2
                        "IsLatest": True,
                        "Size": obj.get("Size", 0),
                        "LastModified": obj.get("LastModified"),
                    })

    except Exception as e:
        console.print(f"[red]Failed to list bucket objects: {str(e)}[/red]")
        return

    total = len(objects)
    if total == 0:
        console.print("[yellow]No objects to download in this bucket/prefix.[/yellow]")
        return

    console.print(f"[green]Found {total} {'versions' if include_versions else 'objects'}. Starting download...[/green]")
    dest_root.mkdir(parents=True, exist_ok=True)

    ok = 0
    failed = 0

    for idx, obj in enumerate(objects, start=1):
        key = obj["Key"]
        version_id = obj.get("VersionId")

        # Build destination path
        rel_path = key[len(prefix):].lstrip("/") if prefix and key.startswith(prefix) else key

        # If downloading all versions and version_id exists, add version suffix
        if include_versions and version_id:
            # Add version ID to filename: file.txt -> file.txt.v<version_id>
            rel_path = f"{rel_path}.v{version_id}"

        dest_path = dest_root.joinpath(rel_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if version_id:
                # Download specific version
                s3.download_file(bucket, key, str(dest_path), ExtraArgs={"VersionId": version_id})
            else:
                # Download latest version (no versioning)
                s3.download_file(bucket, key, str(dest_path))
            ok += 1
        except Exception as e:
            failed += 1
            version_info = f" (version: {version_id})" if version_id else ""
            console.print(f"[red]Failed to download {key}{version_info}: {str(e)[:100]}[/red]")

        if idx % 50 == 0 or idx == total:
            console.print(f"[dim]Progress: {idx}/{total} processed[/dim]")

    console.print(
        f"[green]Download completed. Success: {ok}, Failed: {failed}. Local dir: {dest_root}[/green]"
    )
