"""
GCP Cloud Storage Object Enumeration for Cloud Knife.

Enumerates all objects in a specific Cloud Storage bucket, including:
- Object metadata (name, size, content type)
- Storage class and creation time
- Access control settings
- Custom metadata

Supports authentication via:
- Service Account JSON key file
- Application Default Credentials (ADC)
- Raw access token (via REST API)
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING

import requests
from rich.console import Console
from rich.table import Table
from google.cloud import storage

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# GCS JSON API base URL
GCS_API_BASE = "https://storage.googleapis.com/storage/v1"


def enumerate_bucket_objects(
    session_mgr: "GCPSessionManager",
    bucket_name: str,
    prefix: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Enumerate all objects in a specific Cloud Storage bucket.

    Uses REST API for access_token auth, client library for service_account/ADC.

    Args:
        session_mgr: GCP session manager with valid credentials
        bucket_name: Name of the bucket to enumerate
        prefix: Optional prefix to filter objects (like a folder path)
        max_results: Maximum number of objects to return (default: 1000)

    Returns:
        List of object dictionaries with detailed metadata
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    if not bucket_name:
        console.print("[red]Bucket name is required.[/red]")
        return []

    auth_method = session_mgr.current_session_data.get("auth_method")

    console.print(f"[dim]Enumerating objects in bucket: gs://{bucket_name}[/dim]")
    if prefix:
        console.print(f"[dim]Prefix filter: {prefix}[/dim]")

    try:
        if auth_method == "access_token":
            # Use REST API for access_token auth
            objects = _enumerate_objects_rest_api(session_mgr, bucket_name, prefix, max_results)
        else:
            # Use client library for service_account/ADC
            objects = _enumerate_objects_client_lib(session_mgr, bucket_name, prefix, max_results, credentials)

    except Exception as e:
        console.print(f"[red]Error enumerating objects: {str(e)}[/red]")
        return []

    # Save enumeration results
    session_mgr.save_enumeration_data(f"bucket_objects_{bucket_name}", objects)

    # Display results table
    _display_objects_table(objects, bucket_name)

    return objects


def _enumerate_objects_rest_api(
    session_mgr: "GCPSessionManager",
    bucket_name: str,
    prefix: Optional[str],
    max_results: int,
) -> List[Dict[str, Any]]:
    """Enumerate bucket objects using REST API (for access_token auth)."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return []

    headers = {"Authorization": f"Bearer {token}"}
    objects: List[Dict[str, Any]] = []
    page_token = None

    while len(objects) < max_results:
        # List objects in bucket
        url = f"{GCS_API_BASE}/b/{bucket_name}/o"
        params = {"maxResults": min(1000, max_results - len(objects))}

        if prefix:
            params["prefix"] = prefix
        if page_token:
            params["pageToken"] = page_token

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 404:
                console.print(f"[red]Bucket '{bucket_name}' not found.[/red]")
                return []
            elif response.status_code == 403:
                console.print(f"[red]Access denied to bucket '{bucket_name}'.[/red]")
                return []
            elif response.status_code != 200:
                console.print(f"[red]Error listing objects: {response.status_code}[/red]")
                return []

            data = response.json()
            items = data.get("items", [])

            for item in items:
                obj_data = {
                    "bucket": bucket_name,
                    "name": item.get("name"),
                    "id": item.get("id"),
                    "size": int(item.get("size", 0)),
                    "content_type": item.get("contentType", "unknown"),
                    "storage_class": item.get("storageClass"),
                    "created": item.get("timeCreated"),
                    "updated": item.get("updated"),
                    "generation": item.get("generation"),
                    "metageneration": item.get("metageneration"),
                    "md5_hash": item.get("md5Hash"),
                    "crc32c": item.get("crc32c"),
                    "etag": item.get("etag"),
                    "owner": item.get("owner", {}).get("entity"),
                    "metadata": item.get("metadata", {}),
                    "content_encoding": item.get("contentEncoding"),
                    "content_disposition": item.get("contentDisposition"),
                    "cache_control": item.get("cacheControl"),
                    "kms_key_name": item.get("kmsKeyName"),
                }
                objects.append(obj_data)

            # Check for more pages
            page_token = data.get("nextPageToken")
            if not page_token:
                break

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Request error: {str(e)}[/red]")
            break

    return objects


def _enumerate_objects_client_lib(
    session_mgr: "GCPSessionManager",
    bucket_name: str,
    prefix: Optional[str],
    max_results: int,
    credentials,
) -> List[Dict[str, Any]]:
    """Enumerate bucket objects using client library (for service_account/ADC)."""
    objects: List[Dict[str, Any]] = []

    # Create storage client
    storage_client = storage.Client(credentials=credentials)

    try:
        bucket = storage_client.bucket(bucket_name)

        # List objects with optional prefix
        blobs = bucket.list_blobs(prefix=prefix, max_results=max_results)

        for blob in blobs:
            obj_data = {
                "bucket": bucket_name,
                "name": blob.name,
                "id": blob.id,
                "size": blob.size or 0,
                "content_type": blob.content_type or "unknown",
                "storage_class": blob.storage_class,
                "created": blob.time_created.isoformat() if blob.time_created else None,
                "updated": blob.updated.isoformat() if blob.updated else None,
                "generation": blob.generation,
                "metageneration": blob.metageneration,
                "md5_hash": blob.md5_hash,
                "crc32c": blob.crc32c,
                "etag": blob.etag,
                "owner": blob.owner.get("entity") if blob.owner else None,
                "metadata": dict(blob.metadata) if blob.metadata else {},
                "content_encoding": blob.content_encoding,
                "content_disposition": blob.content_disposition,
                "cache_control": blob.cache_control,
                "kms_key_name": blob.kms_key_name,
            }
            objects.append(obj_data)

    except Exception as e:
        error_msg = str(e).lower()
        if "not found" in error_msg or "404" in error_msg:
            console.print(f"[red]Bucket '{bucket_name}' not found.[/red]")
        elif "forbidden" in error_msg or "403" in error_msg:
            console.print(f"[red]Access denied to bucket '{bucket_name}'.[/red]")
        else:
            raise

    return objects


def _display_objects_table(objects: List[Dict[str, Any]], bucket_name: str) -> None:
    """Display bucket objects in a Rich table."""
    if not objects:
        console.print(f"[yellow]No objects found in bucket '{bucket_name}'.[/yellow]")
        return

    # Calculate total size
    total_size = sum(obj.get("size", 0) for obj in objects)
    total_size_str = _format_size(total_size)

    table = Table(title=f"Objects in gs://{bucket_name} ({len(objects)} objects, {total_size_str})")
    table.add_column("Name", style="green", overflow="fold", no_wrap=False)
    table.add_column("Size", style="cyan", justify="right")
    table.add_column("Content Type")
    table.add_column("Storage Class", style="dim")
    table.add_column("Updated")

    # Show first 50 objects in table
    display_objects = objects[:50]

    for obj in display_objects:
        name = obj["name"]
        size_str = _format_size(obj.get("size", 0))

        # Highlight interesting content types
        content_type = obj.get("content_type", "unknown")
        if content_type in ("application/json", "application/x-gzip", "application/zip"):
            content_type = f"[yellow]{content_type}[/yellow]"
        elif content_type.startswith("text/"):
            content_type = f"[cyan]{content_type}[/cyan]"

        updated = obj.get("updated", "")
        if updated:
            # Show just the date part
            updated = updated.split("T")[0] if "T" in updated else updated

        table.add_row(
            name,
            size_str,
            content_type,
            obj.get("storage_class", "-"),
            updated,
        )

    console.print(table)

    if len(objects) > 50:
        console.print(f"\n[dim]Showing 50 of {len(objects)} objects. Full list saved to enumeration data.[/dim]")

    # Show summary of interesting files
    _show_interesting_files_summary(objects)


def _show_interesting_files_summary(objects: List[Dict[str, Any]]) -> None:
    """Show summary of potentially interesting files."""
    interesting_patterns = {
        "credentials": [".json", ".pem", ".key", ".env", "credentials", "secrets", "config"],
        "backups": [".bak", ".backup", ".sql", ".dump", ".tar", ".gz", ".zip"],
        "logs": [".log", "access_log", "error_log"],
        "code": [".py", ".js", ".sh", ".php", ".rb"],
    }

    findings = {}
    for category, patterns in interesting_patterns.items():
        matches = []
        for obj in objects:
            name = obj["name"].lower()
            for pattern in patterns:
                if pattern in name:
                    matches.append(obj["name"])
                    break
        if matches:
            findings[category] = matches

    if findings:
        console.print("\n[bold yellow]Potentially Interesting Files:[/bold yellow]")
        for category, files in findings.items():
            console.print(f"\n  [cyan]{category.title()}[/cyan] ({len(files)} found):")
            for f in files[:5]:
                console.print(f"    - {f}")
            if len(files) > 5:
                console.print(f"    [dim]... and {len(files) - 5} more[/dim]")


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
