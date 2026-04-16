"""
GCP Secret Manager Enumeration for Cloud Knife.

Enumerates secrets and their versions from Secret Manager API.
Secret Manager stores sensitive data like API keys, passwords,
certificates, and other credentials.

Supports authentication via:
- Service Account JSON key file
- Application Default Credentials (ADC)
- Raw access token (via REST API)
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

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


def enumerate_secrets(
    session_mgr: "GCPSessionManager",
    project_id: Optional[str] = None,
    include_versions: bool = True,
) -> List[Dict[str, Any]]:
    """
    Enumerate all secrets in a project from Secret Manager.

    Args:
        session_mgr: GCP session manager with valid credentials
        project_id: Project ID to enumerate (defaults to current project)
        include_versions: Whether to enumerate versions for each secret

    Returns:
        List of secret dictionaries with metadata and versions
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

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
        return []

    console.print(f"[dim]Enumerating secrets in project: {project_id}[/dim]")

    auth_method = session_mgr.current_session_data.get("auth_method")
    all_secrets: List[Dict[str, Any]] = []

    try:
        if auth_method == "access_token":
            secrets = _enumerate_secrets_rest_api(
                session_mgr, project_id, include_versions
            )
        else:
            secrets = _enumerate_secrets_with_credentials(
                session_mgr, project_id, include_versions, credentials
            )

        all_secrets.extend(secrets)

    except Exception as e:
        console.print(f"[red]Error enumerating secrets: {str(e)}[/red]")
        return []

    # Save enumeration results
    session_mgr.save_enumeration_data(f"secrets_{project_id}", all_secrets)

    # Display results
    _display_secrets_table(all_secrets, project_id)

    return all_secrets


def _enumerate_secrets_rest_api(
    session_mgr: "GCPSessionManager",
    project_id: str,
    include_versions: bool,
) -> List[Dict[str, Any]]:
    """Enumerate secrets using REST API with access_token."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return []

    headers = {"Authorization": f"Bearer {token}"}
    all_secrets = []

    # Query global endpoint
    console.print("[dim]Scanning global Secret Manager endpoint...[/dim]")
    global_secrets = _fetch_secrets(headers, project_id, include_versions, location=None)
    all_secrets.extend(global_secrets)

    # Query regional endpoints
    console.print(f"[dim]Scanning {len(GCP_REGIONS)} regional endpoints...[/dim]")
    for region in GCP_REGIONS:
        regional_secrets = _fetch_secrets(headers, project_id, include_versions, location=region)
        all_secrets.extend(regional_secrets)

    return all_secrets


def _enumerate_secrets_with_credentials(
    session_mgr: "GCPSessionManager",
    project_id: str,
    include_versions: bool,
    credentials,
) -> List[Dict[str, Any]]:
    """Enumerate secrets using service account/ADC credentials."""
    from google.auth.transport.requests import Request
    credentials.refresh(Request())
    token = credentials.token

    headers = {"Authorization": f"Bearer {token}"}
    all_secrets = []

    # Query global endpoint
    console.print("[dim]Scanning global Secret Manager endpoint...[/dim]")
    global_secrets = _fetch_secrets(headers, project_id, include_versions, location=None)
    all_secrets.extend(global_secrets)

    # Query regional endpoints
    console.print(f"[dim]Scanning {len(GCP_REGIONS)} regional endpoints...[/dim]")
    for region in GCP_REGIONS:
        regional_secrets = _fetch_secrets(headers, project_id, include_versions, location=region)
        all_secrets.extend(regional_secrets)

    return all_secrets


def _fetch_secrets(
    headers: Dict[str, str],
    project_id: str,
    include_versions: bool,
    location: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch secrets from the API.

    Args:
        headers: Authorization headers
        project_id: GCP project ID
        include_versions: Whether to fetch versions
        location: GCP region for regional secrets (None for global)

    Returns:
        List of secret dictionaries
    """
    secrets: List[Dict[str, Any]] = []

    # Build URL based on location
    if location:
        # Regional endpoint: https://secretmanager.{region}.rep.googleapis.com/v1/projects/{project}/locations/{region}/secrets
        base_url = f"https://secretmanager.{location}.rep.googleapis.com/v1"
        url = f"{base_url}/projects/{project_id}/locations/{location}/secrets"
    else:
        # Global endpoint: https://secretmanager.googleapis.com/v1/projects/{project}/secrets
        url = f"{SECRET_API_BASE}/projects/{project_id}/secrets"

    page_token = None

    while True:
        params = {"pageSize": 100}
        if page_token:
            params["pageToken"] = page_token

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 404:
                # For regional endpoints, 404 is expected if no secrets in that region
                # Only show warning for global endpoint
                if not location:
                    console.print("[yellow]Secret Manager API not enabled or no secrets found.[/yellow]")
                return []
            elif response.status_code == 403:
                # For regional endpoints, 403 might be expected
                if not location:
                    console.print("[red]Access denied to Secret Manager API.[/red]")
                return []
            elif response.status_code != 200:
                # Only log errors for global endpoint, silently skip regional errors
                if not location:
                    try:
                        error_data = response.json()
                        if isinstance(error_data, dict):
                            error_msg = error_data.get("error", {}).get("message", response.text)
                        else:
                            error_msg = response.text
                    except Exception:
                        error_msg = response.text
                    console.print(f"[red]API error: {error_msg}[/red]")
                return []

            data = response.json()
            items = data.get("secrets", [])

            for item in items:
                # Parse secret name
                # Global format: projects/{project}/secrets/{secret_id}
                # Regional format: projects/{project}/locations/{location}/secrets/{secret_id}
                full_name = item.get("name", "")
                name_parts = full_name.split("/")

                # Extract secret_id and location
                secret_name = name_parts[-1] if name_parts else "unknown"
                secret_location = location if location else "global"

                # If parsing from full_name and it contains 'locations'
                if "locations" in name_parts:
                    location_idx = name_parts.index("locations")
                    if location_idx + 1 < len(name_parts):
                        secret_location = name_parts[location_idx + 1]

                # Extract replication config
                replication = item.get("replication", {})
                if "automatic" in replication:
                    repl_type = "AUTOMATIC"
                elif "userManaged" in replication:
                    replicas = replication.get("userManaged", {}).get("replicas", [])
                    locations = [r.get("location", "") for r in replicas]
                    repl_type = f"USER_MANAGED ({', '.join(locations)})"
                else:
                    repl_type = "AUTOMATIC"

                secret_data = {
                    "name": secret_name,
                    "full_name": full_name,
                    "project": project_id,
                    "location": secret_location,
                    "create_time": item.get("createTime"),
                    "labels": item.get("labels", {}),
                    "replication": repl_type,
                    "versions": [],
                    "version_count": 0,
                }

                # Get versions if requested
                if include_versions:
                    # Pass location for regional endpoint access
                    versions = _fetch_secret_versions(headers, full_name, secret_location if secret_location != "global" else None)
                    secret_data["versions"] = versions
                    secret_data["version_count"] = len(versions)

                secrets.append(secret_data)

            # Only log for global endpoint or when secrets found
            if len(items) > 0:
                location_str = f" in {location}" if location else " (global)"
                console.print(f"[dim]Found {len(items)} secret(s){location_str}[/dim]")

            # Check for more pages
            page_token = data.get("nextPageToken")
            if not page_token:
                break

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Request error: {str(e)}[/red]")
            break

    return secrets


def _fetch_secret_versions(
    headers: Dict[str, str],
    secret_name: str,
    location: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch versions for a specific secret.

    Args:
        headers: Authorization headers
        secret_name: Full secret name (projects/.../secrets/...)
        location: GCP region if this is a regional secret

    Returns:
        List of version dictionaries
    """
    versions: List[Dict[str, Any]] = []

    # Build URL based on location
    if location:
        # Regional endpoint
        base_url = f"https://secretmanager.{location}.rep.googleapis.com/v1"
        url = f"{base_url}/{secret_name}/versions"
    else:
        # Global endpoint
        url = f"{SECRET_API_BASE}/{secret_name}/versions"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            return []

        data = response.json()
        items = data.get("versions", [])

        for item in items:
            # Parse version name
            # Format: projects/{project}/secrets/{secret}/versions/{version_id}
            name_parts = item.get("name", "").split("/")
            version_id = name_parts[-1] if name_parts else "unknown"

            version_data = {
                "version_id": version_id,
                "full_name": item.get("name"),
                "create_time": item.get("createTime"),
                "state": item.get("state", "ENABLED"),
            }
            versions.append(version_data)

    except Exception:
        pass

    return versions


def _display_secrets_table(
    secrets: List[Dict[str, Any]],
    project_id: str,
) -> None:
    """Display secrets in a Rich table."""
    if not secrets:
        console.print(f"[yellow]No secrets found in project '{project_id}'.[/yellow]")
        return

    table = Table(title=f"Secret Manager - {project_id} ({len(secrets)} secrets)", expand=True)
    table.add_column("Name", style="green", no_wrap=False)
    table.add_column("Location", style="yellow", no_wrap=False)
    table.add_column("Replication", style="dim", no_wrap=False)
    table.add_column("Versions", style="cyan", justify="right")
    table.add_column("Created", no_wrap=False)
    table.add_column("Labels", style="dim", no_wrap=False)

    for secret in secrets:
        # Format create time
        created = secret.get("create_time", "")
        if created:
            created = created.split("T")[0] if "T" in created else created

        # Format labels
        labels = secret.get("labels", {})
        labels_str = ", ".join(f"{k}={v}" for k, v in labels.items()) if labels else "-"

        # Version count
        version_count = secret.get("version_count", len(secret.get("versions", [])))

        # Location
        location = secret.get("location", "global")

        table.add_row(
            secret["name"],
            location,
            secret.get("replication", "AUTOMATIC"),
            str(version_count),
            created,
            labels_str,
        )

    console.print(table)

    # Show versions detail if available
    secrets_with_versions = [s for s in secrets if s.get("versions")]
    if secrets_with_versions:
        console.print("\n[bold]Secret Versions Detail:[/bold]")
        console.print("[dim]Showing all versions including old/disabled versions[/dim]\n")

        for secret in secrets_with_versions:
            versions = secret.get("versions", [])
            if not versions:
                continue

            # Group by state
            enabled = [v for v in versions if v.get("state") == "ENABLED"]
            disabled = [v for v in versions if v.get("state") == "DISABLED"]
            destroyed = [v for v in versions if v.get("state") == "DESTROYED"]

            console.print(f"  [cyan]{secret['name']}[/cyan] [dim]({secret.get('location', 'global')})[/dim]")

            # Show enabled versions
            if enabled:
                console.print(f"    [bold green]ENABLED ({len(enabled)}):[/bold green]")
                for v in enabled:
                    created = v.get('create_time', '')[:19] if v.get('create_time') else ''
                    console.print(f"      • v{v['version_id']} - {created}")

            # Show disabled versions
            if disabled:
                console.print(f"    [bold yellow]DISABLED ({len(disabled)}):[/bold yellow]")
                for v in disabled:
                    created = v.get('create_time', '')[:19] if v.get('create_time') else ''
                    console.print(f"      • v{v['version_id']} - {created}")

            # Show destroyed versions
            if destroyed:
                console.print(f"    [bold red]DESTROYED ({len(destroyed)}):[/bold red]")
                for v in destroyed:
                    created = v.get('create_time', '')[:19] if v.get('create_time') else ''
                    console.print(f"      • v{v['version_id']} - {created}")

            console.print("")  # Blank line between secrets

    console.print(f"[dim]Use 'exfil_secrets {project_id}' to extract secret values.[/dim]")
