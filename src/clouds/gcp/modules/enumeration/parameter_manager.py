"""
GCP Parameter Manager Enumeration for Cloud Knife.

Enumerates parameters and their versions from Parameter Manager API.
Parameter Manager stores application configuration that may contain
sensitive data like API keys, connection strings, etc.

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

# Parameter Manager API base URL
PARAM_API_BASE = "https://parametermanager.googleapis.com/v1"


def enumerate_parameters(
    session_mgr: "GCPSessionManager",
    project_id: Optional[str] = None,
    include_versions: bool = True,
) -> List[Dict[str, Any]]:
    """
    Enumerate all parameters in a project from Parameter Manager.

    Args:
        session_mgr: GCP session manager with valid credentials
        project_id: Project ID to enumerate (defaults to current project)
        include_versions: Whether to enumerate versions for each parameter

    Returns:
        List of parameter dictionaries with metadata and versions
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

    console.print(f"[dim]Enumerating parameters in project: {project_id}[/dim]")

    auth_method = session_mgr.current_session_data.get("auth_method")
    all_parameters: List[Dict[str, Any]] = []

    try:
        if auth_method == "access_token":
            parameters = _enumerate_parameters_rest_api(
                session_mgr, project_id, include_versions
            )
        else:
            # For service_account/ADC, also use REST API since there's no
            # official Python client library for Parameter Manager yet
            parameters = _enumerate_parameters_with_credentials(
                session_mgr, project_id, include_versions, credentials
            )

        all_parameters.extend(parameters)

    except Exception as e:
        console.print(f"[red]Error enumerating parameters: {str(e)}[/red]")
        return []

    # Save enumeration results
    session_mgr.save_enumeration_data(f"parameters_{project_id}", all_parameters)

    # Display results
    _display_parameters_table(all_parameters, project_id)

    return all_parameters


def _enumerate_parameters_rest_api(
    session_mgr: "GCPSessionManager",
    project_id: str,
    include_versions: bool,
) -> List[Dict[str, Any]]:
    """Enumerate parameters using REST API with access_token."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return []

    headers = {"Authorization": f"Bearer {token}"}
    return _fetch_parameters(headers, project_id, include_versions)


def _enumerate_parameters_with_credentials(
    session_mgr: "GCPSessionManager",
    project_id: str,
    include_versions: bool,
    credentials,
) -> List[Dict[str, Any]]:
    """Enumerate parameters using service account/ADC credentials."""
    # Get access token from credentials
    from google.auth.transport.requests import Request
    credentials.refresh(Request())
    token = credentials.token

    headers = {"Authorization": f"Bearer {token}"}
    return _fetch_parameters(headers, project_id, include_versions)


def _fetch_parameters(
    headers: Dict[str, str],
    project_id: str,
    include_versions: bool,
) -> List[Dict[str, Any]]:
    """Fetch parameters from the API."""
    parameters: List[Dict[str, Any]] = []

    # List all locations first, then parameters in each location
    # Using "-" as location lists across all locations
    url = f"{PARAM_API_BASE}/projects/{project_id}/locations/-/parameters"
    page_token = None

    while True:
        params = {"pageSize": 100}
        if page_token:
            params["pageToken"] = page_token

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 404:
                console.print("[yellow]Parameter Manager API not enabled or no parameters found.[/yellow]")
                return []
            elif response.status_code == 403:
                console.print("[red]Access denied to Parameter Manager API.[/red]")
                return []
            elif response.status_code != 200:
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
            items = data.get("parameters", [])

            for item in items:
                # Parse parameter name to extract location
                # Format: projects/{project}/locations/{location}/parameters/{name}
                name_parts = item.get("name", "").split("/")
                param_name = name_parts[-1] if name_parts else "unknown"
                location = name_parts[3] if len(name_parts) > 3 else "unknown"

                # Handle format field (can be dict or string)
                format_field = item.get("format", {})
                if isinstance(format_field, dict):
                    format_type = format_field.get("type", "UNFORMATTED")
                else:
                    format_type = str(format_field) if format_field else "UNFORMATTED"

                param_data = {
                    "name": param_name,
                    "full_name": item.get("name"),
                    "project": project_id,
                    "location": location,
                    "create_time": item.get("createTime"),
                    "update_time": item.get("updateTime"),
                    "labels": item.get("labels", {}),
                    "format": format_type,
                    "versions": [],
                }

                # Get versions if requested
                if include_versions:
                    versions = _fetch_parameter_versions(headers, item.get("name"))
                    param_data["versions"] = versions
                    param_data["version_count"] = len(versions)

                parameters.append(param_data)

            console.print(f"[dim]Found {len(items)} parameters...[/dim]")

            # Check for more pages
            page_token = data.get("nextPageToken")
            if not page_token:
                break

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Request error: {str(e)}[/red]")
            break

    return parameters


def _fetch_parameter_versions(
    headers: Dict[str, str],
    parameter_name: str,
) -> List[Dict[str, Any]]:
    """Fetch versions for a specific parameter."""
    versions: List[Dict[str, Any]] = []

    url = f"{PARAM_API_BASE}/{parameter_name}/versions"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            return []

        data = response.json()
        items = data.get("parameterVersions", [])

        for item in items:
            # Parse version name
            name_parts = item.get("name", "").split("/")
            version_id = name_parts[-1] if name_parts else "unknown"

            version_data = {
                "version_id": version_id,
                "full_name": item.get("name"),
                "create_time": item.get("createTime"),
                "update_time": item.get("updateTime"),
                "disabled": item.get("disabled", False),
            }
            versions.append(version_data)

    except Exception:
        pass

    return versions


def _display_parameters_table(
    parameters: List[Dict[str, Any]],
    project_id: str,
) -> None:
    """Display parameters in a Rich table."""
    if not parameters:
        console.print(f"[yellow]No parameters found in project '{project_id}'.[/yellow]")
        return

    table = Table(title=f"Parameter Manager - {project_id} ({len(parameters)} parameters)")
    table.add_column("Name", style="green", overflow="fold", no_wrap=False)
    table.add_column("Location", style="dim")
    table.add_column("Format")
    table.add_column("Versions", style="cyan", justify="right")
    table.add_column("Updated")
    table.add_column("Labels", style="dim", overflow="fold", no_wrap=False)

    for param in parameters:
        # Format update time
        updated = param.get("update_time", "")
        if updated:
            updated = updated.split("T")[0] if "T" in updated else updated

        # Format labels
        labels = param.get("labels", {})
        labels_str = ", ".join(f"{k}={v}" for k, v in labels.items()) if labels else "-"

        # Version count
        version_count = param.get("version_count", len(param.get("versions", [])))

        table.add_row(
            param["name"],
            param.get("location", "-"),
            param.get("format", "UNFORMATTED"),
            str(version_count),
            updated,
            labels_str,
        )

    console.print(table)

    # Show versions detail if available
    params_with_versions = [p for p in parameters if p.get("versions")]
    if params_with_versions:
        console.print("\n[bold]Parameter Versions:[/bold]")
        for param in params_with_versions[:10]:  # Limit to first 10
            versions = param.get("versions", [])
            active_versions = [v for v in versions if not v.get("disabled")]
            disabled_versions = [v for v in versions if v.get("disabled")]

            console.print(f"\n  [cyan]{param['name']}[/cyan] ({param.get('location', '-')})")
            for v in active_versions[:5]:
                console.print(f"    [green]v{v['version_id']}[/green] - {v.get('create_time', '')[:10]}")
            if disabled_versions:
                console.print(f"    [dim]+ {len(disabled_versions)} disabled version(s)[/dim]")
            if len(active_versions) > 5:
                console.print(f"    [dim]+ {len(active_versions) - 5} more version(s)[/dim]")

        if len(params_with_versions) > 10:
            console.print(f"\n[dim]... and {len(params_with_versions) - 10} more parameters with versions[/dim]")

    console.print(f"\n[dim]Use 'exfil_parameters {project_id}' to extract parameter values.[/dim]")
