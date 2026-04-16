"""
GCP Cloud Functions Enumeration for Cloud Knife.

Enumerates all Cloud Functions across projects and regions, including:
- Function metadata (name, runtime, entry point)
- Trigger type (HTTP, Pub/Sub, Cloud Storage, etc.)
- Service account attached
- Environment variables
- Network configuration
- Build configuration

Supports both Cloud Functions v1 (Gen 1) and v2 (Gen 2).
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING

import requests
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()


def enumerate_cloud_functions(
    session_mgr: "GCPSessionManager",
    generation: str = "all",
) -> List[Dict[str, Any]]:
    """
    Enumerate all Cloud Functions across configured projects.

    Automatically uses REST API for access_token auth and client library
    for service account/ADC auth.

    Args:
        session_mgr: GCP session manager with valid credentials
        generation: "v1" for Gen 1 only, "v2" for Gen 2 only, "all" for both

    Returns:
        List of function dictionaries with detailed metadata
    """
    auth_method = session_mgr.current_session_data.get("auth_method")

    # Validate credentials based on auth method
    if auth_method == "access_token":
        token = session_mgr.current_session_data.get("access_token")
        if not token:
            console.print("[red]No access token configured. Use 'set_token' first.[/red]")
            return []
    else:
        credentials = session_mgr.get_credentials()
        if not credentials:
            console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
            return []

    # Get projects to enumerate
    projects = _resolve_projects_for_functions(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return []

    all_functions: List[Dict[str, Any]] = []

    for project in projects:
        console.print(f"[dim]Scanning project: {project}[/dim]")

        # Enumerate Gen 1 functions (v1 API)
        if generation in ("all", "v1"):
            if auth_method == "access_token":
                v1_functions = _enumerate_v1_rest_api(session_mgr, project)
            else:
                v1_functions = _enumerate_v1_client_lib(session_mgr, project)
            all_functions.extend(v1_functions)

        # Enumerate Gen 2 functions (v2 API)
        if generation in ("all", "v2"):
            if auth_method == "access_token":
                v2_functions = _enumerate_v2_rest_api(session_mgr, project)
            else:
                v2_functions = _enumerate_v2_client_lib(session_mgr, project)
            all_functions.extend(v2_functions)

    # Save enumeration results
    session_mgr.save_enumeration_data("cloud_functions", all_functions)

    # Display results table
    _display_functions_table(all_functions)

    return all_functions


def _resolve_projects_for_functions(session_mgr: "GCPSessionManager") -> List[str]:
    """Resolve projects to enumerate, handling access_token auth specially."""
    # Check for explicitly configured projects
    configured = session_mgr.configured_projects
    if configured:
        return configured

    # For access_token, we can't easily discover projects, use default
    auth_method = session_mgr.current_session_data.get("auth_method")
    if auth_method == "access_token":
        default = session_mgr.default_project
        return [default] if default else []

    # Try to auto-discover accessible projects
    discovered = session_mgr.discover_accessible_projects()
    if discovered:
        return discovered

    # Fall back to default project
    default = session_mgr.default_project
    return [default] if default else []


def _enumerate_v1_rest_api(
    session_mgr: "GCPSessionManager",
    project_id: str,
) -> List[Dict[str, Any]]:
    """Enumerate Gen 1 Cloud Functions using REST API (for access_token auth)."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return []

    functions = []
    url = f"https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/-/functions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            result = response.json()
            for func in result.get("functions", []):
                functions.append(_parse_v1_function(func, project_id))
        elif response.status_code == 403:
            console.print(f"[dim]  Gen 1: Permission denied for {project_id}[/dim]")
        elif response.status_code == 404:
            console.print(f"[dim]  Gen 1: Cloud Functions API not enabled for {project_id}[/dim]")

    except requests.RequestException as e:
        console.print(f"[dim]  Gen 1 API error: {e}[/dim]")

    if functions:
        console.print(f"[dim]  Gen 1: Found {len(functions)} function(s)[/dim]")

    return functions


def _enumerate_v1_client_lib(
    session_mgr: "GCPSessionManager",
    project_id: str,
) -> List[Dict[str, Any]]:
    """Enumerate Gen 1 Cloud Functions using client library."""
    try:
        from google.cloud import functions_v1
    except ImportError:
        console.print("[yellow]google-cloud-functions not installed. Using REST API.[/yellow]")
        return _enumerate_v1_rest_api(session_mgr, project_id)

    credentials = session_mgr.get_credentials()
    if not credentials:
        return []

    functions = []

    try:
        client = functions_v1.CloudFunctionsServiceClient(credentials=credentials)
        parent = f"projects/{project_id}/locations/-"

        for func in client.list_functions(parent=parent):
            func_data = {
                "project": project_id,
                "generation": "v1",
                "name": func.name.split("/")[-1],
                "full_name": func.name,
                "location": func.name.split("/")[3] if "/" in func.name else "unknown",
                "runtime": func.runtime,
                "entry_point": func.entry_point,
                "status": func.status.name if hasattr(func.status, "name") else str(func.status),
                "trigger_type": _get_v1_trigger_type(func),
                "trigger_url": func.https_trigger.url if func.https_trigger else None,
                "service_account": func.service_account_email,
                "available_memory_mb": func.available_memory_mb,
                "timeout": func.timeout.seconds if func.timeout else None,
                "vpc_connector": func.vpc_connector,
                "ingress_settings": func.ingress_settings.name if hasattr(func.ingress_settings, "name") else str(func.ingress_settings),
                "environment_variables": dict(func.environment_variables) if func.environment_variables else {},
                "build_environment_variables": dict(func.build_environment_variables) if func.build_environment_variables else {},
                "labels": dict(func.labels) if func.labels else {},
                "update_time": func.update_time.isoformat() if func.update_time else None,
            }
            functions.append(func_data)

    except Exception as e:
        error_str = str(e).lower()
        if "permission" in error_str or "403" in error_str:
            console.print(f"[dim]  Gen 1: Permission denied for {project_id}[/dim]")
        elif "not enabled" in error_str or "404" in error_str:
            console.print(f"[dim]  Gen 1: Cloud Functions API not enabled for {project_id}[/dim]")
        else:
            console.print(f"[dim]  Gen 1 error: {e}[/dim]")

    if functions:
        console.print(f"[dim]  Gen 1: Found {len(functions)} function(s)[/dim]")

    return functions


def _enumerate_v2_rest_api(
    session_mgr: "GCPSessionManager",
    project_id: str,
) -> List[Dict[str, Any]]:
    """Enumerate Gen 2 Cloud Functions using REST API (for access_token auth)."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return []

    functions = []
    url = f"https://cloudfunctions.googleapis.com/v2/projects/{project_id}/locations/-/functions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            result = response.json()
            for func in result.get("functions", []):
                functions.append(_parse_v2_function(func, project_id))
        elif response.status_code == 403:
            console.print(f"[dim]  Gen 2: Permission denied for {project_id}[/dim]")
        elif response.status_code == 404:
            console.print(f"[dim]  Gen 2: Cloud Functions v2 API not enabled for {project_id}[/dim]")

    except requests.RequestException as e:
        console.print(f"[dim]  Gen 2 API error: {e}[/dim]")

    if functions:
        console.print(f"[dim]  Gen 2: Found {len(functions)} function(s)[/dim]")

    return functions


def _enumerate_v2_client_lib(
    session_mgr: "GCPSessionManager",
    project_id: str,
) -> List[Dict[str, Any]]:
    """Enumerate Gen 2 Cloud Functions using client library."""
    try:
        from google.cloud import functions_v2
    except ImportError:
        console.print("[yellow]google-cloud-functions not installed. Using REST API.[/yellow]")
        return _enumerate_v2_rest_api(session_mgr, project_id)

    credentials = session_mgr.get_credentials()
    if not credentials:
        return []

    functions = []

    try:
        client = functions_v2.FunctionServiceClient(credentials=credentials)
        parent = f"projects/{project_id}/locations/-"

        for func in client.list_functions(parent=parent):
            func_data = {
                "project": project_id,
                "generation": "v2",
                "name": func.name.split("/")[-1],
                "full_name": func.name,
                "location": func.name.split("/")[3] if "/" in func.name else "unknown",
                "runtime": func.build_config.runtime if func.build_config else None,
                "entry_point": func.build_config.entry_point if func.build_config else None,
                "status": func.state.name if hasattr(func.state, "name") else str(func.state),
                "trigger_type": _get_v2_trigger_type(func),
                "trigger_url": func.service_config.uri if func.service_config else None,
                "service_account": func.service_config.service_account_email if func.service_config else None,
                "available_memory": func.service_config.available_memory if func.service_config else None,
                "timeout": func.service_config.timeout_seconds if func.service_config else None,
                "vpc_connector": func.service_config.vpc_connector if func.service_config else None,
                "ingress_settings": func.service_config.ingress_settings.name if func.service_config and hasattr(func.service_config.ingress_settings, "name") else None,
                "environment_variables": dict(func.service_config.environment_variables) if func.service_config and func.service_config.environment_variables else {},
                "labels": dict(func.labels) if func.labels else {},
                "update_time": func.update_time.isoformat() if func.update_time else None,
            }
            functions.append(func_data)

    except Exception as e:
        error_str = str(e).lower()
        if "permission" in error_str or "403" in error_str:
            console.print(f"[dim]  Gen 2: Permission denied for {project_id}[/dim]")
        elif "not enabled" in error_str or "404" in error_str:
            console.print(f"[dim]  Gen 2: Cloud Functions v2 API not enabled for {project_id}[/dim]")
        else:
            console.print(f"[dim]  Gen 2 error: {e}[/dim]")

    if functions:
        console.print(f"[dim]  Gen 2: Found {len(functions)} function(s)[/dim]")

    return functions


def _parse_v1_function(func: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    """Parse a Gen 1 function from REST API response."""
    name = func.get("name", "")
    parts = name.split("/")

    # Determine trigger type
    trigger_type = "unknown"
    trigger_url = None
    if func.get("httpsTrigger"):
        trigger_type = "HTTP"
        trigger_url = func["httpsTrigger"].get("url")
    elif func.get("eventTrigger"):
        event_type = func["eventTrigger"].get("eventType", "")
        if "storage" in event_type.lower():
            trigger_type = "Cloud Storage"
        elif "pubsub" in event_type.lower():
            trigger_type = "Pub/Sub"
        elif "firestore" in event_type.lower():
            trigger_type = "Firestore"
        else:
            trigger_type = event_type.split(".")[-1] if "." in event_type else event_type

    return {
        "project": project_id,
        "generation": "v1",
        "name": parts[-1] if parts else name,
        "full_name": name,
        "location": parts[3] if len(parts) > 3 else "unknown",
        "runtime": func.get("runtime"),
        "entry_point": func.get("entryPoint"),
        "status": func.get("status", "UNKNOWN"),
        "trigger_type": trigger_type,
        "trigger_url": trigger_url,
        "service_account": func.get("serviceAccountEmail"),
        "available_memory_mb": func.get("availableMemoryMb"),
        "timeout": func.get("timeout", "").replace("s", "") if func.get("timeout") else None,
        "vpc_connector": func.get("vpcConnector"),
        "ingress_settings": func.get("ingressSettings"),
        "environment_variables": func.get("environmentVariables", {}),
        "build_environment_variables": func.get("buildEnvironmentVariables", {}),
        "labels": func.get("labels", {}),
        "update_time": func.get("updateTime"),
    }


def _parse_v2_function(func: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    """Parse a Gen 2 function from REST API response."""
    name = func.get("name", "")
    parts = name.split("/")

    build_config = func.get("buildConfig", {})
    service_config = func.get("serviceConfig", {})

    # Determine trigger type
    trigger_type = "unknown"
    trigger_url = service_config.get("uri")
    event_trigger = func.get("eventTrigger")
    if event_trigger:
        event_type = event_trigger.get("eventType", "")
        if "storage" in event_type.lower():
            trigger_type = "Cloud Storage"
        elif "pubsub" in event_type.lower():
            trigger_type = "Pub/Sub"
        elif "firestore" in event_type.lower():
            trigger_type = "Firestore"
        elif "audit" in event_type.lower():
            trigger_type = "Audit Log"
        else:
            trigger_type = event_type.split(".")[-1] if "." in event_type else event_type
    elif trigger_url:
        trigger_type = "HTTP"

    return {
        "project": project_id,
        "generation": "v2",
        "name": parts[-1] if parts else name,
        "full_name": name,
        "location": parts[3] if len(parts) > 3 else "unknown",
        "runtime": build_config.get("runtime"),
        "entry_point": build_config.get("entryPoint"),
        "status": func.get("state", "UNKNOWN"),
        "trigger_type": trigger_type,
        "trigger_url": trigger_url,
        "service_account": service_config.get("serviceAccountEmail"),
        "available_memory": service_config.get("availableMemory"),
        "timeout": service_config.get("timeoutSeconds"),
        "vpc_connector": service_config.get("vpcConnector"),
        "ingress_settings": service_config.get("ingressSettings"),
        "environment_variables": service_config.get("environmentVariables", {}),
        "labels": func.get("labels", {}),
        "update_time": func.get("updateTime"),
    }


def _get_v1_trigger_type(func) -> str:
    """Get trigger type for a Gen 1 function from client library object."""
    if func.https_trigger and func.https_trigger.url:
        return "HTTP"
    if func.event_trigger:
        event_type = func.event_trigger.event_type or ""
        if "storage" in event_type.lower():
            return "Cloud Storage"
        elif "pubsub" in event_type.lower():
            return "Pub/Sub"
        elif "firestore" in event_type.lower():
            return "Firestore"
        else:
            return event_type.split(".")[-1] if "." in event_type else event_type
    return "unknown"


def _get_v2_trigger_type(func) -> str:
    """Get trigger type for a Gen 2 function from client library object."""
    if func.event_trigger:
        event_type = func.event_trigger.event_type or ""
        if "storage" in event_type.lower():
            return "Cloud Storage"
        elif "pubsub" in event_type.lower():
            return "Pub/Sub"
        elif "firestore" in event_type.lower():
            return "Firestore"
        elif "audit" in event_type.lower():
            return "Audit Log"
        else:
            return event_type.split(".")[-1] if "." in event_type else event_type
    if func.service_config and func.service_config.uri:
        return "HTTP"
    return "unknown"


def _display_functions_table(functions: List[Dict[str, Any]]) -> None:
    """Display functions in a Rich table."""
    if not functions:
        console.print("[yellow]No Cloud Functions found.[/yellow]")
        return

    table = Table(title=f"Cloud Functions ({len(functions)} found)")
    table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Gen", style="dim", justify="center")
    table.add_column("Location", style="dim")
    table.add_column("Name", style="green", overflow="fold", no_wrap=False)
    table.add_column("Runtime")
    table.add_column("Trigger", style="yellow", overflow="fold", no_wrap=False)
    table.add_column("Status", style="bold")
    table.add_column("Service Account", overflow="fold", no_wrap=False)

    for func in functions:
        # Format status with color
        status = func.get("status", "UNKNOWN")
        if status in ("ACTIVE", "READY"):
            status_styled = f"[green]{status}[/green]"
        elif status in ("FAILED", "OFFLINE"):
            status_styled = f"[red]{status}[/red]"
        else:
            status_styled = f"[yellow]{status}[/yellow]"

        # Format generation
        gen = func.get("generation", "?")
        gen_styled = f"[cyan]{gen}[/cyan]" if gen == "v2" else gen

        # Format trigger
        trigger = func.get("trigger_type", "unknown")
        if trigger == "HTTP":
            trigger_styled = f"[bold yellow]{trigger}[/bold yellow]"
        else:
            trigger_styled = trigger

        # Service account (no truncation)
        sa = func.get("service_account", "") or "-"

        table.add_row(
            func.get("project", ""),
            gen_styled,
            func.get("location", ""),
            func.get("name", ""),
            func.get("runtime", "-") or "-",
            trigger_styled,
            status_styled,
            sa,
        )

    console.print(table)

    # Show HTTP URLs separately
    http_functions = [f for f in functions if f.get("trigger_url")]
    if http_functions:
        console.print("\n[bold yellow]🌐 HTTP Trigger URLs:[/bold yellow]")
        for func in http_functions:
            console.print(f"  [green]{func['name']}[/green]: {func['trigger_url']}")

    # Show detailed configuration for each function
    console.print("\n[bold cyan]📋 Function Details:[/bold cyan]")
    for func in functions:
        console.print(f"\n[bold green]• {func['name']}[/bold green] ({func['generation']})")
        console.print(f"  [dim]Project:[/dim] {func['project']}")
        console.print(f"  [dim]Location:[/dim] {func['location']}")

        # Build & Runtime
        console.print(f"  [cyan]Runtime:[/cyan] {func.get('runtime', 'N/A')}")
        console.print(f"  [cyan]Entry Point:[/cyan] {func.get('entry_point', 'N/A')}")

        # Resources
        if func['generation'] == 'v1':
            memory = func.get('available_memory_mb')
            if memory:
                console.print(f"  [cyan]Memory:[/cyan] {memory} MB")
        else:
            memory = func.get('available_memory')
            if memory:
                console.print(f"  [cyan]Memory:[/cyan] {memory}")

        timeout = func.get('timeout')
        if timeout:
            console.print(f"  [cyan]Timeout:[/cyan] {timeout}s")

        # Network
        vpc = func.get('vpc_connector')
        if vpc:
            console.print(f"  [cyan]VPC Connector:[/cyan] {vpc}")

        ingress = func.get('ingress_settings')
        if ingress:
            console.print(f"  [cyan]Ingress:[/cyan] {ingress}")

        # Service Account
        sa = func.get('service_account')
        if sa:
            console.print(f"  [cyan]Service Account:[/cyan] {sa}")

        # Environment Variables
        env_vars = func.get('environment_variables', {})
        if env_vars:
            console.print(f"  [yellow]Environment Variables ({len(env_vars)}):[/yellow]")
            for key, value in sorted(env_vars.items()):
                # Highlight potentially sensitive keys
                key_lower = key.lower()
                if any(x in key_lower for x in ["key", "secret", "password", "token", "api", "credential"]):
                    console.print(f"    [red]🔑 {key}[/red] = [dim]{value}[/dim]")
                else:
                    console.print(f"    {key} = [dim]{value}[/dim]")

        # Build Environment Variables (Gen 1)
        build_env_vars = func.get('build_environment_variables', {})
        if build_env_vars:
            console.print(f"  [yellow]Build Environment Variables ({len(build_env_vars)}):[/yellow]")
            for key, value in sorted(build_env_vars.items()):
                console.print(f"    {key} = [dim]{value}[/dim]")

        # Labels
        labels = func.get('labels', {})
        if labels:
            console.print(f"  [dim]Labels:[/dim] {', '.join(f'{k}={v}' for k, v in sorted(labels.items()))}")

        # Update time
        update_time = func.get('update_time')
        if update_time:
            console.print(f"  [dim]Last Updated:[/dim] {update_time}")

    # Summary of potentially sensitive environment variables
    sensitive_vars = []
    for func in functions:
        env_vars = func.get('environment_variables', {})
        for key in env_vars:
            key_lower = key.lower()
            if any(x in key_lower for x in ["key", "secret", "password", "token", "api", "credential"]):
                sensitive_vars.append((func["name"], key, env_vars[key]))

    if sensitive_vars:
        console.print("\n[bold red]⚠️  Potentially Sensitive Environment Variables Summary:[/bold red]")
        for func_name, var_name, var_value in sensitive_vars:
            console.print(f"  [green]{func_name}[/green] → [red]{var_name}[/red] = [dim]{var_value}[/dim]")

    # Action Recommendations / Pentest Suggestions
    console.print("\n[bold cyan]💡 Pentest Recommendations & Next Steps:[/bold cyan]")

    # 1. HTTP Functions (unauthenticated access)
    public_http_functions = [f for f in functions if f.get("trigger_type") == "HTTP"]
    if public_http_functions:
        console.print(f"\n[bold yellow]🌐 HTTP Functions ({len(public_http_functions)} found):[/bold yellow]")
        console.print("  [dim]Actions:[/dim]")
        console.print("    • Test for unauthenticated access (functions may allow anonymous invocations)")
        console.print("    • Check IAM policy with: [cyan]gcloud functions get-iam-policy <function_name>[/cyan]")
        console.print("    • Look for allUsers or allAuthenticatedUsers bindings (public access)")
        console.print("    • Test HTTP endpoints for vulnerabilities (SSRF, injection, etc.)")
        console.print("    • Fuzz parameters to discover hidden functionality")
        for func in public_http_functions[:3]:  # Show top 3
            console.print(f"      → Try: [green]curl {func.get('trigger_url')}[/green]")

    # 2. Sensitive Environment Variables
    if sensitive_vars:
        console.print(f"\n[bold red]🔑 Functions with Sensitive Environment Variables ({len(set(x[0] for x in sensitive_vars))} functions):[/bold red]")
        console.print("  [dim]Actions:[/dim]")
        console.print("    • Extract credentials from environment variables shown above")
        console.print("    • Test if credentials are still valid")
        console.print("    • Use credentials for lateral movement (API keys, DB passwords, etc.)")
        console.print("    • Check if you can download function source code:")
        console.print("      [cyan]gcloud functions describe <function_name> --gen2[/cyan]")
        console.print("      [cyan]gcloud functions download <function_name> --region <region>[/cyan]")

    # 3. Service Accounts Analysis
    unique_service_accounts = set(f.get("service_account") for f in functions if f.get("service_account"))
    if unique_service_accounts:
        console.print(f"\n[bold magenta]👤 Service Accounts Used ({len(unique_service_accounts)} unique):[/bold magenta]")
        console.print("  [dim]Actions:[/dim]")
        console.print("    • Check service account permissions with [cyan]enumerate_exploitable_sas[/cyan]")
        console.print("    • Identify privileged service accounts that can be impersonated")
        console.print("    • If function has actAs/impersonate permissions, you can:")
        console.print("      [cyan]impersonate <service_account_email>[/cyan]")
        console.print("    • Download function code to find hardcoded credentials or secrets")
        for idx, sa in enumerate(list(unique_service_accounts)[:3], 1):
            console.print(f"      [{idx}] [yellow]{sa}[/yellow]")

    # 4. Ingress Settings (network security)
    restricted_ingress = [f for f in functions if f.get("ingress_settings") and "INTERNAL" in f.get("ingress_settings", "")]
    if restricted_ingress:
        console.print(f"\n[bold green]🔒 Functions with Restricted Ingress ({len(restricted_ingress)} found):[/bold green]")
        console.print("  [dim]Info:[/dim] These functions have ingress controls (INTERNAL_ONLY or INTERNAL_AND_GCLB)")
        console.print("  [dim]Actions:[/dim]")
        console.print("    • Check if you have VPC access or are inside the network perimeter")
        console.print("    • Look for ways to access internal networks (VPN, compromised instances)")
    else:
        console.print(f"\n[bold yellow]⚠️  No Ingress Restrictions Found:[/bold yellow]")
        console.print("  [dim]All functions may be accessible from the internet (if IAM allows)[/dim]")

    # 5. VPC Connectors (lateral movement potential)
    vpc_functions = [f for f in functions if f.get("vpc_connector")]
    if vpc_functions:
        console.print(f"\n[bold cyan]🌐 Functions with VPC Access ({len(vpc_functions)} found):[/bold cyan]")
        console.print("  [dim]Actions:[/dim]")
        console.print("    • These functions can access internal VPC resources")
        console.print("    • If you can invoke them, you can use them as a proxy to internal services")
        console.print("    • Test for SSRF vulnerabilities to access internal IPs/services")
        console.print("    • Potential to pivot to internal databases, APIs, etc.")

    # 6. Source Code Extraction
    console.print(f"\n[bold cyan]📦 Source Code Extraction:[/bold cyan]")
    console.print("  [dim]Steps to extract function source code:[/dim]")
    console.print("    [yellow]1. Describe function to get source location:[/yellow]")
    console.print("       [cyan]gcloud functions describe <name> --region <region> --format=json[/cyan]")
    console.print("    [yellow]2. For Gen 1 - Download from Cloud Storage:[/yellow]")
    console.print("       • Look for 'sourceArchiveUrl' in describe output (gs://...)")
    console.print("       • Download with: [cyan]gsutil cp <sourceArchiveUrl> ./function-source.zip[/cyan]")
    console.print("       • Extract: [cyan]unzip function-source.zip[/cyan]")
    console.print("    [yellow]3. For Gen 2 - Check build source:[/yellow]")
    console.print("       • Look for 'buildConfig.source' in describe output")
    console.print("       • May reference Cloud Source Repositories or GitHub")
    console.print("       • If CSR: [cyan]gcloud source repos clone <repo>[/cyan]")
    console.print("       • If GitHub: check 'repository' field in buildConfig")
    console.print("  [dim]What to look for in source code:[/dim]")
    console.print("    • Hardcoded API keys, passwords, tokens")
    console.print("    • Database connection strings")
    console.print("    • Internal endpoints and service URLs")
    console.print("    • Business logic vulnerabilities")
    console.print("    • Comments with sensitive information or TODOs")

    # 7. Common Misconfigurations
    console.print(f"\n[bold red]🚨 Common Misconfigurations to Check:[/bold red]")
    console.print("  1. [yellow]Public IAM Bindings:[/yellow]")
    console.print("     [cyan]gcloud functions get-iam-policy <function_name>[/cyan]")
    console.print("     → Look for: allUsers, allAuthenticatedUsers")
    console.print("  2. [yellow]Overprivileged Service Accounts:[/yellow]")
    console.print("     [cyan]enumerate_exploitable_sas[/cyan]")
    console.print("     → Check if function's SA has Owner/Editor or sensitive permissions")
    console.print("  3. [yellow]Source Code Leakage:[/yellow]")
    console.print("     → Functions may be deployed from public GitHub repos (check labels)")
    console.print("     → After downloading source, search for secrets:")
    console.print("       [cyan]grep -r -E '(password|api[_-]?key|secret|token)' .[/cyan]")
    console.print("       [cyan]grep -r -E '(sk_live|pk_live|AIza|ya29\\.)' .[/cyan]")
    console.print("  4. [yellow]Secrets in Environment Variables:[/yellow]")
    console.print("     → Already extracted above - use them!")

    # 8. Quick Commands Summary
    console.print(f"\n[bold green]⚡ Quick Commands:[/bold green]")
    if public_http_functions:
        example_func = public_http_functions[0]
        console.print(f"  • Test HTTP function: [cyan]curl {example_func.get('trigger_url')}[/cyan]")
        console.print(f"  • Check IAM: [cyan]gcloud functions get-iam-policy {example_func.get('name')} --region {example_func.get('location')}[/cyan]")
        console.print(f"  • Get source URL: [cyan]gcloud functions describe {example_func.get('name')} --region {example_func.get('location')} --format='value(sourceArchiveUrl)'[/cyan]")
    if unique_service_accounts:
        example_sa = list(unique_service_accounts)[0]
        console.print(f"  • Impersonate SA: [cyan]impersonate {example_sa}[/cyan]")
    console.print(f"  • Find exploitable SAs: [cyan]enumerate_exploitable_sas[/cyan]")
