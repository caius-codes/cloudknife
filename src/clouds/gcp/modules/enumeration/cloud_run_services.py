"""
GCP Cloud Run Services Enumeration for Cloud Knife.

Enumerates Cloud Run services across projects and regions, including:
- Service URLs and status
- Container images
- Service accounts
- Environment variables (may contain sensitive data like API keys, passwords)
- IAM policies (public/private access)
- Resource limits and scaling configuration
"""

from typing import List, Dict, Any, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from google.cloud import run_v2

from src.clouds.gcp.utils.projects import resolve_projects

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()


def enumerate_cloud_run_services(session_mgr: "GCPSessionManager") -> List[Dict[str, Any]]:
    """
    Enumerate all Cloud Run services across configured projects.

    Uses the wildcard location '-' to automatically enumerate all regions,
    matching the behavior of 'gcloud run services list'.

    Args:
        session_mgr: GCP session manager with valid credentials

    Returns:
        List of service dictionaries with detailed metadata
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    projects = resolve_projects(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return []

    # Create shared services client
    services_client = run_v2.ServicesClient(credentials=credentials)

    console.print(f"[cyan]Enumerating Cloud Run services in {len(projects)} project(s) across all regions...[/cyan]")

    all_services: List[Dict[str, Any]] = []

    # Parallel execution with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task_id = progress.add_task(f"Scanning {len(projects)} project(s)...", total=None)

        # Use ThreadPoolExecutor for parallel API calls
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all tasks (one per project, using wildcard location)
            future_to_project = {
                executor.submit(_enumerate_project, services_client, project): project
                for project in projects
            }

            # Collect results as they complete
            for future in as_completed(future_to_project):
                project = future_to_project[future]
                try:
                    services = future.result()
                    if services:
                        console.print(f"[dim]  ✓ {project}: found {len(services)} service(s)[/dim]")
                    all_services.extend(services)
                except Exception as e:
                    # Log error with context
                    error_msg = str(e)
                    if "Permission denied" not in error_msg and "403" not in error_msg:
                        console.print(f"[yellow]⚠️  {project}: {error_msg[:100]}[/yellow]")

        progress.update(task_id, completed=True)

    # Save enumeration results
    session_mgr.save_enumeration_data("cloud_run_services", all_services)

    # Display results table
    _display_services_table(all_services)

    return all_services


def _enumerate_project(
    services_client: run_v2.ServicesClient,
    project: str
) -> List[Dict[str, Any]]:
    """
    Enumerate Cloud Run services across all regions in a project (worker function for parallel execution).

    Uses the wildcard location '-' to automatically enumerate all regions,
    matching the behavior of 'gcloud run services list'.

    Args:
        services_client: Shared ServicesClient
        project: GCP project ID

    Returns:
        List of service dictionaries for all regions in this project
    """
    project_services: List[Dict[str, Any]] = []

    try:
        # Use wildcard location '-' to enumerate all regions
        parent = f"projects/{project}/locations/-"
        request = run_v2.ListServicesRequest(parent=parent)

        for service in services_client.list_services(request=request):
            # Extract region from full service name
            # Format: projects/{project}/locations/{region}/services/{service}
            name_parts = service.name.split("/")
            region = name_parts[3] if len(name_parts) > 3 else "unknown"

            # Extract service account
            service_account = None
            if service.template and service.template.service_account:
                service_account = service.template.service_account

            # Extract environment variables (MAY CONTAIN SENSITIVE DATA)
            env_vars = {}
            if service.template and service.template.containers:
                for container in service.template.containers:
                    for env in container.env:
                        env_vars[env.name] = env.value if env.value else f"<secret:{env.value_source}>"

            # Extract container image
            container_image = None
            if service.template and service.template.containers:
                container_image = service.template.containers[0].image

            # Check if service is public (unauthenticated access)
            is_public = False
            if hasattr(service, 'ingress') and service.ingress:
                # INGRESS_TRAFFIC_ALL means public
                is_public = service.ingress == run_v2.IngressTraffic.INGRESS_TRAFFIC_ALL

            # Build service record
            service_data = {
                "project": project,
                "region": region,
                "name": service.name.split("/")[-1],
                "full_name": service.name,
                "uri": service.uri,
                "description": service.description or "",
                "service_account": service_account,
                "container_image": container_image,
                "env_vars": env_vars,
                "is_public": is_public,
                "latest_ready_revision": service.latest_ready_revision,
                "latest_created_revision": service.latest_created_revision,
                "traffic": [{"revision": t.revision, "percent": t.percent} for t in service.traffic],
                "create_time": str(service.create_time) if service.create_time else "",
                "update_time": str(service.update_time) if service.update_time else "",
                "labels": dict(service.labels) if service.labels else {},
            }

            project_services.append(service_data)

    except Exception as e:
        # Re-raise with context for better error messages
        error_str = str(e).lower()
        if "permission denied" in error_str or "403" in error_str:
            # Silently skip - common for projects without permission
            pass
        else:
            raise Exception(f"Error enumerating {project}: {str(e)}")

    return project_services


def describe_cloud_run_service(
    session_mgr: "GCPSessionManager",
    service_name: str = None,
    project_id: str = None,
    region: str = None,
) -> Dict[str, Any]:
    """
    Describe a specific Cloud Run service in detail, including environment variables.

    This is particularly useful for finding sensitive information in:
    - Environment variables (API keys, passwords, tokens, database URLs)
    - Service configuration (service account, ingress settings)
    - Container images and configurations

    Args:
        session_mgr: GCP session manager with valid credentials
        service_name: Name of the service to describe
        project_id: GCP project ID (optional, uses default if not provided)
        region: GCP region (optional, will search if not provided)

    Returns:
        Dictionary with detailed service information
    """
    from rich.prompt import Prompt
    from rich.panel import Panel
    from rich.json import JSON
    import json

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return {}

    # Get project
    if not project_id:
        project_id = session_mgr.default_project
        if not project_id:
            project_id = Prompt.ask("[cyan]Project ID[/cyan]")

    # Get service name
    if not service_name:
        # Try to load from enumeration cache
        session_name = session_mgr.current_session
        enumerated_services = (
            session_mgr.enumerated_data.get(session_name, {})
            .get("cloud_run_services", [])
            if session_name in session_mgr.enumerated_data
            else []
        )

        if enumerated_services:
            console.print(f"[green]Found {len(enumerated_services)} Cloud Run services in enumeration cache.[/green]")
            console.print("\n[bold]Available services:[/bold]")
            for idx, svc in enumerate(enumerated_services, 1):
                public_marker = "🌐" if svc["is_public"] else "🔒"
                env_marker = f" ({len(svc['env_vars'])} env vars)" if svc["env_vars"] else ""
                console.print(f"  [{idx}] {svc['name']} ({svc['project']}/{svc['region']}) {public_marker}{env_marker}")

            choice = Prompt.ask(
                "[cyan]Select service number or enter service name[/cyan]",
                default="1"
            )

            try:
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(enumerated_services):
                    selected = enumerated_services[choice_idx]
                    service_name = selected["name"]
                    project_id = selected["project"]
                    region = selected["region"]
                else:
                    service_name = choice
            except ValueError:
                service_name = choice
        else:
            service_name = Prompt.ask("[cyan]Service name[/cyan]")

    # Get region if not provided
    if not region:
        # Try to find region from enumeration cache
        session_name = session_mgr.current_session
        enumerated_services = (
            session_mgr.enumerated_data.get(session_name, {})
            .get("cloud_run_services", [])
            if session_name in session_mgr.enumerated_data
            else []
        )

        found_region = None
        for svc in enumerated_services:
            if svc["name"] == service_name and svc["project"] == project_id:
                found_region = svc["region"]
                break

        if found_region:
            region = found_region
            console.print(f"[dim]Found service in region: {region}[/dim]")
        else:
            region = Prompt.ask("[cyan]Region (e.g., us-central1)[/cyan]")

    console.print(f"\n[bold blue]🔍 Describing Cloud Run Service: {service_name}[/bold blue]")
    console.print(f"[dim]Project: {project_id}[/dim]")
    console.print(f"[dim]Region: {region}[/dim]\n")

    # Get service details
    services_client = run_v2.ServicesClient(credentials=credentials)

    try:
        request = run_v2.GetServiceRequest(
            name=f"projects/{project_id}/locations/{region}/services/{service_name}"
        )

        service = services_client.get_service(request=request)

        # Extract service account
        service_account = None
        if service.template and service.template.service_account:
            service_account = service.template.service_account

        # Extract environment variables
        env_vars = {}
        if service.template and service.template.containers:
            for container in service.template.containers:
                for env in container.env:
                    env_vars[env.name] = env.value if env.value else f"<secret:{env.value_source}>"

        # Extract container image
        container_image = None
        if service.template and service.template.containers:
            container_image = service.template.containers[0].image

        # Check if service is public
        is_public = False
        if hasattr(service, 'ingress') and service.ingress:
            is_public = service.ingress == run_v2.IngressTraffic.INGRESS_TRAFFIC_ALL

        # Build service info
        service_info = {
            "name": service_name,
            "project": project_id,
            "region": region,
            "uri": service.uri,
            "description": service.description or "",
            "service_account": service_account,
            "container_image": container_image,
            "env_vars": env_vars,
            "is_public": is_public,
            "latest_ready_revision": service.latest_ready_revision,
            "latest_created_revision": service.latest_created_revision,
            "create_time": str(service.create_time) if service.create_time else "",
            "update_time": str(service.update_time) if service.update_time else "",
            "labels": dict(service.labels) if service.labels else {},
        }

        # Display basic info
        console.print("[bold]Basic Information:[/bold]")
        console.print(f"  [cyan]Name:[/cyan] {service_name}")
        console.print(f"  [cyan]URL:[/cyan] {service.uri}")
        console.print(f"  [cyan]Description:[/cyan] {service.description or '-'}")

        # Public/Private status
        public_status = "🌐 PUBLIC" if is_public else "🔒 Private"
        public_color = "red" if is_public else "green"
        console.print(f"  [cyan]Access:[/cyan] [{public_color}]{public_status}[/{public_color}]")

        if is_public:
            console.print(f"  [bold red]⚠️  WARNING: Service is publicly accessible without authentication![/bold red]")

        console.print(f"  [cyan]Created:[/cyan] {service.create_time or 'N/A'}")
        console.print(f"  [cyan]Updated:[/cyan] {service.update_time or 'N/A'}")

        # Container info
        console.print("\n[bold]Container Configuration:[/bold]")
        console.print(f"  [cyan]Image:[/cyan] {container_image or 'N/A'}")
        console.print(f"  [cyan]Service Account:[/cyan] {service_account or 'N/A'}")

        # Revisions
        console.print("\n[bold]Revisions:[/bold]")
        console.print(f"  [cyan]Latest Ready:[/cyan] {service.latest_ready_revision or 'N/A'}")
        console.print(f"  [cyan]Latest Created:[/cyan] {service.latest_created_revision or 'N/A'}")

        # Traffic
        if service.traffic:
            console.print("\n[bold]Traffic Distribution:[/bold]")
            for t in service.traffic:
                console.print(f"  • {t.revision}: {t.percent}%")

        # Environment Variables - THIS IS THE IMPORTANT PART
        console.print("\n[bold yellow]⚠️  Environment Variables (may contain sensitive information):[/bold yellow]")
        if env_vars:
            sensitive_patterns = [
                "key", "secret", "password", "token", "api", "auth",
                "credential", "database", "db", "connection", "conn"
            ]

            for key, value in env_vars.items():
                # Check if key contains sensitive patterns
                key_lower = key.lower()
                is_sensitive = any(pattern in key_lower for pattern in sensitive_patterns)

                if is_sensitive:
                    console.print(f"\n  [bold red]🔥 {key}:[/bold red]")
                    console.print(f"    [yellow]{value}[/yellow]")
                else:
                    # Regular env var
                    console.print(f"  [cyan]{key}:[/cyan] {value}")
        else:
            console.print("  [dim]No environment variables found[/dim]")

        # Labels
        if service_info["labels"]:
            console.print("\n[bold]Labels:[/bold]")
            for key, value in service_info["labels"].items():
                console.print(f"  [cyan]{key}:[/cyan] {value}")

        # Display full JSON if requested
        show_full = Prompt.ask(
            "\n[cyan]Show full service JSON?[/cyan]",
            choices=["y", "n"],
            default="n"
        )

        if show_full.lower() == "y":
            # Convert service to dict for JSON display
            service_dict = {
                "name": service.name,
                "uri": service.uri,
                "description": service.description,
                "service_account": service_account,
                "container_image": container_image,
                "env_vars": env_vars,
                "is_public": is_public,
                "labels": service_info["labels"],
                "create_time": service_info["create_time"],
                "update_time": service_info["update_time"],
            }
            console.print(Panel(JSON(json.dumps(service_dict, indent=2)), title="Full Service Details"))

        # Save to session
        session_mgr.save_enumeration_data(f"service_describe_{service_name}", service_info)
        console.print(f"\n[green]Service details saved under key 'service_describe_{service_name}' in session data.[/green]")

        return service_info

    except Exception as e:
        console.print(f"[red]Error describing service: {e}[/red]")
        return {}


def _display_services_table(services: List[Dict[str, Any]]) -> None:
    """Display Cloud Run services in a Rich table."""
    if not services:
        console.print("[yellow]No Cloud Run services found.[/yellow]")
        return

    table = Table(title=f"Cloud Run Services ({len(services)} found)")
    table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Region", style="dim")
    table.add_column("Name", style="green", overflow="fold", no_wrap=False)
    table.add_column("Public", style="bold")
    table.add_column("URL", style="blue", overflow="fold", no_wrap=False)
    table.add_column("Service Account", overflow="fold", no_wrap=False)
    table.add_column("Env Vars", style="yellow")

    for svc in services:
        # Format public status
        public_status = "🌐 PUBLIC" if svc["is_public"] else "🔒 Private"
        public_color = "red" if svc["is_public"] else "green"

        # Show URL or "-"
        url = svc["uri"] or "-"

        # Show SA or "-"
        sa = svc["service_account"] or "-"

        # Count env vars
        env_count = len(svc["env_vars"])
        env_display = f"{env_count} vars" if env_count > 0 else "-"

        table.add_row(
            svc["project"],
            svc["region"],
            svc["name"],
            f"[{public_color}]{public_status}[/{public_color}]",
            url,
            sa,
            env_display,
        )

    console.print(table)

    # Warn if any public services found
    public_services = [s for s in services if s["is_public"]]
    if public_services:
        console.print(f"\n[bold red]⚠️  WARNING: {len(public_services)} public service(s) found![/bold red]")
        console.print("[dim]Public services are accessible without authentication.[/dim]")

    # Warn if env vars found
    services_with_env = [s for s in services if s["env_vars"]]
    if services_with_env:
        console.print(f"\n[bold yellow]⚠️  {len(services_with_env)} service(s) have environment variables[/bold yellow]")
        console.print("[dim]Use 'describe_cloud_run_service' to inspect environment variables for sensitive data.[/dim]")
