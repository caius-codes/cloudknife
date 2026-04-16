"""
GCP Cloud SQL Instance Enumeration for Cloud Knife.

Enumerates all Cloud SQL instances across projects, including:
- Instance metadata (name, database type/version, tier, status)
- Connection details (IP addresses, SSL requirements)
- Databases and users
- Backup configuration
- Settings and flags
- Security: public IP detection, SSL enforcement

Supports MySQL, PostgreSQL, and SQL Server instances.
"""

from typing import List, Dict, Any, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from google.auth.transport.requests import Request
import requests

from src.clouds.gcp.utils.projects import resolve_projects

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# Cloud SQL Admin API base URL
SQLADMIN_API_BASE = "https://sqladmin.googleapis.com/v1"


def _make_api_request(credentials, url: str) -> Dict[str, Any]:
    """Make authenticated request to Cloud SQL Admin API."""
    # Ensure credentials are fresh
    if hasattr(credentials, 'expired') and credentials.expired:
        credentials.refresh(Request())

    if not hasattr(credentials, 'token'):
        credentials.refresh(Request())

    headers = {
        "Authorization": f"Bearer {credentials.token}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()


def _enumerate_databases(credentials, project: str, instance_name: str) -> List[str]:
    """Get list of databases for a SQL instance."""
    try:
        url = f"{SQLADMIN_API_BASE}/projects/{project}/instances/{instance_name}/databases"
        response = _make_api_request(credentials, url)
        databases = response.get("items", [])
        return [db.get("name", "") for db in databases]
    except Exception:
        return []


def _enumerate_users(credentials, project: str, instance_name: str) -> List[Dict[str, str]]:
    """Get list of users for a SQL instance."""
    try:
        url = f"{SQLADMIN_API_BASE}/projects/{project}/instances/{instance_name}/users"
        response = _make_api_request(credentials, url)
        users = response.get("items", [])
        return [
            {
                "name": user.get("name", ""),
                "host": user.get("host", ""),
                "type": user.get("type", "")
            }
            for user in users
        ]
    except Exception:
        return []


def _enumerate_project_instances(
    credentials,
    project: str
) -> List[Dict[str, Any]]:
    """Enumerate all Cloud SQL instances in a single project."""
    instances = []

    try:
        url = f"{SQLADMIN_API_BASE}/projects/{project}/instances"
        response = _make_api_request(credentials, url)

        for instance in response.get("items", []):
            instance_name = instance.get("name", "")

            # Basic metadata
            instance_data = {
                "project": project,
                "name": instance_name,
                "database_version": instance.get("databaseVersion", ""),
                "state": instance.get("state", ""),
                "tier": instance.get("settings", {}).get("tier", ""),
                "region": instance.get("region", ""),
                "gce_zone": instance.get("gceZone", ""),
                "self_link": instance.get("selfLink", ""),
            }

            # Extract database type from version (e.g., MYSQL_8_0 -> MySQL)
            db_version = instance_data["database_version"]
            if db_version.startswith("MYSQL"):
                instance_data["database_type"] = "MySQL"
            elif db_version.startswith("POSTGRES"):
                instance_data["database_type"] = "PostgreSQL"
            elif db_version.startswith("SQLSERVER"):
                instance_data["database_type"] = "SQL Server"
            else:
                instance_data["database_type"] = "Unknown"

            # Connection info
            ip_addresses = instance.get("ipAddresses", [])
            public_ips = [ip["ipAddress"] for ip in ip_addresses if ip.get("type") == "PRIMARY"]
            private_ips = [ip["ipAddress"] for ip in ip_addresses if ip.get("type") == "PRIVATE"]

            instance_data["public_ip"] = public_ips[0] if public_ips else None
            instance_data["private_ip"] = private_ips[0] if private_ips else None
            instance_data["has_public_ip"] = bool(public_ips)

            # Connection name for Cloud SQL Proxy
            instance_data["connection_name"] = instance.get("connectionName", "")

            # SSL/TLS configuration
            settings = instance.get("settings", {})
            ip_config = settings.get("ipConfiguration", {})
            instance_data["require_ssl"] = ip_config.get("requireSsl", False)
            instance_data["ssl_mode"] = ip_config.get("sslMode", "ALLOW_UNENCRYPTED_AND_ENCRYPTED")

            # Authorized networks (IP whitelist)
            authorized_networks = ip_config.get("authorizedNetworks", [])
            instance_data["authorized_networks"] = [
                {
                    "name": net.get("name", ""),
                    "value": net.get("value", "")
                }
                for net in authorized_networks
            ]
            instance_data["has_open_access"] = any(
                net.get("value") == "0.0.0.0/0" for net in authorized_networks
            )

            # Backup configuration
            backup_config = settings.get("backupConfiguration", {})
            instance_data["backup_enabled"] = backup_config.get("enabled", False)
            instance_data["binary_log_enabled"] = backup_config.get("binaryLogEnabled", False)
            instance_data["point_in_time_recovery"] = backup_config.get("pointInTimeRecoveryEnabled", False)

            # Maintenance window
            maintenance_window = settings.get("maintenanceWindow", {})
            instance_data["maintenance_day"] = maintenance_window.get("day", "")
            instance_data["maintenance_hour"] = maintenance_window.get("hour", "")

            # Storage
            instance_data["storage_type"] = settings.get("dataDiskType", "")
            instance_data["storage_size_gb"] = settings.get("dataDiskSizeGb", "")
            instance_data["storage_auto_resize"] = settings.get("storageAutoResize", False)

            # High availability
            instance_data["availability_type"] = settings.get("availabilityType", "ZONAL")

            # Database flags (configuration)
            database_flags = settings.get("databaseFlags", [])
            instance_data["database_flags"] = {
                flag.get("name"): flag.get("value")
                for flag in database_flags
            }

            # Service account (for IAM)
            instance_data["service_account_email"] = instance.get("serviceAccountEmailAddress", "")

            # Enumerate databases and users
            instance_data["databases"] = _enumerate_databases(credentials, project, instance_name)
            instance_data["users"] = _enumerate_users(credentials, project, instance_name)

            instances.append(instance_data)

    except Exception as e:
        error_msg = str(e)[:100]
        console.print(f"[dim red]Failed to enumerate SQL instances in {project}: {error_msg}[/dim red]")

    return instances


def enumerate_cloud_sql(session_mgr: "GCPSessionManager") -> List[Dict[str, Any]]:
    """
    Enumerate all Cloud SQL instances across configured projects.

    Collects comprehensive instance metadata including:
    - Database type/version (MySQL, PostgreSQL, SQL Server)
    - Connection details (public/private IPs, connection name)
    - Security settings (SSL requirements, authorized networks)
    - Backup configuration
    - Databases and users per instance
    - High availability and storage settings

    Args:
        session_mgr: GCP session manager with valid credentials

    Returns:
        List of Cloud SQL instance dictionaries with detailed metadata
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    projects = resolve_projects(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating Cloud SQL instances across {len(projects)} project(s)[/bold blue]\n")

    all_instances: List[Dict[str, Any]] = []

    # Parallel execution with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task("Enumerating Cloud SQL instances...", total=len(projects))

        # Use ThreadPoolExecutor for parallel API calls across projects
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_project = {
                executor.submit(_enumerate_project_instances, credentials, project): project
                for project in projects
            }

            for future in as_completed(future_to_project):
                project = future_to_project[future]
                try:
                    instances = future.result()
                    all_instances.extend(instances)
                except Exception as e:
                    console.print(f"[red]Error enumerating {project}: {str(e)[:100]}[/red]")
                finally:
                    progress.advance(task_id)

    # Save results
    session_mgr.save_enumeration_data("cloud_sql_instances", all_instances)

    if not all_instances:
        console.print("\n[yellow]No Cloud SQL instances found across accessible projects.[/yellow]")
        return all_instances

    # Display summary
    console.print(f"\n[bold green]✓ Found {len(all_instances)} Cloud SQL instance(s)[/bold green]\n")

    # Summary table
    table = Table(title=f"Cloud SQL Instances ({len(all_instances)} total)")
    table.add_column("Project", style="cyan", no_wrap=True)
    table.add_column("Instance", style="bold", no_wrap=True)
    table.add_column("DB Type", style="green")
    table.add_column("Version", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Public IP", style="yellow")
    table.add_column("Security", justify="center")

    # Count by database type
    mysql_count = sum(1 for i in all_instances if i["database_type"] == "MySQL")
    postgres_count = sum(1 for i in all_instances if i["database_type"] == "PostgreSQL")
    sqlserver_count = sum(1 for i in all_instances if i["database_type"] == "SQL Server")

    # Security issues
    public_instances = [i for i in all_instances if i["has_public_ip"]]
    no_ssl_required = [i for i in all_instances if not i["require_ssl"] and i["has_public_ip"]]
    open_access = [i for i in all_instances if i["has_open_access"]]

    for instance in all_instances[:50]:  # Limit display to first 50
        # Status color
        state = instance["state"]
        if state == "RUNNABLE":
            status_text = "[green]Running[/green]"
        elif state == "STOPPED":
            status_text = "[red]Stopped[/red]"
        else:
            status_text = f"[yellow]{state}[/yellow]"

        # Public IP display
        public_ip = instance["public_ip"] if instance["has_public_ip"] else "[dim]none[/dim]"

        # Security indicators
        security_indicators = []
        if instance["has_public_ip"]:
            security_indicators.append("🌐")
        if not instance["require_ssl"] and instance["has_public_ip"]:
            security_indicators.append("[red]⚠️[/red]")
        if instance["has_open_access"]:
            security_indicators.append("[red]🔓[/red]")

        security = " ".join(security_indicators) if security_indicators else "[dim]—[/dim]"

        table.add_row(
            instance["project"],
            instance["name"],
            instance["database_type"],
            instance["database_version"].replace("_", " "),
            status_text,
            public_ip,
            security
        )

    console.print(table)

    if len(all_instances) > 50:
        console.print(f"\n[yellow]Showing first 50 instances (total: {len(all_instances)})[/yellow]")

    # Statistics
    console.print(f"\n[bold]📊 Statistics:[/bold]")
    console.print(f"  [cyan]MySQL:[/cyan] {mysql_count}")
    console.print(f"  [cyan]PostgreSQL:[/cyan] {postgres_count}")
    console.print(f"  [cyan]SQL Server:[/cyan] {sqlserver_count}")
    console.print(f"  [cyan]With Public IP:[/cyan] {len(public_instances)}")

    # Security warnings
    if open_access:
        console.print(f"\n[bold red]🔓 {len(open_access)} instance(s) with 0.0.0.0/0 access (DANGEROUS!):[/bold red]")
        for inst in open_access[:10]:
            console.print(f"  • {inst['project']}/{inst['name']}")

    if no_ssl_required:
        console.print(f"\n[bold yellow]⚠️  {len(no_ssl_required)} public instance(s) without SSL requirement:[/bold yellow]")
        for inst in no_ssl_required[:10]:
            console.print(f"  • {inst['project']}/{inst['name']}")

    console.print(f"\n[green]Results saved to session data under 'cloud_sql_instances'[/green]")
    console.print("[dim]Legend: 🌐=Public IP, ⚠️=No SSL required, 🔓=Open access (0.0.0.0/0)[/dim]")

    return all_instances
