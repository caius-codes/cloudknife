"""
GCP Compute Engine Instance Metadata Enumeration.

Enumerates instance-level and project-level metadata which often contains
sensitive information such as:
- Startup/shutdown scripts
- SSH keys
- Passwords and credentials
- Configuration data
- Custom metadata values

Metadata is a common target for attackers as it often contains secrets
in plaintext that developers assume are "internal only".
"""

from typing import List, Dict, Any, Set, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from google.cloud import compute_v1

from src.clouds.gcp.utils.projects import resolve_projects, get_all_zones

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# Patterns that indicate sensitive data in metadata
SENSITIVE_PATTERNS = [
    r'password',
    r'passwd',
    r'pwd',
    r'secret',
    r'api[_-]?key',
    r'apikey',
    r'access[_-]?key',
    r'private[_-]?key',
    r'token',
    r'credential',
    r'auth',
    r'bearer',
    r'ssh[_-]?key',
    r'rsa[_-]?key',
    r'database[_-]?url',
    r'db[_-]?connection',
    r'connection[_-]?string',
    r'AKIA',  # AWS access key prefix
    r'-----BEGIN',  # Private key indicator
]

# Common metadata keys that often contain sensitive data
SENSITIVE_KEYS = {
    'startup-script',
    'shutdown-script',
    'ssh-keys',
    'sshKeys',
    'windows-keys',
    'sysprep-specialize-script-ps1',
    'sysprep-specialize-script-cmd',
    'windows-startup-script-ps1',
    'windows-startup-script-cmd',
}


def enumerate_compute_metadata(session_mgr: "GCPSessionManager") -> List[Dict[str, Any]]:
    """
    Enumerate instance metadata across all Compute Engine instances.

    Checks both instance-level and project-level metadata for sensitive data.
    Flags metadata keys/values that match sensitive patterns.

    Args:
        session_mgr: GCP session manager with valid credentials

    Returns:
        List of metadata dictionaries with sensitivity analysis
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    projects = resolve_projects(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return []

    console.print("[bold cyan]🔍 Enumerating Compute Engine Metadata[/bold cyan]")
    console.print("[dim]Searching for sensitive data in instance metadata...[/dim]\n")

    # Fetch zones once (cached)
    all_zones = get_all_zones(session_mgr)

    # Create clients
    instances_client = compute_v1.InstancesClient(credentials=credentials)
    projects_client = compute_v1.ProjectsClient(credentials=credentials)

    all_metadata: List[Dict[str, Any]] = []

    # Step 1: Enumerate project-level metadata
    console.print("[cyan]→ Enumerating project-level metadata...[/cyan]")
    for project in projects:
        project_metadata = _enumerate_project_metadata(projects_client, project)
        if project_metadata:
            all_metadata.extend(project_metadata)

    # Step 2: Enumerate instance-level metadata (parallel)
    console.print(f"\n[cyan]→ Enumerating instance-level metadata...[/cyan]")

    tasks = [(project, zone) for project in projects for zone in all_zones]
    total_tasks = len(tasks)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task("Scanning instances...", total=total_tasks)

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_task = {
                executor.submit(_enumerate_zone_metadata, instances_client, project, zone): (project, zone)
                for project, zone in tasks
            }

            for future in as_completed(future_to_task):
                project, zone = future_to_task[future]
                try:
                    metadata_items = future.result()
                    all_metadata.extend(metadata_items)
                except Exception as e:
                    # Silent skip for zones with no instances or errors
                    pass

                progress.update(task_id, advance=1)

    # Analyze and display results
    if not all_metadata:
        console.print("\n[yellow]No metadata found in accessible instances.[/yellow]")
        return []

    # Filter for items with sensitive data
    sensitive_items = [item for item in all_metadata if item.get('is_sensitive', False)]

    # Save all metadata
    session_mgr.save_enumeration_data("compute_metadata", all_metadata)

    # Display results
    _display_metadata_summary(all_metadata, sensitive_items)
    _display_sensitive_metadata(sensitive_items)

    return all_metadata


def _enumerate_project_metadata(
    projects_client: compute_v1.ProjectsClient,
    project: str
) -> List[Dict[str, Any]]:
    """
    Enumerate project-level metadata (applies to all instances in project).

    Args:
        projects_client: ProjectsClient instance
        project: GCP project ID

    Returns:
        List of project metadata dictionaries
    """
    metadata_items = []

    try:
        project_obj = projects_client.get(project=project)

        if project_obj.common_instance_metadata and project_obj.common_instance_metadata.items:
            for item in project_obj.common_instance_metadata.items:
                key = item.key
                value = item.value or ""

                # Analyze sensitivity
                is_sensitive, reasons = _analyze_sensitivity(key, value)

                metadata_items.append({
                    "scope": "project",
                    "project": project,
                    "instance": None,
                    "zone": None,
                    "key": key,
                    "value": value,
                    "value_length": len(value),
                    "is_sensitive": is_sensitive,
                    "sensitive_reasons": reasons,
                })

    except Exception as e:
        # Skip projects with permission errors
        pass

    return metadata_items


def _enumerate_zone_metadata(
    instances_client: compute_v1.InstancesClient,
    project: str,
    zone: str
) -> List[Dict[str, Any]]:
    """
    Enumerate instance-level metadata for all instances in a zone.

    Args:
        instances_client: InstancesClient instance
        project: GCP project ID
        zone: GCP zone name

    Returns:
        List of instance metadata dictionaries
    """
    metadata_items = []

    try:
        request = compute_v1.ListInstancesRequest(project=project, zone=zone)

        for instance in instances_client.list(request=request):
            if instance.metadata and instance.metadata.items:
                for item in instance.metadata.items:
                    key = item.key
                    value = item.value or ""

                    # Analyze sensitivity
                    is_sensitive, reasons = _analyze_sensitivity(key, value)

                    metadata_items.append({
                        "scope": "instance",
                        "project": project,
                        "instance": instance.name,
                        "zone": zone,
                        "key": key,
                        "value": value,
                        "value_length": len(value),
                        "is_sensitive": is_sensitive,
                        "sensitive_reasons": reasons,
                    })

    except Exception as e:
        # Re-raise to be caught by executor
        raise

    return metadata_items


def _analyze_sensitivity(key: str, value: str) -> tuple[bool, List[str]]:
    """
    Analyze if a metadata key/value contains sensitive data.

    Args:
        key: Metadata key name
        value: Metadata value content

    Returns:
        Tuple of (is_sensitive: bool, reasons: List[str])
    """
    reasons = []

    # Check if key is in known sensitive keys
    if key in SENSITIVE_KEYS:
        reasons.append(f"Known sensitive key: {key}")

    # Check key against patterns
    key_lower = key.lower()
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, key_lower, re.IGNORECASE):
            reasons.append(f"Key matches pattern: {pattern}")
            break

    # Check value against patterns (first 500 chars to avoid performance hit)
    value_sample = value[:500]
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, value_sample, re.IGNORECASE):
            reasons.append(f"Value matches pattern: {pattern}")
            break

    # Flag very long values (likely scripts)
    if len(value) > 1000:
        reasons.append(f"Large value ({len(value)} bytes) - likely script")

    is_sensitive = len(reasons) > 0

    return is_sensitive, reasons


def _display_metadata_summary(
    all_metadata: List[Dict[str, Any]],
    sensitive_items: List[Dict[str, Any]]
) -> None:
    """Display summary statistics of metadata findings."""
    total_items = len(all_metadata)
    total_sensitive = len(sensitive_items)

    # Count by scope
    project_level = sum(1 for item in all_metadata if item['scope'] == 'project')
    instance_level = sum(1 for item in all_metadata if item['scope'] == 'instance')

    # Count unique instances and projects
    unique_instances = len(set(
        (item['project'], item['instance'])
        for item in all_metadata
        if item['instance']
    ))
    unique_projects = len(set(item['project'] for item in all_metadata))

    # Build summary table
    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column(style="cyan", justify="right")
    summary_table.add_column()

    summary_table.add_row("Total Metadata Items:", f"[bold]{total_items}[/bold]")
    summary_table.add_row("├─ Project-level:", f"{project_level}")
    summary_table.add_row("└─ Instance-level:", f"{instance_level}")
    summary_table.add_row("", "")
    summary_table.add_row("Unique Projects:", f"{unique_projects}")
    summary_table.add_row("Unique Instances:", f"{unique_instances}")
    summary_table.add_row("", "")

    if total_sensitive > 0:
        percentage = int((total_sensitive / total_items) * 100)
        summary_table.add_row(
            "Sensitive Items:",
            f"[bold red]{total_sensitive}[/bold red] ([red]{percentage}%[/red])"
        )
    else:
        summary_table.add_row("Sensitive Items:", "[green]0[/green]")

    console.print()
    console.print(Panel(
        summary_table,
        title="[bold cyan]Metadata Summary[/bold cyan]",
        border_style="cyan"
    ))
    console.print()


def _display_sensitive_metadata(sensitive_items: List[Dict[str, Any]]) -> None:
    """Display table of sensitive metadata findings."""
    if not sensitive_items:
        console.print("[green]✓ No sensitive metadata patterns detected.[/green]")
        return

    console.print(f"[bold red]🚨 Found {len(sensitive_items)} Sensitive Metadata Items[/bold red]\n")

    table = Table(
        title="Sensitive Metadata Findings",
        show_header=True,
        header_style="bold red"
    )

    table.add_column("Scope", style="cyan", width=10)
    table.add_column("Project", style="dim", width=20, overflow="fold")
    table.add_column("Instance", style="yellow", width=20, overflow="fold")
    table.add_column("Key", style="bold red", width=25, overflow="fold")
    table.add_column("Value Preview", width=40, overflow="fold")
    table.add_column("Reasons", width=30, overflow="fold")

    for item in sensitive_items[:50]:  # Limit to first 50 for readability
        # Truncate value for display
        value_preview = item['value'][:100]
        if len(item['value']) > 100:
            value_preview += f"... ({item['value_length']} bytes total)"

        # Sanitize sensitive patterns in preview
        value_preview = _sanitize_value_preview(value_preview)

        # Format reasons
        reasons_str = "\n".join(item['sensitive_reasons'][:2])  # Show first 2 reasons

        table.add_row(
            item['scope'],
            item['project'],
            item['instance'] or "-",
            item['key'],
            f"[dim]{value_preview}[/dim]",
            f"[yellow]{reasons_str}[/yellow]"
        )

    console.print(table)

    if len(sensitive_items) > 50:
        console.print(f"\n[dim]... and {len(sensitive_items) - 50} more sensitive items[/dim]")

    # Display warning
    console.print()
    console.print(Panel(
        "[bold red]⚠️  WARNING[/bold red]\n\n"
        "Metadata items may contain:\n"
        "• Plaintext passwords and credentials\n"
        "• SSH private keys\n"
        "• API tokens and secrets\n"
        "• Database connection strings\n"
        "• Startup scripts with embedded credentials\n\n"
        "[yellow]Review metadata carefully for privilege escalation opportunities.[/yellow]",
        border_style="red"
    ))


def _sanitize_value_preview(value: str) -> str:
    """
    Sanitize sensitive patterns in value preview for display.

    Replaces potential credentials with [REDACTED] to avoid accidental exposure.
    """
    # Redact AWS access keys
    value = re.sub(r'AKIA[A-Z0-9]{16}', '[AWS_KEY_REDACTED]', value)

    # Redact private keys
    value = re.sub(r'-----BEGIN [A-Z ]+-----[^-]+-----END [A-Z ]+-----', '[PRIVATE_KEY_REDACTED]', value, flags=re.DOTALL)

    # Redact password-like patterns (simple heuristic)
    value = re.sub(r'(password|passwd|pwd)[\s:=]+[^\s]+', r'\1=[REDACTED]', value, flags=re.IGNORECASE)

    return value


def show_metadata_detail(
    session_mgr: "GCPSessionManager",
    project: str = None,
    instance: str = None,
    key: str = None
) -> None:
    """
    Show detailed metadata value (use with caution - may contain sensitive data).

    Args:
        session_mgr: GCP session manager
        project: Project filter (optional)
        instance: Instance filter (optional)
        key: Metadata key filter (optional)
    """
    metadata_cache = session_mgr.enumerated_data.get(
        session_mgr.current_session, {}
    ).get("compute_metadata", [])

    if not metadata_cache:
        console.print("[yellow]No metadata cached. Run 'enumerate_compute_metadata' first.[/yellow]")
        return

    # Filter metadata
    filtered = metadata_cache

    if project:
        filtered = [m for m in filtered if m['project'] == project]

    if instance:
        filtered = [m for m in filtered if m.get('instance') == instance]

    if key:
        filtered = [m for m in filtered if m['key'] == key]

    if not filtered:
        console.print("[yellow]No metadata found matching filters.[/yellow]")
        return

    # Display detailed view
    for item in filtered[:10]:  # Limit to 10 items
        console.print(Panel(
            f"[cyan]Scope:[/cyan] {item['scope']}\n"
            f"[cyan]Project:[/cyan] {item['project']}\n"
            f"[cyan]Instance:[/cyan] {item.get('instance') or 'N/A'}\n"
            f"[cyan]Key:[/cyan] [bold]{item['key']}[/bold]\n"
            f"[cyan]Value:[/cyan]\n[yellow]{item['value']}[/yellow]",
            title=f"[bold]Metadata: {item['key']}[/bold]",
            border_style="red" if item['is_sensitive'] else "cyan"
        ))
        console.print()

    if len(filtered) > 10:
        console.print(f"[dim]... and {len(filtered) - 10} more items[/dim]")
