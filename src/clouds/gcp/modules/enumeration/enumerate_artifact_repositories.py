"""
Enumerate GCP Artifact Registry repositories across all accessible projects.

Permissions required:
- artifactregistry.repositories.list
- artifactregistry.repositories.get (for detailed info)
"""

from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from google.cloud import artifactregistry_v1

from ...gcp_session import GCPSessionManager

console = Console()


def enumerate_artifact_repositories(session_mgr: GCPSessionManager, project_id: str = None) -> None:
    """
    Enumerate all Artifact Registry repositories across accessible projects.

    Args:
        session_mgr: GCP session manager with credentials
        project_id: Optional specific project ID to scan (overrides configured projects)
    """
    console.print("\n[bold cyan]📦 Enumerating Artifact Registry Repositories...[/bold cyan]\n")

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]❌ No credentials configured[/red]")
        return

    # Discover projects to scan
    if project_id:
        projects = [project_id]
        console.print(f"[cyan]Scanning specific project:[/cyan] {project_id}")
    else:
        # Try to use default project from session first
        default_proj = session_mgr.default_project
        if default_proj:
            projects = [default_proj]
            console.print(f"[cyan]Using default project from session:[/cyan] {default_proj}")
        else:
            projects = session_mgr.configured_projects
            if not projects:
                console.print("[dim]No projects configured, discovering accessible projects...[/dim]")
                projects = session_mgr.discover_accessible_projects()

            if not projects:
                console.print("[yellow]⚠ No accessible projects found[/yellow]")
                console.print("[cyan]💡 Tip: Set a project with 'set_project gr-proj-1' or 'set_projects gr-proj-1'[/cyan]")
                console.print("[cyan]💡 Or specify directly: 'enumerate_artifacts gr-proj-1'[/cyan]")
                return

            console.print(f"[cyan]Scanning {len(projects)} project(s):[/cyan] {', '.join(projects)}")

    all_repositories: List[Dict[str, Any]] = []
    total_repos = 0

    # All GCP locations where Artifact Registry is available
    locations = [
        "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
        "asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2",
        "australia-southeast1", "australia-southeast2",
        "europe-central2", "europe-north1", "europe-southwest1", "europe-west1", "europe-west2",
        "europe-west3", "europe-west4", "europe-west6", "europe-west8", "europe-west9",
        "me-central1", "me-west1",
        "northamerica-northeast1", "northamerica-northeast2",
        "southamerica-east1", "southamerica-west1",
        "us-central1", "us-east1", "us-east4", "us-east5",
        "us-south1", "us-west1", "us-west2", "us-west3", "us-west4",
    ]

    try:
        client = artifactregistry_v1.ArtifactRegistryClient(credentials=credentials)

        for proj_id in projects:
            console.print(f"[dim]Scanning project:[/dim] [cyan]{proj_id}[/cyan]")
            project_repo_count = 0

            # Iterate through all locations
            for location in locations:
                try:
                    parent = f"projects/{proj_id}/locations/{location}"
                    request = artifactregistry_v1.ListRepositoriesRequest(parent=parent)
                    repos = client.list_repositories(request=request)

                    for repo in repos:
                        project_repo_count += 1
                        total_repos += 1

                        repo_data = {
                            "project": proj_id,
                            "location": location,
                            "name": repo.name,
                            "repository_id": repo.name.split("/")[-1],
                            "format": artifactregistry_v1.Repository.Format(repo.format_).name,
                            "mode": artifactregistry_v1.Repository.Mode(repo.mode).name,
                            "description": repo.description or "",
                            "create_time": str(repo.create_time) if repo.create_time else "",
                            "update_time": str(repo.update_time) if repo.update_time else "",
                            "size_bytes": repo.size_bytes,
                            "kms_key_name": repo.kms_key_name or "",
                            "labels": dict(repo.labels) if repo.labels else {},
                        }

                        # Add Docker-specific info if applicable
                        if repo.format_ == artifactregistry_v1.Repository.Format.DOCKER:
                            if repo.docker_config:
                                repo_data["immutable_tags"] = repo.docker_config.immutable_tags

                        # Add Maven-specific info if applicable
                        if repo.format_ == artifactregistry_v1.Repository.Format.MAVEN:
                            if repo.maven_config:
                                repo_data["maven_allow_snapshot_overwrites"] = (
                                    repo.maven_config.allow_snapshot_overwrites
                                )

                        all_repositories.append(repo_data)

                        # Display in real-time
                        _display_repository(repo_data)

                except Exception as e:
                    # Silently skip locations where Artifact Registry isn't available or has no repos
                    if "NOT_FOUND" in str(e) or "PERMISSION_DENIED" in str(e):
                        continue
                    # Only report unexpected errors
                    if "INVALID_ARGUMENT" not in str(e):
                        console.print(
                            f"  [yellow]⚠ Error in {location}: {str(e)[:80]}[/yellow]"
                        )

            if project_repo_count > 0:
                console.print(f"  [green]✓ Found {project_repo_count} repositories in {proj_id}[/green]")
            else:
                console.print(f"  [dim]No repositories found in {proj_id}[/dim]")

    except Exception as e:
        console.print(f"[red]❌ Failed to initialize Artifact Registry client: {e}[/red]")
        return

    # Save enumeration data
    if all_repositories:
        session_mgr.save_enumeration_data("artifact_repositories", all_repositories)
        console.print(f"\n[green]✅ Found {total_repos} Artifact Registry repositories[/green]")
        console.print(f"[dim]Data saved to session enumeration[/dim]")

        # Display summary table
        _display_summary(all_repositories)
    else:
        console.print("\n[yellow]⚠ No repositories found[/yellow]")


def _display_repository(repo: Dict[str, Any]) -> None:
    """Display a single repository in compact format."""
    format_icon = {
        "DOCKER": "🐳",
        "MAVEN": "☕",
        "NPM": "📦",
        "PYTHON": "🐍",
        "APT": "📦",
        "YUM": "📦",
        "GO": "🔷",
    }.get(repo["format"], "📦")

    size_mb = repo["size_bytes"] / (1024 * 1024) if repo["size_bytes"] else 0
    size_str = f"{size_mb:.1f}MB" if size_mb > 0 else "-"

    console.print(
        f"  {format_icon} [cyan]{repo['repository_id']}[/cyan] "
        f"[dim]({repo['location']})[/dim] - "
        f"[green]{repo['format']}[/green] - "
        f"[yellow]{size_str}[/yellow]"
    )


def _display_summary(repositories: List[Dict[str, Any]]) -> None:
    """Display summary table of repositories grouped by format."""
    console.print("\n[bold]📊 Summary by Format:[/bold]")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Format", style="green")
    table.add_column("Count", justify="right", style="yellow")
    table.add_column("Total Size", justify="right")
    table.add_column("Locations")

    # Group by format
    format_stats: Dict[str, Dict[str, Any]] = {}
    for repo in repositories:
        fmt = repo["format"]
        if fmt not in format_stats:
            format_stats[fmt] = {
                "count": 0,
                "size_bytes": 0,
                "locations": set(),
            }

        format_stats[fmt]["count"] += 1
        format_stats[fmt]["size_bytes"] += repo["size_bytes"] or 0
        format_stats[fmt]["locations"].add(repo["location"])

    # Display stats
    for fmt, stats in sorted(format_stats.items()):
        size_mb = stats["size_bytes"] / (1024 * 1024)
        size_str = f"{size_mb:.1f}MB" if size_mb > 0 else "-"
        locations_str = ", ".join(sorted(list(stats["locations"]))[:3])
        if len(stats["locations"]) > 3:
            locations_str += f" +{len(stats['locations']) - 3} more"

        table.add_row(
            fmt,
            str(stats["count"]),
            size_str,
            locations_str,
        )

    console.print(table)


def _display_detailed_table(repositories: List[Dict[str, Any]]) -> None:
    """Display detailed table of all repositories."""
    console.print("\n[bold]📋 Detailed Repository List:[/bold]")

    table = Table(show_header=True, header_style="bold cyan", show_lines=True)
    table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Repository", style="green", overflow="fold", no_wrap=False)
    table.add_column("Format")
    table.add_column("Location", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("Description", overflow="fold", no_wrap=False)

    for repo in repositories:
        size_mb = repo["size_bytes"] / (1024 * 1024) if repo["size_bytes"] else 0
        size_str = f"{size_mb:.1f}MB" if size_mb > 0 else "-"

        table.add_row(
            repo["project"],
            repo["repository_id"],
            repo["format"],
            repo["location"],
            size_str,
            repo["description"][:50] if repo["description"] else "-",
        )

    console.print(table)
