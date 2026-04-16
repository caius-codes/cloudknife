"""
Enumerate packages within GCP Artifact Registry repositories.

Permissions required:
- artifactregistry.packages.list
- artifactregistry.packages.get (for detailed info)
"""

from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from google.cloud import artifactregistry_v1

from ...gcp_session import GCPSessionManager

console = Console()


def enumerate_artifact_packages(session_mgr: GCPSessionManager) -> None:
    """
    Enumerate packages within Artifact Registry repositories.

    Can enumerate:
    - All packages across all repositories (if no repositories enumerated yet)
    - Packages in a specific repository (user selection)

    Args:
        session_mgr: GCP session manager with credentials
    """
    console.print("\n[bold cyan]📦 Enumerating Artifact Registry Packages...[/bold cyan]\n")

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]❌ No credentials configured[/red]")
        return

    # Check if repositories were already enumerated
    repositories = session_mgr.get_enumeration_data("artifact_repositories")

    if not repositories:
        console.print(
            "[yellow]⚠ No repositories found in session data. "
            "Run 'enumerate_artifacts' first.[/yellow]"
        )
        choice = Prompt.ask(
            "[cyan]Scan all projects for repositories now?[/cyan]",
            choices=["y", "n"],
            default="n",
        )

        if choice == "y":
            from .enumerate_artifact_repositories import enumerate_artifact_repositories

            enumerate_artifact_repositories(session_mgr)
            repositories = session_mgr.get_enumeration_data("artifact_repositories")

        if not repositories:
            console.print("[red]No repositories available to scan[/red]")
            return

    # Let user choose: scan all or select specific repository
    console.print(f"[green]Found {len(repositories)} repositories[/green]")
    scan_mode = Prompt.ask(
        "[cyan]Scan mode[/cyan]",
        choices=["all", "select"],
        default="all",
    )

    target_repos = repositories

    if scan_mode == "select":
        # Display repositories and let user select
        console.print("\n[bold]Available Repositories:[/bold]")
        for idx, repo in enumerate(repositories, 1):
            console.print(
                f"  {idx}. {repo['repository_id']} ({repo['format']}) - {repo['location']}"
            )

        selection = Prompt.ask("[cyan]Enter repository number[/cyan]", default="1")
        try:
            idx = int(selection) - 1
            if 0 <= idx < len(repositories):
                target_repos = [repositories[idx]]
            else:
                console.print("[red]Invalid selection[/red]")
                return
        except ValueError:
            console.print("[red]Invalid input[/red]")
            return

    # Enumerate packages
    all_packages: List[Dict[str, Any]] = []
    total_packages = 0

    try:
        client = artifactregistry_v1.ArtifactRegistryClient(credentials=credentials)

        for repo in target_repos:
            console.print(
                f"\n[dim]Scanning repository:[/dim] [cyan]{repo['repository_id']}[/cyan] "
                f"[dim]({repo['location']})[/dim]"
            )

            try:
                parent = repo["name"]  # Full resource name
                request = artifactregistry_v1.ListPackagesRequest(parent=parent)
                packages = client.list_packages(request=request)

                repo_package_count = 0
                for package in packages:
                    total_packages += 1
                    repo_package_count += 1

                    package_data = {
                        "repository_id": repo["repository_id"],
                        "repository_location": repo["location"],
                        "repository_format": repo["format"],
                        "project": repo["project"],
                        "name": package.name,
                        "package_id": package.name.split("/")[-1],
                        "display_name": package.display_name or package.name.split("/")[-1],
                        "create_time": str(package.create_time) if package.create_time else "",
                        "update_time": str(package.update_time) if package.update_time else "",
                    }

                    all_packages.append(package_data)

                    # Display in real-time
                    console.print(f"  📦 [green]{package_data['package_id']}[/green]")

                console.print(f"  [dim]Found {repo_package_count} packages[/dim]")

            except Exception as e:
                if "PERMISSION_DENIED" in str(e):
                    console.print(
                        f"  [yellow]⚠ Permission denied for repository {repo['repository_id']}[/yellow]"
                    )
                elif "NOT_FOUND" in str(e):
                    console.print(
                        f"  [yellow]⚠ Repository {repo['repository_id']} not found (may have been deleted)[/yellow]"
                    )
                else:
                    console.print(
                        f"  [red]❌ Error scanning repository {repo['repository_id']}: {str(e)[:100]}[/red]"
                    )

    except Exception as e:
        console.print(f"[red]❌ Failed to initialize Artifact Registry client: {e}[/red]")
        return

    # Save enumeration data
    if all_packages:
        session_mgr.save_enumeration_data("artifact_packages", all_packages)
        console.print(f"\n[green]✅ Found {total_packages} packages across repositories[/green]")
        console.print(f"[dim]Data saved to session enumeration[/dim]")

        # Display summary
        _display_summary(all_packages)
    else:
        console.print("\n[yellow]⚠ No packages found[/yellow]")


def _display_summary(packages: List[Dict[str, Any]]) -> None:
    """Display summary table of packages grouped by repository."""
    console.print("\n[bold]📊 Summary by Repository:[/bold]")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Repository", style="cyan")
    table.add_column("Location")
    table.add_column("Format", style="green")
    table.add_column("Packages", justify="right", style="yellow")

    # Group by repository
    repo_stats: Dict[str, Dict[str, Any]] = {}
    for pkg in packages:
        repo_key = f"{pkg['repository_id']}|{pkg['repository_location']}"
        if repo_key not in repo_stats:
            repo_stats[repo_key] = {
                "repository_id": pkg["repository_id"],
                "location": pkg["repository_location"],
                "format": pkg["repository_format"],
                "count": 0,
            }

        repo_stats[repo_key]["count"] += 1

    # Display stats
    for stats in sorted(repo_stats.values(), key=lambda x: x["count"], reverse=True):
        table.add_row(
            stats["repository_id"],
            stats["location"],
            stats["format"],
            str(stats["count"]),
        )

    console.print(table)
