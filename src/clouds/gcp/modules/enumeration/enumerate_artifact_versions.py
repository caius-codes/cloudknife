"""
Enumerate versions and tags for packages in GCP Artifact Registry.

Permissions required:
- artifactregistry.versions.list
- artifactregistry.tags.list
"""

from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from google.cloud import artifactregistry_v1

from ...gcp_session import GCPSessionManager

console = Console()


def enumerate_artifact_versions(session_mgr: GCPSessionManager) -> None:
    """
    Enumerate versions and tags for packages in Artifact Registry.

    Args:
        session_mgr: GCP session manager with credentials
    """
    console.print("\n[bold cyan]🏷️  Enumerating Artifact Registry Versions & Tags...[/bold cyan]\n")

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]❌ No credentials configured[/red]")
        return

    # Check if packages were already enumerated
    packages = session_mgr.get_enumeration_data("artifact_packages")

    if not packages:
        console.print(
            "[yellow]⚠ No packages found in session data. "
            "Run 'enumerate_artifact_packages' first.[/yellow]"
        )
        return

    # Let user choose: scan all or select specific package
    console.print(f"[green]Found {len(packages)} packages[/green]")
    scan_mode = Prompt.ask(
        "[cyan]Scan mode[/cyan]",
        choices=["all", "select", "top10"],
        default="top10",
    )

    target_packages = packages

    if scan_mode == "select":
        # Display packages and let user select
        console.print("\n[bold]Available Packages:[/bold]")
        for idx, pkg in enumerate(packages[:50], 1):  # Show first 50
            console.print(
                f"  {idx}. {pkg['package_id']} "
                f"[dim]({pkg['repository_id']} - {pkg['repository_format']})[/dim]"
            )

        if len(packages) > 50:
            console.print(f"  [dim]...and {len(packages) - 50} more[/dim]")

        selection = Prompt.ask("[cyan]Enter package number[/cyan]", default="1")
        try:
            idx = int(selection) - 1
            if 0 <= idx < len(packages):
                target_packages = [packages[idx]]
            else:
                console.print("[red]Invalid selection[/red]")
                return
        except ValueError:
            console.print("[red]Invalid input[/red]")
            return
    elif scan_mode == "top10":
        target_packages = packages[:10]
        console.print(f"[dim]Scanning first 10 packages[/dim]")

    # Enumerate versions and tags
    all_versions: List[Dict[str, Any]] = []
    all_tags: List[Dict[str, Any]] = []
    total_versions = 0
    total_tags = 0

    try:
        client = artifactregistry_v1.ArtifactRegistryClient(credentials=credentials)

        for pkg in target_packages:
            console.print(
                f"\n[dim]Scanning package:[/dim] [cyan]{pkg['package_id']}[/cyan] "
                f"[dim]({pkg['repository_format']})[/dim]"
            )

            try:
                parent = pkg["name"]  # Full resource name

                # List versions
                version_request = artifactregistry_v1.ListVersionsRequest(parent=parent)
                versions = client.list_versions(request=version_request)

                pkg_version_count = 0
                for version in versions:
                    total_versions += 1
                    pkg_version_count += 1

                    version_data = {
                        "package_id": pkg["package_id"],
                        "repository_id": pkg["repository_id"],
                        "repository_format": pkg["repository_format"],
                        "project": pkg["project"],
                        "name": version.name,
                        "version_id": version.name.split("/")[-1],
                        "create_time": str(version.create_time) if version.create_time else "",
                        "update_time": str(version.update_time) if version.update_time else "",
                        "related_tags": [],
                    }

                    # Add Docker-specific metadata
                    if pkg["repository_format"] == "DOCKER":
                        if version.metadata:
                            # Docker metadata includes image manifest digest
                            version_data["metadata"] = str(version.metadata)

                    all_versions.append(version_data)

                console.print(f"  [green]✓[/green] Found {pkg_version_count} versions")

                # List tags (primarily for Docker repositories)
                if pkg["repository_format"] == "DOCKER":
                    try:
                        tag_request = artifactregistry_v1.ListTagsRequest(parent=parent)
                        tags = client.list_tags(request=tag_request)

                        pkg_tag_count = 0
                        for tag in tags:
                            total_tags += 1
                            pkg_tag_count += 1

                            tag_data = {
                                "package_id": pkg["package_id"],
                                "repository_id": pkg["repository_id"],
                                "project": pkg["project"],
                                "name": tag.name,
                                "tag_id": tag.name.split("/")[-1],
                                "version": tag.version,
                            }

                            all_tags.append(tag_data)

                            # Link tag to version
                            version_id = tag.version.split("/")[-1] if tag.version else None
                            if version_id:
                                for v in all_versions:
                                    if (
                                        v["package_id"] == pkg["package_id"]
                                        and v["version_id"] == version_id
                                    ):
                                        v["related_tags"].append(tag_data["tag_id"])

                        if pkg_tag_count > 0:
                            console.print(f"  [blue]✓[/blue] Found {pkg_tag_count} tags")

                    except Exception as e:
                        if "PERMISSION_DENIED" not in str(e):
                            console.print(
                                f"  [yellow]⚠ Error listing tags: {str(e)[:80]}[/yellow]"
                            )

            except Exception as e:
                if "PERMISSION_DENIED" in str(e):
                    console.print(
                        f"  [yellow]⚠ Permission denied for package {pkg['package_id']}[/yellow]"
                    )
                elif "NOT_FOUND" in str(e):
                    console.print(
                        f"  [yellow]⚠ Package {pkg['package_id']} not found[/yellow]"
                    )
                else:
                    console.print(
                        f"  [red]❌ Error scanning package {pkg['package_id']}: {str(e)[:100]}[/red]"
                    )

    except Exception as e:
        console.print(f"[red]❌ Failed to initialize Artifact Registry client: {e}[/red]")
        return

    # Save enumeration data
    if all_versions:
        session_mgr.save_enumeration_data("artifact_versions", all_versions)
        console.print(f"\n[green]✅ Found {total_versions} versions[/green]")

    if all_tags:
        session_mgr.save_enumeration_data("artifact_tags", all_tags)
        console.print(f"[blue]✅ Found {total_tags} tags[/blue]")

    if all_versions or all_tags:
        console.print(f"[dim]Data saved to session enumeration[/dim]")
        _display_summary(all_versions, all_tags)
    else:
        console.print("\n[yellow]⚠ No versions or tags found[/yellow]")


def _display_summary(versions: List[Dict[str, Any]], tags: List[Dict[str, Any]]) -> None:
    """Display summary table of versions and tags."""
    console.print("\n[bold]📊 Summary:[/bold]")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Package", style="cyan")
    table.add_column("Repository")
    table.add_column("Versions", justify="right", style="green")
    table.add_column("Tags", justify="right", style="blue")
    table.add_column("Latest Tags", overflow="fold", no_wrap=False)

    # Group by package
    package_stats: Dict[str, Dict[str, Any]] = {}

    for version in versions:
        pkg_key = f"{version['package_id']}|{version['repository_id']}"
        if pkg_key not in package_stats:
            package_stats[pkg_key] = {
                "package_id": version["package_id"],
                "repository_id": version["repository_id"],
                "version_count": 0,
                "tag_count": 0,
                "tags": [],
            }

        package_stats[pkg_key]["version_count"] += 1

        # Collect tags from versions
        if version.get("related_tags"):
            package_stats[pkg_key]["tags"].extend(version["related_tags"])

    # Add tag counts
    for tag in tags:
        pkg_key = f"{tag['package_id']}|{tag['repository_id']}"
        if pkg_key in package_stats:
            package_stats[pkg_key]["tag_count"] += 1

    # Display stats
    for stats in sorted(package_stats.values(), key=lambda x: x["version_count"], reverse=True):
        tags_str = ", ".join(sorted(set(stats["tags"]))[:5])
        if len(set(stats["tags"])) > 5:
            tags_str += f" +{len(set(stats['tags'])) - 5}"

        table.add_row(
            stats["package_id"],
            stats["repository_id"],
            str(stats["version_count"]),
            str(stats["tag_count"]) if stats["tag_count"] > 0 else "-",
            tags_str or "-",
        )

    console.print(table)
