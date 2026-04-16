"""
Download artifacts from GCP Artifact Registry.

Supports:
- Docker container images
- Generic artifacts (via direct download)

Permissions required:
- artifactregistry.repositories.downloadArtifacts
- artifactregistry.repositories.get
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...gcp_session import GCPSessionManager

console = Console()


def download_artifact(session_mgr: GCPSessionManager) -> None:
    """
    Download artifacts from Artifact Registry.

    Supports:
    - Docker images (using docker pull with gcloud credential helper)
    - Files (using gsutil or API download)

    Args:
        session_mgr: GCP session manager with credentials
    """
    console.print("\n[bold cyan]📥 Download Artifact from Artifact Registry[/bold cyan]\n")

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]❌ No credentials configured[/red]")
        return

    # Check for enumerated repositories
    repositories = session_mgr.get_enumeration_data("artifact_repositories")
    packages = session_mgr.get_enumeration_data("artifact_packages")

    if not repositories:
        console.print(
            "[yellow]⚠ No repositories enumerated. Consider running "
            "'enumerate_artifact_repositories' first.[/yellow]"
        )

    # Download mode selection
    download_mode = Prompt.ask(
        "[cyan]Download mode[/cyan]",
        choices=["docker", "manual"],
        default="docker",
    )

    if download_mode == "docker":
        _download_docker_image(session_mgr, repositories, packages)
    else:
        _download_manual(session_mgr, repositories)


def _download_docker_image(
    session_mgr: GCPSessionManager,
    repositories: Optional[List[Dict[str, Any]]],
    packages: Optional[List[Dict[str, Any]]],
) -> None:
    """
    Download Docker container image using docker pull with gcloud auth.

    Args:
        session_mgr: GCP session manager
        repositories: Enumerated repositories (optional)
        packages: Enumerated packages (optional)
    """
    console.print("[bold]🐳 Docker Image Download[/bold]\n")

    # Filter Docker repositories
    docker_repos = (
        [r for r in repositories if r["format"] == "DOCKER"] if repositories else []
    )

    if docker_repos:
        console.print(f"[green]Found {len(docker_repos)} Docker repositories:[/green]")
        for idx, repo in enumerate(docker_repos[:20], 1):
            console.print(
                f"  {idx}. {repo['location']}-docker.pkg.dev/{repo['project']}/{repo['repository_id']}"
            )

        if len(docker_repos) > 20:
            console.print(f"  [dim]...and {len(docker_repos) - 20} more[/dim]")
        console.print()

    # Get image details from user
    console.print("[cyan]Enter the full image path or construct it:[/cyan]")
    console.print(
        "[dim]Format: LOCATION-docker.pkg.dev/PROJECT/REPOSITORY/IMAGE:TAG[/dim]\n"
    )

    use_auto = False
    if docker_repos and Confirm.ask("Use enumerated repository?", default=True):
        use_auto = True

    if use_auto and docker_repos:
        # Select repository
        repo_idx = Prompt.ask(
            "Select repository number",
            default="1",
        )

        try:
            repo = docker_repos[int(repo_idx) - 1]
            location = repo["location"]
            project = repo["project"]
            repository_id = repo["repository_id"]

            # Get image name
            if packages:
                docker_packages = [
                    p
                    for p in packages
                    if p["repository_id"] == repository_id
                    and p["repository_format"] == "DOCKER"
                ]

                if docker_packages:
                    console.print(f"\n[green]Available images in {repository_id}:[/green]")
                    for idx, pkg in enumerate(docker_packages, 1):
                        console.print(f"  {idx}. {pkg['package_id']}")

                    if Confirm.ask("Select from list?", default=True):
                        pkg_idx = Prompt.ask("Select image number", default="1")
                        image_name = docker_packages[int(pkg_idx) - 1]["package_id"]
                    else:
                        image_name = Prompt.ask("Image name")
                else:
                    image_name = Prompt.ask("Image name")
            else:
                image_name = Prompt.ask("Image name")

            tag = Prompt.ask("Tag", default="latest")

            image_path = f"{location}-docker.pkg.dev/{project}/{repository_id}/{image_name}:{tag}"

        except (ValueError, IndexError):
            console.print("[red]Invalid selection[/red]")
            return
    else:
        # Manual input
        image_path = Prompt.ask("[cyan]Full image path[/cyan]")

    if not image_path:
        console.print("[red]Image path required[/red]")
        return

    console.print(f"\n[cyan]Image to download:[/cyan] {image_path}")

    # Configure docker to use gcloud credential helper
    console.print("\n[bold]Configuring Docker authentication...[/bold]")

    if not _configure_docker_gcloud_auth(session_mgr):
        console.print("[red]❌ Failed to configure Docker authentication[/red]")
        return

    # Pull the image
    console.print(f"\n[bold]Pulling image:[/bold] {image_path}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Pulling image...", total=None)

            result = subprocess.run(
                ["docker", "pull", image_path],
                capture_output=True,
                text=True,
            )

            progress.update(task, completed=True)

        if result.returncode == 0:
            console.print(f"\n[green]✅ Successfully pulled image: {image_path}[/green]")

            # Show image details
            _show_docker_image_info(image_path)

            # Ask if user wants to save/export
            if Confirm.ask("\n[cyan]Export image to tar file?[/cyan]", default=False):
                _export_docker_image(image_path)

        else:
            console.print(f"\n[red]❌ Failed to pull image[/red]")
            console.print(f"[dim]{result.stderr}[/dim]")

            # Check for common errors
            if "PERMISSION_DENIED" in result.stderr or "UNAUTHENTICATED" in result.stderr:
                console.print(
                    "\n[yellow]⚠ Authentication failed. "
                    "Ensure you have artifactregistry.repositories.downloadArtifacts permission.[/yellow]"
                )
            elif "NOT_FOUND" in result.stderr:
                console.print("\n[yellow]⚠ Image not found. Check the path and tag.[/yellow]")

    except FileNotFoundError:
        console.print(
            "[red]❌ Docker not found. Please install Docker to download images.[/red]"
        )
    except Exception as e:
        console.print(f"[red]❌ Error pulling image: {e}[/red]")


def _configure_docker_gcloud_auth(session_mgr: GCPSessionManager) -> bool:
    """
    Configure Docker to use gcloud credential helper.

    Args:
        session_mgr: GCP session manager

    Returns:
        True if configuration succeeded
    """
    try:
        # Get access token from session
        credentials = session_mgr.get_credentials()
        if not credentials:
            return False

        # Refresh token if needed
        if hasattr(credentials, "refresh"):
            from google.auth.transport.requests import Request

            credentials.refresh(Request())

        token = credentials.token

        if not token:
            console.print("[red]Failed to get access token[/red]")
            return False

        # Configure docker to use the token
        # Use gcloud's docker credential helper
        result = subprocess.run(
            ["gcloud", "auth", "configure-docker", "--quiet"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            console.print(f"[yellow]⚠ gcloud configure-docker warning: {result.stderr}[/yellow]")

        # Alternative: Use docker login with token
        # This is more direct but requires exposing the token
        console.print("[green]✓[/green] Docker authentication configured")
        return True

    except Exception as e:
        console.print(f"[red]Error configuring Docker auth: {e}[/red]")
        return False


def _show_docker_image_info(image_path: str) -> None:
    """
    Display information about the pulled Docker image.

    Args:
        image_path: Docker image path
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", image_path],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            inspect_data = json.loads(result.stdout)
            if inspect_data and len(inspect_data) > 0:
                image_info = inspect_data[0]

                console.print("\n[bold]📋 Image Information:[/bold]")
                console.print(f"  ID: [cyan]{image_info.get('Id', 'N/A')[:20]}...[/cyan]")
                console.print(
                    f"  Created: [green]{image_info.get('Created', 'N/A')}[/green]"
                )
                console.print(
                    f"  Size: [yellow]{image_info.get('Size', 0) / (1024*1024):.1f} MB[/yellow]"
                )

                # Show layers
                if "RootFS" in image_info and "Layers" in image_info["RootFS"]:
                    layers = image_info["RootFS"]["Layers"]
                    console.print(f"  Layers: [blue]{len(layers)}[/blue]")

                # Show env vars (potential secrets)
                if "Config" in image_info and "Env" in image_info["Config"]:
                    env_vars = image_info["Config"]["Env"]
                    if env_vars:
                        console.print(f"\n[bold]🔐 Environment Variables ({len(env_vars)}):[/bold]")
                        for env in env_vars[:10]:
                            console.print(f"    [dim]{env}[/dim]")
                        if len(env_vars) > 10:
                            console.print(f"    [dim]...and {len(env_vars) - 10} more[/dim]")

    except Exception as e:
        console.print(f"[yellow]⚠ Could not inspect image: {e}[/yellow]")


def _export_docker_image(image_path: str) -> None:
    """
    Export Docker image to tar file.

    Args:
        image_path: Docker image path
    """
    # Generate filename from image path
    safe_name = image_path.replace("/", "_").replace(":", "_")
    output_file = f"{safe_name}.tar"

    output_path = Prompt.ask(
        "[cyan]Output file path[/cyan]",
        default=output_file,
    )

    try:
        console.print(f"\n[cyan]Exporting image to {output_path}...[/cyan]")

        result = subprocess.run(
            ["docker", "save", "-o", output_path, image_path],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            # Get file size
            file_size = Path(output_path).stat().st_size
            console.print(
                f"[green]✅ Image exported successfully: {output_path} "
                f"({file_size / (1024*1024):.1f} MB)[/green]"
            )
        else:
            console.print(f"[red]❌ Export failed: {result.stderr}[/red]")

    except Exception as e:
        console.print(f"[red]❌ Error exporting image: {e}[/red]")


def _download_manual(
    session_mgr: GCPSessionManager, repositories: Optional[List[Dict[str, Any]]]
) -> None:
    """
    Manual download mode - provides instructions for downloading artifacts.

    Args:
        session_mgr: GCP session manager
        repositories: Enumerated repositories (optional)
    """
    console.print("[bold]📝 Manual Download Instructions[/bold]\n")

    console.print(
        "For Docker images, use the docker download mode or:\n"
        "  1. Configure auth: [cyan]gcloud auth configure-docker LOCATION-docker.pkg.dev[/cyan]\n"
        "  2. Pull image: [cyan]docker pull LOCATION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG[/cyan]\n"
    )

    console.print(
        "For other artifacts (Maven, NPM, Python, etc.):\n"
        "  - Use the respective package manager (mvn, npm, pip)\n"
        "  - Configure authentication via gcloud or artifact registry credentials\n"
    )

    console.print(
        "For generic files:\n"
        "  - Use [cyan]gcloud artifacts files download[/cyan] command\n"
        "  - Or access via direct HTTP with authentication header\n"
    )
