"""
GCP Source Repositories Enumeration for Cloud Knife.

Enumerates Google Cloud Source Repositories, including:
- Repository metadata (name, URL, size)
- IAM policies
- Mirror configurations
- Pubsub configs

Supports authentication via:
- Service Account JSON key file
- Application Default Credentials (ADC)
- Raw access token (via REST API)
"""

from typing import List, Dict, Any, TYPE_CHECKING

import requests
from rich.console import Console
from rich.table import Table

from src.clouds.gcp.utils.projects import resolve_projects

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# Source Repositories API base URL
SOURCE_REPO_API_BASE = "https://sourcerepo.googleapis.com/v1"


def enumerate_source_repositories(session_mgr: "GCPSessionManager") -> List[Dict[str, Any]]:
    """
    Enumerate all Source Repositories across configured projects.

    Uses REST API for access_token auth, client library for service_account/ADC.

    Args:
        session_mgr: GCP session manager with valid credentials

    Returns:
        List of repository dictionaries with detailed metadata
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    projects = resolve_projects(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return []

    auth_method = session_mgr.current_session_data.get("auth_method")
    all_repos: List[Dict[str, Any]] = []

    for project in projects:
        console.print(f"[dim]Scanning project: {project}[/dim]")

        try:
            if auth_method == "access_token":
                # Use REST API for access_token auth
                repos = _enumerate_repos_rest_api(session_mgr, project)
            else:
                # Use REST API with refreshed token for service_account/ADC
                repos = _enumerate_repos_with_credentials(session_mgr, project, credentials)

            all_repos.extend(repos)

        except Exception as e:
            console.print(f"[dim red]Error scanning project {project}: {str(e)}[/dim red]")
            continue

    # Save enumeration results
    session_mgr.save_enumeration_data("source_repositories", all_repos)

    # Display results table
    _display_repos_table(all_repos)

    return all_repos


def _enumerate_repos_rest_api(
    session_mgr: "GCPSessionManager", project: str
) -> List[Dict[str, Any]]:
    """Enumerate repositories using REST API (for access_token auth)."""
    token = session_mgr.current_session_data.get("access_token")
    if not token:
        return []

    headers = {"Authorization": f"Bearer {token}"}
    repos: List[Dict[str, Any]] = []

    # List repositories for project
    url = f"{SOURCE_REPO_API_BASE}/projects/{project}/repos"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        # Extract repos from response
        repo_list = data.get("repos", [])

        for repo in repo_list:
            repo_info = _extract_repo_info(repo, project)

            # Try to fetch IAM policy
            try:
                iam_policy = _get_repo_iam_policy(repo["name"], headers)
                repo_info["iam_policy"] = iam_policy
            except Exception:
                repo_info["iam_policy"] = None

            repos.append(repo_info)

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            console.print(f"[dim yellow]Access denied to project {project}[/dim yellow]")
        elif e.response.status_code == 404:
            # API not enabled or no repos
            pass
        else:
            console.print(f"[dim red]HTTP error for {project}: {e}[/dim red]")
    except Exception as e:
        console.print(f"[dim red]Error for {project}: {str(e)}[/dim red]")

    return repos


def _enumerate_repos_with_credentials(
    session_mgr: "GCPSessionManager", project: str, credentials
) -> List[Dict[str, Any]]:
    """Enumerate repositories using service account/ADC credentials."""
    from google.auth.transport.requests import Request

    # Refresh credentials to get a valid token
    credentials.refresh(Request())
    token = credentials.token

    headers = {"Authorization": f"Bearer {token}"}
    repos: List[Dict[str, Any]] = []

    # List repositories for project
    url = f"{SOURCE_REPO_API_BASE}/projects/{project}/repos"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        # Extract repos from response
        repo_list = data.get("repos", [])

        for repo in repo_list:
            repo_info = _extract_repo_info(repo, project)

            # Try to fetch IAM policy
            try:
                iam_policy = _get_repo_iam_policy(repo["name"], headers)
                repo_info["iam_policy"] = iam_policy
            except Exception:
                repo_info["iam_policy"] = None

            repos.append(repo_info)

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            console.print(f"[dim yellow]Access denied to project {project}[/dim yellow]")
        elif e.response.status_code == 404:
            # API not enabled or no repos
            pass
        else:
            console.print(f"[dim red]HTTP error for {project}: {e}[/dim red]")
    except Exception as e:
        console.print(f"[dim red]Error for {project}: {str(e)}[/dim red]")

    return repos


def _extract_repo_info(repo: Dict[str, Any], project: str) -> Dict[str, Any]:
    """Extract repository information from API response."""
    repo_name = repo.get("name", "")
    # Extract just the repo ID from full name (projects/{project}/repos/{repo})
    repo_id = repo_name.split("/")[-1] if "/" in repo_name else repo_name

    return {
        "project": project,
        "name": repo_id,
        "full_name": repo_name,
        "url": repo.get("url", ""),
        "size": repo.get("size", 0),
        "mirror_config": repo.get("mirrorConfig"),
        "pubsub_configs": repo.get("pubsubConfigs", []),
    }


def _get_repo_iam_policy(repo_name: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """Fetch IAM policy for a repository."""
    url = f"{SOURCE_REPO_API_BASE}/{repo_name}:getIamPolicy"

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    return response.json()


def _display_repos_table(repos: List[Dict[str, Any]]) -> None:
    """Display source repositories in a formatted table."""
    if not repos:
        console.print("[yellow]No source repositories found.[/yellow]")
        return

    table = Table(title=f"Source Repositories ({len(repos)} total)")
    table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Repository", style="green", overflow="fold", no_wrap=False)
    table.add_column("URL", style="blue", overflow="fold", no_wrap=False)
    table.add_column("Size", style="magenta")
    table.add_column("IAM", style="yellow")

    for repo in repos:
        iam_status = "✓" if repo.get("iam_policy") else "✗"

        # Format size in human-readable format
        size_bytes = repo.get("size", 0)
        if size_bytes == 0:
            size_str = "N/A"
        elif size_bytes < 1024:
            size_str = f"{size_bytes}B"
        elif size_bytes < 1024 * 1024:
            size_str = f"{size_bytes / 1024:.1f}KB"
        elif size_bytes < 1024 * 1024 * 1024:
            size_str = f"{size_bytes / (1024 * 1024):.1f}MB"
        else:
            size_str = f"{size_bytes / (1024 * 1024 * 1024):.1f}GB"

        table.add_row(
            repo.get("project", ""),
            repo.get("name", ""),
            repo.get("url", ""),
            size_str,
            iam_status,
        )

    console.print(table)

    # Summary of interesting findings
    repos_with_iam = [r for r in repos if r.get("iam_policy")]
    if repos_with_iam:
        console.print(f"\n[green]✓ {len(repos_with_iam)} repositories with accessible IAM policies[/green]")

    repos_with_mirrors = [r for r in repos if r.get("mirror_config")]
    if repos_with_mirrors:
        console.print(f"[cyan]ℹ {len(repos_with_mirrors)} repositories with mirror configs[/cyan]")
