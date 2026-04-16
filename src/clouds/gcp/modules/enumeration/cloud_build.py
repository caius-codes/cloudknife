"""
GCP Cloud Build Enumeration for Cloud Knife.

Enumerates Cloud Build triggers, build history, and build logs, including:
- Build triggers with repository connections
- Environment variables and substitutions (may contain sensitive data)
- Secrets and service accounts
- Build history and logs (may expose credentials, tokens, API keys)
- Build configurations and steps
"""

from typing import List, Dict, Any, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from google.auth.transport.requests import Request
import requests

from src.clouds.gcp.utils.projects import resolve_projects

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# Cloud Build API base URLs
CLOUDBUILD_API_BASE = "https://cloudbuild.googleapis.com/v1"
LOGGING_API_BASE = "https://logging.googleapis.com/v2"


def _make_api_request(credentials, url: str) -> Dict[str, Any]:
    """Make authenticated request to Cloud Build API."""
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


def enumerate_cloud_build_triggers(session_mgr: "GCPSessionManager") -> List[Dict[str, Any]]:
    """
    Enumerate all Cloud Build triggers across configured projects.

    Triggers may contain sensitive information in:
    - Substitution variables (environment variables)
    - Secrets mounted as environment variables
    - Repository connection details (GitHub, GitLab, Bitbucket tokens)
    - Service accounts with elevated permissions

    Args:
        session_mgr: GCP session manager with valid credentials

    Returns:
        List of trigger dictionaries with detailed metadata
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    projects = resolve_projects(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return []

    console.print(f"[cyan]Enumerating Cloud Build triggers in {len(projects)} project(s)...[/cyan]")

    all_triggers: List[Dict[str, Any]] = []

    # Parallel execution with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task_id = progress.add_task(f"Scanning {len(projects)} project(s)...", total=None)

        # Use ThreadPoolExecutor for parallel API calls
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_project = {
                executor.submit(_enumerate_triggers_project, credentials, project): project
                for project in projects
            }

            for future in as_completed(future_to_project):
                project = future_to_project[future]
                try:
                    triggers = future.result()
                    if triggers:
                        console.print(f"[dim]  ✓ {project}: found {len(triggers)} trigger(s)[/dim]")
                    all_triggers.extend(triggers)
                except Exception as e:
                    error_msg = str(e)
                    if "Permission denied" not in error_msg and "403" not in error_msg:
                        console.print(f"[yellow]⚠️  {project}: {error_msg[:100]}[/yellow]")

        progress.update(task_id, completed=True)

    # Save enumeration results
    session_mgr.save_enumeration_data("cloud_build_triggers", all_triggers)

    # Display results table
    _display_triggers_table(all_triggers)

    return all_triggers


def _enumerate_triggers_project(
    credentials,
    project: str
) -> List[Dict[str, Any]]:
    """Enumerate Cloud Build triggers in a single project (worker function)."""
    project_triggers: List[Dict[str, Any]] = []

    try:
        url = f"{CLOUDBUILD_API_BASE}/projects/{project}/triggers"
        data = _make_api_request(credentials, url)

        triggers = data.get("triggers", [])

        for trigger in triggers:
            # Extract repository info
            repo_info = {}
            if "github" in trigger:
                github = trigger["github"]
                repo_info = {
                    "type": "github",
                    "owner": github.get("owner", ""),
                    "name": github.get("name", ""),
                    "push_branch": github.get("push", {}).get("branch"),
                    "pull_request": bool(github.get("pullRequest")),
                }
            elif "triggerTemplate" in trigger:
                template = trigger["triggerTemplate"]
                repo_info = {
                    "type": "cloud_source_repo",
                    "repo_name": template.get("repoName", ""),
                    "branch_name": template.get("branchName", ""),
                    "tag_name": template.get("tagName", ""),
                }
            elif "webhookConfig" in trigger:
                repo_info = {
                    "type": "webhook",
                }
            elif "pubsubConfig" in trigger:
                repo_info = {
                    "type": "pubsub",
                    "topic": trigger["pubsubConfig"].get("topic", ""),
                }

            # Extract substitutions (environment variables)
            substitutions = trigger.get("substitutions", {})

            # Extract secrets
            secrets = []
            if "build" in trigger and "secrets" in trigger["build"]:
                for secret in trigger["build"]["secrets"]:
                    secrets.append({
                        "kms_key": secret.get("kmsKeyName", ""),
                        "secret_env": secret.get("secretEnv", {}),
                    })

            # Extract service account
            service_account = trigger.get("serviceAccount")

            # Extract build config
            build_config = None
            if "build" in trigger:
                build = trigger["build"]
                build_config = {
                    "steps": len(build.get("steps", [])),
                    "timeout": build.get("timeout"),
                    "images": build.get("images", []),
                }
            elif "filename" in trigger:
                build_config = {
                    "filename": trigger["filename"],
                }

            # Build trigger record
            trigger_data = {
                "project": project,
                "id": trigger.get("id", ""),
                "name": trigger.get("name", ""),
                "description": trigger.get("description", ""),
                "disabled": trigger.get("disabled", False),
                "repository": repo_info,
                "substitutions": substitutions,
                "secrets": secrets,
                "service_account": service_account,
                "build_config": build_config,
                "create_time": trigger.get("createTime", ""),
                "tags": trigger.get("tags", []),
            }

            project_triggers.append(trigger_data)

    except Exception as e:
        error_str = str(e).lower()
        if "permission denied" not in error_str and "403" not in error_str:
            raise Exception(f"Error enumerating {project}: {str(e)}")

    return project_triggers


def _display_triggers_table(triggers: List[Dict[str, Any]]) -> None:
    """Display Cloud Build triggers in a Rich table."""
    if not triggers:
        console.print("[yellow]No Cloud Build triggers found.[/yellow]")
        return

    table = Table(title=f"Cloud Build Triggers ({len(triggers)} found)")
    table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Name", style="green", overflow="fold", no_wrap=False)
    table.add_column("Status", style="bold")
    table.add_column("Repository", overflow="fold", no_wrap=False)
    table.add_column("Service Account", overflow="fold", no_wrap=False)
    table.add_column("Substitutions", style="yellow")
    table.add_column("Secrets", style="red")

    for trg in triggers:
        # Format status
        status = "Disabled" if trg["disabled"] else "Enabled"
        status_color = "red" if trg["disabled"] else "green"

        # Format repository
        repo = trg["repository"]
        if repo.get("type") == "github":
            repo_display = f"GitHub: {repo.get('owner')}/{repo.get('name')}"
        elif repo.get("type") == "cloud_source_repo":
            repo_display = f"CSR: {repo.get('repo_name')}"
        elif repo.get("type") == "webhook":
            repo_display = "Webhook"
        elif repo.get("type") == "pubsub":
            repo_display = f"PubSub: {repo.get('topic')}"
        else:
            repo_display = "-"

        # Format substitutions count
        sub_count = len(trg["substitutions"])
        sub_display = f"{sub_count} vars" if sub_count > 0 else "-"

        # Format secrets count
        secret_count = len(trg["secrets"])
        secret_display = f"{secret_count} secrets" if secret_count > 0 else "-"

        table.add_row(
            trg["project"],
            trg["name"],
            f"[{status_color}]{status}[/{status_color}]",
            repo_display,
            trg["service_account"] or "-",
            sub_display,
            secret_display,
        )

    console.print(table)

    # Warn if substitutions found
    triggers_with_subs = [t for t in triggers if t["substitutions"]]
    if triggers_with_subs:
        console.print(f"\n[bold yellow]⚠️  {len(triggers_with_subs)} trigger(s) have substitution variables[/bold yellow]")
        console.print("[dim]Substitutions may contain sensitive data. Use 'describe_cloud_build_trigger' to inspect.[/dim]")

    # Warn if secrets found
    triggers_with_secrets = [t for t in triggers if t["secrets"]]
    if triggers_with_secrets:
        console.print(f"\n[bold red]⚠️  {len(triggers_with_secrets)} trigger(s) have secrets configured[/bold red]")


def enumerate_cloud_build_history(
    session_mgr: "GCPSessionManager",
    max_builds: int = 50
) -> List[Dict[str, Any]]:
    """
    Enumerate recent Cloud Build history across configured projects.

    Build logs may contain sensitive information like:
    - API keys and tokens printed in build output
    - Database credentials
    - Internal URLs and endpoints
    - Environment variables exposed in logs

    Args:
        session_mgr: GCP session manager with valid credentials
        max_builds: Maximum number of builds to retrieve per project (default: 50)

    Returns:
        List of build dictionaries with metadata
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return []

    projects = resolve_projects(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return []

    console.print(f"[cyan]Enumerating Cloud Build history in {len(projects)} project(s)...[/cyan]")

    all_builds: List[Dict[str, Any]] = []

    # Parallel execution with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task_id = progress.add_task(f"Scanning {len(projects)} project(s)...", total=None)

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_project = {
                executor.submit(_enumerate_builds_project, credentials, project, max_builds): project
                for project in projects
            }

            for future in as_completed(future_to_project):
                project = future_to_project[future]
                try:
                    builds = future.result()
                    if builds:
                        console.print(f"[dim]  ✓ {project}: found {len(builds)} build(s)[/dim]")
                    all_builds.extend(builds)
                except Exception as e:
                    error_msg = str(e)
                    if "Permission denied" not in error_msg and "403" not in error_msg:
                        console.print(f"[yellow]⚠️  {project}: {error_msg[:100]}[/yellow]")

        progress.update(task_id, completed=True)

    # Save enumeration results
    session_mgr.save_enumeration_data("cloud_build_history", all_builds)

    # Display results table
    _display_builds_table(all_builds)

    return all_builds


def _enumerate_builds_project(
    credentials,
    project: str,
    max_builds: int
) -> List[Dict[str, Any]]:
    """Enumerate Cloud Build history in a single project (worker function)."""
    project_builds: List[Dict[str, Any]] = []

    try:
        url = f"{CLOUDBUILD_API_BASE}/projects/{project}/builds?pageSize={max_builds}"
        data = _make_api_request(credentials, url)

        builds = data.get("builds", [])

        for build in builds:
            # Extract source info
            source_info = {}
            if "source" in build:
                source = build["source"]
                if "repoSource" in source:
                    repo = source["repoSource"]
                    source_info = {
                        "type": "repo",
                        "project_id": repo.get("projectId", ""),
                        "repo_name": repo.get("repoName", ""),
                        "branch_name": repo.get("branchName", ""),
                        "tag_name": repo.get("tagName", ""),
                        "commit_sha": repo.get("commitSha", ""),
                    }
                elif "storageSource" in source:
                    storage = source["storageSource"]
                    source_info = {
                        "type": "storage",
                        "bucket": storage.get("bucket", ""),
                        "object": storage.get("object", ""),
                    }

            # Extract substitutions
            substitutions = build.get("substitutions", {})

            # Build record
            build_data = {
                "project": project,
                "id": build.get("id", ""),
                "status": build.get("status", "UNKNOWN"),
                "source": source_info,
                "substitutions": substitutions,
                "service_account": build.get("serviceAccount"),
                "log_url": build.get("logUrl"),
                "logs_bucket": build.get("logsBucket"),
                "create_time": build.get("createTime", ""),
                "start_time": build.get("startTime", ""),
                "finish_time": build.get("finishTime", ""),
                "steps": len(build.get("steps", [])),
                "images": build.get("images", []),
                "tags": build.get("tags", []),
            }

            project_builds.append(build_data)

            # Only get the requested number
            if len(project_builds) >= max_builds:
                break

    except Exception as e:
        error_str = str(e).lower()
        if "permission denied" not in error_str and "403" not in error_str:
            raise Exception(f"Error enumerating {project}: {str(e)}")

    return project_builds


def _display_builds_table(builds: List[Dict[str, Any]]) -> None:
    """Display Cloud Build history in a Rich table."""
    if not builds:
        console.print("[yellow]No Cloud Build history found.[/yellow]")
        return

    table = Table(title=f"Cloud Build History ({len(builds)} found)")
    table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Build ID", style="dim", overflow="fold", no_wrap=False)
    table.add_column("Status", style="bold")
    table.add_column("Source", overflow="fold", no_wrap=False)
    table.add_column("Steps", style="yellow")
    table.add_column("Service Account", overflow="fold", no_wrap=False)
    table.add_column("Created", style="dim")

    for build in builds:
        # Format status with color
        status = build["status"]
        if status == "SUCCESS":
            status_styled = f"[green]{status}[/green]"
        elif status in ("FAILURE", "TIMEOUT", "CANCELLED"):
            status_styled = f"[red]{status}[/red]"
        elif status in ("WORKING", "QUEUED"):
            status_styled = f"[yellow]{status}[/yellow]"
        else:
            status_styled = status

        # Format source
        source = build["source"]
        if source.get("type") == "repo":
            repo_name = source.get("repo_name", "")
            branch = source.get("branch_name") or source.get("tag_name") or source.get("commit_sha", "")[:7]
            source_display = f"{repo_name}@{branch}"
        elif source.get("type") == "storage":
            source_display = f"gs://{source.get('bucket')}/{source.get('object', '')[:20]}..."
        else:
            source_display = "-"

        # Truncate build ID
        build_id = build["id"][:12] if build["id"] else "-"

        # Format create time (just date)
        create_time = build["create_time"].split("T")[0] if build["create_time"] else "-"

        table.add_row(
            build["project"],
            build_id,
            status_styled,
            source_display,
            str(build["steps"]),
            build["service_account"] or "-",
            create_time,
        )

    console.print(table)

    # Show stats
    status_counts = {}
    for build in builds:
        status = build["status"]
        status_counts[status] = status_counts.get(status, 0) + 1

    console.print(f"\n[bold]Build Status Summary:[/bold]")
    for status, count in sorted(status_counts.items()):
        console.print(f"  {status}: {count}")

    console.print(f"\n[dim]Use 'describe_cloud_build <build_id> [project]' to view logs and detailed information.[/dim]")


def describe_cloud_build(
    session_mgr: "GCPSessionManager",
    build_id: str = None,
    project_id: str = None,
) -> Dict[str, Any]:
    """
    Describe a specific Cloud Build with detailed logs.

    Build logs often contain sensitive information:
    - API keys and tokens printed during build
    - Database credentials
    - Internal URLs and endpoints
    - Environment variables exposed in output
    - Debug information with secrets

    Args:
        session_mgr: GCP session manager with valid credentials
        build_id: Build ID to describe
        project_id: GCP project ID (optional, uses default if not provided)

    Returns:
        Dictionary with detailed build information
    """
    from rich.prompt import Prompt
    from rich.panel import Panel

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return {}

    # Get project
    if not project_id:
        project_id = session_mgr.default_project
        if not project_id:
            project_id = Prompt.ask("[cyan]Project ID[/cyan]")

    # Get build ID
    if not build_id:
        # Try to load from enumeration cache
        session_name = session_mgr.current_session
        enumerated_builds = (
            session_mgr.enumerated_data.get(session_name, {})
            .get("cloud_build_history", [])
            if session_name in session_mgr.enumerated_data
            else []
        )

        if enumerated_builds:
            console.print(f"[green]Found {len(enumerated_builds)} builds in enumeration cache.[/green]")
            console.print("\n[bold]Available builds:[/bold]")
            for idx, b in enumerate(enumerated_builds[:20], 1):  # Show max 20
                status_color = "green" if b["status"] == "SUCCESS" else "red" if b["status"] == "FAILURE" else "yellow"
                console.print(f"  [{idx}] {b['id'][:12]} - [{status_color}]{b['status']}[/{status_color}] - {b['create_time'].split('T')[0]}")

            choice = Prompt.ask(
                "[cyan]Select build number or enter build ID[/cyan]",
                default="1"
            )

            try:
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(enumerated_builds):
                    selected = enumerated_builds[choice_idx]
                    build_id = selected["id"]
                    project_id = selected["project"]
                else:
                    build_id = choice
            except ValueError:
                build_id = choice
        else:
            build_id = Prompt.ask("[cyan]Build ID[/cyan]")

    console.print(f"\n[bold blue]🔍 Describing Cloud Build: {build_id}[/bold blue]")
    console.print(f"[dim]Project: {project_id}[/dim]\n")

    try:
        # Get build details using REST API
        url = f"{CLOUDBUILD_API_BASE}/projects/{project_id}/builds/{build_id}"
        build = _make_api_request(credentials, url)

        # Extract detailed info
        build_info = {
            "id": build.get("id", ""),
            "project": project_id,
            "status": build.get("status", "UNKNOWN"),
            "create_time": build.get("createTime", ""),
            "start_time": build.get("startTime", ""),
            "finish_time": build.get("finishTime", ""),
            "log_url": build.get("logUrl", ""),
            "logs_bucket": build.get("logsBucket", ""),
            "service_account": build.get("serviceAccount"),
        }

        # Display basic info
        console.print("[bold]Basic Information:[/bold]")
        console.print(f"  [cyan]Build ID:[/cyan] {build.get('id', '')}")
        console.print(f"  [cyan]Status:[/cyan] {build.get('status', 'UNKNOWN')}")
        console.print(f"  [cyan]Service Account:[/cyan] {build.get('serviceAccount') or 'N/A'}")
        console.print(f"  [cyan]Created:[/cyan] {build.get('createTime', 'N/A')}")
        console.print(f"  [cyan]Started:[/cyan] {build.get('startTime', 'N/A')}")
        console.print(f"  [cyan]Finished:[/cyan] {build.get('finishTime', 'N/A')}")

        # Source info
        if "source" in build:
            console.print("\n[bold]Source:[/bold]")
            source = build["source"]
            if "repoSource" in source:
                repo = source["repoSource"]
                console.print(f"  [cyan]Type:[/cyan] Cloud Source Repository")
                console.print(f"  [cyan]Repo:[/cyan] {repo.get('repoName', '')}")
                console.print(f"  [cyan]Branch:[/cyan] {repo.get('branchName', '-')}")
                console.print(f"  [cyan]Tag:[/cyan] {repo.get('tagName', '-')}")
                console.print(f"  [cyan]Commit:[/cyan] {repo.get('commitSha', '-')}")
            elif "storageSource" in source:
                storage = source["storageSource"]
                console.print(f"  [cyan]Type:[/cyan] Cloud Storage")
                console.print(f"  [cyan]Bucket:[/cyan] {storage.get('bucket', '')}")
                console.print(f"  [cyan]Object:[/cyan] {storage.get('object', '')}")

        # Substitutions (environment variables)
        substitutions = build.get("substitutions", {})
        if substitutions:
            console.print("\n[bold yellow]⚠️  Substitution Variables (may contain sensitive data):[/bold yellow]")
            sensitive_patterns = [
                "key", "secret", "password", "token", "api", "auth",
                "credential", "database", "db", "connection", "conn"
            ]

            for key, value in substitutions.items():
                key_lower = key.lower()
                is_sensitive = any(pattern in key_lower for pattern in sensitive_patterns)

                if is_sensitive:
                    console.print(f"  [bold red]🔥 {key}:[/bold red] [yellow]{value}[/yellow]")
                else:
                    console.print(f"  [cyan]{key}:[/cyan] {value}")

        # Build steps
        steps = build.get("steps", [])
        if steps:
            console.print(f"\n[bold]Build Steps ({len(steps)}):[/bold]")
            for idx, step in enumerate(steps, 1):
                console.print(f"  [{idx}] {step.get('name', '')}")
                if "args" in step:
                    console.print(f"      Args: {' '.join(step['args'])}")

        # Images produced
        images = build.get("images", [])
        if images:
            console.print(f"\n[bold]Images Produced:[/bold]")
            for img in images:
                console.print(f"  • {img}")

        # Log URL
        log_url = build.get("logUrl")
        if log_url:
            console.print(f"\n[bold]Logs:[/bold]")
            console.print(f"  [cyan]URL:[/cyan] {log_url}")

            # Ask if user wants to fetch logs
            fetch_logs = Prompt.ask(
                "\n[cyan]Fetch build logs? (may contain sensitive data)[/cyan]",
                choices=["y", "n"],
                default="n"
            )

            if fetch_logs.lower() == "y":
                console.print("\n[yellow]Fetching logs...[/yellow]")

                # Build logs are stored in Cloud Logging - use REST API
                try:
                    # Use Cloud Logging REST API
                    logging_url = f"{LOGGING_API_BASE}/entries:list"

                    # Ensure credentials are fresh
                    if hasattr(credentials, 'expired') and credentials.expired:
                        credentials.refresh(Request())
                    if not hasattr(credentials, 'token'):
                        credentials.refresh(Request())

                    headers = {
                        "Authorization": f"Bearer {credentials.token}",
                        "Content-Type": "application/json"
                    }

                    # Build logs filter
                    log_filter = f'resource.type="build" AND resource.labels.build_id="{build.get("id")}"'

                    payload = {
                        "resourceNames": [f"projects/{project_id}"],
                        "filter": log_filter,
                        "pageSize": 1000,
                        "orderBy": "timestamp asc"
                    }

                    response = requests.post(logging_url, headers=headers, json=payload, timeout=30)
                    response.raise_for_status()
                    log_data = response.json()

                    entries = log_data.get("entries", [])

                    if entries:
                        logs = []
                        for entry in entries:
                            if "textPayload" in entry:
                                logs.append(entry["textPayload"])
                            elif "jsonPayload" in entry:
                                logs.append(str(entry["jsonPayload"]))

                        console.print(f"\n[bold]Build Logs ({len(logs)} entries):[/bold]")
                        full_log = "\n".join(logs)

                        # Check for sensitive patterns in logs
                        console.print("\n[bold yellow]⚠️  Scanning logs for sensitive patterns...[/bold yellow]")
                        sensitive_found = []
                        for pattern in sensitive_patterns:
                            if pattern in full_log.lower():
                                sensitive_found.append(pattern)

                        if sensitive_found:
                            console.print(f"[bold red]🔥 Found potential sensitive patterns: {', '.join(sensitive_found)}[/bold red]")

                        # Display logs with syntax highlighting
                        console.print(Panel(Syntax(full_log[:5000], "bash", theme="monokai", line_numbers=False), title="Build Logs (truncated to 5000 chars)"))

                        if len(full_log) > 5000:
                            console.print(f"[dim]Log truncated. Full log has {len(full_log)} characters.[/dim]")
                    else:
                        console.print("[yellow]No logs found. They may have been deleted or aren't accessible.[/yellow]")

                except Exception as log_err:
                    console.print(f"[red]Error fetching logs: {log_err}[/red]")
                    console.print(f"[dim]You can view logs at: {log_url}[/dim]")

        # Save to session
        session_mgr.save_enumeration_data(f"build_describe_{build_id}", build_info)
        console.print(f"\n[green]Build details saved under key 'build_describe_{build_id}' in session data.[/green]")

        return build_info

    except Exception as e:
        console.print(f"[red]Error describing build: {e}[/red]")
        return {}
