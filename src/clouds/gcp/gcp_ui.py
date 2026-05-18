"""
GCP UI components for Cloud Knife.

Provides Rich-based UI elements for the GCP CLI including:
- Session tables
- Help menus
- Prompts and confirmations
"""

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...version import __version__

console = Console()


def print_banner(version: str = __version__):
    """Display GCP module banner."""
    console.print(f"\n[bold purple]☁️ Cloud Knife v{version} - GCP Module[/bold purple]")
    console.print("[dim]Authorized use ONLY![/dim]\n")


def show_sessions_table(sessions):
    """Display existing GCP sessions in a table."""
    if not sessions:
        console.print("[yellow]No GCP sessions found.[/yellow]")
        return

    table = Table(title="Existing GCP Sessions")
    table.add_column("Name", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Session ID", style="dim")
    table.add_column("Auth")
    table.add_column("Project", overflow="fold", no_wrap=False)
    table.add_column("Service Account", overflow="fold", no_wrap=False)
    table.add_column("Active")

    for s in sessions:
        active = "[bold green]★[/bold green]" if s["current"] else ""

        # Format auth method
        auth_method = s.get("auth_method", "")
        if auth_method == "service_account":
            auth_display = "[green]SA Key[/green]"
        elif auth_method == "adc":
            auth_display = "[cyan]ADC[/cyan]"
        elif auth_method == "access_token":
            # Check if impersonated
            if s.get("impersonated_sa"):
                auth_display = "[magenta]Impersonated[/magenta]"
            else:
                auth_display = "[yellow]Token[/yellow]"
        else:
            auth_display = "[red]Not set[/red]"

        # Show full service account email (use impersonated_sa if available)
        sa_email = s.get("impersonated_sa", "") or s.get("service_account", "") or "-"

        session_id = s.get("session_id", "") or "N/A"

        table.add_row(
            f"{s['name']}{active}",
            session_id,
            auth_display,
            s.get("project_id", "") or "[dim]-[/dim]",
            sa_email,
            "Yes" if s["current"] else "No",
        )

    console.print(table)


def ask_initial_session_choice(has_sessions: bool, session_names: list[str]) -> tuple[str, bool]:
    """
    At startup, ask whether to use a new or existing session.

    Returns:
        Tuple of (session_name, is_new_session)
    """
    if has_sessions:
        choice = Prompt.ask(
            "[cyan][1] New session [2] Use existing[/cyan]",
            choices=["1", "2"],
            default="2"
        )
    else:
        console.print("[yellow]No sessions yet. Creating a new one.[/yellow]")
        choice = "1"

    if choice == "1":
        name = Prompt.ask("[cyan]New session name[/cyan]")
        return name, True
    else:
        # Return empty string to indicate existing session selection needed
        return "", False


def show_prompt_status(session_name: str | None, has_credentials: bool):
    """Show prompt status with credential indicator."""
    status = "[green]✓[/green]" if has_credentials else "[red]✗[/red]"
    console.print(f"[dim]Prompt: cloudknife[{session_name} {status}]> [/dim]\n")


def confirm_delete_session(session_name: str) -> bool:
    """Ask for confirmation before deleting a session."""
    return Confirm.ask(f"[bold red]Delete session '{session_name}' permanently?[/bold red]")


def print_help():
    """Display help menu with all available GCP commands."""
    # Collect all commands and descriptions to calculate max widths for consistent alignment
    all_data = [
        # General
        ("help / ?", "Show this help"),
        ("search <keyword>", "Search modules by keyword"),
        ("clear_sessions", "Delete all saved GCP sessions from disk"),
        (r"cloud \[aws | gcp | azure]", "Switch to another cloud provider"),
        ("delete_session [name]", "Delete a session"),
        ("discover_projects", "List all accessible GCP projects"),
        ("list_sessions", "List all GCP sessions"),
        ("new_session <name>", "Create a new session"),
        ("set_adc", "Use Application Default Credentials (gcloud auth)"),
        ("set_credentials <path>", "Set service account JSON key file"),
        ("set_project <project-id>", "Set default project for operations"),
        ("set_projects <p1> <p2> | all", "Set projects list for enumeration"),
        ("set_token <token> [project] [sa_email]", "Set raw access token (from SSRF, metadata, etc.)"),
        ("set_token_file <path> [project]", "Set access token from file"),
        ("set_zones <z1> <z2> | all", "Set zones list for enumeration"),
        ("show_config", "Show current session configuration"),
        ("token_info", "Show access token details (expiry, scopes, identity)"),
        ("use_session [name]", "Switch to an existing session"),
        ("whoami", "Show current GCP identity"),
        ("exit / quit", "Exit Cloud Knife"),
        # Enumeration (alphabetically sorted)
        ("analyze_privilege_escalation_paths", "Analyze privilege escalation paths from bruteforce results"),
        ("describe_cloud_build [build_id] [project]", "Describe Cloud Build with logs (may contain API keys, passwords, credentials in build output)"),
        ("describe_cloud_run_service [name] [project] [region]", "Describe Cloud Run service with detailed env vars (highlights sensitive data: API keys, passwords)"),
        ("describe_drive_file <file_id>", "Show detailed permissions for a Google Drive file"),
        ("describe_instance [name] [project] [zone]", "Describe instance with metadata/startup scripts (highlights sensitive data: passwords, keys)"),
        ("describe_metadata_detail [instance] [key]", "Describe full metadata value for an instance or project"),
        ("describe_role [role] [project]", "Describe an IAM role and its permissions (highlights dangerous ones)"),
        ("describe_service_account_iam_policy [sa_email]", "Describe who can impersonate a service account (IAM bindings)"),
        ("enumerate_artifact_packages", "List packages within Artifact Registry repositories"),
        ("enumerate_artifact_versions", "List versions and tags for packages in Artifact Registry"),
        ("enumerate_artifacts [project]", "List Artifact Registry repositories (Docker, Maven, NPM, etc.) across projects"),
        ("enumerate_bruteforce_permissions [svc] [mode]", "Enumerate IAM permissions via testIamPermissions API (fast: 109 perms/7 svc | full: 246 perms/18 svc | low: 112 perms/22 svc)"),
        ("enumerate_build_history [max]", "List recent Cloud Build history (status, source, service accounts)"),
        ("enumerate_build_triggers", "List Cloud Build triggers (repo connections, substitutions, secrets, service accounts)"),
        ("enumerate_compute", "List Compute Engine VMs (IPs, service accounts, status) across projects/zones"),
        ("enumerate_compute_metadata", "Enumerate instance & project metadata (detects sensitive data: passwords, keys, scripts)"),
        ("enumerate_delegation_chains [proj] [sa|file]", "Discover implicitDelegation by testing actual chains (sa: email or file path with SA list)"),
        ("enumerate_drive [query] [max]", "List Google Drive files (with permissions analysis, highlights publicly shared files)"),
        ("enumerate_exploitable_sas [project] [sa|file]", "Find SAs with dangerous permissions - accepts single SA email or file (one SA per line) or uses enumerate_iam results"),
        ("enumerate_functions [v1|v2|all]", "List Cloud Functions (v1: Gen 1 only | v2: Gen 2 only | all: both generations) with triggers, runtime, service accounts"),
        ("enumerate_iam", "Enumerate IAM policies, service accounts, and keys across projects"),
        ("enumerate_objects <bucket> [prefix]", "List all objects in a specific bucket (with optional prefix filter)"),
        ("enumerate_parameters [project]", "List Parameter Manager parameters and versions in a project"),
        ("enumerate_predefined_roles [filter]", "Enumerate predefined GCP roles (filter by name pattern)"),
        ("enumerate_resource_permissions [type] [name]", "Discover permissions on a specific resource (bucket, function, SA, etc.)"),
        ("enumerate_run_services", "List Cloud Run services (URLs, env vars, public/private, service accounts)"),
        ("enumerate_secrets [project]", "List Secret Manager secrets and versions in a project"),
        ("enumerate_shared_files [public]", "Enumerate shared Google Drive files (use 'public' to show only publicly accessible files)"),
        ("enumerate_source_repos", "List Google Source Repositories (code repos) with IAM policies and mirror configs across projects"),
        ("enumerate_sql", "List Cloud SQL instances (MySQL, PostgreSQL, SQL Server) with databases, users, and security settings"),
        ("enumerate_storage", "List Cloud Storage buckets (public access, IAM, encryption) across projects"),
        ("quick_enum", "Quick overview of key GCP services (Compute, Functions, Run, Storage, Secrets, IAM) - Fast!"),
        ("search_drive [keyword1] [keyword2] ...", "Search Google Drive for files with sensitive keywords (default: password, secret, key, token)"),
        # Lateral Movement
        ("create_sa_key [sa_email]", "Create a persistent key for a service account"),
        ("delete_sa_key [sa_email] [key_id]", "Delete a service account key"),
        ("find_chains [target_sa]", "Find delegation chains to reach a target service account"),
        ("gen_token_curl <sa> [delegates]", "Generate curl command for implicit delegation attack"),
        ("get_sa_iam_policy [sa_email]", "View IAM policy for a service account"),
        ("impersonate [sa | chain N]", "Impersonate a service account (sa: direct impersonation with email | chain N: use delegation chain number N from enumerate_delegation_chains)"),
        ("list_sa_keys [sa_email]", "List keys for a service account"),
        ("map_impersonation [project]", "Map impersonation graph (who can impersonate which SA)"),
        ("remove_sa_iam_binding [sa] [member] [role]", "Remove a binding from SA IAM policy"),
        ("set_sa_iam_policy [sa] [member] [role]", "Grant impersonation rights on SA (privilege escalation!)"),
        ("sign_blob [sa_email]", "Sign arbitrary data as a service account"),
        ("sign_jwt [sa_email]", "Sign JWT as SA and exchange for access token"),
        ("sign_jwt_batch", "Sign JWT as SA and exchange for access token through a delegate, or batch it"),
        ("impersonate_jwt [--template id] [options]", "Impersonate SA using JWT (interactive wizard or template-based)"),
        ("show_jwt_templates", "Show available JWT templates for common scenarios (Drive, Workspace, etc.)"),
        ("generate_jwt [--template id] [options]", "Generate self-signed JWT with custom claims"),
        ("exchange_jwt <jwt_token>", "Exchange JWT for OAuth access token"),
        # Exfiltration (alphabetically sorted)
        ("clone_all_source_repos [project] [output_dir]", "Clone all Source Repositories from a project (uses session credentials including impersonation)"),
        ("clone_source_repo [repo] [project] [output_dir]", "Clone a single Source Repository (useful when only specific SAs have access)"),
        ("download_artifact", "Download artifacts from Artifact Registry (Docker images, packages, etc.)"),
        ("download_drive_file <file_id> [dir] [name]", "Download a single Google Drive file (exports Google Docs/Sheets as PDF)"),
        ("download_drive_files [dir] [workers]", "Download all files from enumeration results (batch download with parallel workers)"),
        ("download_object <bucket> <object>", "Download a single object from a bucket"),
        ("download_bucket <bucket> [prefix]", "Download all objects from a bucket (with size/count limits)"),
        ("exfiltrate_parameter <name> [project] [loc]", "Extract a single parameter value"),
        ("exfiltrate_parameters [project]", "Extract all Parameter Manager values (auto base64 decode)"),
        ("exfiltrate_secret <name> [project] [version] [location]", "Extract a single secret value (location for regional secrets)"),
        ("exfiltrate_secrets [project]", "Extract all Secret Manager values (auto base64 decode)"),
        # Miscellaneous
        ("gcloud ...", "Run gcloud CLI with session credentials (pipe | jq supported)"),
        ("gsutil ...", "Run gsutil CLI with session credentials (pipe | jq supported)"),
    ]

    # Calculate max widths for consistent column alignment across all tables
    max_cmd_width = max(len(cmd) for cmd, _ in all_data)
    max_desc_width = max(len(desc) for _, desc in all_data)

    with console.pager(styles=True):
        console.print("\n[bold blue]GCP Session Commands[/bold blue]\n")

        # General (alphabetically sorted)
        table1 = Table(title="[cyan]General[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table1.add_column("Command", style="bold", width=max_cmd_width)
        table1.add_column("Description", width=max_desc_width)
        table1.add_row("clear_sessions", "Delete all saved GCP sessions from disk")
        table1.add_row(r"cloud \[aws | gcp | azure]", "Switch to another cloud provider")
        table1.add_row("delete_session [name]", "Delete a session")
        table1.add_row("discover_projects", "List all accessible GCP projects")
        table1.add_row("exit / quit", "Exit Cloud Knife")
        table1.add_row("help / ?", "Show this help")
        table1.add_row("list_sessions", "List all GCP sessions")
        table1.add_row("new_session <name>", "Create a new session")
        table1.add_row("set_adc", "Use Application Default Credentials (gcloud auth)")
        table1.add_row("set_credentials <path>", "Set service account JSON key file")
        table1.add_row("set_project <project-id>", "Set default project for operations")
        table1.add_row("set_projects <p1> <p2> | all", "Set projects list for enumeration")
        table1.add_row("set_token <token> [project] [sa_email]", "Set raw access token (from SSRF, metadata, etc.)")
        table1.add_row("set_token_file <path> [project]", "Set access token from file")
        table1.add_row("set_zones <z1> <z2> | all", "Set zones list for enumeration")
        table1.add_row("show_config", "Show current session configuration")
        table1.add_row("token_info", "Show access token details (expiry, scopes, identity)")
        table1.add_row("use_session [name]", "Switch to an existing session")
        table1.add_row("whoami", "Show current GCP identity")
        console.print(table1)

        console.print()

        # Enumeration (alphabetically sorted)
        table2 = Table(title="[cyan]Enumeration[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table2.add_column("Command", style="bold", width=max_cmd_width)
        table2.add_column("Description", width=max_desc_width)
        table2.add_row(
            "analyze_privilege_escalation_paths",
            "Analyze privilege escalation paths from bruteforce results",
        )
        table2.add_row(
            "describe_cloud_build [build_id] [project]",
            "Describe Cloud Build with logs (may contain API keys, passwords, credentials in build output)",
        )
        table2.add_row(
            "describe_cloud_run_service [name] [project] [region]",
            "Describe Cloud Run service with detailed env vars (highlights sensitive data: API keys, passwords)",
        )
        table2.add_row(
            "describe_drive_file <file_id>",
            "Show detailed permissions for a Google Drive file",
        )
        table2.add_row(
            "describe_instance [name] [project] [zone]",
            "Describe instance with metadata/startup scripts (highlights sensitive data: passwords, keys)",
        )
        table2.add_row(
            "describe_metadata_detail [instance] [key]",
            "Describe full metadata value for an instance or project",
        )
        table2.add_row(
            "describe_role [role] [project]",
            "Describe an IAM role and its permissions (highlights dangerous ones)",
        )
        table2.add_row(
            "describe_service_account_iam_policy [sa_email]",
            "Describe who can impersonate a service account (IAM bindings)",
        )
        table2.add_row(
            "enumerate_artifact_packages",
            "List packages within Artifact Registry repositories",
        )
        table2.add_row(
            "enumerate_artifact_versions",
            "List versions and tags for packages in Artifact Registry",
        )
        table2.add_row(
            "enumerate_artifacts [project]",
            "List Artifact Registry repositories (Docker, Maven, NPM, etc.) across projects",
        )
        table2.add_row(
            "enumerate_bruteforce_permissions [svc] [mode]",
            "Enumerate IAM permissions via testIamPermissions API (fast: 109 perms/7 svc | full: 246 perms/18 svc | low: 112 perms/22 svc)",
        )
        table2.add_row(
            "enumerate_build_history [max]",
            "List recent Cloud Build history (status, source, service accounts)",
        )
        table2.add_row(
            "enumerate_build_triggers",
            "List Cloud Build triggers (repo connections, substitutions, secrets, service accounts)",
        )
        table2.add_row(
            "enumerate_compute",
            "List Compute Engine VMs (IPs, service accounts, status) across projects/zones",
        )
        table2.add_row(
            "enumerate_compute_metadata",
            "Enumerate instance & project metadata (detects sensitive data: passwords, keys, scripts)",
        )
        table2.add_row(
            "enumerate_delegation_chains [proj] [sa]",
            "Discover implicitDelegation by testing actual chains (works without IAM read!)",
        )
        table2.add_row(
            "enumerate_drive [query] [max]",
            "List Google Drive files (with permissions analysis, highlights publicly shared files)",
        )
        table2.add_row(
            "enumerate_exploitable_sas [project]",
            "Find SAs where you have dangerous permissions (impersonate, signJwt, etc.)",
        )
        table2.add_row(
            "enumerate_functions [v1|v2|all]",
            "List Cloud Functions (v1: Gen 1 only | v2: Gen 2 only | all: both generations) with triggers, runtime, service accounts",
        )
        table2.add_row(
            "enumerate_iam",
            "Enumerate IAM policies, service accounts, and keys across projects",
        )
        table2.add_row(
            "enumerate_objects <bucket> [prefix]",
            "List all objects in a specific bucket (with optional prefix filter)",
        )
        table2.add_row(
            "enumerate_parameters [project]",
            "List Parameter Manager parameters and versions in a project",
        )
        table2.add_row(
            "enumerate_predefined_roles [filter]",
            "Enumerate predefined GCP roles (filter by name pattern)",
        )
        table2.add_row(
            "enumerate_resource_permissions [type] [name]",
            "Discover permissions on a specific resource (bucket, function, SA, etc.)",
        )
        table2.add_row(
            "enumerate_run_services",
            "List Cloud Run services (URLs, env vars, public/private, service accounts)",
        )
        table2.add_row(
            "enumerate_secrets [project]",
            "List Secret Manager secrets and versions in a project",
        )
        table2.add_row(
            "enumerate_shared_files [public]",
            "Enumerate shared Google Drive files (use 'public' to show only publicly accessible files)",
        )
        table2.add_row(
            "enumerate_source_repos",
            "List Google Source Repositories (code repos) with IAM policies and mirror configs across projects",
        )
        table2.add_row(
            "enumerate_sql",
            "List Cloud SQL instances (MySQL, PostgreSQL, SQL Server) with databases, users, and security settings",
        )
        table2.add_row(
            "enumerate_storage",
            "List Cloud Storage buckets (public access, IAM, encryption) across projects",
        )
        table2.add_row(
            "quick_enum",
            "Quick overview of key GCP services (Compute, Functions, Run, Storage, Secrets, IAM) - Fast!",
        )
        table2.add_row(
            "search_drive [keyword1] [keyword2] ...",
            "Search Google Drive for files with sensitive keywords (default: password, secret, key, token)",
        )
        console.print(table2)

        console.print()

        # Lateral Movement (alphabetically sorted)
        table3 = Table(title="[cyan]Lateral Movement[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table3.add_column("Command", style="bold", width=max_cmd_width)
        table3.add_column("Description", width=max_desc_width)
        table3.add_row(
            "create_sa_key [sa_email]",
            "Create a persistent key for a service account",
        )
        table3.add_row(
            "delete_sa_key [sa_email] [key_id]",
            "Delete a service account key",
        )
        table3.add_row(
            "exchange_jwt <jwt_token>",
            "Exchange JWT for OAuth access token",
        )
        table3.add_row(
            "find_chains [target_sa]",
            "Find delegation chains to reach a target service account",
        )
        table3.add_row(
            "gen_token_curl <sa> [delegates]",
            "Generate curl command for implicit delegation attack",
        )
        table3.add_row(
            "generate_jwt [--template id] [options]",
            "Generate self-signed JWT with custom claims",
        )
        table3.add_row(
            "get_sa_iam_policy [sa_email]",
            "View IAM policy for a service account",
        )
        table3.add_row(
            "impersonate [sa | chain N]",
            "Impersonate a service account (sa: direct impersonation with email | chain N: use delegation chain number N from enumerate_delegation_chains)",
        )
        table3.add_row(
            "impersonate_jwt [--template id] [options]",
            "Impersonate SA using JWT (interactive wizard or template-based)",
        )
        table3.add_row(
            "list_sa_keys [sa_email]",
            "List keys for a service account",
        )
        table3.add_row(
            "map_impersonation [project]",
            "Map impersonation graph (who can impersonate which SA)",
        )
        table3.add_row(
            "remove_sa_iam_binding [sa] [member] [role]",
            "Remove a binding from SA IAM policy",
        )
        table3.add_row(
            "set_sa_iam_policy [sa] [member] [role]",
            "Grant impersonation rights on SA (privilege escalation!)",
        )
        table3.add_row(
            "show_jwt_templates",
            "Show available JWT templates for common scenarios (Drive, Workspace, etc.)",
        )
        table3.add_row(
            "sign_blob [sa_email]",
            "Sign arbitrary data as a service account",
        )
        table3.add_row(
            "sign_jwt [sa_email]",
            "Sign JWT as SA and exchange for access token",
        )
        table3.add_row(
            "sign_jwt_batch",
            "Sign JWT as SA and exchange for access token through a delegate, or batch it",
        )
        console.print(table3)

        console.print()

        # Exfiltration (alphabetically sorted)
        table4 = Table(title="[cyan]Exfiltration[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table4.add_column("Command", style="bold", width=max_cmd_width)
        table4.add_column("Description", width=max_desc_width)
        table4.add_row(
            "download_artifact",
            "Download artifacts from Artifact Registry (Docker images, packages, etc.)",
        )
        table4.add_row(
            "download_drive_file <file_id> [dir] [name]",
            "Download a single Google Drive file (exports Google Docs/Sheets as PDF)",
        )
        table4.add_row(
            "download_drive_files [dir] [workers]",
            "Download all files from enumeration results (batch download with parallel workers)",
        )
        table4.add_row(
            "download_object <bucket> <object>",
            "Download a single object from a bucket",
        )
        table4.add_row(
            "download_bucket <bucket> [prefix]",
            "Download all objects from a bucket (with size/count limits)",
        )
        table4.add_row(
            "exfiltrate_parameter <name> [project] [loc]",
            "Extract a single parameter value",
        )
        table4.add_row(
            "exfiltrate_parameters [project]",
            "Extract all Parameter Manager values (auto base64 decode)",
        )
        table4.add_row(
            "exfiltrate_secret <name> [project] [version] [location]",
            "Extract a single secret value (location for regional secrets)",
        )
        table4.add_row(
            "exfiltrate_secrets [project]",
            "Extract all Secret Manager values (auto base64 decode)",
        )
        console.print(table4)

        console.print()

        # Miscellaneous
        table5 = Table(title="[cyan]Miscellaneous[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table5.add_column("Command", style="bold", width=max_cmd_width)
        table5.add_column("Description", width=max_desc_width)
        table5.add_row(
            "gcloud ...",
            "Run gcloud CLI with session credentials (pipe | jq supported)",
        )
        table5.add_row(
            "gsutil ...",
            "Run gsutil CLI with session credentials (pipe | jq supported)",
        )
        console.print(table5)

        console.print("\n[dim]Tip: Use enumerate_exploitable_sas to find targets for lateral movement[/dim]\n")
