# src/clouds/azure/azure_ui.py

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...version import __version__

console = Console()

AZURE_LOGO = "[bold blue]AZURE[/bold blue]"


def print_banner(version: str = __version__):
    console.print(f"\n[bold dodger_blue2]☁️ Cloud Knife v{version} - Azure Module[/bold dodger_blue2]")
    console.print("[dim]Authorized use ONLY![/dim]\n")


def show_sessions_table(sessions):
    azure_sessions = [s for s in sessions if s.get("cloud") in (None, "azure")]

    if not azure_sessions:
        console.print("[yellow]No Azure sessions found.[/yellow]")
        return

    table = Table(title="Azure Sessions")
    table.add_column("Name", style="cyan")
    table.add_column("Session ID", style="dim")
    table.add_column("Subscription")
    table.add_column("Tenant")
    table.add_column("Account")
    table.add_column("Active")

    for s in azure_sessions:
        active = "[bold green]★[/bold green]" if s["current"] else ""
        # Show complete UUID
        session_id = s.get("session_id", "") or "N/A"
        table.add_row(
            f"{s['name']}{active}",
            session_id,
            s.get("subscription_name", s.get("subscription_id", "")) or "",
            s.get("tenant_id", "") or "",
            s.get("account_name", "") or "",
            "Yes" if s["current"] else "No",
        )

    console.print(table)


def ask_initial_session_choice(has_sessions: bool, session_names: list[str]) -> tuple[str, bool]:
    if has_sessions:
        choice = Prompt.ask(
            "[cyan][1] New Azure session [2] Use existing[/cyan]",
            choices=["1", "2"],
            default="2",
        )
    else:
        console.print("[yellow]No Azure sessions yet. Creating a new one.[/yellow]")
        choice = "1"

    if choice == "1":
        name = Prompt.ask("[cyan]New Azure session name[/cyan]")
        return name, True
    else:
        return "", False


def show_prompt_status(session_name: str | None, has_login: bool):
    status = "[green]✓[/green] " if has_login else "[red]✗[/red] "
    console.print(f"[dim]Prompt: AZURE cloudknife[{session_name} {status}]> [/dim]\n")


def confirm_delete_session(session_name: str) -> bool:
    return Confirm.ask(
        f"[bold red]Delete Azure session '{session_name}' permanently?[/bold red]"
    )


def print_help():
    # Collect all commands and descriptions to calculate max widths for consistent alignment
    all_data = [
        # Authentication
        ("az_login", "Legacy: Try username/password then fallback to browser (use login_az_cli instead)"),
        ("login_az_cli", "Browser login via Azure CLI (recommended for MFA/Conditional Access)"),
        ("set_service_principal", "Service principal auth (tenant_id, client_id, client_secret) — for automation/scripts"),
        ("login_interactive", "Browser login via SDK (may fail with Conditional Access — use login_az_cli instead)"),
        ("login_device_code", "Device code flow for remote/SSH sessions (shows code to enter on another device)"),
        ("login_password", "Username/password (ROPC flow) — for ADFS/federated tenants or MFA bypass testing"),
        ("set_token", "Use stolen/SSRF access token — auto-detects audience (Graph/ARM/etc.) from JWT"),
        ("set_refresh_token", "Use stolen refresh token — auto-discovers accessible services (CloudProwl: tests 8 Microsoft APIs)"),
        ("login_managed_identity", "Managed identity auth (for Azure VM/container with identity enabled)"),
        ("get_graph_token", "Get Graph API token — choose automatic (limited scopes) or manual/ROPC (full scopes: Files, Sites, Mail)"),
        ("get_teams_token", "Get Teams API token automatically (reuses current auth) or fallback to ROPC — bypasses Conditional Access"),
        # General
        ("help / ?", "Show this help"),
        ("search <keyword>", "Search modules by keyword"),
        ("clear_sessions", "Delete all saved sessions from disk"),
        (r"cloud \[aws | gcp | azure]", "Change cloud"),
        ("delete_session [name]", "Delete an Azure session"),
        ("list_sessions", "List all Azure sessions"),
        ("new_session", "Create a new empty Azure session"),
        ("use_session [name]", "Switch to existing Azure session"),
        ("set_subscription [id] [name]", "Set active subscription for resource enumeration (interactive or with ID)"),
        ("whoami", "Show information about the current Azure identity"),
        ("exit / quit", "Exit Azure mode"),
        # Enumeration
        ("discover_services / cloudprowl", "Discover accessible Microsoft services via token exchange (Graph, ARM, DevOps, Power Platform, Teams, Exchange) - requires refresh_token"),
        ("quick_enum", "Quick overview of key Azure services (VMs, storage, functions, web apps, users, groups) - Fast!"),
        ("enumerate_administrative_unit_members", "Enumerate direct members of an administrative unit (requires admin unit ID)"),
        ("enumerate_administrative_unit_scoped_members", "Enumerate scoped role members of an administrative unit (requires admin unit ID)"),
        ("enumerate_administrative_units", "Enumerate administrative units in the directory"),
        ("enumerate_all_roles", "Enumerate all the possile roles"),
        ("enumerate_blobs", "List blobs in a storage container (account, container and JMESPath query; default shows name/version/isCurrent)"),
        ("enumerate_storage_accounts", "Enumerate all storage accounts in the subscription"),
        ("enumerate_storage_containers", "Enumerate all containers in a storage account"),
        ("enumerate_storage_full", "Complete storage enumeration: accounts → containers → blob counts"),
        ("enumerate_container_apps", "Enumerate all Azure Container Apps in the subscription"),
        ("enumerate_container_apps_full", "Complete Container Apps enumeration: apps → secrets"),
        ("enumerate_disks", "Enumerate all Managed Disks with encryption status and attachment state"),
        ("enumerate_virtual_machines", "Enumerate all Virtual Machines in the subscription with detailed information"),
        ("enumerate_functions", "Enumerate functions in a Function App (SDK with CLI fallback)"),
        ("enumerate_group_members", "Enumerate all members in a group"),
        ("enumerate_groups", "Enumerate all groups in the tenant"),
        ("enumerate_keyvault_secrets", "Enumerate a keyvault secret"),
        ("enumerate_nics", "Enumerate all Network Interfaces with IP configurations and NSG associations"),
        ("enumerate_nsgs", "Enumerate all Network Security Groups with inbound/outbound rules analysis"),
        ("enumerate_public_ips", "Enumerate all Public IP Addresses with allocation details and associations"),
        ("enumerate_resources", "Enumerate all resources in the subscription (SDK with CLI fallback)"),
        ("enumerate_snapshots", "Enumerate all Disk Snapshots with encryption and public access analysis"),
        ("enumerate_sql_vms", "Enumerate all SQL Virtual Machines with patching and Key Vault integration"),
        ("enumerate_vnets", "Enumerate all Virtual Networks with subnets, peerings, and DDoS protection status"),
        ("enumerate_roles", "Enumerate the users's roles"),
        ("enumerate_subscriptions", "Enumerate all accessible Azure subscriptions"),
        ("enumerate_users", "Enumerate all users in the tenant"),
        ("enumerate_user_memberships", "Enumerate groups and roles a user is member of (like Get-MgUserMemberOf) — works with all auth methods"),
        ("enumerate_user_owned_objects", "Enumerate apps, service principals, groups, and devices owned by a user (like Get-MgUserOwnedObject) — shows privilege escalation opportunities"),
        ("enumerate_external_users", "Enumerate external/guest users by mail prefix (e.g. 'ext.') + all guests — uses Graph ConsistencyLevel: eventual"),
        ("enumerate_webapps", "Enumerate Web Apps in the subscription (SDK with CLI fallback)"),
        # Microsoft Graph Operations
        ("enumerate_bruteforce_graph_permissions [fast|full]", "Test Graph API permissions via HTTP calls with false positive detection (fast: ~31 perms | full: ~90 perms) - write ops returning 404 marked UNCERTAIN"),
        ("enumerate_bruteforce_aad_permissions [fast|full]", "⚠️  LEGACY: Enumerate Azure AD Graph API permissions (graph.windows.net - deprecated)"),
        ("enumerate_users_legacy", "⚠️  LEGACY: Enumerate users via Azure AD Graph API (graph.windows.net)"),
        ("enumerate_groups_legacy", "⚠️  LEGACY: Enumerate groups via Azure AD Graph API (graph.windows.net)"),
        ("enumerate_apps_legacy", "⚠️  LEGACY: Enumerate apps/service principals via Azure AD Graph API (graph.windows.net)"),
        ("graph_mail", "Search mailbox by keyword or browse folders — [1] search (like GraphRunner Invoke-SearchMailbox) [2] browse (requires Mail.Read)"),
        ("graph_teams", "Search Teams messages by keyword or browse teams/channels — [1] search (like GraphRunner Invoke-SearchTeams) [2] browse (requires Team.ReadBasic.All, ChannelMessage.Read.All)"),
        ("graph_sharepoint", "Enumerate SharePoint sites and document libraries (requires Sites.Read.All)"),
        ("graph_files", "Search or browse OneDrive/SharePoint files and download — [1] search by keyword (like GraphRunner) [2] browse drives (requires Files.Read.All)"),
        ("graph_apps", "Enumerate app registrations and service principals (requires Application.Read.All)"),
        ("graph_ca_policies", "Enumerate Conditional Access policies (requires Policy.Read.All)"),
        ("teams_messages", "Enumerate Teams messages via native API (requires teams_access_token from get_teams_token - bypasses CA)"),
        # Exfiltration
        ("download_blob", "Download a blob from a storage container using Azure AD (auth-mode login)."),
        ("exfiltrate_app_settings", "Extract application settings and connection strings from Function Apps or Web Apps"),
        ("exfiltrate_container_app_secrets", "Extract secrets from an Azure Container App using the /listSecrets endpoint"),
        ("exfiltrate_keyvault", "Exfiltrate secrets (with values) and key metadata from a Key Vault — SDK → REST → CLI fallback."),
        # Exploitation
        ("change_user_password", "Change a user's password via Microsoft Graph API (requires user ID in email format)"),
        ("vm_run_command", "Execute commands on Azure Virtual Machines using RunCommand API (supports Linux and Windows)"),
        # Miscellaneous
        ("audit_mfa_gaps [fast|full] [--ua_all] [-r <url>]", "Search for MFA bypass opportunities (fast: common endpoints | full: comprehensive scan) — use --ua_all to test all user agents (like FindMeAccess)"),
        ("az ...", "Run az CLI in shell"),
        ("mfa", "Quick shortcut for audit_mfa_gaps (MFA bypass audit)"),
    ]

    # Calculate max widths for consistent column alignment across all tables
    max_cmd_width = max(len(cmd) for cmd, _ in all_data)
    max_desc_width = max(len(desc) for _, desc in all_data)

    with console.pager(styles=True):
        console.print("\n[bold blue]Azure Session Commands[/bold blue]\n")

        # Authentication (alphabetically sorted)
        auth_table = Table(title="[cyan]Authentication (SDK)[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        auth_table.add_column("Command", style="bold", width=max_cmd_width)
        auth_table.add_column("Description", width=max_desc_width)
        auth_table.add_row("az_login", "Legacy: Authenticate using Azure CLI (requires az CLI installed)")
        auth_table.add_row("get_graph_token", "Get Graph API token via username/password (ROPC flow, like AADInternals)")
        auth_table.add_row("get_teams_token", "Get Teams API token via username/password (ROPC flow, like AADInternals)")
        auth_table.add_row("login_az_cli", "Authenticate using Azure CLI (recommended for Conditional Access)")
        auth_table.add_row("login_device_code", "Device code flow for remote/SSH sessions")
        auth_table.add_row("login_interactive", "Browser-based interactive login (may fail with Conditional Access)")
        auth_table.add_row("login_managed_identity", "Authenticate using managed identity (Azure VM/container)")
        auth_table.add_row("login_password", "Username/password login (ROPC flow) — useful for ADFS and federated scenarios")
        auth_table.add_row("set_service_principal", "Configure service principal authentication (tenant_id, client_id, client_secret)")
        auth_table.add_row("set_token", "Set access token (from env/file/input) — auto-detects audience from JWT and stores in correct slot")
        auth_table.add_row("set_refresh_token", "Set refresh token and auto-discover accessible services (CloudProwl technique) - tests 8 Microsoft services")
        console.print(auth_table)
        console.print()

        table = Table(title="[cyan]General[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table.add_column("Command", style="bold", width=max_cmd_width)
        table.add_column("Description", width=max_desc_width)
        table.add_row("clear_sessions", "Delete all saved sessions from disk")
        table.add_row(r"cloud \[aws | gcp | azure]", "Change cloud")
        table.add_row("delete_session [name]", "Delete an Azure session")
        table.add_row("exit / quit", "Exit Azure mode")
        table.add_row("help / ?", "Show this help")
        table.add_row("list_sessions", "List all Azure sessions")
        table.add_row("new_session", "Create a new empty Azure session")
        table.add_row("set_subscription [id] [name]", "Set active subscription for resource enumeration (interactive or with ID)")
        table.add_row("use_session [name]", "Switch to existing Azure session")
        table.add_row("whoami", "Show information about the current Azure identity")

        console.print(table)
        console.print()

        # Enumeration (alphabetically sorted)
        table2 = Table(title="[cyan]Enumeration[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table2.add_column("Command", style="bold", width=max_cmd_width)
        table2.add_column("Description", width=max_desc_width)
        table2.add_row("discover_services / cloudprowl", "Discover accessible Microsoft services via token exchange (Graph, ARM, DevOps, Power Platform, Teams, Exchange) - requires refresh_token")
        table2.add_row("enumerate_administrative_unit_members", "Enumerate direct members of an administrative unit (requires admin unit ID)")
        table2.add_row("enumerate_administrative_unit_scoped_members", "Enumerate scoped role members of an administrative unit (requires admin unit ID)")
        table2.add_row("enumerate_administrative_units", "Enumerate administrative units in the directory")
        table2.add_row("enumerate_all_roles", "Enumerate all the possile roles")
        table2.add_row(
            "enumerate_blobs",
            "List blobs in a storage container (account, container and JMESPath query; default shows name/version/isCurrent)",
        )
        table2.add_row("enumerate_container_apps", "Enumerate all Azure Container Apps in the subscription")
        table2.add_row("enumerate_container_apps_full", "Complete Container Apps enumeration: apps → secrets")
        table2.add_row("enumerate_disks", "Enumerate all Managed Disks with encryption status and attachment state")
        table2.add_row("enumerate_external_users", "Enumerate external/guest users by mail prefix (e.g. 'ext.') + all guests — uses Graph ConsistencyLevel: eventual")
        table2.add_row("enumerate_functions", "Enumerate functions in a Function App (SDK with CLI fallback)")
        table2.add_row("enumerate_group_members", "Enumerate all members in a group")
        table2.add_row("enumerate_groups", "Enumerate all groups in the tenant")
        table2.add_row("enumerate_keyvault_secrets", "Enumerate a keyvault secret")
        table2.add_row("enumerate_nics", "Enumerate all Network Interfaces with IP configurations and NSG associations")
        table2.add_row("enumerate_nsgs", "Enumerate all Network Security Groups with inbound/outbound rules analysis")
        table2.add_row("enumerate_public_ips", "Enumerate all Public IP Addresses with allocation details and associations")
        table2.add_row("enumerate_resources", "Enumerate all resources in the subscription (SDK with CLI fallback)")
        table2.add_row("enumerate_snapshots", "Enumerate all Disk Snapshots with encryption and public access analysis")
        table2.add_row("enumerate_sql_vms", "Enumerate all SQL Virtual Machines with patching and Key Vault integration")
        table2.add_row("enumerate_vnets", "Enumerate all Virtual Networks with subnets, peerings, and DDoS protection status")
        table2.add_row("enumerate_roles", "Enumerate the users's roles")
        table2.add_row("enumerate_storage_accounts", "Enumerate all storage accounts in the subscription")
        table2.add_row("enumerate_storage_containers", "Enumerate all containers in a storage account")
        table2.add_row("enumerate_storage_full", "Complete storage enumeration: accounts → containers → blob counts")
        table2.add_row("enumerate_subscriptions", "Enumerate all accessible Azure subscriptions")
        table2.add_row("enumerate_users", "Enumerate all users in the tenant")
        table2.add_row("enumerate_virtual_machines", "Enumerate all Virtual Machines in the subscription with detailed information")
        table2.add_row("enumerate_webapps", "Enumerate Web Apps in the subscription (SDK with CLI fallback)")
        table2.add_row("quick_enum", "Quick overview of key Azure services (VMs, storage, functions, web apps, users, groups) - Fast!")
        console.print(table2)
        console.print()

        # Microsoft Graph Operations (alphabetically sorted)
        table_graph = Table(title="[cyan]Microsoft Graph Operations[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table_graph.add_column("Command", style="bold", width=max_cmd_width)
        table_graph.add_column("Description", width=max_desc_width)
        table_graph.add_row("enumerate_bruteforce_aad_permissions [fast|full]", "⚠️  LEGACY: Enumerate Azure AD Graph API permissions (graph.windows.net - deprecated)")
        table_graph.add_row("enumerate_bruteforce_graph_permissions [fast|full]", "Test Graph API permissions via HTTP calls with false positive detection (fast: ~31 perms | full: ~90 perms) - write ops returning 404 marked UNCERTAIN")
        table_graph.add_row("enumerate_apps_legacy", "⚠️  LEGACY: Enumerate apps/service principals via Azure AD Graph API (graph.windows.net)")
        table_graph.add_row("enumerate_groups_legacy", "⚠️  LEGACY: Enumerate groups via Azure AD Graph API (graph.windows.net)")
        table_graph.add_row("enumerate_users_legacy", "⚠️  LEGACY: Enumerate users via Azure AD Graph API (graph.windows.net)")
        table_graph.add_row("graph_apps", "Enumerate app registrations and service principals (requires Application.Read.All)")
        table_graph.add_row("graph_ca_policies", "Enumerate Conditional Access policies (requires Policy.Read.All)")
        table_graph.add_row("graph_files", "Search or browse OneDrive/SharePoint files and download — [1] search by keyword (like GraphRunner) [2] browse drives (requires Files.Read.All)")
        table_graph.add_row("graph_mail", "Search mailbox by keyword or browse folders — [1] search (like GraphRunner Invoke-SearchMailbox) [2] browse (requires Mail.Read)")
        table_graph.add_row("graph_sharepoint", "Enumerate SharePoint sites and document libraries (requires Sites.Read.All)")
        table_graph.add_row("graph_teams", "Search Teams messages by keyword or browse teams/channels — [1] search (like GraphRunner Invoke-SearchTeams) [2] browse (requires Team.ReadBasic.All, ChannelMessage.Read.All)")
        table_graph.add_row("teams_messages", "Enumerate Teams messages via native API (requires teams_access_token from get_teams_token - bypasses CA)")
        console.print(table_graph)
        console.print()

        # Exfiltration
        table3 = Table(title="[cyan]Exfiltration[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table3.add_column("Command", style="bold", width=max_cmd_width)
        table3.add_column("Description", width=max_desc_width)
        table3.add_row(
            "download_blob",
            "Download a blob from a storage container using Azure AD (auth-mode login).",
        )
        table3.add_row(
            "exfiltrate_app_settings",
            "Extract application settings and connection strings from Function Apps or Web Apps",
        )
        table3.add_row(
            "exfiltrate_container_app_secrets",
            "Extract secrets from an Azure Container App using the /listSecrets endpoint",
        )
        table3.add_row(
            "exfiltrate_keyvault",
            "Exfiltrate secrets (with values) and key metadata from a Key Vault — SDK → REST → CLI fallback.",
        )
        console.print(table3)
        console.print()

        # Exploitation
        table4 = Table(title="[cyan]Exploitation[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table4.add_column("Command", style="bold", width=max_cmd_width)
        table4.add_column("Description", width=max_desc_width)
        table4.add_row(
            "change_user_password",
            "Change a user's password via Microsoft Graph API (requires user ID in email format)",
        )
        table4.add_row(
            "vm_run_command",
            "Execute commands on Azure Virtual Machines using RunCommand API (supports Linux and Windows)",
        )
        console.print(table4)
        console.print()

        # Miscellaneous
        table6 = Table(title="[cyan]Miscellaneous[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table6.add_column("Command", style="bold", width=max_cmd_width)
        table6.add_column("Description", width=max_desc_width)
        table6.add_row(
            "audit_mfa_gaps [fast|full] [--ua_all] [-r <url>]",
            "Search for MFA bypass opportunities (fast: common endpoints | full: comprehensive scan) — use --ua_all to test all user agents (like FindMeAccess)",
        )
        table6.add_row(
            "az ...",
            "Run az CLI in shell",
        )
        table6.add_row(
            "mfa",
            "Quick shortcut for audit_mfa_gaps (MFA bypass audit)",
        )
        console.print(table6)
