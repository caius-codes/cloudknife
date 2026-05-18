# src/clouds/azure/azure_cli.py

import subprocess

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML

from src.core.icons import icons

# Enumeration modules - alphabetically sorted
from .modules.enumeration import (
    enumerate_accessible_services,
    enumerate_administrative_unit_members,
    enumerate_administrative_unit_scoped_members,
    enumerate_administrative_units,
    enumerate_all_role_assignments,
    enumerate_apps,
    enumerate_apps_legacy,
    enumerate_bruteforce_aad_permissions,
    enumerate_bruteforce_graph_permissions,
    enumerate_ca_policies,
    enumerate_container_apps,
    enumerate_container_apps_full,
    enumerate_external_users,
    enumerate_files,
    enumerate_functions,
    enumerate_group_members,
    enumerate_groups,
    enumerate_groups_legacy,
    enumerate_keyvault_secrets,
    enumerate_mail,
    enumerate_disks,
    enumerate_nics,
    enumerate_nsgs,
    enumerate_public_ips,
    enumerate_resources,
    enumerate_role_assignments,
    enumerate_sharepoint,
    enumerate_snapshots,
    enumerate_sql_vms,
    enumerate_storage_accounts,
    enumerate_storage_blobs,
    enumerate_storage_containers,
    enumerate_storage_full,
    enumerate_subscriptions,
    enumerate_teams,
    enumerate_teams_messages,
    enumerate_users,
    enumerate_users_legacy,
    enumerate_virtual_machines,
    enumerate_vnets,
    enumerate_webapps,
    quick_enum,
)

# Exfiltration modules - alphabetically sorted
from .modules.exfiltration import (
    download_storage_blob,
    exfiltrate_app_settings,
    exfiltrate_container_app_secrets,
    exfiltrate_keyvault,
)

# Exploitation modules - alphabetically sorted
from .modules.exploitation import (
    change_user_password,
    vm_run_command,
)

# Miscellaneous modules - alphabetically sorted
from .modules.miscellaneous import (
    audit_mfa_gaps as run_mfa_audit,
    create_bypass_sessions,
    display_bypass_results,
)

# Other utilities
from .modules.az_passthrough import run_az_command

from rich.console import Console
from rich.prompt import Prompt, Confirm

from .azure_session import AzureSessionManager
from .azure_ui import (
    print_banner,
    show_sessions_table,
    ask_initial_session_choice,
    show_prompt_status,
    confirm_delete_session,
    print_help,
)

from ...logging import get_command_logger
from .search import search_modules as search_azure_modules

console = Console()
logger = get_command_logger()


def _log_command(session_mgr: AzureSessionManager, command: str, status: str = "executed") -> None:
    """
    Helper to log Azure commands.

    Consolidates the logging boilerplate that was previously duplicated
    across 13+ locations in the Azure CLI (DUP-002 fix).

    Args:
        session_mgr: Azure session manager with session metadata
        command: Command name to log
        status: Command status (default: "executed")
    """
    if logger.should_log_command(command):
        logger.log_command(
            cloud="azure",
            session_id=session_mgr.session_id or "unknown",
            session_name=session_mgr.current_session or "unknown",
            command=command,
            status=status,
        )


style = Style.from_dict(
    {
        "badge": "bold blue",
        "prompt": "bold green",
        "session": "bold cyan",
    }
)


def build_completer(session_mgr: AzureSessionManager) -> WordCompleter:
    sessions = [s["name"] for s in session_mgr.list_sessions()]
    commands = [
        # General
        "az",
        "az_login",
        "clear_sessions",
        "cloud",
        "delete_session",
        "exit",
        "help",
        "search",
        "list_sessions",
        "new_session",
        "quit",
        "set_subscription",
        "use_session",
        "whoami",
        # Authentication
        "get_graph_token",
        "get_teams_token",
        "login_az_cli",
        "login_device_code",
        "login_interactive",
        "login_managed_identity",
        "login_password",
        "set_service_principal",
        "set_token",
        "set_refresh_token",
        # Enumeration (alphabetically)
        "enumerate_bruteforce_aad_permissions",
        "enumerate_bruteforce_graph_permissions",
        "cloudprowl",
        "discover_services",
        "enumerate_administrative_unit_members",
        "enumerate_administrative_unit_scoped_members",
        "enumerate_administrative_units",
        "enumerate_all_roles",
        "enumerate_blobs",
        "enumerate_container_apps",
        "enumerate_container_apps_full",
        "enumerate_disks",
        "enumerate_external_users",
        "enumerate_functions",
        "enumerate_group_members",
        "enumerate_groups",
        "enumerate_keyvault_secrets",
        "enumerate_nics",
        "enumerate_nsgs",
        "enumerate_public_ips",
        "enumerate_resources",
        "enumerate_roles",
        "enumerate_snapshots",
        "enumerate_sql_vms",
        "enumerate_storage_accounts",
        "enumerate_storage_containers",
        "enumerate_storage_full",
        "enumerate_subscriptions",
        "enumerate_users",
        "enumerate_virtual_machines",
        "enumerate_vnets",
        "enumerate_webapps",
        "graph_apps",
        "graph_ca_policies",
        "graph_files",
        "graph_mail",
        "graph_sharepoint",
        "graph_teams",
        "quick_enum",
        "teams_messages",
        # Legacy enumeration
        "enumerate_apps_legacy",
        "enumerate_groups_legacy",
        "enumerate_users_legacy",
        # Exfiltration (alphabetically)
        "download_blob",
        "exfiltrate_app_settings",
        "exfiltrate_container_app_secrets",
        "exfiltrate_keyvault",
        # Exploitation (alphabetically)
        "change_user_password",
        "vm_run_command",
        # Miscellaneous (alphabetically)
        "audit_mfa_gaps",
        "mfa",
    ]
    return WordCompleter(commands + sessions, ignore_case=True)


def _offer_mfa_bypass_audit(session_mgr: AzureSessionManager, username: str = None, password: str = None, tenant_id: str = None) -> bool:
    """
    Helper function to offer MFA bypass audit when authentication fails due to MFA.

    Args:
        session_mgr: Azure session manager
        username: Optional username (will prompt if not provided)
        password: Optional password (will prompt if not provided)
        tenant_id: Optional tenant ID

    Returns:
        True if bypasses were found and sessions created, False otherwise
    """
    from getpass import getpass

    console.print("\n[yellow]💡 MFA is blocking this login method.[/yellow]")
    console.print("[dim]Would you like to search for authentication bypasses that don't require MFA?[/dim]")

    if not Confirm.ask("[cyan]Run MFA bypass audit?[/cyan]", default=True):
        return False

    # Get credentials if not provided
    if not username:
        username = Prompt.ask("[cyan]Username (email/UPN)[/cyan]").strip()
    if not password:
        password = getpass("Password: ").strip()
    if not tenant_id:
        tenant_id = "organizations"

    if not username or not password:
        console.print("[red]Username and password required for audit.[/red]")
        return False

    try:
        # Run audit in fast mode
        console.print("\n[cyan]🔍 Auditing MFA gaps (fast mode, ~30 seconds)...[/cyan]")
        bypasses = run_mfa_audit(
            username=username,
            password=password,
            tenant_id=tenant_id,
            fast_mode=True
        )

        # Display results
        display_bypass_results(bypasses)

        # Offer to create sessions
        if bypasses:
            if Confirm.ask("\n[cyan]Create CloudKnife sessions for these bypasses?[/cyan]", default=True):
                created = create_bypass_sessions(session_mgr, bypasses)
                console.print(f"\n[green]✓ Created {len(created)} session(s):[/green]")
                for sess_name in created:
                    console.print(f"  • [cyan]{sess_name}[/cyan]")

                if created:
                    # Automatically switch to the first created session
                    first_session = created[0]
                    session_mgr.create_or_load_session(first_session)
                    console.print(f"\n[green]✓ Automatically switched to session: [cyan]{first_session}[/cyan][/green]")
                    from .azure_ui import show_prompt_status
                    show_prompt_status(session_mgr.current_session, True)
                return True

        return False

    except Exception as e:
        console.print(f"[red]MFA bypass audit failed: {e}[/red]")
        return False


def run_azure_cli(session_mgr: AzureSessionManager) -> str:
    """
    Azure Sub-CLI: manages Azure sessions and commands.

    Returns:
    - "aws" / "azure" / "gcp" for direct switch
    - "switch" to return to cloud menu
    - "exit" to exit the tool
    """
    print_banner()

    existing_sessions = session_mgr.list_sessions()
    show_sessions_table(existing_sessions)
    existing_names = [s["name"] for s in existing_sessions]

    session_name, is_new = ask_initial_session_choice(bool(existing_sessions), existing_names)

    if is_new:
        session_mgr.create_or_load_session(session_name)
    else:
        if not existing_names:
            session_mgr.create_or_load_session("azure-default")
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
                        "Existing Azure session name (TAB for autocomplete): ",
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

    has_login = False  # con SDK non sappiamo ancora se ha token
    show_prompt_status(session_mgr.current_session, has_login)

    console.print("\n[dim]💡 Tip: Type 'mfa' anytime to run MFA bypass audit[/dim]\n")

    session_prompt = PromptSession(
        completer=build_completer(session_mgr),
        style=style,
        auto_suggest=AutoSuggestFromHistory(),
    )

    AZURE_BADGE = f"AZURE {icons.azure}"

    while True:
        try:
            if session_mgr.current_session:
                prompt_text = HTML(
                    f"<badge>{AZURE_BADGE}</badge>cloudknife[<session>{session_mgr.current_session}</session>]> "
                )
            else:
                prompt_text = HTML(f"<badge>{AZURE_BADGE}</badge>cloudknife> ")

            user_input = session_prompt.prompt(prompt_text)
            parts = user_input.strip().split()
            if not parts:
                continue

            cmd = parts[0].lower()
            args = parts[1:]

            # switch cloud
            if cmd == "cloud":
                if args and args[0].lower() in ("aws", "azure", "gcp"):
                    return args[0].lower()
                return "switch"

            if cmd in ("help", "?"):
                print_help()
                continue

            if cmd == "search":
                query = " ".join(args) if args else None
                search_azure_modules(session_mgr, query)
                _log_command(session_mgr, cmd)
                continue

            # Alias: "mfa" is shorthand for "audit_mfa_gaps"
            if cmd == "mfa":
                cmd = "audit_mfa_gaps"

            if cmd == "az_login":
                session_mgr.azure_login()
                has_login = True
                show_prompt_status(session_mgr.current_session, has_login)
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd)

            elif cmd == "set_service_principal":
                from getpass import getpass

                tenant_id = Prompt.ask("[cyan]Tenant ID[/cyan]").strip()
                client_id = Prompt.ask("[cyan]Client ID (Application ID)[/cyan]").strip()
                client_secret = getpass("Client Secret: ").strip()

                if not tenant_id or not client_id or not client_secret:
                    console.print("[red]All fields are required.[/red]")
                    continue

                session_mgr.current_session_data["auth_method"] = "service_principal"
                session_mgr.current_session_data["tenant_id"] = tenant_id
                session_mgr.current_session_data["client_id"] = client_id
                session_mgr.current_session_data["client_secret"] = client_secret
                session_mgr.save_current_session()

                console.print("[green]Service principal configured successfully.[/green]")

                # Try to sync user info (may fail if SP doesn't have Graph permissions)
                console.print("[dim]Retrieving service principal information...[/dim]")
                if session_mgr.sync_user_info_from_graph():
                    console.print("[green]Service principal information retrieved.[/green]")
                else:
                    console.print("[yellow]Note: Could not retrieve info (SP may lack Graph permissions).[/yellow]")

                # Sync subscriptions from SDK
                console.print("[dim]Retrieving subscriptions...[/dim]")
                session_mgr.sync_subscriptions_from_sdk()

                has_login = True
                show_prompt_status(session_mgr.current_session, has_login)
                _log_command(session_mgr, cmd)

            elif cmd == "login_az_cli":
                # Use Azure CLI for authentication - works with Conditional Access policies
                console.print("[cyan]Launching Azure CLI login...[/cyan]")
                console.print("[dim]This will open a browser window using Azure CLI.[/dim]")
                console.print("[yellow]⚠️  If browser asks for MFA: press Ctrl+C to cancel, then type 'mfa' to run bypass audit[/yellow]")

                try:
                    # Run az login
                    result = subprocess.run(
                        ["az", "login", "--allow-no-subscriptions"],
                        capture_output=True,
                        text=True,
                        timeout=60,  # Reduced from 120s - fail faster if user closes browser
                    )
                    result.check_returncode()

                    # Set auth method to use AzureCliCredential
                    session_mgr.current_session_data["auth_method"] = "az_cli"
                    session_mgr.save_current_session()

                    # Sync account information from Azure CLI
                    session_mgr.azure_sync_from_current_account()

                    console.print("[green]Azure CLI login successful![/green]")

                    # Sync user info from Graph API
                    console.print("[dim]Retrieving user information...[/dim]")
                    if session_mgr.sync_user_info_from_graph():
                        console.print("[green]User information retrieved.[/green]")

                    has_login = True
                    show_prompt_status(session_mgr.current_session, has_login)

                except KeyboardInterrupt:
                    console.print("\n[yellow]Azure CLI login interrupted.[/yellow]")
                    console.print("[cyan]💡 Type 'mfa' to search for MFA bypass opportunities[/cyan]")
                    has_login = False
                except FileNotFoundError:
                    console.print("[red]Azure CLI (az) not found. Please install it first.[/red]")
                    console.print("[yellow]https://docs.microsoft.com/en-us/cli/azure/install-azure-cli[/yellow]")
                except subprocess.CalledProcessError as e:
                    console.print(f"[red]Azure CLI login failed: {e.stderr}[/red]")
                    console.print("[cyan]💡 If MFA blocked you, type 'mfa' to search for bypass opportunities[/cyan]")
                except subprocess.TimeoutExpired:
                    console.print("[red]Azure CLI login timed out (browser closed or took too long).[/red]")
                    console.print("[cyan]💡 If MFA blocked you, type 'mfa' to search for bypass opportunities[/cyan]")
                except Exception as e:
                    console.print(f"[red]Error during login: {e}[/red]")

                _log_command(session_mgr, cmd)

            elif cmd == "login_interactive":

                tenant_id = Prompt.ask(
                    "[cyan]Tenant ID (optional, leave empty for default)[/cyan]",
                    default=""
                ).strip()

                console.print("\n[dim]Select login method:[/dim]")
                console.print("  [bold]1[/bold]  Browser-based login (SDK)")
                console.print("  [bold]2[/bold]  Azure CLI directly [dim](use this if you get stuck on a device code)[/dim]\n")
                method_choice = Prompt.ask("Choice", choices=["1", "2"], default="1")

                session_mgr.current_session_data["auth_method"] = "interactive"
                if tenant_id:
                    session_mgr.current_session_data["tenant_id"] = tenant_id
                session_mgr.save_current_session()

                login_successful = False

                # Helper: run az login and sync session (used for direct choice and fallback)
                def _run_az_login():
                    try:
                        result = subprocess.run(
                            ["az", "login", "--allow-no-subscriptions"],
                            capture_output=True, text=True, timeout=60,  # Reduced from 120s
                        )
                        result.check_returncode()
                        session_mgr.current_session_data["auth_method"] = "az_cli"
                        session_mgr.save_current_session()
                        session_mgr.azure_sync_from_current_account()
                        console.print("[green]Azure CLI login successful![/green]")
                        console.print("[dim]Run 'whoami' to see user details.[/dim]")
                        return True
                    except Exception as az_err:
                        console.print(f"[red]Azure CLI login failed: {az_err}[/red]")
                        console.print("[yellow]Try running 'login_az_cli' directly.[/yellow]")
                        return False

                if method_choice == "2":
                    # Go directly to Azure CLI without trying the SDK
                    console.print("[cyan]Using Azure CLI...[/cyan]")
                    if _run_az_login():
                        login_successful = True
                        has_login = True
                        show_prompt_status(session_mgr.current_session, has_login)
                    else:
                        has_login = False
                else:
                    # method_choice == "1": try SDK browser login
                    console.print("[cyan]Testing interactive browser login...[/cyan]")
                    console.print("[yellow]⚠️  If browser asks for MFA: press Ctrl+C to cancel, then type 'mfa' to run bypass audit[/yellow]")
                    credential = session_mgr.get_credential("graph")

                    if credential:
                        try:
                            token = credential.get_token("https://graph.microsoft.com/.default")
                            console.print("[green]Interactive login successful![/green]")

                            # Extract tenant ID from token if not provided
                            if not session_mgr.current_session_data.get("tenant_id"):
                                console.print("[dim]Extracting tenant ID from token...[/dim]")
                                extracted_tenant = session_mgr.extract_tenant_from_token()
                                if extracted_tenant:
                                    session_mgr.current_session_data["tenant_id"] = extracted_tenant
                                    session_mgr.save_current_session()
                                    console.print(f"[green]Tenant ID: {extracted_tenant}[/green]")

                            # Sync user info from Graph API
                            console.print("[dim]Retrieving user information...[/dim]")
                            if session_mgr.sync_user_info_from_graph():
                                console.print("[green]User information retrieved.[/green]")

                            # Sync subscriptions from SDK
                            console.print("[dim]Retrieving subscriptions...[/dim]")
                            session_mgr.sync_subscriptions_from_sdk()

                            login_successful = True
                            has_login = True
                            show_prompt_status(session_mgr.current_session, has_login)

                        except KeyboardInterrupt:
                            # CTRL+C during SDK login → ask if MFA was the issue
                            console.print("\n[yellow]Login interrupted.[/yellow]")

                            # Ask if MFA was blocking
                            if Confirm.ask("[cyan]Was MFA blocking the login?[/cyan]", default=False):
                                _offer_mfa_bypass_audit(session_mgr, tenant_id=tenant_id)
                                has_login = False
                            else:
                                # Not MFA, try Azure CLI fallback
                                console.print("[cyan]Falling back to Azure CLI...[/cyan]")
                                if _run_az_login():
                                    login_successful = True
                                    has_login = True
                                    show_prompt_status(session_mgr.current_session, has_login)
                                else:
                                    has_login = False

                        except Exception as e:
                            error_str = str(e)
                            # Check if error is MFA-related
                            is_mfa_error = any(indicator in error_str for indicator in [
                                "AADSTS50076",  # MFA required
                                "AADSTS50079",  # MFA enrollment required
                                "multi-factor",
                                "MFA",
                                "authentication_required"
                            ])

                            if is_mfa_error:
                                console.print(f"[red]Authentication failed: MFA required[/red]")
                                console.print(f"[dim]Details: {error_str}[/dim]")

                                # Offer MFA bypass audit
                                _offer_mfa_bypass_audit(session_mgr, tenant_id=tenant_id)
                                has_login = False
                            else:
                                # Not MFA error, try fallback
                                console.print(f"[yellow]Interactive login failed: {e}[/yellow]")
                                console.print("[cyan]Attempting fallback to Azure CLI authentication...[/cyan]")
                                if _run_az_login():
                                    login_successful = True
                                    has_login = True
                                    show_prompt_status(session_mgr.current_session, has_login)
                                else:
                                    has_login = False
                    else:
                        console.print("[red]Failed to create credential.[/red]")
                        has_login = False

                _log_command(session_mgr, cmd)

            elif cmd == "login_device_code":

                tenant_id = Prompt.ask(
                    "[cyan]Tenant ID (optional, leave empty for default)[/cyan]",
                    default=""
                ).strip()

                session_mgr.current_session_data["auth_method"] = "device_code"
                if tenant_id:
                    session_mgr.current_session_data["tenant_id"] = tenant_id
                session_mgr.save_current_session()

                console.print("[cyan]Testing device code login...[/cyan]")
                console.print("[yellow]A device code will be displayed. Follow the instructions.[/yellow]")
                console.print("[dim]Press CTRL+C to cancel and fall back to Azure CLI.[/dim]")
                credential = session_mgr.get_credential("graph")
                login_successful = False

                if credential:
                    try:
                        token = credential.get_token("https://graph.microsoft.com/.default")
                        console.print("[green]Device code login successful![/green]")

                        # Extract tenant ID from token if not provided
                        if not session_mgr.current_session_data.get("tenant_id"):
                            console.print("[dim]Extracting tenant ID from token...[/dim]")
                            extracted_tenant = session_mgr.extract_tenant_from_token()
                            if extracted_tenant:
                                session_mgr.current_session_data["tenant_id"] = extracted_tenant
                                session_mgr.save_current_session()
                                console.print(f"[green]Tenant ID: {extracted_tenant}[/green]")

                        # Sync user info from Graph API
                        console.print("[dim]Retrieving user information...[/dim]")
                        if session_mgr.sync_user_info_from_graph():
                            console.print("[green]User information retrieved.[/green]")

                        # Sync subscriptions from SDK
                        console.print("[dim]Retrieving subscriptions...[/dim]")
                        session_mgr.sync_subscriptions_from_sdk()

                        login_successful = True
                        has_login = True
                        show_prompt_status(session_mgr.current_session, has_login)

                    except KeyboardInterrupt:
                        # CTRL+C during device code entry → fallback to az login
                        # (without this, CTRL+C propagates to outer handler and exits the session)
                        console.print("\n[yellow]Device code login interrupted. Falling back to Azure CLI...[/yellow]")
                        try:
                            result = subprocess.run(
                                ["az", "login", "--allow-no-subscriptions"],
                                capture_output=True, text=True, timeout=120,
                            )
                            result.check_returncode()
                            session_mgr.current_session_data["auth_method"] = "az_cli"
                            session_mgr.save_current_session()
                            session_mgr.azure_sync_from_current_account()
                            console.print("[green]Azure CLI login successful![/green]")
                            console.print("[dim]Retrieving user information...[/dim]")
                            if session_mgr.sync_user_info_from_graph():
                                console.print("[green]User information retrieved.[/green]")
                            login_successful = True
                            has_login = True
                            show_prompt_status(session_mgr.current_session, has_login)
                        except Exception as az_err:
                            console.print(f"[red]Azure CLI login failed: {az_err}[/red]")
                            console.print("[yellow]Try running 'login_az_cli' directly.[/yellow]")
                            has_login = False

                    except Exception as e:
                        error_str = str(e)
                        # Check if error is MFA-related
                        is_mfa_error = any(indicator in error_str for indicator in [
                            "AADSTS50076", "AADSTS50079", "multi-factor", "MFA", "authentication_required"
                        ])

                        if is_mfa_error:
                            console.print(f"[red]Authentication failed: MFA required[/red]")
                            console.print(f"[dim]Details: {error_str}[/dim]")
                            _offer_mfa_bypass_audit(session_mgr, tenant_id=tenant_id)
                            has_login = False
                        else:
                            console.print(f"[yellow]Device code login failed: {e}[/yellow]")
                            console.print("[cyan]Attempting fallback to Azure CLI authentication...[/cyan]")
                            try:
                                result = subprocess.run(
                                    ["az", "login", "--allow-no-subscriptions"],
                                    capture_output=True, text=True, timeout=120,
                                )
                                result.check_returncode()
                                session_mgr.current_session_data["auth_method"] = "az_cli"
                                session_mgr.save_current_session()
                                session_mgr.azure_sync_from_current_account()
                                console.print("[green]Azure CLI fallback successful![/green]")
                                console.print("[dim]Retrieving user information...[/dim]")
                                if session_mgr.sync_user_info_from_graph():
                                    console.print("[green]User information retrieved.[/green]")
                                login_successful = True
                                has_login = True
                                show_prompt_status(session_mgr.current_session, has_login)
                            except Exception as fallback_error:
                                console.print(f"[red]Fallback to Azure CLI also failed: {fallback_error}[/red]")
                                console.print("[yellow]Try running 'login_az_cli' directly.[/yellow]")
                                has_login = False
                else:
                    console.print("[red]Failed to create credential.[/red]")
                    has_login = False

                _log_command(session_mgr, cmd)

            elif cmd == "login_password":
                from getpass import getpass

                console.print("[cyan]Username/Password Login (ROPC Flow)[/cyan]")
                console.print("[dim]Useful for ADFS and federated scenarios where device code doesn't work.[/dim]")
                console.print("[yellow]Note: Does not support MFA. Password is stored in session.[/yellow]")

                username = Prompt.ask("[cyan]Username (email/UPN)[/cyan]").strip()
                password = getpass("Password: ").strip()
                tenant_id = Prompt.ask(
                    "[cyan]Tenant ID (optional, leave empty for multi-tenant)[/cyan]",
                    default=""
                ).strip() or None

                if not username or not password:
                    console.print("[red]Username and password are required.[/red]")
                    continue

                # Use the new set_password_auth method
                if session_mgr.set_password_auth(username, password, tenant_id):
                    console.print("[green]Password authentication configured successfully![/green]")
                    has_login = True
                    show_prompt_status(session_mgr.current_session, has_login)
                else:
                    console.print("[red]Password authentication failed.[/red]")
                    has_login = False

                _log_command(session_mgr, cmd)

            elif cmd == "set_token":
                from getpass import getpass
                import base64
                import json as _json
                import time as _time
                from pathlib import Path

                # Interactive token input method selection
                console.print("\n[cyan]Access Token Input:[/cyan]")
                console.print("[dim]Note: Azure access tokens can be very long (1000+ chars)[/dim]")
                console.print("[dim]Quick tip: pbpaste > /tmp/token.txt (then use option 2)[/dim]")
                console.print("[1] From environment variable (AZURE_ACCESS_TOKEN)")
                console.print("[2] From file (recommended for long tokens)")
                console.print("[3] Direct input (hidden)")

                token_method = Prompt.ask(
                    "[cyan]Choose input method[/cyan]",
                    choices=["1", "2", "3"],
                    default="2",
                )

                access_token = ""
                if token_method == "1":
                    # Environment variable
                    import os
                    env_token = os.environ.get("AZURE_ACCESS_TOKEN", "").strip()
                    if env_token:
                        console.print(f"[green]Found token in AZURE_ACCESS_TOKEN env var ({len(env_token)} chars)[/green]")
                        access_token = env_token
                    else:
                        console.print("[yellow]AZURE_ACCESS_TOKEN environment variable not set[/yellow]")
                        continue
                elif token_method == "2":
                    # From file (most reliable for long tokens)
                    file_path = Prompt.ask(
                        "[cyan]Path to file containing token[/cyan]",
                        default="/tmp/token.txt"
                    )
                    try:
                        token_file = Path(file_path.strip()).expanduser()
                        access_token = token_file.read_text().strip()
                        console.print(f"[green]Token loaded from file: {token_file} ({len(access_token)} chars)[/green]")
                    except Exception as e:
                        console.print(f"[red]Error reading token file: {e}[/red]")
                        continue
                elif token_method == "3":
                    # Direct input (hidden)
                    access_token = getpass("Access Token: ").strip()

                if not access_token:
                    console.print("[red]Access token is required.[/red]")
                    continue

                # --- Decode JWT claims (no verification needed) ---
                claims = {}
                try:
                    parts = access_token.split(".")
                    if len(parts) == 3:
                        payload = parts[1]
                        payload += "=" * (4 - len(payload) % 4)
                        claims = _json.loads(base64.urlsafe_b64decode(payload))
                except Exception:
                    pass

                # Detect audience → determine which resource slot to populate
                aud = claims.get("aud", "")
                AUDIENCE_MAP = {
                    "https://graph.microsoft.com":           ("graph",      "graph_access_token"),
                    "https://graph.windows.net":             ("graph",      "graph_access_token"),  # Legacy Azure AD Graph
                    "https://management.azure.com/":         ("management", "management_access_token"),
                    "https://management.azure.com":          ("management", "management_access_token"),
                    "https://management.core.windows.net/":  ("management", "management_access_token"),  # Legacy Azure Service Management
                    "https://storage.azure.com/":            ("storage",    "storage_access_token"),
                    "https://vault.azure.net":               ("vault",      "vault_access_token"),
                    "https://api.spaces.skype.com":          ("teams",      "teams_access_token"),
                    "https://manage.office.com":             ("office",     "office_access_token"),  # Office 365 Management API
                    "https://outlook.office365.com":         ("outlook",    "outlook_access_token"),  # Outlook/Exchange API
                }
                scope_name, token_key = AUDIENCE_MAP.get(aud, ("unknown", "unknown_access_token"))

                # Extract expiry from JWT exp claim (override manual input)
                jwt_expires_at = None
                if claims.get("exp"):
                    try:
                        jwt_expires_at = int(claims["exp"])
                    except (ValueError, TypeError):
                        pass

                # Show what we detected
                console.print()
                console.print("[bold cyan]Token decoded:[/bold cyan]")
                console.print(f"  [cyan]Audience:[/cyan] {aud or '(unknown)'}")
                console.print(f"  [cyan]Scope slot:[/cyan] {scope_name}")
                if claims.get("tid"):
                    console.print(f"  [cyan]Tenant:[/cyan] {claims['tid']}")
                upn = claims.get("upn") or claims.get("unique_name") or claims.get("email")
                if upn:
                    console.print(f"  [cyan]User:[/cyan] {upn}")
                if claims.get("oid"):
                    console.print(f"  [cyan]Object ID:[/cyan] {claims['oid']}")
                if jwt_expires_at:
                    from datetime import datetime
                    exp_str = datetime.fromtimestamp(jwt_expires_at).strftime("%Y-%m-%d %H:%M:%S")
                    remaining = jwt_expires_at - int(_time.time())
                    if remaining > 0:
                        mins = remaining // 60
                        console.print(f"  [cyan]Expires:[/cyan] {exp_str} ({mins} min remaining)")
                    else:
                        console.print(f"  [red]Expired:[/red] {exp_str}")

                scp = claims.get("scp", "") or " ".join(claims.get("roles", []))
                if scp:
                    console.print(f"  [cyan]Scopes:[/cyan] {scp}")
                console.print()

                # Store token in the right resource-specific slot
                expires_at = jwt_expires_at

                session_mgr.current_session_data["auth_method"] = "access_token"

                # Only set generic access_token if we don't know the audience (for backwards compatibility)
                if scope_name == "unknown":
                    session_mgr.current_session_data["access_token"] = access_token
                    if expires_at:
                        session_mgr.current_session_data["token_expires_at"] = expires_at

                # Always store in the specific slot
                session_mgr.current_session_data[token_key] = access_token
                if expires_at:
                    session_mgr.current_session_data[f"{scope_name}_token_expires_at"] = expires_at

                # Populate session metadata from JWT claims
                if claims.get("tid") and not session_mgr.current_session_data.get("tenant_id"):
                    session_mgr.current_session_data["tenant_id"] = claims["tid"]
                if upn and not session_mgr.current_session_data.get("account_name"):
                    session_mgr.current_session_data["account_name"] = upn
                if claims.get("oid") and not session_mgr.current_session_data.get("user_id"):
                    session_mgr.current_session_data["user_id"] = claims["oid"]

                session_mgr.save_current_session()

                console.print(f"[green]Token stored in slot:[/green] [bold]{token_key}[/bold]")
                console.print("[yellow]Note: This token cannot be refreshed automatically.[/yellow]")

                # Try to sync user info from Graph if we have a Graph token
                if scope_name == "graph":
                    console.print("[dim]Attempting to retrieve user information...[/dim]")
                    if session_mgr.sync_user_info_from_graph():
                        console.print("[green]User information retrieved.[/green]")
                    else:
                        console.print("[yellow]Could not retrieve user info.[/yellow]")

                has_login = True
                show_prompt_status(session_mgr.current_session, has_login)
                _log_command(session_mgr, cmd)

            elif cmd == "set_refresh_token":
                from getpass import getpass
                from pathlib import Path

                # Interactive token input method selection (same as set_token)
                console.print("\n[cyan]Refresh Token Input:[/cyan]")
                console.print("[dim]Refresh tokens allow automatic token exchange to discover service access[/dim]")
                console.print("[dim]Based on CloudProwl - discovers Microsoft services accessible with this token[/dim]")
                console.print("[1] From environment variable (AZURE_REFRESH_TOKEN)")
                console.print("[2] From file (recommended for long tokens)")
                console.print("[3] Direct input (hidden)")

                token_method = Prompt.ask(
                    "[cyan]Choose input method[/cyan]",
                    choices=["1", "2", "3"],
                    default="2",
                )

                refresh_token = ""
                if token_method == "1":
                    # Environment variable
                    import os
                    env_token = os.environ.get("AZURE_REFRESH_TOKEN", "").strip()
                    if env_token:
                        console.print(f"[green]Found token in AZURE_REFRESH_TOKEN env var ({len(env_token)} chars)[/green]")
                        refresh_token = env_token
                    else:
                        console.print("[yellow]AZURE_REFRESH_TOKEN environment variable not set[/yellow]")
                        continue
                elif token_method == "2":
                    # From file (most reliable for long tokens)
                    file_path = Prompt.ask(
                        "[cyan]Path to file containing refresh token[/cyan]",
                        default="/tmp/refresh_token.txt"
                    )
                    try:
                        token_file = Path(file_path.strip()).expanduser()
                        refresh_token = token_file.read_text().strip()
                        console.print(f"[green]Refresh token loaded from file: {token_file} ({len(refresh_token)} chars)[/green]")
                    except Exception as e:
                        console.print(f"[red]Error reading token file: {e}[/red]")
                        continue
                elif token_method == "3":
                    # Direct input (hidden)
                    refresh_token = getpass("Refresh Token: ").strip()

                if not refresh_token:
                    console.print("[red]Refresh token is required.[/red]")
                    continue

                # Optional: ask for tenant ID
                tenant_id = Prompt.ask(
                    "[cyan]Tenant ID (or press Enter for 'organizations')[/cyan]",
                    default="organizations"
                ).strip()

                # Store refresh token in session
                session_mgr.current_session_data["auth_method"] = "refresh_token"
                session_mgr.current_session_data["refresh_token"] = refresh_token
                session_mgr.current_session_data["tenant_id"] = tenant_id
                session_mgr.save_current_session()

                console.print(f"[green]✓ Refresh token stored ({len(refresh_token)} chars)[/green]")
                console.print(f"[cyan]Tenant:[/cyan] {tenant_id}\n")

                # Automatically launch service discovery (CloudProwl functionality)
                console.print("[cyan]Launching automatic service discovery...[/cyan]")
                from src.clouds.azure.modules.enumeration.token_exchange_discovery import (
                    discover_accessible_services
                )

                discover_accessible_services(session_mgr)

                has_login = True
                show_prompt_status(session_mgr.current_session, has_login)
                _log_command(session_mgr, cmd)

            elif cmd == "login_managed_identity":

                client_id = Prompt.ask(
                    "[cyan]Client ID (optional, for user-assigned identity)[/cyan]",
                    default=""
                ).strip()

                session_mgr.current_session_data["auth_method"] = "managed_identity"
                if client_id:
                    session_mgr.current_session_data["client_id"] = client_id
                session_mgr.save_current_session()

                console.print("[cyan]Testing managed identity authentication...[/cyan]")
                # Test credential by getting token
                credential = session_mgr.get_credential("management")
                if credential:
                    try:
                        token = credential.get_token("https://management.azure.com/.default")
                        console.print("[green]Managed identity authentication successful![/green]")

                        # Try to retrieve user information
                        console.print("[dim]Retrieving user information...[/dim]")
                        if session_mgr.sync_user_info_from_graph():
                            console.print("[green]User information retrieved.[/green]")
                        else:
                            console.print("[yellow]Could not retrieve user info (managed identity may lack Graph API permissions).[/yellow]")

                        has_login = True
                        show_prompt_status(session_mgr.current_session, has_login)
                    except Exception as e:
                        console.print(f"[red]Managed identity authentication failed: {e}[/red]")
                        console.print("[yellow]Ensure this is running in an Azure VM/container with managed identity enabled.[/yellow]")
                        has_login = False
                else:
                    console.print("[red]Failed to create credential.[/red]")
                    has_login = False

                _log_command(session_mgr, cmd)

            elif cmd == "get_graph_token":
                from getpass import getpass

                console.print("\n[bold cyan]Get Graph API Token (ROPC Flow)[/bold cyan]")
                console.print("[dim]Similar to AADInternals' Get-AADIntAccessTokenForMSGraph[/dim]")
                console.print("[yellow]Note: Does not work with MFA-enabled or federated accounts.[/yellow]\n")

                # Prompt for credentials
                username = Prompt.ask("[cyan]Username (email)[/cyan]").strip()
                if not username:
                    console.print("[red]Username is required.[/red]")
                    continue

                password = getpass("Password: ").strip()
                if not password:
                    console.print("[red]Password is required.[/red]")
                    continue

                # Optional: tenant ID (default to "organizations")
                tenant = Prompt.ask(
                    "[cyan]Tenant ID (optional, leave empty for auto-detect)[/cyan]",
                    default=""
                ).strip()

                # Use None if empty (will default to "organizations")
                tenant_param = tenant if tenant else None

                # Authenticate via ROPC
                if session_mgr.get_graph_token_via_ropc(username, password, tenant_param):
                    console.print("\n[green]Success! Graph API token obtained and stored.[/green]")
                    console.print("[dim]You can now use graph_* commands (e.g., graph_mail, graph_teams).[/dim]")
                else:
                    console.print("\n[red]Failed to obtain Graph API token.[/red]")
                    console.print("[yellow]Check your credentials and try again.[/yellow]")

                _log_command(session_mgr, cmd)

            elif cmd == "get_teams_token":
                from getpass import getpass

                console.print("\n[bold cyan]Get Teams API Token (ROPC Flow)[/bold cyan]")
                console.print("[dim]Similar to AADInternals' Get-AADIntAccessTokenForTeams[/dim]")
                console.print("[yellow]Note: Does not work with MFA-enabled or federated accounts.[/yellow]\n")

                # Prompt for credentials
                username = Prompt.ask("[cyan]Username (email)[/cyan]").strip()
                if not username:
                    console.print("[red]Username is required.[/red]")
                    continue

                password = getpass("Password: ").strip()
                if not password:
                    console.print("[red]Password is required.[/red]")
                    continue

                # Optional: tenant ID (default to "organizations")
                tenant = Prompt.ask(
                    "[cyan]Tenant ID (optional, leave empty for auto-detect)[/cyan]",
                    default=""
                ).strip()

                # Use None if empty (will default to "organizations")
                tenant_param = tenant if tenant else None

                # Authenticate via ROPC
                if session_mgr.get_teams_token_via_ropc(username, password, tenant_param):
                    console.print("\n[green]Success! Teams API token obtained and stored.[/green]")
                    console.print("[dim]This token allows access to Teams messages and channels.[/dim]")
                else:
                    console.print("\n[red]Failed to obtain Teams API token.[/red]")
                    console.print("[yellow]Check your credentials and try again.[/yellow]")

                _log_command(session_mgr, cmd)

            elif cmd == "whoami":
                data = session_mgr.current_session_data or {}

                # Show Session ID
                if session_mgr.session_id:
                    console.print(f"[cyan]CloudKnife Session ID:[/cyan] [dim]{session_mgr.session_id}[/dim]")

                # Show authentication method
                auth_method = data.get("auth_method")
                if auth_method:
                    console.print(f"[cyan]Authentication Method:[/cyan] {auth_method}")
                else:
                    console.print("[yellow]No authentication configured.[/yellow]")

                # Show tenant and subscription info
                if data.get("tenant_id"):
                    console.print(f"[cyan]Tenant:[/cyan] {data.get('tenant_id')}")

                if data.get("account_name"):
                    console.print(f"[cyan]Account:[/cyan] {data.get('account_name')}")

                if data.get("subscription_id"):
                    console.print(
                        f"[cyan]Subscription:[/cyan] {data.get('subscription_name')} "
                        f"({data.get('subscription_id')})"
                    )

                # User data saved in session
                if data.get("user_id"):
                    console.print(f"[cyan]ObjectId:[/cyan] {data.get('user_id')}")
                if data.get("user_display_name"):
                    console.print(f"[cyan]Display name:[/cyan] {data.get('user_display_name')}")
                if data.get("user_principal_name"):
                    console.print(f"[cyan]User principal name:[/cyan] {data.get('user_principal_name')}")
                if data.get("user_job_title"):
                    console.print(f"[cyan]Job title:[/cyan] {data.get('user_job_title')}")

                # Show token audience information
                import base64
                import json as _json
                import time as _time

                token_info = []
                for scope_name in ["graph", "management", "storage", "vault", "teams", "office", "outlook", "unknown"]:
                    token_key = f"{scope_name}_access_token"
                    token = data.get(token_key)

                    if token:
                        try:
                            parts = token.split(".")
                            if len(parts) == 3:
                                payload = parts[1]
                                payload += "=" * (4 - len(payload) % 4)
                                claims = _json.loads(base64.urlsafe_b64decode(payload))

                                aud = claims.get("aud", "unknown")
                                exp = claims.get("exp")

                                # Check if expired
                                is_expired = False
                                exp_str = ""
                                if exp:
                                    is_expired = _time.time() > exp
                                    from datetime import datetime
                                    exp_str = datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S")

                                status = "[red]EXPIRED[/red]" if is_expired else "[green]VALID[/green]"
                                token_info.append((scope_name, aud, status, exp_str))
                        except Exception:
                            pass

                if token_info:
                    console.print()
                    console.print("[bold cyan]Available Tokens:[/bold cyan]")
                    for scope_name, aud, status, exp_str in token_info:
                        console.print(f"  [cyan]{scope_name}:[/cyan] {status}")
                        console.print(f"    [dim]Audience: {aud}[/dim]")
                        if exp_str:
                            console.print(f"    [dim]Expires: {exp_str}[/dim]")

                # --- Graph API Permissions summary from bruteforce_graph_permissions ---
                bruteforce_data = session_mgr.get_enumeration_data("graph_permissions_bruteforce")

                if bruteforce_data:
                    from collections import defaultdict
                    from rich.table import Table

                    granted_permissions = bruteforce_data.get("granted_permissions", [])
                    total_tested = bruteforce_data.get("total_tested", 0)
                    total_granted = len(granted_permissions)

                    # Group permissions by category
                    by_category = defaultdict(list)
                    for perm in granted_permissions:
                        # Import from the module to get PERMISSION_CATEGORIES
                        from .modules.enumeration.graph_permissions_bruteforce import PERMISSION_CATEGORIES
                        category = PERMISSION_CATEGORIES.get(perm, "Other")
                        by_category[category].append(perm)

                    console.print()
                    perm_table = Table(
                        title=f"Graph API Permissions (GRANTED: {total_granted} / TESTED: {total_tested})"
                    )
                    perm_table.add_column("Category", style="cyan")
                    perm_table.add_column("Granted permissions")

                    if not by_category:
                        perm_table.add_row("–", "No GRANTED permissions recorded in bruteforce_graph_permissions.")
                    else:
                        for category in sorted(by_category.keys()):
                            perms = by_category[category]
                            perms_str = ", ".join(sorted(perms))
                            perm_table.add_row(category, perms_str)

                    console.print(perm_table)
                    console.print(
                        "[dim]Note: permissions above come from 'bruteforce_graph_permissions' results and reflect only tested actions.[/dim]"
                    )
                    console.print()
                elif auth_method:
                    # Only show hint if authenticated but no bruteforce data
                    console.print(
                        "\n[yellow]No Graph API permission data found for this session. "
                        "Run 'bruteforce_graph_permissions' to enumerate Graph permissions.[/yellow]\n"
                    )

                # Show warning if no auth configured
                if not auth_method:
                    console.print(
                        "[yellow]Use one of the authentication commands to configure access:[/yellow]"
                    )
                    console.print(
                        "[dim]  - set_service_principal: Service principal with client secret[/dim]"
                    )
                    console.print(
                        "[dim]  - login_interactive: Browser-based login[/dim]"
                    )
                    console.print(
                        "[dim]  - login_device_code: Device code flow[/dim]"
                    )
                    console.print(
                        "[dim]  - set_token: Use stolen/SSRF access token[/dim]"
                    )



            elif cmd == "list_sessions":
                show_sessions_table(session_mgr.list_sessions())

            elif cmd == "az":
                run_az_command(session_mgr, args)
                # Logging for az is handled internally in az_passthrough.py

            elif cmd == "discover_services" or cmd == "cloudprowl":
                """
                Discover accessible Microsoft services via token exchange.

                This command uses the CloudProwl technique to automatically discover
                which Microsoft services are accessible from a refresh token.

                Requires: refresh_token authentication (use set_refresh_token first)

                Services tested:
                - Microsoft Graph
                - Azure Resource Manager
                - Azure DevOps
                - Power Platform (BAP)
                - Power Apps
                - Microsoft Flow
                - Microsoft Teams
                - Outlook/Exchange Online
                """
                try:
                    from src.clouds.azure.modules.enumeration.token_exchange_discovery import (
                        discover_accessible_services
                    )

                    if not session_mgr.current_session_data.get("refresh_token"):
                        console.print("[red]No refresh token configured.[/red]")
                        console.print("[cyan]Use 'set_refresh_token' to configure a refresh token first.[/cyan]")
                        status = "failed"
                    else:
                        discover_accessible_services(session_mgr)
                        status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    import traceback
                    traceback.print_exc()
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_users":
                try:
                    enumerate_users(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_external_users":
                try:
                    enumerate_external_users(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_groups":
                try:
                    enumerate_groups(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_group_members":
                try:
                    enumerate_group_members(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_roles":
                try:
                    enumerate_role_assignments(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_all_roles":
                try:
                    enumerate_all_role_assignments(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_blobs":
                try:
                    enumerate_storage_blobs(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_storage_accounts":
                try:
                    enumerate_storage_accounts(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_storage_containers":
                try:
                    enumerate_storage_containers(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_storage_full":
                try:
                    enumerate_storage_full(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_container_apps":
                try:
                    enumerate_container_apps(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_container_apps_full":
                try:
                    enumerate_container_apps_full(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "exfiltrate_container_app_secrets":
                try:
                    exfiltrate_container_app_secrets(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_public_ips":
                try:
                    enumerate_public_ips(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_disks":
                try:
                    enumerate_disks(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_snapshots":
                try:
                    enumerate_snapshots(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_nsgs":
                try:
                    enumerate_nsgs(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_vnets":
                try:
                    enumerate_vnets(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_nics":
                try:
                    enumerate_nics(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_sql_vms":
                try:
                    enumerate_sql_vms(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_virtual_machines":
                try:
                    enumerate_virtual_machines(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "exfiltrate_app_settings":
                try:
                    exfiltrate_app_settings(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "vm_run_command":
                try:
                    vm_run_command(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_resources":
                try:
                    enumerate_resources(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_subscriptions":
                try:
                    enumerate_subscriptions(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "quick_enum":
                try:
                    quick_enum(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "set_subscription":

                # Check if subscription_id provided as argument
                if args and args[0]:
                    subscription_id = args[0].strip()
                    subscription_name = args[1].strip() if len(args) > 1 else None
                else:
                    # Try to load from enumeration data
                    subscriptions = session_mgr.get_enumeration_data("subscriptions")

                    if not subscriptions:
                        console.print("[yellow]No subscriptions found in enumeration data.[/yellow]")
                        console.print("[cyan]Run 'enumerate_subscriptions' first, or provide subscription ID:[/cyan]")
                        console.print("  set_subscription <subscription_id> [name]")
                        continue

                    # Display subscriptions
                    console.print(f"\n[cyan]Available subscriptions ({len(subscriptions)}):[/cyan]")
                    for idx, sub in enumerate(subscriptions, 1):
                        display_name = sub.get("display_name", "N/A")
                        sub_id = sub.get("subscription_id", "N/A")
                        state = sub.get("state", "Unknown")

                        state_color = "green" if state == "Enabled" else "red"
                        console.print(f"  [{state_color}]{idx}.[/{state_color}] {display_name}")
                        console.print(f"      [dim]{sub_id}[/dim]")

                    console.print()

                    # Ask user to select
                    choice = Prompt.ask(
                        "[cyan]Select subscription number (or 'q' to cancel)[/cyan]",
                        default="1"
                    )

                    if choice.lower() == 'q':
                        console.print("[yellow]Cancelled.[/yellow]")
                        continue

                    try:
                        idx = int(choice) - 1
                        if idx < 0 or idx >= len(subscriptions):
                            console.print("[red]Invalid selection.[/red]")
                            continue

                        selected_sub = subscriptions[idx]
                        subscription_id = selected_sub.get("subscription_id")
                        subscription_name = selected_sub.get("display_name")
                    except ValueError:
                        console.print("[red]Invalid input. Please enter a number.[/red]")
                        continue

                # Validate subscription_id format (GUID)
                import re
                if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', subscription_id, re.IGNORECASE):
                    console.print(f"[red]Invalid subscription ID format: {subscription_id}[/red]")
                    console.print("[dim]Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx[/dim]")
                    continue

                # Set subscription in session
                session_mgr.current_session_data["subscription_id"] = subscription_id
                if subscription_name:
                    session_mgr.current_session_data["subscription_name"] = subscription_name

                session_mgr.save_current_session()

                console.print(f"\n[green]✓ Subscription set successfully![/green]")
                if subscription_name:
                    console.print(f"  [cyan]Name:[/cyan] {subscription_name}")
                console.print(f"  [cyan]ID:[/cyan] {subscription_id}")
                console.print()
                console.print("[dim]This subscription will be used for resource enumeration commands.[/dim]")

                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_functions":
                try:
                    enumerate_functions(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_webapps":
                try:
                    enumerate_webapps(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            # MFA Bypass Audit
            elif cmd == "audit_mfa_gaps":
                from getpass import getpass

                console.print("\n[bold cyan]🔍 MFA Bypass Audit[/bold cyan]")
                console.print("[dim]Search for authentication bypasses that don't require MFA[/dim]\n")

                # Get credentials
                username = Prompt.ask("[cyan]Username (email/UPN)[/cyan]").strip()
                if not username:
                    console.print("[red]Username is required.[/red]")
                    continue

                password = getpass("Password: ").strip()
                if not password:
                    console.print("[red]Password is required.[/red]")
                    continue

                # Optional tenant ID
                tenant_id = Prompt.ask(
                    "[cyan]Tenant ID (optional, leave empty for auto-detect)[/cyan]",
                    default=""
                ).strip() or "organizations"

                # Parse arguments
                # Syntax: audit_mfa_gaps [fast|full] [--ua_all] [-r <resource_url>]
                fast_mode = True
                test_all_user_agents = False
                specific_resource = None

                i = 0
                while i < len(args):
                    arg = args[i].lower()
                    if arg in ["fast", "full"]:
                        fast_mode = (arg == "fast")
                    elif arg == "--ua_all":
                        test_all_user_agents = True
                    elif arg == "-r" and i + 1 < len(args):
                        specific_resource = args[i + 1]
                        i += 1  # Skip next arg (resource URL)
                    i += 1

                # Show what we're testing
                if test_all_user_agents:
                    console.print("[yellow]⚠️  Testing ALL user agents (10 UAs) - this will take longer![/yellow]")
                if specific_resource:
                    console.print(f"[cyan]Testing specific resource: {specific_resource}[/cyan]")

                try:
                    # Run audit
                    bypasses = run_mfa_audit(
                        username=username,
                        password=password,
                        tenant_id=tenant_id,
                        fast_mode=fast_mode,
                        test_all_user_agents=test_all_user_agents,
                        specific_resource=specific_resource
                    )

                    # Display results
                    display_bypass_results(bypasses)

                    # Offer to create sessions
                    if bypasses:
                        try:
                            if Confirm.ask("\n[cyan]Create CloudKnife sessions for these bypasses?[/cyan]", default=True):
                                created = create_bypass_sessions(session_mgr, bypasses)
                                console.print(f"\n[green]✓ Created {len(created)} session(s)[/green]")
                                for sess_name in created:
                                    console.print(f"  • [cyan]{sess_name}[/cyan]")

                                if created:
                                    # Automatically switch to the first created session
                                    first_session = created[0]
                                    session_mgr.create_or_load_session(first_session)
                                    console.print(f"\n[green]✓ Automatically switched to session: [cyan]{first_session}[/cyan][/green]")
                                    has_login = True
                                    show_prompt_status(session_mgr.current_session, has_login)
                        except Exception as session_err:
                            console.print(f"[red]Failed to create sessions: {session_err}[/red]")
                            import traceback
                            traceback.print_exc()

                    status = "success"
                except Exception as e:
                    console.print(f"[red]Audit failed: {e}[/red]")
                    import traceback
                    traceback.print_exc()
                    status = "failed"

                _log_command(session_mgr, cmd, status)

            # Microsoft Graph API Operations
            elif cmd == "enumerate_bruteforce_graph_permissions":
                try:
                    # Parse mode from args (default: fast)
                    mode = args[0].lower() if args else "fast"
                    # Validate mode
                    if mode not in ["fast", "full"]:
                        console.print(f"[yellow]Unknown mode '{mode}'. Using 'fast'.[/yellow]")
                        console.print("[dim]Usage: bruteforce_graph_permissions [fast|full][/dim]")
                        mode = "fast"

                    bruteforce_graph_permissions(session_mgr, mode=mode)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_bruteforce_aad_permissions":
                try:
                    # Parse mode from args (default: fast)
                    mode = args[0].lower() if args else "fast"
                    # Validate mode
                    if mode not in ["fast", "full"]:
                        console.print(f"[yellow]Unknown mode '{mode}'. Using 'fast'.[/yellow]")
                        console.print("[dim]Usage: bruteforce_aad_permissions [fast|full][/dim]")
                        mode = "fast"

                    bruteforce_aad_permissions(session_mgr, mode=mode)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_users_legacy":
                try:
                    enumerate_users_legacy(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_groups_legacy":
                try:
                    enumerate_groups_legacy(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_apps_legacy":
                try:
                    enumerate_apps_legacy(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "graph_mail":
                try:
                    # Optional: graph_mail [user_id]
                    user_id = args[0] if args else None
                    enumerate_mail(session_mgr, user_id=user_id)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "graph_teams":
                try:
                    enumerate_teams(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "graph_sharepoint":
                try:
                    enumerate_sharepoint(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "graph_files":
                try:
                    enumerate_files(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "graph_apps":
                try:
                    enumerate_apps(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "graph_ca_policies":
                try:
                    enumerate_ca_policies(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "teams_messages":
                try:
                    enumerate_teams_messages(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "download_blob":
                try:
                    download_storage_blob(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_keyvault_secrets":
                try:
                    enumerate_keyvault_secrets(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "exfiltrate_keyvault":
                try:
                    exfiltrate_keyvault(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_administrative_units":
                try:
                    enumerate_administrative_units(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_administrative_unit_scoped_members":
                try:
                    enumerate_administrative_unit_scoped_members(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "enumerate_administrative_unit_members":
                try:
                    enumerate_administrative_unit_members(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "change_user_password":
                try:
                    change_user_password(session_mgr)
                    status = "success"
                except Exception as e:
                    console.print(f"[red]Command failed: {e}[/red]")
                    status = "failed"
                # DUP-002: Use centralized logging helper
                _log_command(session_mgr, cmd, status)

            elif cmd == "use_session":
                name = args[0] if args else None
                if not name:
                    sessions = session_mgr.list_sessions()
                    names = [s["name"] for s in sessions]
                    if not names:
                        console.print("[yellow]No sessions available.[/yellow]")
                    else:
                        select_prompt = PromptSession(
                            completer=WordCompleter(names, ignore_case=True),
                            style=style,
                            auto_suggest=AutoSuggestFromHistory(),
                        )
                        chosen = select_prompt.prompt(
                            "Azure session name (TAB for autocomplete): ",
                        )
                        name = chosen.strip()

                if name:
                    session_mgr.azure_use_session(name)
                    has_login = bool(session_mgr.current_session_data.get("subscription_id"))
                    show_prompt_status(session_mgr.current_session, has_login)


            elif cmd == "delete_session":
                name = args[0] if args else None
                if not name:
                    console.print("[red]Specify a session name.[/red]")
                    continue

                if confirm_delete_session(name):
                    deleted = session_mgr.delete_session(name)
                    if deleted:
                        console.print("[green]Session deleted.[/green]")
                    else:
                        console.print("[yellow]Session could not be deleted.[/yellow]")

            elif cmd == "new_session":
                new_name = args[0] if args else None
                if not new_name:
                    new_name = PromptSession().prompt("New Azure session name: ")

                session_mgr.create_or_load_session(new_name)
                # Invalidate credential cache for new session
                session_mgr.clear_credential_cache()
                has_login = False
                show_prompt_status(session_mgr.current_session, has_login)

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
                    deleted = session_mgr.delete_all_sessions()
                    console.print(f"\n[green]✓ Deleted {deleted} session(s).[/green]")
                    has_login = False
                    show_prompt_status(session_mgr.current_session, has_login)
                else:
                    console.print("\n[yellow]Aborted. No sessions were deleted.[/yellow]")

            elif cmd in ("exit", "quit"):
                console.print("[red]Exit Azure mode...[/red]")
                return "exit"

            else:
                console.print(
                    f"[yellow]Unknown command: {' '.join(parts)}. Type 'help'.[/yellow]"
                )

        except KeyboardInterrupt:
            console.print("\n[red]Exit Azure mode...[/red]")
            return "exit"
        except EOFError:
            return "exit"
