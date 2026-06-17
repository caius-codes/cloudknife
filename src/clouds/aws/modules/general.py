from collections import defaultdict
from typing import List
import os
from rich.prompt import Prompt, Confirm
from rich.console import Console
from rich.table import Table
from ..aws_session import AWSSessionManager

console = Console()


def set_keys(session_mgr: AWSSessionManager) -> None:
    console.print("[bold yellow]🔑 AWS Credentials for current session[/bold yellow]")
    access_key = Prompt.ask("[cyan]Access Key ID[/cyan]")
    secret_key = Prompt.ask("[cyan]Secret Access Key[/cyan]", password=True)

    # Session token with multiple input methods for long tokens
    console.print("\n[cyan]Session Token (optional):[/cyan]")
    console.print("[dim]Note: AWS session tokens can be very long (1000+ chars)[/dim]")
    console.print("[dim]Quick tip: pbpaste > /tmp/token.txt (then use option 2)[/dim]")
    console.print("[1] From environment variable (AWS_SESSION_TOKEN)")
    console.print("[2] From file (recommended for long tokens)")
    console.print("[3] Skip (no session token)")

    token_method = Prompt.ask(
        "[cyan]Choose input method[/cyan]",
        choices=["1", "2", "3"],
        default="3",
    )

    session_token = ""
    if token_method == "1":
        # Environment variable
        env_token = os.environ.get("AWS_SESSION_TOKEN", "").strip()
        if env_token:
            console.print(f"[green]Found token in AWS_SESSION_TOKEN env var ({len(env_token)} chars)[/green]")
            session_token = env_token
        else:
            console.print("[yellow]AWS_SESSION_TOKEN environment variable not set[/yellow]")
    elif token_method == "2":
        # From file (most reliable for long tokens)
        file_path = Prompt.ask(
            "[cyan]Path to file containing token[/cyan]",
            default="/tmp/token.txt"
        )
        try:
            with open(file_path.strip(), 'r') as f:
                session_token = f.read().strip()
            console.print(f"[green]Token read from file ({len(session_token)} chars)[/green]")
        except Exception as e:
            console.print(f"[red]Error reading file: {e}[/red]")
    # else: method == "3" -> skip (leave empty)

    region = Prompt.ask("[cyan]Default region[/cyan]", default="us-east-1")

    session_mgr.current_session_data.update(
        {
            "access_key": access_key,
            "secret_key": secret_key,
            "session_token": session_token if session_token else None,
            "region": region,
        }
    )
    session_mgr.save_current_session()
    console.print("[green]Credentials saved for current session![/green]")


def set_sso_profile(session_mgr: AWSSessionManager) -> None:
    """Set AWS credentials from existing SSO profile (profile-based approach)."""
    import configparser
    import boto3
    from botocore.exceptions import ProfileNotFound, SSOTokenLoadError

    console.print("[bold yellow]🔐 AWS SSO Profile Authentication[/bold yellow]")
    console.print("[dim]Uses existing AWS CLI SSO profiles from ~/.aws/config[/dim]\n")

    # Read AWS config to find SSO profiles
    config_path = os.path.expanduser('~/.aws/config')

    if not os.path.exists(config_path):
        console.print("[red]~/.aws/config not found.[/red]")
        console.print("[dim]Configure SSO with: aws configure sso[/dim]")
        return

    config = configparser.ConfigParser()
    config.read(config_path)

    # Find all SSO profiles
    sso_profiles = []
    for section in config.sections():
        # Sections are like "profile my-profile" or "default"
        if config.has_option(section, 'sso_account_id'):
            profile_name = section.replace('profile ', '') if section.startswith('profile ') else section
            account_id = config.get(section, 'sso_account_id')
            role_name = config.get(section, 'sso_role_name')
            sso_profiles.append({
                'name': profile_name,
                'account_id': account_id,
                'role_name': role_name,
                'section': section,
            })

    if not sso_profiles:
        console.print("[red]No SSO profiles found in ~/.aws/config[/red]")
        console.print("[dim]Configure SSO with: aws configure sso[/dim]")
        return

    # Display available profiles
    console.print("[cyan]Available SSO profiles:[/cyan]")
    for idx, profile in enumerate(sso_profiles, 1):
        console.print(f"  [{idx}] {profile['name']} - {profile['role_name']} in account {profile['account_id']}")

    # Let user select
    choice = Prompt.ask(
        "\n[cyan]Select profile[/cyan]",
        choices=[str(i) for i in range(1, len(sso_profiles) + 1)]
    )
    selected = sso_profiles[int(choice) - 1]
    profile_name = selected['name']

    console.print(f"\n[cyan]Authenticating with profile '{profile_name}'...[/cyan]")

    try:
        # Boto3 automatically handles SSO token caching and refresh
        session = boto3.Session(profile_name=profile_name)
        credentials = session.get_credentials()

        if credentials is None:
            console.print(f"\n[red]Failed to get credentials. SSO token may be expired.[/red]")
            console.print(f"[yellow]Run: aws sso login --profile {profile_name}[/yellow]")
            return

        # Get frozen credentials (to avoid lazy loading issues)
        frozen_creds = credentials.get_frozen_credentials()

        # Save credentials to session
        session_mgr.current_session_data.update({
            "access_key": frozen_creds.access_key,
            "secret_key": frozen_creds.secret_key,
            "session_token": frozen_creds.token,
            "region": session.region_name or "us-east-1",
            "auth_method": "sso_profile",
            "sso_profile": profile_name,
            "sso_account_id": selected['account_id'],
            "sso_role_name": selected['role_name'],
        })
        session_mgr.save_current_session()

        console.print(f"\n[green]✓ Authenticated with SSO profile '{profile_name}'[/green]")
        console.print(f"[dim]Account: {selected['account_id']} | Role: {selected['role_name']}[/dim]")

    except ProfileNotFound:
        console.print(f"[red]Profile '{profile_name}' not found in ~/.aws/config[/red]")
    except SSOTokenLoadError:
        console.print(f"\n[red]SSO token expired or not found.[/red]")
        console.print(f"[yellow]Run: aws sso login --profile {profile_name}[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def set_sso_interactive(session_mgr: AWSSessionManager) -> None:
    """Interactive SSO login with dynamic account/role selection (API-only, no CLI dependency)."""
    import boto3
    import webbrowser
    import time
    from botocore.exceptions import ClientError

    console.print("[bold yellow]🔐 AWS SSO Interactive Authentication[/bold yellow]")
    console.print("[dim]Select account and role dynamically after SSO login[/dim]\n")

    # 1. Get SSO configuration
    sso_start_url = Prompt.ask(
        "[cyan]SSO Start URL[/cyan]",
        default="https://d-xxxxxxxxxx.awsapps.com/start"
    )
    sso_region = Prompt.ask("[cyan]SSO Region[/cyan]", default="us-east-1")

    try:
        # 2. Register OAuth client with SSO OIDC
        oidc_client = boto3.client('sso-oidc', region_name=sso_region)

        console.print("\n[cyan]Registering OAuth client...[/cyan]")
        client_response = oidc_client.register_client(
            clientName='cloudknife-sso',
            clientType='public'
        )

        client_id = client_response['clientId']
        client_secret = client_response['clientSecret']

        # 3. Start device authorization flow
        console.print("[cyan]Starting device authorization...[/cyan]")
        device_response = oidc_client.start_device_authorization(
            clientId=client_id,
            clientSecret=client_secret,
            startUrl=sso_start_url
        )

        device_code = device_response['deviceCode']
        user_code = device_response['userCode']
        verification_uri = device_response['verificationUri']
        verification_uri_complete = device_response.get('verificationUriComplete', verification_uri)
        expires_in = device_response['expiresIn']
        interval = device_response.get('interval', 5)

        # 4. Display instructions and open browser
        console.print(f"\n[yellow]Opening browser for authentication...[/yellow]")
        console.print(f"[dim]Verification URL: {verification_uri}[/dim]")
        console.print(f"[dim]User Code: {user_code}[/dim]\n")

        # Open browser automatically
        webbrowser.open(verification_uri_complete)
        console.print("[green]✓ Browser opened! Please complete authentication in your browser.[/green]")
        console.print("[dim]Waiting for authorization...[/dim]\n")

        # 5. Poll for token (device authorization grant flow)
        access_token = None
        start_time = time.time()

        while time.time() - start_time < expires_in:
            try:
                time.sleep(interval)

                token_response = oidc_client.create_token(
                    clientId=client_id,
                    clientSecret=client_secret,
                    grantType='urn:ietf:params:oauth:grant-type:device_code',
                    deviceCode=device_code
                )

                access_token = token_response['accessToken']
                console.print("[green]✓ Authorization successful![/green]\n")
                break

            except ClientError as e:
                error_code = e.response['Error']['Code']

                if error_code == 'AuthorizationPendingException':
                    # Still waiting for user to authorize
                    continue
                elif error_code == 'SlowDownException':
                    # Requested to slow down polling
                    interval += 5
                    continue
                elif error_code == 'ExpiredTokenException':
                    console.print("[red]Authorization expired. Please try again.[/red]")
                    return
                else:
                    raise

        if not access_token:
            console.print("[red]Authorization timeout. Please try again.[/red]")
            return

        # 6. Create SSO client and list accounts
        sso_client = boto3.client('sso', region_name=sso_region)

        console.print("[cyan]Fetching available accounts...[/cyan]")
        accounts_response = sso_client.list_accounts(accessToken=access_token)
        accounts = accounts_response.get('accountList', [])

        if not accounts:
            console.print("[red]No accounts found. Check your SSO permissions.[/red]")
            return

        # Display accounts
        console.print(f"\n[cyan]Available accounts ({len(accounts)}):[/cyan]")
        for idx, account in enumerate(accounts, 1):
            console.print(f"  [{idx}] {account['accountName']} ({account['accountId']})")

        # Select account
        account_choice = Prompt.ask(
            "\n[cyan]Select account[/cyan]",
            choices=[str(i) for i in range(1, len(accounts) + 1)]
        )
        selected_account = accounts[int(account_choice) - 1]

        # 7. List roles for selected account
        console.print(f"\n[cyan]Fetching roles for {selected_account['accountName']}...[/cyan]")
        roles_response = sso_client.list_account_roles(
            accessToken=access_token,
            accountId=selected_account['accountId']
        )
        roles = roles_response.get('roleList', [])

        if not roles:
            console.print("[red]No roles found for this account.[/red]")
            return

        # Display roles
        console.print(f"\n[cyan]Available roles ({len(roles)}):[/cyan]")
        for idx, role in enumerate(roles, 1):
            console.print(f"  [{idx}] {role['roleName']}")

        # Select role
        role_choice = Prompt.ask(
            "\n[cyan]Select role[/cyan]",
            choices=[str(i) for i in range(1, len(roles) + 1)]
        )
        selected_role = roles[int(role_choice) - 1]

        # 8. Get credentials for selected account + role
        console.print(f"\n[cyan]Obtaining credentials for {selected_role['roleName']}...[/cyan]")
        creds_response = sso_client.get_role_credentials(
            accessToken=access_token,
            accountId=selected_account['accountId'],
            roleName=selected_role['roleName']
        )
        creds = creds_response['roleCredentials']

        # 9. Save credentials to session
        session_mgr.current_session_data.update({
            "access_key": creds['accessKeyId'],
            "secret_key": creds['secretAccessKey'],
            "session_token": creds['sessionToken'],
            "region": sso_region,
            "auth_method": "sso_interactive",
            "sso_account_id": selected_account['accountId'],
            "sso_account_name": selected_account['accountName'],
            "sso_role_name": selected_role['roleName'],
            "sso_start_url": sso_start_url,
        })
        session_mgr.save_current_session()

        console.print(f"\n[green]✓ Authenticated as {selected_role['roleName']} in {selected_account['accountName']}[/green]")
        console.print(f"[dim]Account ID: {selected_account['accountId']}[/dim]")

    except ClientError as e:
        console.print(f"[red]AWS API Error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _format_regions(regions: List[str]) -> str:
    if not regions:
        return "(none → use default region only)"
    if regions == ["all"]:
        return "ALL AWS regions (will be prompted per module)"
    return ", ".join(regions)


def set_regions(session_mgr: AWSSessionManager) -> None:
    """
    Set regions for enumeration modules (e.g. 'eu-west-1,us-east-1' or 'all').
    """
    current = session_mgr.configured_regions
    console.print("[bold yellow]🌍 Configure regions for enumeration modules[/bold yellow]")
    console.print(f"Current default region: [cyan]{session_mgr.default_region}[/cyan]")
    console.print(f"Current regions list: [cyan]{_format_regions(current)}[/cyan]")
    console.print(
        "Examples:\n"
        "  - 'eu-west-1,us-east-1' → enumerate only in these regions\n"
        "  - 'all' → tool will ask before scanning all available regions\n"
        "  - empty input → reset to default-region-only behaviour"
    )

    value = Prompt.ask("[cyan]Regions (comma-separated, 'all' or empty)[/cyan]", default="")
    value = value.strip()
    if not value:
        session_mgr.set_regions([])
        console.print("[green]Regions list cleared. Modules will use default region only.[/green]")
        return

    if value.lower() == "all":
        session_mgr.set_regions(["all"])
        console.print("[green]Regions set to 'all'. Modules may ask before scanning all AWS regions.[/green]")
        return

    regions = [r.strip() for r in value.split(",") if r.strip()]
    session_mgr.set_regions(regions)
    console.print(f"[green]Regions list updated: {', '.join(regions)}[/green]")


def set_region(session_mgr: AWSSessionManager, new_region: str = None) -> None:
    """
    Change the default region for the current session.
    Affects all modules that use the default region (lambda_details, bruteforce, etc.).
    """
    current = session_mgr.default_region
    if new_region:
        new_region = new_region.strip()
    else:
        console.print(f"Current default region: [cyan]{current}[/cyan]")
        new_region = Prompt.ask("[cyan]New default region[/cyan]", default=current).strip()

    if new_region == current:
        console.print("[yellow]Region unchanged.[/yellow]")
        return

    session_mgr.current_session_data["region"] = new_region
    session_mgr.save_current_session()
    console.print(f"[green]Default region updated: {current} → {new_region}[/green]")


def show_regions(session_mgr: AWSSessionManager) -> None:
    table = Table(title="Region configuration for current session")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Default region", session_mgr.default_region)
    table.add_row("Regions list", _format_regions(session_mgr.configured_regions))
    console.print(table)


def whoami(session_mgr: AWSSessionManager) -> None:
    """
    Show current AWS identity + summary of allowed actions from bruteforce_permissions.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    # --- Identity section ---
    try:
        aws_sess = session_mgr.get_boto3_session()
        sts = aws_sess.client("sts")
        identity = sts.get_caller_identity()
    except Exception as e:
        console.print(f"[red]AWS Error while calling STS:GetCallerIdentity: {str(e)}[/red]")
        console.print("[yellow]Check credentials and permissions.[/yellow]")
        return

    # Save identity data to session for use by other modules
    session_mgr.current_session_data["arn"] = identity["Arn"]
    session_mgr.current_session_data["user_id"] = identity["UserId"]
    session_mgr.current_session_data["account"] = identity["Account"]
    session_mgr.save_current_session()

    id_table = Table(title=f"AWS Identity - Session: {session_mgr.current_session}")
    id_table.add_column("Attribute", style="cyan")
    id_table.add_column("Value")
    if session_mgr.session_id:
        id_table.add_row("CloudKnife Session ID", f"[dim]{session_mgr.session_id}[/dim]")
    id_table.add_row("UserId", identity["UserId"])
    id_table.add_row("Account", identity["Account"])
    id_table.add_row("Arn", identity["Arn"])
    id_table.add_row("DefaultRegion", session_mgr.default_region)
    id_table.add_row("RegionsList", _format_regions(session_mgr.configured_regions))
    console.print(id_table)

    # --- Permissions summary from bruteforce_permissions ---
    bruteforce_data = (
        session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_bruteforce")
        if session_mgr.current_session in session_mgr.enumerated_data
        else None
    )

    if not bruteforce_data:
        console.print(
            "[yellow]No bruteforce permission data found for this session. "
            "Run 'enumerate_bruteforce_permissions' to enumerate allowed actions.[/yellow]"
        )
        return

    allowed_by_service = defaultdict(list)
    total_allowed = 0
    total_tested = len(bruteforce_data)

    for entry in bruteforce_data:
        if entry.get("status") == "ALLOWED":
            svc = entry.get("service", "unknown")
            allowed_by_service[svc].append(entry.get("action"))
            total_allowed += 1

    perm_table = Table(
        title=f"Bruteforce Permissions Summary (ALLOWED: {total_allowed} / TESTED: {total_tested})"
    )
    perm_table.add_column("Service", style="cyan")
    perm_table.add_column("Allowed actions (sample)")

    if not allowed_by_service:
        perm_table.add_row("–", "No ALLOWED actions recorded in bruteforce_permissions.")
    else:
        for svc, actions in allowed_by_service.items():
            actions_str = ", ".join(sorted(actions))
            perm_table.add_row(svc, actions_str)

    console.print(perm_table)
    console.print(
        "[dim]Note: permissions above come from 'bruteforce_permissions' results and reflect only tested actions.[/dim]"
    )


def list_sessions(session_mgr: AWSSessionManager) -> None:
    sessions = session_mgr.list_sessions()
    from ..aws_ui import show_sessions_table

    show_sessions_table(sessions)


def use_session(session_mgr: AWSSessionManager, name: str | None) -> None:
    from rich.prompt import Prompt
    from ..aws_ui import show_prompt_status

    if not name:
        name = Prompt.ask("[cyan]Session to use[/cyan]")
    available = {s["name"] for s in session_mgr.list_sessions()}
    if name not in available:
        console.print(f"[red]Session '{name}' not found.[/red]")
        return

    session_mgr.create_or_load_session(name)
    has_keys = bool(session_mgr.current_session_data.get("access_key"))
    show_prompt_status(session_mgr.current_session, has_keys)
    console.print(f"[bold green]Active session: {session_mgr.current_session}[/bold green]")


def delete_session(session_mgr: AWSSessionManager, name: str | None) -> None:
    from rich.prompt import Prompt
    from ..aws_ui import confirm_delete_session

    all_sessions = session_mgr.list_sessions()
    if len(all_sessions) <= 1:
        console.print(
            "[bold red]Cannot delete: at least one session must exist. "
            "Create a new one first.[/bold red]"
        )
        return

    if not name:
        name = Prompt.ask("[cyan]Session to delete[/cyan]")

    if name == session_mgr.current_session:
        console.print(
            "[bold red]Cannot delete the current session. "
            'Switch with "use_session" first.[/bold red]'
        )
        return

    available = {s["name"] for s in all_sessions}
    if name not in available:
        console.print(f"[red]Session '{name}' not found.[/red]")
        return

    if confirm_delete_session(name):
        deleted = session_mgr.delete_session(name)
        if deleted:
            console.print(f"[green]Session '{name}' deleted.[/green]")
        else:
            console.print("[red]Delete refused by safety checks.[/red]")


def new_session(session_mgr: AWSSessionManager) -> None:
    from rich.prompt import Prompt
    from ..aws_ui import show_prompt_status

    name = Prompt.ask("[cyan]New session name[/cyan]")
    session_mgr.create_or_load_session(name)
    has_keys = bool(session_mgr.current_session_data.get("access_key"))
    show_prompt_status(session_mgr.current_session, has_keys)
    console.print(f"[green]New session '{name}' created and activated.[/green]")
