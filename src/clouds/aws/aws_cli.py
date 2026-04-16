#!/usr/bin/env python3

import os
import shlex
import subprocess
import sys

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML

from src.core.icons import icons
from .aws_session import AWSSessionManager
from .aws_ui import (
    print_banner,
    show_sessions_table,
    ask_initial_session_choice,
    show_prompt_status,
    print_help,
)

from .modules import (
    set_keys,
    set_sso_profile,
    set_sso_interactive,
    whoami,
    list_sessions as list_sessions_cmd,
    use_session as use_session_cmd,
    delete_session as delete_session_cmd,
    new_session as new_session_cmd,
    set_region,
    set_regions,
    show_regions,
)

from .modules.enumeration import (
    enumerate_users,
    bruteforce_permissions,
    analyze_privilege_escalation,
    show_privilege_escalation_paths,
    enumerate_policies_interactive,
    enumerate_inline_user_policies,
    enumerate_inline_role_policies,
    enumerate_attached_user_policies,
    enumerate_attached_role_policies,
    show_policy_document,
    enumerate_action_query,
    enumerate_vulnerable_oidc,
    enumerate_oidc_providers,
    enumerate_ec2,
    show_ec2_userdata,
    enumerate_lambda,
    show_lambda_details,
    enumerate_secrets,
    enumerate_ssm_parameters,
    enumerate_s3_buckets,
    enumerate_s3_objects,
    enumerate_roles,
    enumerate_ebs_snapshots,
    enumerate_groups,
    enumerate_dynamodb_tables,
    dynamodb_table_details,
    enumerate_ecr_repositories,
    enumerate_mq_brokers,
    quick_enum,
    sns_enum,
    enumerate_iam_users_unauth_interactive,
    enumerate_rds_instances,
    enumerate_rds_snapshots,
    enumerate_rds_public_snapshots_interactive,
    enumerate_groundstation,
    enumerate_elasticbeanstalk,
    enumerate_launch_templates,
)

from .modules.exfiltration import (
    s3_download_object,
    s3_download_bucket,
    download_ebs_snapshot,
    dynamodb_scan,
    ec2_get_password,
    secret_value,
    get_ssm_parameter_value,
    ssm_bulk_download,
    collect_iamgraph_data,
    generate_rds_iam_token,
    generate_rds_iam_tokens_bulk,
    ecr_get_login,
)

from .modules.lateral import assume_role_new_session

from .modules.exploitation import (
    ssm_rce_ec2,
    ssm_start_session,
    ec2_startup_shell,
)

from .modules.persistence import (
    create_access_key_interactive,
    delete_access_key_interactive,
    list_access_keys_interactive,
)

from ...logging import get_command_logger

logger = get_command_logger()

style = Style.from_dict(
    {
        "badge": "bold orange",
        "prompt": "bold green",
        "session": "bold cyan",
    }
)


def _log_command(session_mgr: AWSSessionManager, command: str, status: str = "executed") -> None:
    """Helper per loggare comandi AWS."""
    if logger.should_log_command(command):
        logger.log_command(
            cloud="aws",
            session_id=session_mgr.session_id or "unknown",
            session_name=session_mgr.current_session or "unknown",
            command=command,
            status=status,
        )


def run_aws_cli_from_shell(raw_cmd: str, session_mgr: AWSSessionManager) -> None:
    """
    Esegui un comando AWS CLI tramite shell, usando le credenziali
    della sessione corrente di Cloud Knife (env vars AWS_*).
    Supporta pipe (es. | jq).
    """
    from rich.console import Console

    console = Console()

    raw_cmd = raw_cmd.strip()
    if not raw_cmd or not raw_cmd.startswith("aws"):
        console.print(
            "[yellow]Use: aws ... (this wrapper is only for AWS CLI commands).[/yellow]"
        )
        return

    # Estrai credenziali dalla sessione corrente
    sess = session_mgr.current_session_data or {}
    access_key = sess.get("access_key")
    secret_key = sess.get("secret_key")
    session_token = sess.get("session_token")

    # region can be stored in different ways
    region = (
        sess.get("region")
        or (sess.get("regions", [None])[0] if isinstance(sess.get("regions"), list) else sess.get("regions"))
    )

    if not access_key or not secret_key:
        console.print(
            "[red]No AWS keys set in current Cloud Knife session. Use set_keys first.[/red]"
        )
        return

    console.print(
        "[bold yellow]🚀 Running AWS CLI with Cloud Knife session credentials (env AWS_*).[/bold yellow]"
    )
    console.print(
        "[dim]This overrides AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN for this command only.[/dim]"
    )

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    if session_token:
        env["AWS_SESSION_TOKEN"] = session_token
    if region:
        env["AWS_REGION"] = region
        env["AWS_DEFAULT_REGION"] = region

    try:
        proc = subprocess.Popen(
            raw_cmd,
            shell=True,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
            universal_newlines=True,
            bufsize=1,
            env=env,
        )
        proc.wait()

        # Log comando
        if proc.returncode == 0:
            logger.log_command(
                cloud="aws",
                session_id=session_mgr.session_id or "unknown",
                session_name=session_mgr.current_session or "unknown",
                command=raw_cmd,
                status="executed",
                exit_code=0,
            )
        else:
            console.print(f"[red]AWS CLI exited with code {proc.returncode}[/red]")
            logger.log_command(
                cloud="aws",
                session_id=session_mgr.session_id or "unknown",
                session_name=session_mgr.current_session or "unknown",
                command=raw_cmd,
                status="failed",
                exit_code=proc.returncode,
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        logger.log_command(
            cloud="aws",
            session_id=session_mgr.session_id or "unknown",
            session_name=session_mgr.current_session or "unknown",
            command=raw_cmd,
            status="failed",
            error_message="Interrupted by user",
        )
    except Exception as e:
        console.print(f"[red]Error running AWS CLI: {e}[/red]")
        logger.log_command(
            cloud="aws",
            session_id=session_mgr.session_id or "unknown",
            session_name=session_mgr.current_session or "unknown",
            command=raw_cmd,
            status="failed",
            error_message=str(e),
        )


def build_completer(session_mgr: AWSSessionManager) -> WordCompleter:
    sessions = [s["name"] for s in session_mgr.list_sessions()]
    commands = [
        "help",
        "set_keys",
        "set_sso_profile",
        "set_sso_interactive",
        "set_region",
        "set_regions",
        "show_regions",
        "whoami",
        "list_sessions",
        "use_session",
        "delete_session",
        "new_session",
        "enumerate_users",
        "enumerate_roles",
        "enumerate_groups",
        "enumerate_policies",
        "enumerate_action_query",
        "enumerate_vulnerable_oidc",
        "enumerate_oidc_providers",
        "enumerate_iam_users_unauth",
        "enumerate_ec2",
        "enumerate_mq",
        "enumerate_sns",
        "show_ec2_userdata",
        "enumerate_lambda",
        "lambda_details",
        "enumerate_secrets",
        "secret_value",
        "enumerate_ssm",
        "ssm_parameter_value",
        "ssm_bulk_download",
        "collect_iamgraph_data",
        "show_policy_document",
        "enumerate_s3_buckets",
        "enumerate_s3_objects",
        "s3_download_object",
        "s3_download_bucket",
        "bruteforce_permissions",
        "analyze_privesc",
        "show_escalation_paths",
        "assume_role_session",
        "enumerate_ebs_snapshots",
        "download_ebs_snapshot",
        "ec2_get_password",
        "ssm_rce_ec2",
        "ssm_start_session",
        "create_access_key",
        "delete_access_key",
        "list_access_keys",
        "enumerate_dynamodb",
        "dynamodb_table_details",
        "dynamodb_scan",
        "enumerate_ecr",
        "clear_sessions",
        "quick_enum",
        "ec2_startup_shell",
        "enumerate_rds",
        "enumerate_rds_snapshots",
        "enumerate_rds_public_snapshots",
        "rds_iam_token",
        "rds_iam_tokens_bulk",
        "enumerate_groundstation",
        "enumerate_elasticbeanstalk",
        "enumerate_launch_templates",
        "ecr_get_login",
        "aws",
        "cloud",
        "exit",
        "quit",
    ]
    return WordCompleter(commands + sessions, ignore_case=True)


def run_aws_cli(session_mgr: AWSSessionManager) -> str:
    """
    Sub-CLI AWS: gestisce sessioni e comandi AWS.
    Ritorna:
      - "aws" / "azure" / "gcp" per switch diretto
      - "switch" per tornare al menu cloud
      - "exit" per uscire dal tool
    """
    from rich.console import Console

    console = Console()

    print_banner()

    existing_sessions = session_mgr.list_sessions()
    show_sessions_table(existing_sessions)

    existing_names = [s["name"] for s in existing_sessions]

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

    has_keys = bool(session_mgr.current_session_data.get("access_key"))
    show_prompt_status(session_mgr.current_session, has_keys)

    session_prompt = PromptSession(
        completer=build_completer(session_mgr),
        style=style,
        auto_suggest=AutoSuggestFromHistory(),
    )

    AWS_BADGE = f"AWS {icons.aws}"

    while True:
        try:
            if session_mgr.current_session:
                prompt_text = HTML(
                    f"<badge>{AWS_BADGE}</badge><prompt>cloudknife[<session>{session_mgr.current_session or 'no-session'}</session>]&gt; </prompt>"
                )
            else:
                prompt_text = HTML(f"<badge>{AWS_BADGE}</badge><prompt>cloudknife&gt; </prompt>")

            user_input = session_prompt.prompt(prompt_text, style=style)
            parts = user_input.strip().split()
            if not parts:
                continue
            cmd = parts[0].lower()
            args = parts[1:]

            # passthrough AWS CLI
            if cmd == "aws":
                run_aws_cli_from_shell(user_input, session_mgr)
                continue

            # switch cloud
            if cmd == "cloud":
                # cloud -> torna al menu; cloud azure -> passa ad Azure, ecc.
                if args and args[0].lower() in ("aws", "azure", "gcp"):
                    return args[0].lower()
                return "switch"

            if cmd in ("help", "?"):
                print_help()

            elif cmd == "set_keys":
                set_keys(session_mgr)

            elif cmd == "set_sso_profile":
                set_sso_profile(session_mgr)

            elif cmd == "set_sso_interactive":
                set_sso_interactive(session_mgr)

            elif cmd == "set_region":
                # Accepts optional inline arg: set_region eu-west-1
                set_region(session_mgr, args[0] if args else None)

            elif cmd == "set_regions":
                set_regions(session_mgr)

            elif cmd == "show_regions":
                show_regions(session_mgr)

            elif cmd == "whoami":
                whoami(session_mgr)

            elif cmd == "list_sessions":
                list_sessions_cmd(session_mgr)

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
                            "Session name (TAB for autocomplete): ",
                            style=style,
                        )
                        name = chosen.strip()
                if name:
                    use_session_cmd(session_mgr, name)

            elif cmd == "delete_session":
                name = args[0] if args else None
                delete_session_cmd(session_mgr, name)

            elif cmd == "new_session":
                new_session_cmd(session_mgr)

            elif cmd == "enumerate_users":
                enumerate_users(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "clear_sessions":
                from rich.console import Console
                from rich.prompt import Confirm

                console = Console()
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
                else:
                    console.print("\n[yellow]Aborted. No sessions were deleted.[/yellow]")

            elif cmd == "enumerate_groups":
                include_members = False
                if len(args) > 0 and args[0].lower() in ("members", "with_members", "full"):
                    include_members = True
                enumerate_groups(session_mgr, include_members)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_roles":
                enumerate_roles(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_policies":
                enumerate_policies_interactive(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_action_query":
                # Parse arguments: query, --all-or-none, --role, --user
                if not args:
                    console.print("[red]Usage: enumerate_action_query <query> [--all-or-none] [--role <role>] [--user <user>][/red]")
                    console.print("[dim]Example: enumerate_action_query s3:GetObject,iam:ListUsers --all-or-none[/dim]")
                    continue

                query = args[0]
                all_or_none = False
                role_filter = None
                user_filter = None

                i = 1
                while i < len(args):
                    if args[i] == "--all-or-none":
                        all_or_none = True
                        i += 1
                    elif args[i] == "--role" and i + 1 < len(args):
                        role_filter = args[i + 1]
                        i += 2
                    elif args[i] == "--user" and i + 1 < len(args):
                        user_filter = args[i + 1]
                        i += 2
                    else:
                        i += 1

                enumerate_action_query(session_mgr, query, all_or_none, role_filter, user_filter)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_vulnerable_oidc":
                provider_filter = args[0] if args else None
                enumerate_vulnerable_oidc(session_mgr, provider_filter)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_oidc_providers":
                enumerate_oidc_providers(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_iam_users_unauth":
                enumerate_iam_users_unauth_interactive(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "show_policy_document":
                arn = args[0] if args else None
                show_policy_document(session_mgr, arn)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_ec2":
                enumerate_ec2(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_sns":
                result = sns_enum(
                    session_mgr,
                    max_topics=getattr(args, "max_topics", 100),
                    verbose=getattr(args, "verbose", False),
                )
                _log_command(session_mgr, cmd)
                return result

            elif cmd == "enumerate_mq":
                enumerate_mq_brokers(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_ecr":
                enumerate_ecr_repositories(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_dynamodb":
                enumerate_dynamodb_tables(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "dynamodb_table_details":
                tname = args[0] if args else None
                dynamodb_table_details(session_mgr, tname)
                _log_command(session_mgr, cmd)

            elif cmd == "dynamodb_scan":
                tname = args[0] if len(args) > 0 else None
                limit = args[1] if len(args) > 1 else None
                dynamodb_scan(session_mgr, tname, limit)
                _log_command(session_mgr, cmd)

            elif cmd == "ec2_get_password":
                inst_id = args[0] if len(args) > 0 else None
                key_path = args[1] if len(args) > 1 else None
                region = None
                # Parse --region flag
                for i, arg in enumerate(args):
                    if arg == "--region" and i + 1 < len(args):
                        region = args[i + 1]
                        break
                ec2_get_password(session_mgr, inst_id, key_path, region)
                _log_command(session_mgr, cmd)

            elif cmd == "ssm_rce_ec2":
                inst_arg = args[0] if len(args) > 0 else None
                cmd_arg = args[1] if len(args) > 1 else None
                ssm_rce_ec2(session_mgr, inst_arg, cmd_arg)
                _log_command(session_mgr, cmd)

            elif cmd == "ssm_start_session":
                inst_id = args[0] if len(args) > 0 else None
                ssm_start_session(session_mgr, inst_id)
                _log_command(session_mgr, cmd)

            elif cmd == "create_access_key":
                create_access_key_interactive(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "delete_access_key":
                delete_access_key_interactive(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "list_access_keys":
                list_access_keys_interactive(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_lambda":
                enumerate_lambda(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "lambda_details":
                fn_name = None
                region = None
                skip_next = False
                for i, arg in enumerate(args):
                    if skip_next:
                        skip_next = False
                        continue
                    if arg == "--region" and i + 1 < len(args):
                        region = args[i + 1]
                        skip_next = True
                    elif not arg.startswith("--"):
                        fn_name = arg
                show_lambda_details(session_mgr, fn_name, region)
                _log_command(session_mgr, cmd)

            elif cmd == "quick_enum":
                quick_enum(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "show_ec2_userdata":
                inst_id = args[0] if args else None
                show_ec2_userdata(session_mgr, inst_id)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_secrets":
                enumerate_secrets(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "secret_value":
                sec_id = args[0] if args else None
                secret_value(session_mgr, sec_id)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_ssm":
                enumerate_ssm_parameters(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "ssm_parameter_value":
                param_name = args[0] if len(args) > 0 else None
                region = args[1] if len(args) > 1 else None
                get_ssm_parameter_value(session_mgr, param_name, region)
                _log_command(session_mgr, cmd)

            elif cmd == "ssm_bulk_download":
                path_filter = args[0] if len(args) > 0 else None
                region = args[1] if len(args) > 1 else None
                output_dir = args[2] if len(args) > 2 else None
                ssm_bulk_download(session_mgr, path_filter, region, output_dir)
                _log_command(session_mgr, cmd)

            elif cmd == "collect_iamgraph_data":
                output_path = args[0] if args else None
                collect_iamgraph_data(session_mgr, output_path)
                _log_command(session_mgr, cmd)

            elif cmd == "assume_role_session":
                role_arn = args[0] if len(args) > 0 else None
                new_name = args[1] if len(args) > 1 else None
                assume_role_new_session(session_mgr, role_arn, new_name)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_ebs_snapshots":
                enumerate_ebs_snapshots(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "ec2_startup_shell":
                ec2_startup_shell(session_mgr, args)
                _log_command(session_mgr, cmd)

            elif cmd == "bruteforce_permissions":
                services_arg = None
                mode = "fast"
                if len(args) == 1:
                    if args[0].lower() in ("full", "low"):
                        services_arg = None
                        mode = args[0].lower()
                    else:
                        services_arg = args[0]
                        mode = "fast"
                elif len(args) >= 2:
                    services_arg = args[0]
                    mode = args[1]
                bruteforce_permissions(session_mgr, services_arg, mode)
                _log_command(session_mgr, cmd)

            elif cmd == "analyze_privesc":
                scan_type = "quick"
                severity_filter = None
                if len(args) >= 1:
                    scan_type = args[0].lower()
                if len(args) >= 2:
                    severity_filter = args[1].upper()
                analyze_privilege_escalation(session_mgr, scan_type, severity_filter)
                _log_command(session_mgr, cmd)

            elif cmd == "show_escalation_paths":
                show_privilege_escalation_paths(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_s3_buckets":
                enumerate_s3_buckets(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_s3_objects":
                bucket = args[0] if len(args) > 0 else None
                prefix = args[1] if len(args) > 1 else None
                enumerate_s3_objects(session_mgr, bucket, prefix)
                _log_command(session_mgr, cmd)

            elif cmd == "s3_download_object":
                bucket = args[0] if len(args) > 0 else None
                key = args[1] if len(args) > 1 else None
                dest = args[2] if len(args) > 2 else None
                s3_download_object(session_mgr, bucket, key, dest)
                _log_command(session_mgr, cmd)

            elif cmd == "s3_download_bucket":
                bucket = args[0] if len(args) > 0 else None
                prefix = args[1] if len(args) > 1 else None
                dest = args[2] if len(args) > 2 else None
                s3_download_bucket(session_mgr, bucket, prefix, dest)
                _log_command(session_mgr, cmd)

            elif cmd == "download_ebs_snapshot":
                snap_id = args[0] if len(args) > 0 else None
                out_dir = args[1] if len(args) > 1 else None
                download_ebs_snapshot(session_mgr, snap_id, out_dir)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_rds":
                enumerate_rds_instances(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_rds_snapshots":
                snapshot_type = "all"
                check_sharing = True
                for arg in args:
                    if arg in ("manual", "automated"):
                        snapshot_type = arg
                    elif arg == "--no-sharing":
                        check_sharing = False
                enumerate_rds_snapshots(session_mgr, snapshot_type, check_sharing)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_rds_public_snapshots":
                enumerate_rds_public_snapshots_interactive(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "rds_iam_token":
                host = args[0] if len(args) > 0 else None
                port = int(args[1]) if len(args) > 1 else None
                user = args[2] if len(args) > 2 else None
                region = args[3] if len(args) > 3 else None
                generate_rds_iam_token(session_mgr, host, port, user, region)
                _log_command(session_mgr, cmd)

            elif cmd == "rds_iam_tokens_bulk":
                generate_rds_iam_tokens_bulk(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_groundstation":
                enumerate_groundstation(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_elasticbeanstalk":
                enumerate_elasticbeanstalk(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "enumerate_launch_templates":
                enumerate_launch_templates(session_mgr)
                _log_command(session_mgr, cmd)

            elif cmd == "ecr_get_login":
                reg_id = None
                region = None
                skip_next = False
                for i, arg in enumerate(args):
                    if skip_next:
                        skip_next = False
                        continue
                    if arg == "--region" and i + 1 < len(args):
                        region = args[i + 1]
                        skip_next = True
                    elif not arg.startswith("--"):
                        reg_id = arg
                ecr_get_login(session_mgr, reg_id, region)
                _log_command(session_mgr, cmd)

            elif cmd in ("exit", "quit"):
                console.print("[red]Exit AWS mode...[/red]")
                return "exit"

            else:
                console.print(
                    f"[yellow]Unknown command: {' '.join(parts)}. Type 'help'.[/yellow]"
                )

        except KeyboardInterrupt:
            console.print("\n[red]Exit AWS mode...[/red]")
            return "exit"
        except EOFError:
            return "exit"
