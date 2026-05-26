from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...version import __version__

console = Console()

def print_banner(version: str = __version__):
    console.print(f"\n[bold orange1]☁️ Cloud Knife v{version} - AWS Module[/bold orange1]")
    console.print("[dim]Authorized use ONLY![/dim]\n")


def show_sessions_table(sessions):
    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    table = Table(title="Existing Sessions")
    table.add_column("Name", style="cyan")
    table.add_column("Session ID", style="dim")
    table.add_column("Keys")
    table.add_column("Account")
    table.add_column("Identity")
    table.add_column("Default Region")
    table.add_column("Regions List")
    table.add_column("Active")
    for s in sessions:
        active = "[bold green]★[/bold green]" if s["current"] else ""
        regions_list = ", ".join(s.get("regions", [])) if s.get("regions") else "(default only)"
        session_id = s.get("session_id", "") or "N/A"

        account = s.get("account", "") or "[dim]—[/dim]"
        arn = s.get("arn", "")
        if arn:
            # Extract principal from ARN: arn:aws:iam::123:user/alice → user/alice
            # or arn:aws:sts::123:assumed-role/RoleName/session → assumed-role/RoleName/session
            parts = arn.split(":")
            identity = parts[-1] if parts else arn
        else:
            identity = "[dim]—[/dim]"

        table.add_row(
            f"{s['name']}{active}",
            session_id,
            "[green]Yes[/green]" if s["keys_set"] else "[red]No[/red]",
            account,
            identity,
            s["region"],
            regions_list,
            "Yes" if s["current"] else "No",
        )
    console.print(table)


def ask_initial_session_choice(has_sessions: bool, session_names: list[str]) -> tuple[str, bool]:
    """
    At startup, ask whether to use a new or existing session.
    For existing sessions we only ask the name; autocomplete is handled in the main CLI.
    """
    if has_sessions:
        choice = Prompt.ask(
            "[cyan][1] New session [2] Use existing[/cyan]", choices=["1", "2"], default="2"
        )
    else:
        console.print("[yellow]No sessions yet. Creating a new one.[/yellow]")
        choice = "1"

    if choice == "1":
        name = Prompt.ask("[cyan]New session name[/cyan]")
        return name, True
    else:
        # For existing sessions we don't ask for input here: the actual name is prompted by the CLI with autocomplete.
        # Just return a placeholder to signal the main loop to load an existing session.
        return "", False


def show_prompt_status(session_name: str | None, has_keys: bool):
    status = "[green]✓[/green]" if has_keys else "[red]✗[/red]"
    console.print(f"[dim]Prompt: cloudknife[{session_name} {status}]> [/dim]\n")


def confirm_delete_session(session_name: str) -> bool:
    return Confirm.ask(f"[bold red]Delete session '{session_name}' permanently?[/bold red]")


def print_help():
    # Collect all commands and descriptions to calculate max widths for consistent alignment
    all_data = [
        # General
        ("help / ?", "Show this help"),
        ("search <keyword>", "Search modules by keyword"),
        ("clear_sessions", "Delete all saved sessions from disk"),
        (r"cloud \[aws | gcp | azure]", "Change cloud"),
        ("delete_session [name]", "Delete a session"),
        ("list_sessions", "List all sessions"),
        ("new_session", "Create a new session"),
        ("set_keys", "Set AWS credentials and default region for current session"),
        ("set_sso_profile", "Authenticate using existing AWS SSO profile"),
        ("set_sso_interactive", "Interactive SSO login with account/role selection"),
        ("set_region [region]", "Change the default region for the current session"),
        ("set_regions", "Configure regions list for enumeration modules"),
        ("show_regions", "Show default region and regions list"),
        ("use_session [name]", "Switch to an existing session"),
        ("whoami", "Show current AWS identity and bruteforce summary"),
        ("exit / quit", "Exit Cloud Knife"),
        # Enumeration
        ("analyze_privesc [quick|deep] [CRITICAL|HIGH|MEDIUM]", "Analyze IAM privilege escalation paths (quick: fast scan | deep: comprehensive analysis) - filter by severity (requires enumerate_bruteforce_permissions first)"),
        ("enumerate_bruteforce_permissions [services] [mode]", "Bruteforce IAM permissions across services (fast: 46 perms/12 svc | full: 148 perms/22 svc | low: 130 perms/24 svc)"),
        ("describe_dynamodb_table [TableName]", "Show detailed metadata and DescribeTable JSON for a DynamoDB table"),
        ("enumerate_action_query <query> [--all-or-none] [--role <role>] [--user <user>]", "Query which principals have specific IAM permissions (auto-enumerates policies)"),
        ("enumerate_dynamodb", "List DynamoDB tables (keys, encryption, PITR, streams) across regions"),
        ("enumerate_ebs_snapshots", "List EBS snapshots across regions and flag encryption"),
        ("enumerate_ec2", "List EC2 instances and collect userData (flag 📜 if present)"),
        ("enumerate_launch_templates", "Enumerate EC2 Launch Templates across regions: decodes UserData and scans for secrets (passwords, tokens, API keys, private keys)"),
        ("enumerate_ecr", "List ECR repositories and a sample of images per repo across regions"),
        ("enumerate_elasticbeanstalk", "Enumerate Elastic Beanstalk applications, environments, and application versions across regions"),
        ("enumerate_groundstation", "Enumerate Ground Station resources: sites, satellites, mission profiles, configs, dataflow groups, contacts, minute usage"),
        ("enumerate_groups [members]", "List IAM groups and optionally their members"),
        ("enumerate_iam_users_unauth", "Enumerate IAM users in target account (unauthenticated cross-account)"),
        ("enumerate_lambda", "List Lambda functions, env vars flag, and event sources"),
        ("enumerate_mq", "List Amazon MQ brokers (engine, state, exposure, users) across regions"),
        ("enumerate_policies", "List IAM policies (Scope, OnlyAttached filters)"),
        ("enumerate_rds", "List RDS instances and Aurora clusters (endpoints, IAM auth, encryption)"),
        ("enumerate_rds_snapshots [manual|automated] [--no-sharing]", "List RDS/Aurora snapshots (manual: user-created | automated: AWS-created | both if omitted) and check sharing attributes"),
        ("enumerate_rds_public_snapshots", "Search for PUBLIC RDS snapshots from other accounts (misconfigurations)"),
        ("enumerate_roles", "List IAM roles and test sts:AssumeRole (✅/❌/⚠️)"),
        ("enumerate_s3_buckets [bucket_name]", "List all S3 buckets or analyze a specific bucket (optional: bucket_name)"),
        ("enumerate_s3_objects [bucket] [prefix]", "Recursively list objects in a bucket/prefix"),
        ("enumerate_secrets", "List Secrets Manager secrets across regions"),
        ("enumerate_ssm", "List SSM Parameter Store parameters across regions (flags SecureString)"),
        ("enumerate_sns [--max-topics N] [--verbose]", "Enumerate SNS topics and subscriptions across regions"),
        ("enumerate_users", "List all IAM users (paginated)"),
        ("enumerate_oidc_providers", "List all OpenID Connect identity providers with details (issuer URLs, thumbprints, client IDs)"),
        ("enumerate_vulnerable_oidc [provider]", "Scan for vulnerable GitHub OIDC trust policies (missing/bypassable subject validation)"),
        ("describe_lambda_function [FunctionName] [--region eu-west-1]", "Show detailed configuration & env vars for a Lambda"),
        ("quick_enum", "Lightweight overview: counts for EC2, Lambda, DynamoDB, ECR, Secrets, MQ"),
        ("describe_ec2_userdata [InstanceId]", "Show cached userData for a specific EC2 instance"),
        ("analyze_privilege_escalation_paths", "Display previously analyzed privilege escalation paths from session"),
        ("describe_policy_document", "View IAM policy document (managed or inline)"),
        # Exfiltration
        ("download_iamgraph_data [output_path]", "Export complete IAM account authorization details for IAMGraph visualization"),
        ("download_ebs_snapshot [SnapshotId] [out_dir]", "Download an EBS snapshot as a local disk image using dsnap"),
        ("exfiltrate_dynamodb_table [TableName] [limit]", "Scan a DynamoDB table and exfiltrate a limited set of items"),
        ("exfiltrate_ec2_password [InstanceId] [key.pem] [--region]", "Retrieve and decrypt Windows EC2 Administrator password using private key"),
        ("download_s3_bucket [bucket] [prefix] [dest]", "Recursively download a bucket/prefix to local dir"),
        ("generate_rds_token [host] [port] [user] [region]", "Generate IAM auth token for RDS (15-min passwordless access)"),
        ("generate_rds_tokens_bulk", "Generate IAM tokens for all IAM-auth-enabled DBs (requires enumerate_rds first)"),
        ("get_ecr_credentials [registry_id] [--region r]", "Get ECR auth token + ready-to-use docker/podman login commands"),
        ("download_s3_object [bucket] [key] [dest]", "Download a single S3 object to local disk"),
        ("exfiltrate_secret [Name/ARN]", "Retrieve and display a specific secret value"),
        ("exfiltrate_ssm_parameters [path] [region] [output_dir]", "Bulk download SSM parameters recursively under a path to JSON file"),
        ("exfiltrate_ssm_parameter [name] [region]", "Retrieve single SSM parameter value (auto-decrypts SecureString)"),
        # Lateral movement
        ("assume_role_session [RoleArn] [NewSessionName]", "Assume an IAM role via STS and create a new Cloud Knife session"),
        # Exploitation
        ("ec2_startup_shell [InstanceId] [script] [--region]", "Abuse EC2 userData: stop, replace with shell script, start (exec at boot as root/SYSTEM)"),
        ("ssm_rce_ec2 [InstanceIds] [cmd]", "Run arbitrary commands on SSM-managed EC2 via Run Command"),
        ("ssm_start_session [InstanceId]", "Open an interactive SSM Session Manager shell (session-manager-plugin required)"),
        # Persistence
        ("create_access_key [username]", "Create a new access key for persistence (uses current user if not specified)"),
        ("enumerate_access_keys [username]", "List all access keys for a user (uses current user if not specified)"),
        ("delete_access_key", "Delete an access key for cleanup/revocation"),
        # Miscellaneous
        ("aws ...", "Run AWS CLI in shell (pipe | jq supported)"),
    ]

    # Calculate max widths for consistent column alignment across all tables
    max_cmd_width = max(len(cmd) for cmd, _ in all_data)
    max_desc_width = max(len(desc) for _, desc in all_data)

    with console.pager(styles=True):
        console.print("\n[bold orange]AWS Session Commands[/bold orange]\n")

        # General (alphabetically sorted)
        table1 = Table(title="[cyan]General[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table1.add_column("Command", style="bold", width=max_cmd_width)
        table1.add_column("Description", width=max_desc_width)
        table1.add_row("clear_sessions", "Delete all saved sessions from disk")
        table1.add_row(r"cloud \[aws | gcp | azure]", "Change cloud")
        table1.add_row("delete_session [name]", "Delete a session")
        table1.add_row("exit / quit", "Exit Cloud Knife")
        table1.add_row("help / ?", "Show this help")
        table1.add_row("list_sessions", "List all sessions")
        table1.add_row("new_session", "Create a new session")
        table1.add_row("set_keys", "Set AWS credentials and default region for current session")
        table1.add_row("set_sso_profile", "Authenticate using existing AWS SSO profile")
        table1.add_row("set_sso_interactive", "Interactive SSO login with account/role selection")
        table1.add_row("set_region [region]", "Change the default region for the current session")
        table1.add_row("set_regions", "Configure regions list for enumeration modules")
        table1.add_row("show_regions", "Show default region and regions list")
        table1.add_row("use_session [name]", "Switch to an existing session")
        table1.add_row("whoami", "Show current AWS identity and bruteforce summary")
        console.print(table1)

        console.print()

        # Enumeration (alphabetically sorted)
        table2 = Table(title="[cyan]Enumeration[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table2.add_column("Command", style="bold", width=max_cmd_width)
        table2.add_column("Description", width=max_desc_width)
        table2.add_row(
            "analyze_privesc [quick|deep] [CRITICAL|HIGH|MEDIUM]",
            "Analyze IAM privilege escalation paths (quick: fast scan | deep: comprehensive analysis) - filter by severity (requires enumerate_bruteforce_permissions first)",
        )
        table2.add_row(
            "analyze_privilege_escalation_paths",
            "Display previously analyzed privilege escalation paths from session",
        )
        table2.add_row(
            "describe_dynamodb_table [TableName]",
            "Show detailed metadata and DescribeTable JSON for a DynamoDB table",
        )
        table2.add_row("describe_ec2_userdata [InstanceId]", "Show cached userData for a specific EC2 instance")
        table2.add_row("describe_lambda_function [FunctionName] [--region eu-west-1]", "Show detailed configuration & env vars for a Lambda")
        table2.add_row("describe_policy_document", "View IAM policy document (managed or inline)")
        table2.add_row("enumerate_action_query <query> [--all-or-none] [--role <role>] [--user <user>]", "Query which principals have specific IAM permissions (auto-enumerates policies)")
        table2.add_row(
            "enumerate_bruteforce_permissions [services] [mode]",
            "Bruteforce IAM permissions across services (fast: 46 perms/12 svc | full: 148 perms/22 svc | low: 130 perms/24 svc)",
        )
        table2.add_row(
            "enumerate_dynamodb",
            "List DynamoDB tables (keys, encryption, PITR, streams) across regions",
        )
        table2.add_row("enumerate_ebs_snapshots", "List EBS snapshots across regions and flag encryption")
        table2.add_row("enumerate_ec2", "List EC2 instances and collect userData (flag 📜 if present)")
        table2.add_row(
            "enumerate_ecr",
            "List ECR repositories and a sample of images per repo across regions",
        )
        table2.add_row("enumerate_elasticbeanstalk", "Enumerate Elastic Beanstalk applications, environments, and application versions across regions")
        table2.add_row("enumerate_groundstation", "Enumerate Ground Station resources: sites, satellites, mission profiles, configs, dataflow groups, contacts, minute usage")
        table2.add_row("enumerate_groups [members]", "List IAM groups and optionally their members")
        table2.add_row("enumerate_iam_users_unauth", "Enumerate IAM users in target account (unauthenticated cross-account)")
        table2.add_row("enumerate_lambda", "List Lambda functions, env vars flag, and event sources")
        table2.add_row("enumerate_launch_templates", "Enumerate EC2 Launch Templates across regions: decodes UserData and scans for secrets (passwords, tokens, API keys, private keys)")
        table2.add_row(
            "enumerate_mq",
            "List Amazon MQ brokers (engine, state, exposure, users) across regions",
        )
        table2.add_row("enumerate_oidc_providers", "List all OpenID Connect identity providers with details (issuer URLs, thumbprints, client IDs)")
        table2.add_row("enumerate_policies", "List IAM policies (Scope, OnlyAttached filters)")
        table2.add_row("enumerate_rds", "List RDS instances and Aurora clusters (endpoints, IAM auth, encryption)")
        table2.add_row(
            "enumerate_rds_public_snapshots",
            "Search for PUBLIC RDS snapshots from other accounts (misconfigurations)",
        )
        table2.add_row(
            "enumerate_rds_snapshots [manual|automated] [--no-sharing]",
            "List RDS/Aurora snapshots (manual: user-created | automated: AWS-created | both if omitted) and check sharing attributes",
        )
        table2.add_row("enumerate_roles", "List IAM roles and test sts:AssumeRole (✅/❌/⚠️)")
        table2.add_row("enumerate_s3_buckets", "List all S3 buckets in the account")
        table2.add_row("enumerate_s3_objects [bucket] [prefix]", "Recursively list objects in a bucket/prefix")
        table2.add_row("enumerate_secrets", "List Secrets Manager secrets across regions")
        table2.add_row(
            "enumerate_sns [--max-topics N] [--verbose]",
            "Enumerate SNS topics and subscriptions across regions",
        )
        table2.add_row("enumerate_ssm", "List SSM Parameter Store parameters across regions (flags SecureString)")
        table2.add_row("enumerate_users", "List all IAM users (paginated)")
        table2.add_row("enumerate_vulnerable_oidc [provider]", "Scan for vulnerable GitHub OIDC trust policies (missing/bypassable subject validation)")
        table2.add_row(
            "quick_enum",
            "Lightweight overview: counts for EC2, Lambda, DynamoDB, ECR, Secrets, MQ",
        )



        console.print(table2)

        console.print()

        # Exfiltration (alphabetically sorted)
        table3 = Table(title="[cyan]Exfiltration[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table3.add_column("Command", style="bold", width=max_cmd_width)
        table3.add_column("Description", width=max_desc_width)
        table3.add_row(
            "download_ebs_snapshot [SnapshotId] [out_dir]",
            "Download an EBS snapshot as a local disk image using dsnap",
        )
        table3.add_row(
            "download_iamgraph_data [output_path]",
            "Export complete IAM account authorization details for IAMGraph visualization",
        )
        table3.add_row(
            "download_s3_bucket [bucket] [prefix] [dest]",
            "Recursively download a bucket/prefix to local dir",
        )
        table3.add_row("download_s3_object [bucket] [key] [dest]", "Download a single S3 object to local disk")
        table3.add_row(
            "exfiltrate_dynamodb_table [TableName] [limit]",
            "Scan a DynamoDB table and exfiltrate a limited set of items",
        )
        table3.add_row(
            "exfiltrate_ec2_password [InstanceId] [key.pem] [--region]",
            "Retrieve and decrypt Windows EC2 Administrator password using private key",
        )
        table3.add_row("exfiltrate_secret [Name/ARN]", "Retrieve and display a specific secret value")
        table3.add_row("exfiltrate_ssm_parameter [name] [region]", "Retrieve single SSM parameter value (auto-decrypts SecureString)")
        table3.add_row("exfiltrate_ssm_parameters [path] [region] [output_dir]", "Bulk download SSM parameters recursively under a path to JSON file")
        table3.add_row(
            "generate_rds_token [host] [port] [user] [region]",
            "Generate IAM auth token for RDS (15-min passwordless access)",
        )
        table3.add_row(
            "generate_rds_tokens_bulk",
            "Generate IAM tokens for all IAM-auth-enabled DBs (requires enumerate_rds first)",
        )
        table3.add_row("get_ecr_credentials [registry_id] [--region r]", "Get ECR auth token + ready-to-use docker/podman login commands")

        console.print(table3)

        console.print()

        # Lateral movement
        table4 = Table(title="[cyan]Lateral movement[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table4.add_column("Command", style="bold", width=max_cmd_width)
        table4.add_column("Description", width=max_desc_width)
        table4.add_row(
            "assume_role_session [RoleArn] [NewSessionName]",
            "Assume an IAM role via STS and create a new Cloud Knife session",
        )
        console.print(table4)

        # Exploitation (alphabetically sorted)
        table5 = Table(title="[cyan]Exploitation[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table5.add_column("Command", style="bold", width=max_cmd_width)
        table5.add_column("Description", width=max_desc_width)
        table5.add_row(
            "ec2_startup_shell [InstanceId] [script] [--region]",
            "Abuse EC2 userData: stop, replace with shell script, start (exec at boot as root/SYSTEM)",
        )
        table5.add_row(
            "ssm_rce_ec2 [InstanceIds] [cmd]",
            "Run arbitrary commands on SSM-managed EC2 via Run Command",
        )
        table5.add_row(
            "ssm_start_session [InstanceId]",
            "Open an interactive SSM Session Manager shell (session-manager-plugin required)",
        )
        console.print(table5)

        console.print()

        # Persistence (alphabetically sorted)
        table6 = Table(title="[cyan]Persistence[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table6.add_column("Command", style="bold", width=max_cmd_width)
        table6.add_column("Description", width=max_desc_width)
        table6.add_row(
            "create_access_key [username]",
            "Create a new access key for persistence (uses current user if not specified)",
        )
        table6.add_row(
            "delete_access_key",
            "Delete an access key for cleanup/revocation",
        )
        table6.add_row(
            "enumerate_access_keys [username]",
            "List all access keys for a user (uses current user if not specified)",
        )
        console.print(table6)

        console.print()

        # Miscellaneous
        table7 = Table(title="[cyan]Miscellaneous[/cyan]", show_header=False, box=None, padding=(0, 1), title_justify="center")
        table7.add_column("Command", style="bold", width=max_cmd_width)
        table7.add_column("Description", width=max_desc_width)
        table7.add_row(
            "aws ...",
            "Run AWS CLI in shell (pipe | jq supported)",
        )
        console.print(table7)
    
        console.print("\n[dim]Future categories: evasion...[/dim]\n")
