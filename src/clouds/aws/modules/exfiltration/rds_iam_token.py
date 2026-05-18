"""
RDS IAM Authentication Token Generator

Generates IAM authentication tokens for RDS/Aurora databases that have
IAM database authentication enabled.

When IAM auth is enabled:
- No database password is needed
- Access is controlled via IAM policies
- Tokens are valid for 15 minutes
- Connection requires SSL

This is useful when:
- You have rds-db:connect permission
- The database has IAMDatabaseAuthenticationEnabled=true
- You know the database username (can be a DB user or IAM user mapped)

Supported engines: MySQL, PostgreSQL, Aurora MySQL, Aurora PostgreSQL
"""

from typing import Optional, Dict, Any, List

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import RegionalClientFactory


console = Console()


def generate_rds_token(
    session_mgr: AWSSessionManager,
    db_host: Optional[str] = None,
    db_port: Optional[int] = None,
    db_user: Optional[str] = None,
    region: Optional[str] = None,
) -> Optional[str]:
    """
    Generate an IAM authentication token for RDS database access.

    Args:
        session_mgr: Session manager instance
        db_host: RDS endpoint hostname
        db_port: Database port (default: 3306 for MySQL, 5432 for PostgreSQL)
        db_user: Database username (IAM user or DB user with IAM auth)
        region: AWS region of the database

    Returns:
        Authentication token string, or None on failure
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return None

    # Interactive input if not provided
    if not db_host:
        db_host = Prompt.ask("[cyan]RDS endpoint hostname[/cyan]")

    if not db_port:
        port_str = Prompt.ask("[cyan]Database port[/cyan]", default="3306")
        try:
            db_port = int(port_str)
        except ValueError:
            db_port = 3306

    if not db_user:
        db_user = Prompt.ask("[cyan]Database username[/cyan]")

    if not region:
        region = session_mgr.default_region
        region = Prompt.ask("[cyan]AWS region[/cyan]", default=region)

    console.print(f"\n[bold blue]🔑 Generating IAM auth token for:[/bold blue]")
    console.print(f"  Host: {db_host}")
    console.print(f"  Port: {db_port}")
    console.print(f"  User: {db_user}")
    console.print(f"  Region: {region}")

    try:
        client_factory = RegionalClientFactory(session_mgr)
        rds = client_factory.get_client("rds", region)

        # Generate the authentication token
        token = rds.generate_db_auth_token(
            DBHostname=db_host,
            Port=db_port,
            DBUsername=db_user,
            Region=region,
        )

        console.print("\n[bold green]✓ Token generated successfully![/bold green]")
        console.print(f"[dim]Token is valid for 15 minutes[/dim]\n")

        # Display the token
        console.print("[bold]Authentication Token:[/bold]")
        console.print(f"[cyan]{token}[/cyan]")

        # Show connection examples
        _show_connection_examples(db_host, db_port, db_user, token)

        # Save to session data
        token_data = {
            "host": db_host,
            "port": db_port,
            "user": db_user,
            "region": region,
            "token": token,
        }
        session_mgr.save_enumeration_data("rds_iam_token_last", token_data)

        return token

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        message = e.response.get("Error", {}).get("Message", "")

        if code in ("AccessDenied", "AccessDeniedException"):
            console.print(f"[bold red]✗ Access denied[/bold red]")
            console.print("[yellow]You need the 'rds-db:connect' permission to generate tokens.[/yellow]")
            console.print("[dim]Example IAM policy statement:[/dim]")
            console.print("""
  {
    "Effect": "Allow",
    "Action": "rds-db:connect",
    "Resource": "arn:aws:rds-db:<region>:<account>:dbuser:<resource-id>/<db-user>"
  }
""")
        else:
            console.print(f"[red]Error generating token: {code} - {message}[/red]")

        return None

    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        return None


def generate_rds_tokens_bulk(session_mgr: AWSSessionManager) -> None:
    """
    Generate IAM tokens for all IAM-auth-enabled databases found in session data.
    Requires running enumerate_rds_instances first.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    # Get enumerated RDS instances
    enum_data = session_mgr.enumerated_data.get(session_mgr.current_session, {})
    instances = enum_data.get("rds_instances", [])
    clusters = enum_data.get("rds_clusters", [])

    if not instances and not clusters:
        console.print("[yellow]No RDS data found. Run 'enumerate_rds' first.[/yellow]")
        return

    # Find IAM-auth-enabled databases
    iam_enabled_instances = [
        i for i in instances
        if i.get("IAMDatabaseAuthenticationEnabled") and i.get("Endpoint")
    ]
    iam_enabled_clusters = [
        c for c in clusters
        if c.get("IAMDatabaseAuthenticationEnabled") and c.get("Endpoint")
    ]

    total = len(iam_enabled_instances) + len(iam_enabled_clusters)
    if total == 0:
        console.print("[yellow]No IAM-auth-enabled databases found.[/yellow]")
        console.print("[dim]IAM authentication must be enabled on the database.[/dim]")
        return

    console.print(f"[bold blue]🔑 Found {total} database(s) with IAM authentication enabled[/bold blue]\n")

    # Prompt for database username
    db_user = Prompt.ask(
        "[cyan]Database username to generate tokens for[/cyan]",
        default="admin",
    )

    generated_tokens: List[Dict[str, Any]] = []

    # Generate tokens for instances
    for inst in iam_enabled_instances:
        console.print(f"\n[cyan]→ {inst['DBInstanceIdentifier']}[/cyan]")
        try:
            client_factory = RegionalClientFactory(session_mgr)
            rds = client_factory.get_client("rds", inst["Region"])

            token = rds.generate_db_auth_token(
                DBHostname=inst["Endpoint"],
                Port=inst["Port"],
                DBUsername=db_user,
                Region=inst["Region"],
            )

            generated_tokens.append({
                "Type": "Instance",
                "Identifier": inst["DBInstanceIdentifier"],
                "Endpoint": inst["Endpoint"],
                "Port": inst["Port"],
                "Engine": inst["Engine"],
                "Region": inst["Region"],
                "User": db_user,
                "Token": token,
            })
            console.print(f"[green]  ✓ Token generated[/green]")

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            console.print(f"[red]  ✗ Failed: {code}[/red]")

    # Generate tokens for clusters
    for cluster in iam_enabled_clusters:
        console.print(f"\n[cyan]→ {cluster['DBClusterIdentifier']} (cluster)[/cyan]")
        try:
            client_factory = RegionalClientFactory(session_mgr)
            rds = client_factory.get_client("rds", cluster["Region"])

            token = rds.generate_db_auth_token(
                DBHostname=cluster["Endpoint"],
                Port=cluster["Port"],
                DBUsername=db_user,
                Region=cluster["Region"],
            )

            generated_tokens.append({
                "Type": "Cluster",
                "Identifier": cluster["DBClusterIdentifier"],
                "Endpoint": cluster["Endpoint"],
                "Port": cluster["Port"],
                "Engine": cluster["Engine"],
                "Region": cluster["Region"],
                "User": db_user,
                "Token": token,
            })
            console.print(f"[green]  ✓ Token generated[/green]")

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            console.print(f"[red]  ✗ Failed: {code}[/red]")

    # Save results
    session_mgr.save_enumeration_data("rds_iam_tokens", generated_tokens)

    # Display summary
    if generated_tokens:
        _display_tokens_table(generated_tokens)
        console.print(
            f"\n[green]Generated {len(generated_tokens)} token(s). Stored under 'rds_iam_tokens' in session data.[/green]"
        )
        console.print("[yellow]Tokens are valid for 15 minutes.[/yellow]")
    else:
        console.print("\n[red]No tokens generated. Check IAM permissions.[/red]")


def _show_connection_examples(host: str, port: int, user: str, token: str) -> None:
    """Show connection command examples for different database engines."""
    console.print("\n[bold]Connection Examples:[/bold]")

    # Detect engine type from port (rough guess)
    if port == 3306:
        # MySQL
        console.print("\n[cyan]MySQL/Aurora MySQL:[/cyan]")
        console.print(f"""  mysql -h {host} -P {port} -u {user} \\
    --password='{token[:50]}...' \\
    --enable-cleartext-plugin --ssl-mode=REQUIRED
""")
    elif port == 5432:
        # PostgreSQL
        console.print("\n[cyan]PostgreSQL/Aurora PostgreSQL:[/cyan]")
        console.print(f"""  PGPASSWORD='{token[:50]}...' psql \\
    -h {host} -p {port} -U {user} \\
    "sslmode=require"
""")
    else:
        # Generic
        console.print(f"\n[dim]Use the token as password with SSL enabled on port {port}[/dim]")

    console.print("[dim]Note: Token is truncated in examples above. Use full token from output.[/dim]")
    console.print("[dim]SSL/TLS is REQUIRED when using IAM authentication.[/dim]")


def _display_tokens_table(tokens: List[Dict[str, Any]]) -> None:
    """Display generated tokens in a table."""
    table = Table(title="Generated IAM Authentication Tokens")
    table.add_column("Type", style="dim")
    table.add_column("Identifier", style="cyan")
    table.add_column("Endpoint")
    table.add_column("Port")
    table.add_column("Engine")
    table.add_column("User")
    table.add_column("Token (truncated)")

    for t in tokens:
        table.add_row(
            t["Type"],
            t["Identifier"],
            t["Endpoint"][:30] + "..." if len(t["Endpoint"]) > 30 else t["Endpoint"],
            str(t["Port"]),
            t["Engine"],
            t["User"],
            t["Token"][:40] + "...",
        )

    console.print(table)
