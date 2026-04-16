"""
List Access Keys - AWS IAM Enumeration

Lists all access keys for an IAM user. If no username is provided,
uses the current session's username.
"""

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager

console = Console()


def list_access_keys(session_mgr: AWSSessionManager, username: str = None) -> None:
    """
    List all access keys for an IAM user.

    Args:
        session_mgr: AWS session manager
        username: IAM username (optional, uses current user if not provided)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    # Get username from session if not provided
    if not username:
        # Try to extract username from ARN
        arn = session_mgr.current_session_data.get("arn")
        if arn and ":user/" in arn:
            # Extract username from ARN like "arn:aws:iam::123456789:user/username"
            username = arn.split(":user/")[-1]
            console.print(f"[dim]Using current session user: {username} (from ARN)[/dim]")
        else:
            if arn:
                console.print(f"[yellow]Current identity is not an IAM user (ARN: {arn}).[/yellow]")
            else:
                console.print("[yellow]No identity found in session. Run 'whoami' first.[/yellow]")
            console.print("[yellow]Please provide an IAM username explicitly.[/yellow]")
            return

    console.print(f"[bold blue]🔍 Listing access keys for user: {username}[/bold blue]")

    # Get IAM client
    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    try:
        response = iam.list_access_keys(UserName=username)
        access_keys = response.get("AccessKeyMetadata", [])

        if not access_keys:
            console.print(f"[yellow]No access keys found for user {username}.[/yellow]")
            return

        # Display results
        table = Table(title=f"Access Keys for {username}")
        table.add_column("Access Key ID", style="cyan", no_wrap=True)
        table.add_column("Status", style="green")
        table.add_column("Created", style="dim")

        for key in access_keys:
            status = key.get("Status", "Unknown")
            status_color = "green" if status == "Active" else "yellow"
            table.add_row(
                key.get("AccessKeyId", ""),
                f"[{status_color}]{status}[/{status_color}]",
                str(key.get("CreateDate", ""))[:19]
            )

        console.print(table)
        console.print(f"[dim]Total: {len(access_keys)} access key(s)[/dim]")

        # Save to session data
        keys_data = {
            "username": username,
            "access_keys": access_keys
        }
        session_mgr.save_enumeration_data(f"access_keys:{username}", keys_data)
        console.print(f"[green]Results saved to session data under 'access_keys:{username}'.[/green]")

    except iam.exceptions.NoSuchEntityException:
        console.print(f"[red]User {username} does not exist.[/red]")
    except Exception as e:
        console.print(f"[red]Failed to list access keys: {str(e)}[/red]")


def list_access_keys_interactive(session_mgr: AWSSessionManager) -> None:
    """Interactive wrapper for list_access_keys."""
    console.print("[bold yellow]🔍 List IAM Access Keys[/bold yellow]")
    console.print("[dim]Lists all access keys for a user (max 2 per user).[/dim]\n")

    username = Prompt.ask(
        "[cyan]IAM username (press Enter to use current session user)[/cyan]",
        default=""
    ).strip()

    list_access_keys(session_mgr, username if username else None)
