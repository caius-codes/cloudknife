"""
Create Access Key - AWS IAM Persistence

Creates a new access key for an IAM user. If no username is provided,
uses the current session's username (from GetUser or whoami).
"""

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...aws_session import AWSSessionManager

console = Console()


def create_access_key(session_mgr: AWSSessionManager, username: str = None) -> None:
    """
    Create a new access key for an IAM user.

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

    console.print(f"[bold blue]🔑 Creating access key for user: {username}[/bold blue]")

    # Confirm action
    if not Confirm.ask(
        f"[yellow]Create new access key for {username}?[/yellow]",
        default=False
    ):
        console.print("[yellow]Operation cancelled.[/yellow]")
        return

    # Get IAM client
    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    try:
        response = iam.create_access_key(UserName=username)
        access_key = response.get("AccessKey", {})

        # Display results
        console.print("[green]✓ Access key created successfully![/green]")

        table = Table(title=f"New Access Key for {username}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Access Key ID", access_key.get("AccessKeyId", ""))
        table.add_row("Secret Access Key", access_key.get("SecretAccessKey", ""))
        table.add_row("Status", access_key.get("Status", ""))
        table.add_row("Created", str(access_key.get("CreateDate", ""))[:19])

        console.print(table)

        console.print("\n[bold red]⚠️  IMPORTANT: Save the Secret Access Key now![/bold red]")
        console.print("[dim]You won't be able to retrieve it again.[/dim]")

        # Save to session data
        key_data = {
            "username": username,
            "access_key_id": access_key.get("AccessKeyId"),
            "created_at": str(access_key.get("CreateDate"))
        }
        session_mgr.save_enumeration_data("created_access_keys", [key_data])
        console.print("\n[green]Key metadata saved to session data under 'created_access_keys'.[/green]")

    except iam.exceptions.LimitExceededException:
        console.print(f"[red]Access key limit exceeded for user {username}.[/red]")
        console.print("[yellow]Each user can have a maximum of 2 access keys.[/yellow]")
    except iam.exceptions.NoSuchEntityException:
        console.print(f"[red]User {username} does not exist.[/red]")
    except Exception as e:
        console.print(f"[red]Failed to create access key: {str(e)}[/red]")


def create_access_key_interactive(session_mgr: AWSSessionManager) -> None:
    """Interactive wrapper for create_access_key."""
    console.print("[bold yellow]🔑 Create IAM Access Key[/bold yellow]")
    console.print("[dim]Creates a new access key for persistence/privilege escalation.[/dim]\n")

    username = Prompt.ask(
        "[cyan]IAM username (press Enter to use current session user)[/cyan]",
        default=""
    ).strip()

    create_access_key(session_mgr, username if username else None)
