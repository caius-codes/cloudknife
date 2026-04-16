"""
Delete Access Key - AWS IAM Cleanup

Deletes an access key for an IAM user. If no username is provided,
uses the current session's username.
"""

from rich.console import Console
from rich.prompt import Prompt, Confirm

from ...aws_session import AWSSessionManager

console = Console()


def delete_access_key(
    session_mgr: AWSSessionManager,
    access_key_id: str,
    username: str = None
):
    """
    Delete an access key for an IAM user.

    Args:
        session_mgr: AWS session manager
        access_key_id: The access key ID to delete
        username: IAM username (optional, uses current user if not provided)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    if not access_key_id:
        console.print("[red]Access Key ID is required.[/red]")
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

    console.print(f"[bold blue]🗑️  Deleting access key for user: {username}[/bold blue]")
    console.print(f"[cyan]Access Key ID:[/cyan] {access_key_id}")

    # Confirm action
    if not Confirm.ask(
        f"[red]Delete access key {access_key_id} for {username}?[/red]",
        default=False
    ):
        console.print("[yellow]Operation cancelled.[/yellow]")
        return

    # Get IAM client
    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    try:
        iam.delete_access_key(
            UserName=username,
            AccessKeyId=access_key_id
        )

        console.print(f"[green]✓ Access key {access_key_id} deleted successfully![/green]")
        console.print(f"[dim]User {username} can no longer use this key.[/dim]")

    except iam.exceptions.NoSuchEntityException:
        console.print(f"[red]Access key {access_key_id} or user {username} does not exist.[/red]")
    except Exception as e:
        console.print(f"[red]Failed to delete access key: {str(e)}[/red]")


def delete_access_key_interactive(session_mgr: AWSSessionManager) -> None:
    """Interactive wrapper for delete_access_key."""
    console.print("[bold yellow]🗑️  Delete IAM Access Key[/bold yellow]")
    console.print("[dim]Removes an access key for cleanup/revocation.[/dim]\n")

    access_key_id = Prompt.ask("[cyan]Access Key ID to delete[/cyan]").strip()

    username = Prompt.ask(
        "[cyan]IAM username (press Enter to use current session user)[/cyan]",
        default=""
    ).strip()

    delete_access_key(
        session_mgr,
        access_key_id,
        username if username else None
    )
