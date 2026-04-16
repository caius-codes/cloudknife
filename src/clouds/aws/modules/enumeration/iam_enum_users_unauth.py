"""
IAM User Enumeration (Unauthenticated/Cross-Account)

This module enumerates IAM users in a target AWS account without having credentials
in that account. It works by attempting to update the AssumeRole policy of a role
in YOUR account with explicit deny statements for potential users in the TARGET account.

Technique inspired by Pacu's iam__enum_users module by Spencer Gietzen.

Requirements:
- A role in your account with iam:UpdateAssumeRolePolicy permission
- Target account ID (12 digits)
- Wordlist of potential usernames

Note: This will generate many CloudTrail logs in YOUR account (iam:UpdateAssumeRolePolicy).
The target account will NOT see any logs.
"""

import json
import time
from typing import List, Dict
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...aws_session import AWSSessionManager

console = Console()

# Path to default wordlist (1135 words)
# From: src/clouds/aws/modules/enumeration/ -> src/data/
DEFAULT_WORDLIST_PATH = Path(__file__).parent.parent.parent.parent.parent / "data" / "default-word-list.txt"


def _create_test_policy(account_id: str, username: str) -> str:
    """
    Create an AssumeRole policy with explicit deny for the test user.
    This ensures no security holes are opened during enumeration.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {
                    "AWS": f"arn:aws:iam::{account_id}:user/{username}"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    return json.dumps(policy)


def _test_username(iam_client, role_name: str, account_id: str, username: str) -> Dict:
    """
    Test if a username exists by trying to update the AssumeRole policy.

    Returns dict with:
    - username: str
    - exists: bool
    - error: str (if any)
    """
    policy_doc = _create_test_policy(account_id, username)

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=policy_doc
        )
        # If no error, the user likely exists
        return {
            "username": username,
            "exists": True,
            "error": None
        }
    except iam_client.exceptions.MalformedPolicyDocumentException as e:
        # This error typically means the principal (user) doesn't exist
        error_msg = str(e)
        if "Invalid principal" in error_msg or "does not exist" in error_msg:
            return {
                "username": username,
                "exists": False,
                "error": "User does not exist"
            }
        else:
            # Other malformed policy error
            return {
                "username": username,
                "exists": False,
                "error": f"Policy error: {error_msg}"
            }
    except iam_client.exceptions.NoSuchEntityException:
        # Role doesn't exist
        return {
            "username": username,
            "exists": False,
            "error": "Role not found"
        }
    except Exception as e:
        # Other errors
        return {
            "username": username,
            "exists": False,
            "error": f"Error: {str(e)}"
        }


def _load_wordlist(wordlist_path: str = None) -> List[str]:
    """Load wordlist from file or return default."""
    # Use custom wordlist if provided
    if wordlist_path:
        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            console.print(f"[green]Loaded {len(words)} words from {wordlist_path}[/green]")
            return words
        except Exception as e:
            console.print(f"[red]Error loading custom wordlist: {e}[/red]")
            console.print("[yellow]Falling back to default wordlist[/yellow]")

    # Load default wordlist
    try:
        if DEFAULT_WORDLIST_PATH.exists():
            with open(DEFAULT_WORDLIST_PATH, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            console.print(f"[green]Loaded {len(words)} words from default wordlist[/green]")
            return words
        else:
            console.print(f"[red]Default wordlist not found at {DEFAULT_WORDLIST_PATH}[/red]")
            return []
    except Exception as e:
        console.print(f"[red]Error loading default wordlist: {e}[/red]")
        return []


def enumerate_iam_users_unauth(
    session_mgr: AWSSessionManager,
    role_name: str,
    account_id: str,
    wordlist_path: str = None,
    delay: float = 0.1
):
    """
    Enumerate IAM users in a target account by testing AssumeRole policy updates.

    Args:
        session_mgr: AWS session manager
        role_name: Name of role in YOUR account to use for testing
        account_id: Target AWS account ID (12 digits)
        wordlist_path: Path to custom wordlist (optional)
        delay: Delay between requests in seconds (default 0.1)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    # Validate account ID
    if not account_id.isdigit() or len(account_id) != 12:
        console.print("[red]Invalid account ID. Must be 12 numeric characters.[/red]")
        return

    console.print(f"[bold blue]🔍 IAM User Enumeration (Unauthenticated)[/bold blue]")
    console.print(f"[cyan]Target Account:[/cyan] {account_id}")
    console.print(f"[cyan]Test Role:[/cyan] {role_name}")
    console.print(f"[yellow]Warning: This will generate many CloudTrail logs in YOUR account![/yellow]")

    if not Confirm.ask("[cyan]Continue with enumeration?[/cyan]", default=False):
        console.print("[yellow]Enumeration cancelled.[/yellow]")
        return

    # Load wordlist
    wordlist = _load_wordlist(wordlist_path)
    console.print(f"[cyan]Testing {len(wordlist)} potential usernames...[/cyan]\n")

    # Get IAM client
    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    # Test each username
    results = []
    found_users = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Enumerating users...", total=len(wordlist))

        for username in wordlist:
            result = _test_username(iam, role_name, account_id, username)
            results.append(result)

            if result["exists"]:
                found_users.append(result["username"])
                console.print(f"[green]✓ Found: {result['username']}[/green]")

            progress.advance(task)

            # Rate limiting
            if delay > 0:
                time.sleep(delay)

    # Save results
    enumeration_data = {
        "target_account_id": account_id,
        "role_name": role_name,
        "total_tested": len(wordlist),
        "found_users": found_users,
        "all_results": results
    }
    session_mgr.save_enumeration_data("iam_enum_users_unauth", enumeration_data)

    # Display results
    console.print(f"\n[bold green]Found {len(found_users)} valid IAM users:[/bold green]")

    if found_users:
        table = Table(title=f"Enumerated IAM Users in Account {account_id}")
        table.add_column("Username", style="cyan", no_wrap=True)
        table.add_column("ARN", style="dim")

        for user in found_users:
            arn = f"arn:aws:iam::{account_id}:user/{user}"
            table.add_row(user, arn)

        console.print(table)
    else:
        console.print("[yellow]No users found with the current wordlist.[/yellow]")
        console.print("[dim]Tip: Try a custom wordlist with --word-list[/dim]")

    console.print(f"\n[green]Results saved to session data under 'iam_enum_users_unauth'[/green]")
    console.print(f"[dim]Tested {len(wordlist)} usernames in account {account_id}[/dim]")


def enumerate_iam_users_unauth_interactive(session_mgr: AWSSessionManager) -> None:
    """Interactive wrapper for iam_enum_users_unauth."""
    console.print("[bold yellow]⚠️  IAM User Enumeration (Unauthenticated Cross-Account)[/bold yellow]")
    console.print("[dim]This technique tests usernames by updating AssumeRole policies.[/dim]")
    console.print("[dim]Requires: iam:UpdateAssumeRolePolicy permission on a role in YOUR account.[/dim]\n")

    role_name = Prompt.ask("[cyan]Role name in YOUR account to use for testing[/cyan]")
    account_id = Prompt.ask("[cyan]Target AWS account ID (12 digits)[/cyan]")

    use_custom = Confirm.ask(
        "[cyan]Use custom wordlist?[/cyan]",
        default=False
    )

    wordlist_path = None
    if use_custom:
        wordlist_path = Prompt.ask("[cyan]Path to wordlist file[/cyan]")

    delay_str = Prompt.ask(
        "[cyan]Delay between requests (seconds)[/cyan]",
        default="0.1"
    )

    try:
        delay = float(delay_str)
    except ValueError:
        console.print("[yellow]Invalid delay, using 0.1 seconds[/yellow]")
        delay = 0.1

    enumerate_iam_users_unauth(
        session_mgr,
        role_name=role_name,
        account_id=account_id,
        wordlist_path=wordlist_path,
        delay=delay
    )
