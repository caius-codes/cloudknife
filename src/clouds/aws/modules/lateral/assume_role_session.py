from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from boto3 import Session as Boto3Session
from botocore.exceptions import ClientError

from ...aws_session import AWSSessionManager

console = Console()


def assume_role_new_session(
    session_mgr: AWSSessionManager,
    role_arn: Optional[str] = None,
    new_session_name: Optional[str] = None,
):
    """
    Assume an IAM role and create a new Cloud Knife session with the assumed-role credentials.

    - Uses current session's credentials to call sts:AssumeRole.
    - Stores the returned AccessKeyId/SecretAccessKey/SessionToken as a new session.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    base_session_name = session_mgr.current_session or "default"
    default_region = session_mgr.default_region

    if not role_arn:
        role_arn = Prompt.ask("[cyan]Role ARN to assume[/cyan]")

    if not new_session_name:
        # Use only valid characters (alphanumeric, hyphens, underscores)
        suggested = f"{base_session_name}-{role_arn.split('/')[-1]}"
        new_session_name = Prompt.ask("[cyan]New session name for assumed role[/cyan]", default=suggested)

    # Validate session name
    while not session_mgr.validate_session_name(new_session_name):
        console.print(
            "[red]Invalid session name. Only alphanumeric characters, hyphens (-), and underscores (_) are allowed.[/red]"
        )
        new_session_name = Prompt.ask("[cyan]Enter a valid session name[/cyan]")

    console.print(f"[bold blue]🔁 Lateral movement via sts:AssumeRole[/bold blue]")
    console.print(f"Base session: [cyan]{base_session_name}[/cyan]")
    console.print(f"Role ARN:     [cyan]{role_arn}[/cyan]")
    console.print(f"New session:  [cyan]{new_session_name}[/cyan]")
    console.print(f"Region:       [cyan]{default_region}[/cyan]")

    if not Confirm.ask("Proceed to assume role and create new session?"):
        console.print("[yellow]Aborted assume-role operation.[/yellow]")
        return

    base_boto_sess: Boto3Session = session_mgr.get_boto3_session()
    sts = base_boto_sess.client("sts")

    try:
        resp = sts.assume_role(  # sts:AssumeRole[web:133][web:142]
            RoleArn=role_arn,
            RoleSessionName=f"cloudknife-{base_session_name}",
            DurationSeconds=3600,
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        console.print(f"[red]AssumeRole failed: {code} - {str(e)[:200]}[/red]")
        console.print(
            "[yellow]Ensure the current identity is allowed to assume this role "
            "and that the trust policy permits it.[/yellow]"
        )
        return
    except Exception as e:
        console.print(f"[red]AssumeRole failed: {str(e)[:200]}[/red]")
        return

    creds = resp["Credentials"]
    access_key = creds["AccessKeyId"]
    secret_key = creds["SecretAccessKey"]
    session_token = creds["SessionToken"]
    expiration = creds.get("Expiration", "")

    # Crea una nuova session Cloud Knife con queste credenziali
    session_mgr.create_or_load_session(new_session_name)
    session_mgr.current_session_data.update(
        {
            "access_key": access_key,
            "secret_key": secret_key,
            "session_token": session_token,
            "region": default_region,
        }
    )
    session_mgr.save_current_session()

    console.print("[green]✓ New session created with assumed-role credentials.[/green]\n")

    # Display temporary credentials (no truncation)
    console.print(f"[bold cyan]Assumed Role Credentials - Session: {new_session_name}[/bold cyan]\n")
    console.print(f"[cyan]AWS_ACCESS_KEY_ID:[/cyan]")
    console.print(f"[yellow]{access_key}[/yellow]\n")
    console.print(f"[cyan]AWS_SECRET_ACCESS_KEY:[/cyan]")
    console.print(f"[yellow]{secret_key}[/yellow]\n")
    console.print(f"[cyan]AWS_SESSION_TOKEN:[/cyan]")
    console.print(f"[yellow]{session_token}[/yellow]\n")
    if expiration:
        console.print(f"[cyan]Expiration:[/cyan]")
        console.print(f"[yellow]{str(expiration)[:19]}[/yellow]\n")
    console.print(f"[cyan]AWS_DEFAULT_REGION:[/cyan]")
    console.print(f"[yellow]{default_region}[/yellow]")

    console.print(
        "\n[dim]💡 Tip: Use 'use_session {name}' to switch between base and assumed-role sessions.[/dim]"
    )
