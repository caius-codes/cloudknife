from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm

from ...aws_session import AWSSessionManager

console = Console()


def _load_secrets_cache(session_mgr: AWSSessionManager) -> List[Dict[str, Any]]:
    session_name = session_mgr.current_session
    if not session_name:
        return []
    return (
        session_mgr.enumerated_data.get(session_name, {}).get("secrets_manager", [])
        if session_name in session_mgr.enumerated_data
        else []
    )


def secret_value(session_mgr: AWSSessionManager, secret_id: Optional[str] = None) -> None:
    """
    Retrieve and show the value of a specific secret (Name or ARN).
    Uses cache to infer region when possible; otherwise asks.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    cache = _load_secrets_cache(session_mgr)

    if not secret_id:
        secret_id = Prompt.ask("[cyan]Secret name or ARN[/cyan]")

    # Try to infer region from cache
    region = session_mgr.default_region
    if cache:
        candidates = [s for s in cache if s.get("Name") == secret_id or s.get("ARN") == secret_id]
        if len(candidates) == 1:
            region = candidates[0]["Region"]
        elif len(candidates) > 1:
            console.print(
                "[yellow]Secret found in multiple regions; please specify region explicitly.[/yellow]"
            )
            region = Prompt.ask("[cyan]Region for this secret[/cyan]", default=session_mgr.default_region)
        else:
            region = Prompt.ask("[cyan]Region for this secret[/cyan]", default=session_mgr.default_region)
    else:
        region = Prompt.ask("[cyan]Region for this secret[/cyan]", default=session_mgr.default_region)

    console.print(
        "[bold yellow]⚠️ Secret values may contain highly sensitive data "
        "(passwords, tokens, private keys). Handle with care.[/bold yellow]"
    )
    if not Confirm.ask(f"Retrieve value for secret '{secret_id}' in region '{region}'?"):
        console.print("[yellow]Aborted secret retrieval.[/yellow]")
        return

    from boto3 import Session as Boto3Session

    base_sess = session_mgr.get_boto3_session()
    reg_sess = Boto3Session(
        aws_access_key_id=base_sess.get_credentials().access_key,
        aws_secret_access_key=base_sess.get_credentials().secret_key,
        aws_session_token=base_sess.get_credentials().token,
        region_name=region,
    )
    sm = reg_sess.client("secretsmanager")

    try:
        resp = sm.get_secret_value(SecretId=secret_id)
    except Exception as e:
        console.print(f"[red]Failed to get secret value: {str(e)}[/red]")
        console.print(
            "[yellow]Ensure SecretsManager:GetSecretValue permission and correct name/region.[/yellow]"
        )
        return

    secret_string = resp.get("SecretString")
    secret_binary = resp.get("SecretBinary")

    meta = Table(title="Secret Metadata")
    meta.add_column("Field", style="cyan")
    meta.add_column("Value")
    meta.add_row("SecretId", Text(secret_id))
    meta.add_row("Region", region)
    if "ARN" in resp:
        meta.add_row("ARN", Text(resp["ARN"]))
    if "VersionId" in resp:
        meta.add_row("VersionId", Text(resp["VersionId"]))
    console.print(meta)

    # ---- Colored secret output ----
    if secret_string is not None:
        console.print("[bold cyan]SecretString:[/bold cyan]")
        console.print(f"[magenta]{secret_string}[/magenta]")
    elif secret_binary is not None:
        console.print("[bold magenta]SecretBinary (base64-encoded):[/bold magenta]")
        console.print(str(secret_binary), markup=False, emoji=False)
    else:
        console.print("[yellow]No SecretString or SecretBinary found in response.[/yellow]")

    session_mgr.save_enumeration_data(
        "secret_last_value",
        {"SecretId": secret_id, "Region": region, "SecretString": secret_string, "SecretBinary": bool(secret_binary)},
    )
    console.print(
        "[green]Last secret value stored under key 'secret_last_value' in session data (for this run).[/green]"
    )

