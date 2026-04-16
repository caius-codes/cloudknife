"""
AWS Systems Manager Parameter Store single value retrieval.

Retrieves a single SSM parameter value with automatic KMS decryption for SecureString types.
"""

from typing import Optional, List, Dict, Any

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...aws_session import AWSSessionManager


console = Console()


def _load_ssm_cache(session_mgr: AWSSessionManager) -> List[Dict[str, Any]]:
    """Load SSM parameters cache from session."""
    session_name = session_mgr.current_session
    if not session_name:
        return []
    return (
        session_mgr.enumerated_data.get(session_name, {}).get("ssm_parameters", [])
        if session_name in session_mgr.enumerated_data
        else []
    )


def get_ssm_parameter_value(
    session_mgr: AWSSessionManager,
    parameter_name: Optional[str] = None,
    region: Optional[str] = None
) -> None:
    """
    Retrieve and display the value of a specific SSM parameter.
    Uses cache to infer region when possible; otherwise prompts user.

    Args:
        session_mgr: AWS session manager instance
        parameter_name: Parameter name (prompts if not provided)
        region: AWS region (infers from cache if not provided)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    # Load cache
    cache = _load_ssm_cache(session_mgr)

    # Prompt for parameter name if not provided
    if not parameter_name:
        if cache:
            console.print(
                "[dim]Tip: Run 'enumerate_ssm' first to see all available parameters.[/dim]"
            )
        parameter_name = Prompt.ask("[cyan]Parameter name (e.g., /app/database/password)[/cyan]")

    # Try to infer region from cache
    if not region:
        if cache:
            candidates = [p for p in cache if p.get("Name") == parameter_name]
            if len(candidates) == 1:
                region = candidates[0]["Region"]
                console.print(f"[dim]Auto-detected region from cache: {region}[/dim]")
            elif len(candidates) > 1:
                console.print(
                    "[yellow]Parameter found in multiple regions. Please specify region.[/yellow]"
                )
                region = Prompt.ask(
                    "[cyan]Region for this parameter[/cyan]",
                    default=session_mgr.default_region
                )
            else:
                # Not in cache, use default or ask
                region = Prompt.ask(
                    "[cyan]Region for this parameter[/cyan]",
                    default=session_mgr.default_region
                )
        else:
            region = Prompt.ask(
                "[cyan]Region for this parameter[/cyan]",
                default=session_mgr.default_region
            )

    # Check if it's a SecureString from cache
    param_type = None
    if cache:
        matching = [p for p in cache if p.get("Name") == parameter_name and p.get("Region") == region]
        if matching:
            param_type = matching[0].get("Type")

    # Security warning
    console.print(
        "[bold yellow]⚠️  Parameter values may contain sensitive data "
        "(credentials, connection strings, API keys).[/bold yellow]"
    )

    if param_type == "SecureString":
        console.print(
            "[yellow]This is a SecureString parameter (KMS-encrypted). "
            "Requires kms:Decrypt permission.[/yellow]"
        )

    if not Confirm.ask(f"Retrieve value for parameter '{parameter_name}' in region '{region}'?"):
        console.print("[yellow]Aborted parameter retrieval.[/yellow]")
        return

    # Create regional boto3 client
    from boto3 import Session as Boto3Session

    base_sess = session_mgr.get_boto3_session()
    reg_sess = Boto3Session(
        aws_access_key_id=base_sess.get_credentials().access_key,
        aws_secret_access_key=base_sess.get_credentials().secret_key,
        aws_session_token=base_sess.get_credentials().token,
        region_name=region,
    )
    ssm = reg_sess.client("ssm")

    # Retrieve parameter with decryption
    try:
        resp = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        error_msg = e.response.get("Error", {}).get("Message", str(e))

        if error_code == "ParameterNotFound":
            console.print(f"[red]✗ Parameter not found: '{parameter_name}' in region '{region}'[/red]")
            console.print("[dim]Check the parameter name and region are correct.[/dim]")
        elif error_code == "AccessDeniedException":
            console.print(f"[red]✗ Access denied: {error_msg}[/red]")
            console.print("[yellow]Required permission: ssm:GetParameter[/yellow]")
        elif "KMS" in error_code or "Decrypt" in error_msg:
            console.print(f"[red]✗ KMS decryption failed: {error_msg}[/red]")
            console.print(
                "[yellow]This SecureString parameter requires kms:Decrypt permission "
                "for the associated KMS key.[/yellow]"
            )
            console.print("[dim]Try re-running with IAM role/user that has KMS decrypt access.[/dim]")
        else:
            console.print(f"[red]✗ Failed to get parameter value: {error_msg}[/red]")

        return
    except Exception as e:
        console.print(f"[red]✗ Unexpected error: {str(e)}[/red]")
        return

    # Extract parameter details
    param = resp.get("Parameter", {})
    param_name = param.get("Name", "")
    param_value = param.get("Value", "")
    param_type = param.get("Type", "")
    param_version = param.get("Version", 0)
    param_arn = param.get("ARN", "")
    param_last_modified = str(param.get("LastModifiedDate", ""))[:19] if param.get("LastModifiedDate") else ""

    # Display metadata
    meta_table = Table(title="Parameter Metadata")
    meta_table.add_column("Field", style="cyan", width=20)
    meta_table.add_column("Value", width=80, overflow="fold")

    meta_table.add_row("Name", param_name)
    meta_table.add_row("Type", param_type)
    meta_table.add_row("Region", region)
    meta_table.add_row("Version", str(param_version))
    meta_table.add_row("Last Modified", param_last_modified)
    if param_arn:
        meta_table.add_row("ARN", param_arn)

    console.print()
    console.print(meta_table)

    # Display parameter value (color-coded by type)
    console.print()
    if param_type == "SecureString":
        console.print("[bold yellow]Parameter Value (Decrypted SecureString):[/bold yellow]")
    elif param_type == "StringList":
        console.print("[bold cyan]Parameter Value (StringList):[/bold cyan]")
    else:
        console.print("[bold cyan]Parameter Value (String):[/bold cyan]")

    # Color-code the value
    if param_type == "SecureString":
        console.print(f"[magenta]{param_value}[/magenta]")
    else:
        console.print(f"[yellow]{param_value}[/yellow]")

    # Save to session
    session_mgr.save_enumeration_data(
        "ssm_last_parameter_value",
        {
            "Name": param_name,
            "Value": param_value,
            "Type": param_type,
            "Region": region,
            "Version": param_version,
        },
    )

    console.print()
    console.print(
        "[green]✓ Parameter value stored under key 'ssm_last_parameter_value' in session data.[/green]"
    )

    if param_type == "SecureString":
        console.print(
            "[bold red]⚠️  WARNING: This value was KMS-decrypted. Handle with care![/bold red]"
        )
