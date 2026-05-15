"""
AWS Systems Manager Parameter Store bulk download.

Recursively downloads all parameters under a specified path with KMS decryption.
Saves results to JSON file with proper error handling and security warnings.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from botocore.exceptions import ClientError
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...aws_session import AWSSessionManager


console = Console()


def ssm_bulk_download(
    session_mgr: AWSSessionManager,
    path_filter: Optional[str] = None,
    region: Optional[str] = None,
    output_dir: Optional[str] = None
) -> None:
    """
    Bulk download SSM parameters under a specified path (recursive).

    Args:
        session_mgr: AWS session manager instance
        path_filter: Parameter path to download (e.g., /app/), prompts if not provided
        region: AWS region (prompts if not provided)
        output_dir: Output directory for JSON file (default: ./ssm_downloads)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    # Prompt for path filter
    if not path_filter:
        console.print(
            "[dim]Enter the parameter path to download (e.g., /app/ or /prod/database/).[/dim]"
        )
        console.print("[dim]Use '/' to download all parameters (may be large!).[/dim]")
        path_filter = Prompt.ask("[cyan]Parameter path[/cyan]", default="/")

    # Ensure path starts with /
    if not path_filter.startswith("/"):
        path_filter = "/" + path_filter

    # Prompt for region
    if not region:
        region = Prompt.ask(
            "[cyan]Region for bulk download[/cyan]",
            default=session_mgr.default_region
        )

    # Set output directory
    if not output_dir:
        exfil_dir = session_mgr.get_exfil_dir("ssm")
        output_dir = str(exfil_dir)

    # Security warning
    console.print()
    console.print(
        f"[bold yellow]⚠️  WARNING: Bulk downloading all parameters under '{path_filter}'[/bold yellow]"
    )
    console.print(
        "[yellow]This will retrieve ALL parameter values (including SecureStrings with KMS decryption).[/yellow]"
    )
    console.print(
        "[yellow]Downloaded file will contain SENSITIVE CREDENTIALS in plaintext JSON.[/yellow]"
    )
    console.print()

    if not Confirm.ask(f"Proceed with bulk download from region '{region}'?"):
        console.print("[yellow]Aborted bulk download.[/yellow]")
        return

    # Create output directory
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        console.print(f"[red]Failed to create output directory: {str(e)}[/red]")
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

    # Bulk download with progress tracking
    downloaded_params: List[Dict[str, Any]] = []
    failed_params: List[Dict[str, Any]] = []

    console.print()
    console.print(f"[cyan]→ Downloading parameters from path '{path_filter}' (recursive)...[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching parameters...", total=None)

        try:
            paginator = ssm.get_paginator("get_parameters_by_path")

            page_count = 0
            for page in paginator.paginate(
                Path=path_filter,
                Recursive=True,
                WithDecryption=True,
                MaxResults=10,  # AWS limit
            ):
                page_count += 1
                progress.update(task, description=f"Processing page {page_count}...")

                for param in page.get("Parameters", []):
                    try:
                        downloaded_params.append({
                            "Name": param.get("Name", ""),
                            "Type": param.get("Type", ""),
                            "Value": param.get("Value", ""),
                            "Version": param.get("Version", 0),
                            "LastModifiedDate": str(param.get("LastModifiedDate", ""))[:19]
                            if param.get("LastModifiedDate")
                            else "",
                            "ARN": param.get("ARN", ""),
                        })
                    except Exception as e:
                        # Per-parameter error (shouldn't happen in get_parameters_by_path)
                        failed_params.append({
                            "Name": param.get("Name", "UNKNOWN"),
                            "Error": str(e),
                        })

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = e.response.get("Error", {}).get("Message", str(e))

            progress.update(task, description="[red]Failed[/red]")

            if error_code == "AccessDeniedException":
                console.print(f"\n[red]✗ Access denied: {error_msg}[/red]")
                console.print("[yellow]Required permissions: ssm:GetParametersByPath[/yellow]")
            elif "KMS" in error_code or "Decrypt" in error_msg:
                console.print(f"\n[red]✗ KMS decryption failed: {error_msg}[/red]")
                console.print(
                    "[yellow]SecureString parameters require kms:Decrypt permission "
                    "for the associated KMS key.[/yellow]"
                )
            else:
                console.print(f"\n[red]✗ Failed to download parameters: {error_msg}[/red]")

            return
        except Exception as e:
            progress.update(task, description="[red]Failed[/red]")
            console.print(f"\n[red]✗ Unexpected error: {str(e)}[/red]")
            return

        progress.update(task, description="[green]Complete[/green]")

    # Display summary
    console.print()
    total_params = len(downloaded_params)
    total_failed = len(failed_params)

    if total_params == 0 and total_failed == 0:
        console.print(
            f"[yellow]No parameters found under path '{path_filter}' in region '{region}'.[/yellow]"
        )
        return

    console.print(f"[green]✓ Downloaded {total_params} parameters[/green]")
    if total_failed > 0:
        console.print(f"[yellow]⚠️  {total_failed} parameters failed to download[/yellow]")

    # Count SecureString parameters
    secure_count = sum(1 for p in downloaded_params if p.get("Type") == "SecureString")
    if secure_count > 0:
        console.print(f"[yellow]⚠️  {secure_count} SecureString parameters (KMS-decrypted)[/yellow]")

    # Save to JSON file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize path for filename (replace / with _)
    safe_path = path_filter.strip("/").replace("/", "_") or "root"
    output_filename = f"ssm_params_{safe_path}_{region}_{timestamp}.json"
    output_path = Path(output_dir) / output_filename

    output_data = {
        "metadata": {
            "region": region,
            "path_filter": path_filter,
            "download_timestamp": datetime.now().isoformat(),
            "total_downloaded": total_params,
            "total_failed": total_failed,
            "secure_string_count": secure_count,
        },
        "parameters": downloaded_params,
        "failed": failed_params,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, default=str)

        # Set restrictive file permissions (owner read/write only)
        os.chmod(output_path, 0o600)

        console.print()
        console.print(f"[green]✓ Parameters saved to: {output_path.resolve()}[/green]")
        console.print(f"[dim]File permissions: 0600 (owner read/write only)[/dim]")

        # Final security warning
        console.print()
        console.print(
            "[bold red]🔒 SECURITY WARNING:[/bold red] "
            "The downloaded file contains SENSITIVE CREDENTIALS in plaintext!"
        )
        console.print(
            "[yellow]• Secure the file immediately (encrypt, move to secure storage, or delete after use)[/yellow]"
        )
        console.print(
            "[yellow]• Do NOT commit to version control or upload to unsecured locations[/yellow]"
        )
        console.print(
            "[yellow]• Consider using AWS Secrets Manager for programmatic secret access instead[/yellow]"
        )

    except Exception as e:
        console.print(f"[red]✗ Failed to save output file: {str(e)}[/red]")
        return
