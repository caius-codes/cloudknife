"""
AWS Systems Manager Parameter Store enumeration.

Enumerates SSM parameters across configured regions, identifies SecureString
parameters (KMS-encrypted), and saves metadata to session.
"""

from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def enumerate_ssm_parameters(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate AWS Systems Manager parameters across configured regions.
    Saves results under 'ssm_parameters' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="SSM Parameter Store")
    console.print(
        f"[bold blue]🔍 Enumerating SSM Parameter Store in regions: {', '.join(regions)}[/bold blue]"
    )

    # Use factory for efficient multi-region client creation
    client_factory = RegionalClientFactory(session_mgr)
    all_parameters: List[Dict[str, Any]] = []

    for region in regions:
        console.print(f"[cyan]→ Region: {region}[/cyan]")
        try:
            ssm = client_factory.get_client("ssm", region)

            # Paginate describe_parameters (metadata only, no values)
            paginator = ssm.get_paginator("describe_parameters")
            region_count = 0

            for page in paginator.paginate(MaxResults=50):
                for param in page.get("Parameters", []):
                    region_count += 1
                    all_parameters.append(
                        {
                            "Region": region,
                            "Name": param.get("Name", ""),
                            "Type": param.get("Type", ""),  # String | SecureString | StringList
                            "KeyId": param.get("KeyId", ""),  # KMS key for SecureString
                            "LastModifiedDate": str(param.get("LastModifiedDate", ""))[:19]
                            if param.get("LastModifiedDate")
                            else "",
                            "Version": param.get("Version", 0),
                            "Tier": param.get("Tier", "Standard"),  # Standard | Advanced | Intelligent-Tiering
                            "Description": (param.get("Description", "") or "")[:60],  # Truncate long descriptions
                            "ARN": param.get("ARN", ""),
                        }
                    )

            if region_count > 0:
                console.print(f"  [green]✓[/green] Found {region_count} parameters")

        except Exception as e:
            console.print(f"[red]SSM enumeration failed in region {region}: {str(e)}[/red]")

    session_mgr.save_enumeration_data("ssm_parameters", all_parameters)

    if not all_parameters:
        console.print("[yellow]No SSM parameters found in the selected regions.[/yellow]")
        return

    # Count SecureString parameters (KMS-encrypted)
    secure_count = sum(1 for p in all_parameters if p["Type"] == "SecureString")
    string_count = sum(1 for p in all_parameters if p["Type"] == "String")
    stringlist_count = sum(1 for p in all_parameters if p["Type"] == "StringList")

    # Display summary
    console.print(
        f"\n[bold green]✓ Found {len(all_parameters)} total parameters[/bold green]"
    )
    console.print(f"  • String: {string_count}")
    console.print(f"  • SecureString (KMS-encrypted): [yellow]{secure_count}[/yellow]")
    console.print(f"  • StringList: {stringlist_count}\n")

    # Display parameters table
    table = Table(title=f"SSM Parameter Store - Parameters (total: {len(all_parameters)})")
    table.add_column("Region", style="magenta", width=12)
    table.add_column("Name", style="cyan", width=50, overflow="fold")
    table.add_column("Type", width=12)
    table.add_column("Version", justify="right", width=8)
    table.add_column("Last Modified", width=19)

    for param in all_parameters:
        # Color-code SecureString parameters
        type_display = param["Type"]
        if param["Type"] == "SecureString":
            type_display = f"[yellow]{param['Type']}[/yellow]"
        elif param["Type"] == "String":
            type_display = f"[green]{param['Type']}[/green]"

        table.add_row(
            param["Region"],
            param["Name"],
            type_display,
            str(param["Version"]),
            param["LastModifiedDate"],
        )

    console.print(table)
    console.print(
        "[green]Parameters metadata stored under key 'ssm_parameters' in session data.[/green]"
    )

    if secure_count > 0:
        console.print(
            f"\n[yellow]⚠️  {secure_count} SecureString parameters detected (KMS-encrypted).[/yellow]"
        )
        console.print(
            "[dim]Retrieving values requires ssm:GetParameter and kms:Decrypt permissions.[/dim]"
        )

    console.print(
        "\n[dim]Use 'ssm_parameter_value <name>' to retrieve a single parameter value (authorized testing only).[/dim]"
    )
    console.print(
        "[dim]Use 'ssm_bulk_download <path>' to download all parameters under a path.[/dim]"
    )
