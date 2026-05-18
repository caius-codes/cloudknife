"""
IAMGraph Data Collector Module

Exports complete IAM account authorization details for import into IAMGraph.
Uses the get-account-authorization-details API to retrieve comprehensive IAM data.

IAMGraph: https://github.com/withsecurelabs/IAMGraph
"""

import json
import os
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

from ...aws_session import AWSSessionManager

console = Console()


def download_iamgraph_data(session_mgr: AWSSessionManager, output_path: Optional[str] = None) -> None:
    """
    Download IAM account authorization details and save to JSON file for IAMGraph.

    This exports:
    - All IAM users and their policies
    - All IAM groups and their policies
    - All IAM roles and their policies
    - All IAM policies (managed and inline)

    Args:
        session_mgr: Session manager instance
        output_path: Optional path where to save the JSON file
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    console.print(Panel(
        "[bold blue]IAMGraph Data Collection[/bold blue]\n\n"
        "This module exports complete IAM account authorization details.\n"
        "The output can be imported into IAMGraph for visualization and analysis.\n\n"
        "[dim]IAMGraph: https://github.com/withsecurelabs/IAMGraph[/dim]",
        border_style="blue"
    ))

    # Ask for output path if not provided
    if not output_path:
        exfil_dir = session_mgr.get_exfil_dir("iam")
        default_path = str(exfil_dir / "iam_account_authorization_details.json")
        output_path = Prompt.ask(
            "[cyan]Output file path[/cyan]",
            default=default_path
        )

    # Expand ~ to home directory
    output_path = os.path.expanduser(output_path)

    # Check if file exists
    if os.path.exists(output_path):
        if not Confirm.ask(f"[yellow]File already exists. Overwrite?[/yellow]"):
            console.print("[yellow]Aborted.[/yellow]")
            return

    console.print("\n[bold blue]🔍 Collecting IAM account authorization details...[/bold blue]")
    console.print("[dim]This may take a few seconds for large accounts...[/dim]\n")

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    try:
        # Call get_account_authorization_details with pagination
        console.print("[dim]→ Fetching users, groups, roles, and policies...[/dim]")

        # This API returns everything in one call (with pagination support)
        paginator = iam.get_paginator("get_account_authorization_details")

        # Aggregate all results
        all_data = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }

        page_count = 0
        for page in paginator.paginate():
            page_count += 1
            console.print(f"[dim]  Processing page {page_count}...[/dim]")

            all_data["UserDetailList"].extend(page.get("UserDetailList", []))
            all_data["GroupDetailList"].extend(page.get("GroupDetailList", []))
            all_data["RoleDetailList"].extend(page.get("RoleDetailList", []))
            all_data["Policies"].extend(page.get("Policies", []))

        # Summary
        console.print(f"\n[green]✓ Collection complete![/green]")
        console.print(f"  [dim]Users: {len(all_data['UserDetailList'])}[/dim]")
        console.print(f"  [dim]Groups: {len(all_data['GroupDetailList'])}[/dim]")
        console.print(f"  [dim]Roles: {len(all_data['RoleDetailList'])}[/dim]")
        console.print(f"  [dim]Policies: {len(all_data['Policies'])}[/dim]")

    except Exception as e:
        console.print(f"[red]Failed to collect IAM data: {str(e)}[/red]")
        console.print("[yellow]Ensure you have the following permission:[/yellow]")
        console.print("[dim]  iam:GetAccountAuthorizationDetails[/dim]")
        return

    # Save to file
    try:
        console.print(f"\n[dim]→ Saving to {output_path}...[/dim]")

        # Ensure directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, default=str)

        file_size = os.path.getsize(output_path)
        file_size_mb = file_size / (1024 * 1024)

        console.print(f"[green]✓ Data saved successfully![/green]")
        console.print(f"  [dim]File: {output_path}[/dim]")
        console.print(f"  [dim]Size: {file_size_mb:.2f} MB[/dim]")

    except Exception as e:
        console.print(f"[red]Failed to save file: {str(e)}[/red]")
        return

    # Final message
    console.print(Panel(
        "[bold green]✓ IAM data collection complete![/bold green]\n\n"
        f"[cyan]Output file:[/cyan] {output_path}\n\n"
        "[bold yellow]Now you can import your data in IAMGraph[/bold yellow]\n\n"
        "[dim]IAMGraph installation and usage:[/dim]\n"
        "[dim]1. git clone https://github.com/withsecurelabs/IAMGraph[/dim]\n"
        "[dim]2. Follow the setup instructions in the README[/dim]\n"
        "[dim]3. Import this JSON file into IAMGraph for visualization[/dim]",
        title="[bold green]Success[/bold green]",
        border_style="green"
    ))

    # Save to session data
    session_mgr.save_enumeration_data("iamgraph_export", {
        "output_path": output_path,
        "user_count": len(all_data["UserDetailList"]),
        "group_count": len(all_data["GroupDetailList"]),
        "role_count": len(all_data["RoleDetailList"]),
        "policy_count": len(all_data["Policies"]),
        "file_size_mb": file_size_mb,
    })
