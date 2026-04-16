"""
RDS Snapshot Enumeration Module

Enumerates RDS snapshots (both manual and automated) and Aurora cluster snapshots.
Key security insights:
- Unencrypted snapshots can be shared/restored more easily
- Snapshot sharing attributes reveal potential data exposure
- Manual snapshots may contain historical sensitive data
"""

from typing import List, Dict, Any, Optional

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def enumerate_rds_snapshots(
    session_mgr: AWSSessionManager,
    snapshot_type: str = "all",
    check_sharing: bool = True,
) -> None:
    """
    Enumerate RDS and Aurora snapshots across configured regions.

    Args:
        session_mgr: Session manager instance
        snapshot_type: "manual", "automated", or "all" (default)
        check_sharing: Whether to check snapshot sharing attributes (slower but reveals exposure)

    Stores results under 'rds_snapshots' and 'rds_cluster_snapshots' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    regions = resolve_regions(session_mgr, service_name="RDS")
    console.print(
        f"[bold blue]🔍 Enumerating RDS snapshots in regions: {', '.join(regions)}[/bold blue]"
    )
    if check_sharing:
        console.print("[dim]Checking snapshot sharing attributes (this may take longer)...[/dim]")

    client_factory = RegionalClientFactory(session_mgr)
    all_snapshots: List[Dict[str, Any]] = []
    all_cluster_snapshots: List[Dict[str, Any]] = []

    for region in regions:
        console.print(f"[cyan]→ Region: {region}[/cyan]")
        try:
            rds = client_factory.get_client("rds", region)

            # Enumerate DB snapshots
            try:
                paginator = rds.get_paginator("describe_db_snapshots")
                paginate_kwargs = {}
                if snapshot_type != "all":
                    paginate_kwargs["SnapshotType"] = snapshot_type

                for page in paginator.paginate(**paginate_kwargs):
                    for snap in page.get("DBSnapshots", []):
                        snapshot_data = _extract_snapshot_data(snap, region)

                        # Check sharing attributes if requested
                        if check_sharing and snapshot_data["SnapshotType"] == "manual":
                            sharing = _get_snapshot_sharing(rds, snapshot_data["DBSnapshotIdentifier"])
                            snapshot_data["SharedWith"] = sharing

                        all_snapshots.append(snapshot_data)

            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException"):
                    console.print(f"[yellow]  Access denied for DescribeDBSnapshots in {region}[/yellow]")
                else:
                    console.print(f"[red]  Error listing snapshots: {code}[/red]")

            # Enumerate Aurora cluster snapshots
            try:
                paginator = rds.get_paginator("describe_db_cluster_snapshots")
                paginate_kwargs = {}
                if snapshot_type != "all":
                    paginate_kwargs["SnapshotType"] = snapshot_type

                for page in paginator.paginate(**paginate_kwargs):
                    for snap in page.get("DBClusterSnapshots", []):
                        snapshot_data = _extract_cluster_snapshot_data(snap, region)

                        # Check sharing attributes if requested
                        if check_sharing and snapshot_data["SnapshotType"] == "manual":
                            sharing = _get_cluster_snapshot_sharing(
                                rds, snapshot_data["DBClusterSnapshotIdentifier"]
                            )
                            snapshot_data["SharedWith"] = sharing

                        all_cluster_snapshots.append(snapshot_data)

            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException"):
                    console.print(f"[yellow]  Access denied for DescribeDBClusterSnapshots in {region}[/yellow]")
                else:
                    console.print(f"[red]  Error listing cluster snapshots: {code}[/red]")

            snap_count = len([s for s in all_snapshots if s["Region"] == region])
            cluster_snap_count = len([s for s in all_cluster_snapshots if s["Region"] == region])
            console.print(f"[green]  Found {snap_count} DB snapshots, {cluster_snap_count} cluster snapshots[/green]")

        except Exception as e:
            console.print(f"[red]Snapshot enumeration failed in region {region}: {str(e)}[/red]")

    # Save results
    session_mgr.save_enumeration_data("rds_snapshots", all_snapshots)
    session_mgr.save_enumeration_data("rds_cluster_snapshots", all_cluster_snapshots)

    # Display tables
    if all_snapshots:
        _display_snapshots_table(all_snapshots)
    else:
        console.print("[yellow]No RDS snapshots found.[/yellow]")

    if all_cluster_snapshots:
        _display_cluster_snapshots_table(all_cluster_snapshots)

    # Security summary
    _display_security_summary(all_snapshots, all_cluster_snapshots)

    console.print(
        "[green]Snapshot data stored under keys 'rds_snapshots' and 'rds_cluster_snapshots' in session data.[/green]"
    )


def _extract_snapshot_data(snap: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Extract relevant fields from a DBSnapshot response."""
    return {
        "Region": region,
        "DBSnapshotIdentifier": snap.get("DBSnapshotIdentifier", ""),
        "DBInstanceIdentifier": snap.get("DBInstanceIdentifier", ""),
        "SnapshotType": snap.get("SnapshotType", ""),  # manual, automated, shared, public
        "Engine": snap.get("Engine", ""),
        "EngineVersion": snap.get("EngineVersion", ""),
        "Status": snap.get("Status", ""),
        "AllocatedStorage": snap.get("AllocatedStorage", 0),
        "SnapshotCreateTime": str(snap.get("SnapshotCreateTime", ""))[:19],
        "MasterUsername": snap.get("MasterUsername", ""),
        "Encrypted": snap.get("Encrypted", False),
        "KmsKeyId": snap.get("KmsKeyId", ""),
        "DBSnapshotArn": snap.get("DBSnapshotArn", ""),
        "VpcId": snap.get("VpcId", ""),
        "SourceDBSnapshotIdentifier": snap.get("SourceDBSnapshotIdentifier", ""),
        "SourceRegion": snap.get("SourceRegion", ""),
        "SharedWith": [],  # Populated separately
    }


def _extract_cluster_snapshot_data(snap: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Extract relevant fields from a DBClusterSnapshot response."""
    return {
        "Region": region,
        "DBClusterSnapshotIdentifier": snap.get("DBClusterSnapshotIdentifier", ""),
        "DBClusterIdentifier": snap.get("DBClusterIdentifier", ""),
        "SnapshotType": snap.get("SnapshotType", ""),
        "Engine": snap.get("Engine", ""),
        "EngineVersion": snap.get("EngineVersion", ""),
        "EngineMode": snap.get("EngineMode", ""),
        "Status": snap.get("Status", ""),
        "AllocatedStorage": snap.get("AllocatedStorage", 0),
        "SnapshotCreateTime": str(snap.get("SnapshotCreateTime", ""))[:19],
        "MasterUsername": snap.get("MasterUsername", ""),
        "StorageEncrypted": snap.get("StorageEncrypted", False),
        "KmsKeyId": snap.get("KmsKeyId", ""),
        "DBClusterSnapshotArn": snap.get("DBClusterSnapshotArn", ""),
        "VpcId": snap.get("VpcId", ""),
        "SharedWith": [],  # Populated separately
    }


def _get_snapshot_sharing(rds, snapshot_identifier: str) -> List[str]:
    """Get list of account IDs that a snapshot is shared with."""
    try:
        resp = rds.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=snapshot_identifier
        )
        attributes = resp.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", [])
        for attr in attributes:
            if attr.get("AttributeName") == "restore":
                values = attr.get("AttributeValues", [])
                return values  # List of account IDs or "all" for public
        return []
    except ClientError:
        return []


def _get_cluster_snapshot_sharing(rds, snapshot_identifier: str) -> List[str]:
    """Get list of account IDs that a cluster snapshot is shared with."""
    try:
        resp = rds.describe_db_cluster_snapshot_attributes(
            DBClusterSnapshotIdentifier=snapshot_identifier
        )
        attributes = resp.get("DBClusterSnapshotAttributesResult", {}).get("DBClusterSnapshotAttributes", [])
        for attr in attributes:
            if attr.get("AttributeName") == "restore":
                values = attr.get("AttributeValues", [])
                return values
        return []
    except ClientError:
        return []


def _display_snapshots_table(snapshots: List[Dict[str, Any]]) -> None:
    """Display RDS snapshots in a formatted table."""
    table = Table(title=f"RDS Snapshots (total: {len(snapshots)})")
    table.add_column("Region", style="magenta")
    table.add_column("Snapshot ID", style="cyan")
    table.add_column("DB Instance")
    table.add_column("Type")
    table.add_column("Engine")
    table.add_column("Encrypted")
    table.add_column("Size (GB)")
    table.add_column("Created")
    table.add_column("Shared")

    # Sort by creation time (newest first)
    sorted_snaps = sorted(snapshots, key=lambda x: x.get("SnapshotCreateTime", ""), reverse=True)

    for snap in sorted_snaps[:100]:  # Limit display
        enc_flag = "[green]Yes[/green]" if snap["Encrypted"] else "[red]NO[/red]"
        shared = snap.get("SharedWith", [])
        if "all" in shared:
            shared_flag = "[bold red]PUBLIC[/bold red]"
        elif shared:
            shared_flag = f"[yellow]{len(shared)} accounts[/yellow]"
        else:
            shared_flag = "-"

        table.add_row(
            snap["Region"],
            snap["DBSnapshotIdentifier"][:30],
            snap["DBInstanceIdentifier"][:20],
            snap["SnapshotType"],
            snap["Engine"],
            enc_flag,
            str(snap["AllocatedStorage"]),
            snap["SnapshotCreateTime"],
            shared_flag,
        )

    console.print(table)


def _display_cluster_snapshots_table(snapshots: List[Dict[str, Any]]) -> None:
    """Display Aurora cluster snapshots in a formatted table."""
    table = Table(title=f"Aurora Cluster Snapshots (total: {len(snapshots)})")
    table.add_column("Region", style="magenta")
    table.add_column("Snapshot ID", style="cyan")
    table.add_column("Cluster")
    table.add_column("Type")
    table.add_column("Engine")
    table.add_column("Encrypted")
    table.add_column("Created")
    table.add_column("Shared")

    sorted_snaps = sorted(snapshots, key=lambda x: x.get("SnapshotCreateTime", ""), reverse=True)

    for snap in sorted_snaps[:50]:  # Limit display
        enc_flag = "[green]Yes[/green]" if snap["StorageEncrypted"] else "[red]NO[/red]"
        shared = snap.get("SharedWith", [])
        if "all" in shared:
            shared_flag = "[bold red]PUBLIC[/bold red]"
        elif shared:
            shared_flag = f"[yellow]{len(shared)} accounts[/yellow]"
        else:
            shared_flag = "-"

        table.add_row(
            snap["Region"],
            snap["DBClusterSnapshotIdentifier"][:30],
            snap["DBClusterIdentifier"][:20],
            snap["SnapshotType"],
            snap["Engine"],
            enc_flag,
            snap["SnapshotCreateTime"],
            shared_flag,
        )

    console.print(table)


def _display_security_summary(
    snapshots: List[Dict[str, Any]],
    cluster_snapshots: List[Dict[str, Any]],
) -> None:
    """Display security-relevant summary."""
    total = len(snapshots) + len(cluster_snapshots)
    if total == 0:
        return

    # Analyze DB snapshots
    unencrypted_snaps = [s for s in snapshots if not s.get("Encrypted")]
    public_snaps = [s for s in snapshots if "all" in s.get("SharedWith", [])]
    shared_snaps = [s for s in snapshots if s.get("SharedWith") and "all" not in s.get("SharedWith", [])]
    manual_snaps = [s for s in snapshots if s.get("SnapshotType") == "manual"]

    # Analyze cluster snapshots
    unencrypted_cluster_snaps = [s for s in cluster_snapshots if not s.get("StorageEncrypted")]
    public_cluster_snaps = [s for s in cluster_snapshots if "all" in s.get("SharedWith", [])]
    shared_cluster_snaps = [
        s for s in cluster_snapshots
        if s.get("SharedWith") and "all" not in s.get("SharedWith", [])
    ]

    console.print("\n[bold]Security Summary:[/bold]")

    # Public snapshots (critical!)
    all_public = public_snaps + public_cluster_snaps
    if all_public:
        console.print(f"[bold red]  🚨 {len(all_public)} PUBLIC snapshot(s) - data exposed to all AWS accounts![/bold red]")
        for snap in all_public[:5]:
            name = snap.get("DBSnapshotIdentifier") or snap.get("DBClusterSnapshotIdentifier")
            console.print(f"    - {name}")

    # Shared snapshots
    all_shared = shared_snaps + shared_cluster_snaps
    if all_shared:
        console.print(f"[bold yellow]  ⚠ {len(all_shared)} snapshot(s) shared with other accounts[/bold yellow]")

    # Unencrypted snapshots
    all_unencrypted = unencrypted_snaps + unencrypted_cluster_snaps
    if all_unencrypted:
        console.print(f"[bold yellow]  ⚠ {len(all_unencrypted)} unencrypted snapshot(s)[/bold yellow]")
        console.print("    [dim]Unencrypted snapshots can be shared and restored more easily[/dim]")

    # Manual snapshots (potential for historical data)
    if manual_snaps:
        console.print(f"[dim]  📁 {len(manual_snaps)} manual snapshot(s) (may contain point-in-time data)[/dim]")

    if not all_public and not all_shared and not all_unencrypted:
        console.print("[green]  ✓ No critical snapshot security issues found[/green]")
