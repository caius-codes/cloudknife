from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table

from ...aws_session import AWSSessionManager
from src.clouds.aws.utils.regions import resolve_regions, RegionalClientFactory


console = Console()


def enumerate_ebs_snapshots(session_mgr: AWSSessionManager) -> None:
    """
    Enumerate EBS snapshots across configured regions.

    - Uses ec2:DescribeSnapshots with OwnerIds=['self'] in each region.
    - Records whether each snapshot is encrypted.
    - Stores results under 'ebs_snapshots' in session data.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    target_regions = resolve_regions(session_mgr, service_name="EBS")

    console.print(
        f"[bold blue]🔍 Enumerating EBS snapshots in regions:[/bold blue] "
        + ", ".join(target_regions)
    )

    all_snapshots: List[Dict[str, Any]] = []

    # Use factory for efficient multi-region client creation
    client_factory = RegionalClientFactory(session_mgr)

    for region in target_regions:
        try:
            ec2 = client_factory.get_client("ec2", region)

            paginator = ec2.get_paginator("describe_snapshots")
            page_iterator = paginator.paginate(OwnerIds=["self"])

            region_snapshots: List[Dict[str, Any]] = []

            for page in page_iterator:
                for snap in page.get("Snapshots", []):
                    snapshot_id = snap.get("SnapshotId")
                    volume_id = snap.get("VolumeId")
                    start_time = snap.get("StartTime")
                    state = snap.get("State")
                    size_gib = snap.get("VolumeSize")  # GiB
                    encrypted = snap.get("Encrypted", False)
                    owner_id = snap.get("OwnerId")
                    description = snap.get("Description", "")

                    region_snapshots.append(
                        {
                            "SnapshotId": snapshot_id,
                            "Region": region,
                            "VolumeId": volume_id,
                            "StartTime": start_time.isoformat() if hasattr(start_time, "isoformat") else str(start_time),
                            "State": state,
                            "VolumeSizeGiB": size_gib,
                            "Encrypted": encrypted,
                            "OwnerId": owner_id,
                            "Description": description,
                        }
                    )

            console.print(
                f"[green]Region {region}: found {len(region_snapshots)} snapshots.[/green]"
            )
            all_snapshots.extend(region_snapshots)

        except Exception as e:
            console.print(
                f"[red]Failed to enumerate EBS snapshots in region {region}: {str(e)}[/red]"
            )
            console.print(
                "[yellow]Ensure ec2:DescribeSnapshots permission for that region.[/yellow]"
            )

    session_mgr.save_enumeration_data("ebs_snapshots", all_snapshots)

    if not all_snapshots:
        console.print("[yellow]No EBS snapshots found in selected regions.[/yellow]")
        return

    total = len(all_snapshots)
    unencrypted = [s for s in all_snapshots if not s.get("Encrypted")]
    total_unencrypted = len(unencrypted)

    table = Table(title=f"EBS Snapshots (total: {total}, unencrypted: {total_unencrypted})")
    table.add_column("SnapshotId", style="cyan")
    table.add_column("Region")
    table.add_column("VolumeId")
    table.add_column("Enc")
    table.add_column("State")
    table.add_column("SizeGiB")
    table.add_column("StartTime")
    table.add_column("OwnerId")

    max_rows = 200
    for snap in all_snapshots[:max_rows]:
        table.add_row(
            snap.get("SnapshotId") or "",
            snap.get("Region") or "",
            snap.get("VolumeId") or "",
            "✅" if snap.get("Encrypted") else "❌",
            snap.get("State") or "",
            str(snap.get("VolumeSizeGiB") or ""),
            snap.get("StartTime") or "",
            snap.get("OwnerId") or "",
        )

    console.print(table)

    if total > max_rows:
        console.print(
            f"[dim]Showing first {max_rows} snapshots out of {total}. "
            f"All data stored under key 'ebs_snapshots' in session data.[/dim]"
        )
    else:
        console.print("[dim]All snapshots stored under key 'ebs_snapshots' in session data.[/dim]")

    if total_unencrypted > 0:
        console.print(
            "[bold red]Warning:[/bold red] found unencrypted EBS snapshots. "
            "Consider deeper inspection or exfil with a future module."
        )
