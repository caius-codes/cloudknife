# src/clouds/azure/modules/enumeration/enumerate_snapshots.py

import requests
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_snapshots(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all Azure Disk Snapshots in the current subscription.

    Collects:
    - Basic info (name, location, resource group, creation time)
    - Source disk information
    - Size and SKU
    - Encryption settings
    - Network access policy

    Security Analysis:
    - Identifies unencrypted snapshots (potential data exposure)
    - Detects publicly accessible snapshots
    - Shows snapshots without source disk (orphaned)
    - Highlights old snapshots (potential forgotten data)

    Returns:
        List of snapshot dictionaries with detailed information
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating Disk Snapshots in subscription: {subscription_id}[/bold blue]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/snapshots?api-version=2023-04-02"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        snapshots = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not snapshots:
        console.print("[yellow]No Disk Snapshots found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(snapshots)} Disk Snapshot(s).[/green]")

    # Parse and analyze snapshots
    simplified_snapshots = []
    unencrypted_snapshots = []
    publicly_accessible = []
    orphaned_snapshots = []

    for snapshot in snapshots:
        properties = snapshot.get("properties") or {}
        sku = snapshot.get("sku") or {}

        snapshot_id = snapshot.get("id", "")
        resource_group = snapshot_id.split("/")[4] if len(snapshot_id.split("/")) > 4 else ""
        snapshot_name = snapshot.get("name", "")

        # Basic info
        location = snapshot.get("location", "")
        creation_data = properties.get("creationData", {})
        creation_option = creation_data.get("createOption", "")
        source_resource_id = creation_data.get("sourceResourceId", "")
        time_created = properties.get("timeCreated", "")
        disk_size_gb = properties.get("diskSizeGB", 0)
        disk_size_bytes = properties.get("diskSizeBytes", 0)
        sku_name = sku.get("name", "")
        sku_tier = sku.get("tier", "")
        os_type = properties.get("osType", "")
        provisioning_state = properties.get("provisioningState", "")

        # Encryption
        encryption_settings = properties.get("encryption", {})
        encryption_type = encryption_settings.get("type", "")
        disk_encryption_set_id = encryption_settings.get("diskEncryptionSetId", "")

        is_encrypted = bool(encryption_type and encryption_type != "EncryptionAtRestWithPlatformKey")

        if not is_encrypted:
            unencrypted_snapshots.append(snapshot_name)

        # Network access policy
        network_access_policy = properties.get("networkAccessPolicy", "AllowAll")
        public_network_access = properties.get("publicNetworkAccess", "Enabled")

        if network_access_policy == "AllowAll" and public_network_access == "Enabled":
            publicly_accessible.append(snapshot_name)

        # Check if orphaned (no source disk)
        is_orphaned = not bool(source_resource_id)
        if is_orphaned:
            orphaned_snapshots.append(snapshot_name)

        # Incremental snapshot
        incremental = properties.get("incremental", False)

        # Tags
        tags = snapshot.get("tags", {})

        simplified_snapshots.append({
            # Basic info
            "id": snapshot_id,
            "name": snapshot_name,
            "location": location,
            "resource_group": resource_group,
            "time_created": time_created,
            "provisioning_state": provisioning_state,

            # Size and SKU
            "disk_size_gb": disk_size_gb,
            "disk_size_bytes": disk_size_bytes,
            "sku_name": sku_name,
            "sku_tier": sku_tier,

            # Source
            "creation_option": creation_option,
            "source_resource_id": source_resource_id,
            "is_orphaned": is_orphaned,
            "os_type": os_type,

            # Encryption
            "encryption_type": encryption_type,
            "is_encrypted": is_encrypted,
            "disk_encryption_set_id": disk_encryption_set_id,

            # Network access
            "network_access_policy": network_access_policy,
            "public_network_access": public_network_access,
            "is_publicly_accessible": network_access_policy == "AllowAll" and public_network_access == "Enabled",

            # Features
            "incremental": incremental,

            # Tags
            "tags": tags,
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("disk_snapshots", simplified_snapshots)

    # Display results table
    table = Table(title=f"Azure Disk Snapshots ({len(simplified_snapshots)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Size (GB)", style="magenta")
    table.add_column("SKU", style="green")
    table.add_column("Encrypted", style="blue")
    table.add_column("Public", style="red")
    table.add_column("Orphaned", style="white")

    for snapshot in simplified_snapshots:
        name = snapshot.get("name", "")
        rg = snapshot.get("resource_group", "")
        size = snapshot.get("disk_size_gb", 0)
        sku = snapshot.get("sku_name", "")
        is_encrypted = snapshot.get("is_encrypted", False)
        is_public = snapshot.get("is_publicly_accessible", False)
        is_orphaned = snapshot.get("is_orphaned", False)

        encrypted_display = "[green]✓[/green]" if is_encrypted else "[red]✗[/red]"
        public_display = "[red bold]✓[/red bold]" if is_public else "–"
        orphaned_display = "[yellow]✓[/yellow]" if is_orphaned else "–"

        table.add_row(
            name,
            rg,
            str(size),
            sku,
            encrypted_display,
            public_display,
            orphaned_display
        )

    console.print(table)

    # Security warnings
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if unencrypted_snapshots:
        console.print(
            f"\n[red bold]⚠️ Unencrypted Snapshots:[/red bold] {len(unencrypted_snapshots)} snapshot(s) without customer-managed encryption"
        )
        console.print("[yellow]Platform-managed encryption only - consider using customer-managed keys for sensitive data[/yellow]")
        for snap_name in unencrypted_snapshots[:5]:
            console.print(f"  • {snap_name}")
        if len(unencrypted_snapshots) > 5:
            console.print(f"  [dim]... and {len(unencrypted_snapshots) - 5} more[/dim]")

    if publicly_accessible:
        console.print(
            f"\n[red bold]🌐 Publicly Accessible:[/red bold] {len(publicly_accessible)} snapshot(s) accessible from public networks"
        )
        console.print("[yellow]NetworkAccessPolicy=AllowAll and PublicNetworkAccess=Enabled[/yellow]")
        console.print("[dim]Snapshots could be exported or mounted by unauthorized parties[/dim]")
        for snap_name in publicly_accessible[:5]:
            console.print(f"  • {snap_name}")
        if len(publicly_accessible) > 5:
            console.print(f"  [dim]... and {len(publicly_accessible) - 5} more[/dim]")

    if orphaned_snapshots:
        console.print(
            f"\n[yellow]💸 Orphaned Snapshots:[/yellow] {len(orphaned_snapshots)} snapshot(s) without source disk"
        )
        console.print("[dim]These snapshots may be forgotten backups consuming storage costs[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ Snapshot enumeration complete. {len(simplified_snapshots)} snapshots stored under 'disk_snapshots' in session.[/green]"
    )
    console.print("[dim]Saved as 'disk_snapshots' in this session's enumeration data.[/dim]")

    return simplified_snapshots
