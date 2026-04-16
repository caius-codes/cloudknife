# src/clouds/azure/modules/enumeration/enumerate_disks.py

import requests
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_disks(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all Azure Managed Disks in the current subscription.

    Collects:
    - Basic info (name, location, resource group, disk type)
    - Size and SKU
    - Encryption settings (platform-managed vs customer-managed)
    - Attached VM (if any)
    - Network access policy
    - Disk state (attached/unattached)

    Security Analysis:
    - Identifies unencrypted disks
    - Detects unattached disks (potential data residue)
    - Highlights publicly accessible disks
    - Shows disks without encryption at host

    Returns:
        List of disk dictionaries with detailed information
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating Managed Disks in subscription: {subscription_id}[/bold blue]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/disks?api-version=2023-04-02"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        disks = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not disks:
        console.print("[yellow]No Managed Disks found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(disks)} Managed Disk(s).[/green]")

    # Parse and analyze disks
    simplified_disks = []
    unencrypted_disks = []
    unattached_disks = []
    publicly_accessible = []

    for disk in disks:
        properties = disk.get("properties") or {}
        sku = disk.get("sku") or {}

        disk_id = disk.get("id", "")
        resource_group = disk_id.split("/")[4] if len(disk_id.split("/")) > 4 else ""
        disk_name = disk.get("name", "")

        # Basic info
        location = disk.get("location", "")
        disk_size_gb = properties.get("diskSizeGB", 0)
        disk_size_bytes = properties.get("diskSizeBytes", 0)
        sku_name = sku.get("name", "")
        sku_tier = sku.get("tier", "")
        os_type = properties.get("osType", "")
        provisioning_state = properties.get("provisioningState", "")
        time_created = properties.get("timeCreated", "")

        # Disk state (attached/unattached)
        disk_state = properties.get("diskState", "")
        managed_by = disk.get("managedBy", "")
        is_attached = bool(managed_by)

        if not is_attached:
            unattached_disks.append(disk_name)

        # Creation data
        creation_data = properties.get("creationData", {})
        creation_option = creation_data.get("createOption", "")
        source_resource_id = creation_data.get("sourceResourceId", "")

        # Encryption
        encryption_settings = properties.get("encryption", {})
        encryption_type = encryption_settings.get("type", "")
        disk_encryption_set_id = encryption_settings.get("diskEncryptionSetId", "")

        encryption_at_host = properties.get("encryptionSettingsCollection", {}).get("enabled", False)

        is_encrypted = bool(encryption_type and encryption_type != "EncryptionAtRestWithPlatformKey")

        if not is_encrypted:
            unencrypted_disks.append(disk_name)

        # Network access policy
        network_access_policy = properties.get("networkAccessPolicy", "AllowAll")
        public_network_access = properties.get("publicNetworkAccess", "Enabled")

        if network_access_policy == "AllowAll" and public_network_access == "Enabled":
            publicly_accessible.append(disk_name)

        # Performance tier
        tier = properties.get("tier", "")

        # Max shares
        max_shares = properties.get("maxShares", 1)

        # Tags
        tags = disk.get("tags", {})

        # Zones
        zones = disk.get("zones", [])

        simplified_disks.append({
            # Basic info
            "id": disk_id,
            "name": disk_name,
            "location": location,
            "resource_group": resource_group,
            "time_created": time_created,
            "provisioning_state": provisioning_state,

            # Size and SKU
            "disk_size_gb": disk_size_gb,
            "disk_size_bytes": disk_size_bytes,
            "sku_name": sku_name,
            "sku_tier": sku_tier,
            "tier": tier,

            # State
            "disk_state": disk_state,
            "managed_by": managed_by,
            "is_attached": is_attached,
            "os_type": os_type,

            # Creation
            "creation_option": creation_option,
            "source_resource_id": source_resource_id,

            # Encryption
            "encryption_type": encryption_type,
            "is_encrypted": is_encrypted,
            "disk_encryption_set_id": disk_encryption_set_id,
            "encryption_at_host": encryption_at_host,

            # Network access
            "network_access_policy": network_access_policy,
            "public_network_access": public_network_access,
            "is_publicly_accessible": network_access_policy == "AllowAll" and public_network_access == "Enabled",

            # Features
            "max_shares": max_shares,
            "zones": zones,

            # Tags
            "tags": tags,
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("managed_disks", simplified_disks)

    # Display results table
    table = Table(title=f"Azure Managed Disks ({len(simplified_disks)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Size (GB)", style="magenta")
    table.add_column("SKU", style="green")
    table.add_column("State", style="blue")
    table.add_column("Encrypted", style="white")
    table.add_column("Public", style="red")

    for disk in simplified_disks:
        name = disk.get("name", "")
        rg = disk.get("resource_group", "")
        size = disk.get("disk_size_gb", 0)
        sku = disk.get("sku_name", "")
        is_attached = disk.get("is_attached", False)
        is_encrypted = disk.get("is_encrypted", False)
        is_public = disk.get("is_publicly_accessible", False)

        state_display = "[green]Attached[/green]" if is_attached else "[yellow]Unattached[/yellow]"
        encrypted_display = "[green]✓[/green]" if is_encrypted else "[red]✗[/red]"
        public_display = "[red bold]✓[/red bold]" if is_public else "–"

        table.add_row(
            name,
            rg,
            str(size),
            sku,
            state_display,
            encrypted_display,
            public_display
        )

    console.print(table)

    # Security warnings
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if unencrypted_disks:
        console.print(
            f"\n[red bold]⚠️ Unencrypted Disks:[/red bold] {len(unencrypted_disks)} disk(s) without customer-managed encryption"
        )
        console.print("[yellow]Platform-managed encryption only - consider using customer-managed keys for sensitive data[/yellow]")
        for disk_name in unencrypted_disks[:5]:
            console.print(f"  • {disk_name}")
        if len(unencrypted_disks) > 5:
            console.print(f"  [dim]... and {len(unencrypted_disks) - 5} more[/dim]")

    if unattached_disks:
        console.print(
            f"\n[yellow]💸 Unattached Disks:[/yellow] {len(unattached_disks)} disk(s) not attached to any VM"
        )
        console.print("[dim]These disks may contain residual data and incur storage costs[/dim]")
        for disk_name in unattached_disks[:5]:
            console.print(f"  • {disk_name}")
        if len(unattached_disks) > 5:
            console.print(f"  [dim]... and {len(unattached_disks) - 5} more[/dim]")

    if publicly_accessible:
        console.print(
            f"\n[red bold]🌐 Publicly Accessible:[/red bold] {len(publicly_accessible)} disk(s) accessible from public networks"
        )
        console.print("[yellow]NetworkAccessPolicy=AllowAll and PublicNetworkAccess=Enabled[/yellow]")

    # Summary
    console.print(
        f"\n[green]✓ Disk enumeration complete. {len(simplified_disks)} disks stored under 'managed_disks' in session.[/green]"
    )
    console.print("[dim]Saved as 'managed_disks' in this session's enumeration data.[/dim]")

    return simplified_disks
