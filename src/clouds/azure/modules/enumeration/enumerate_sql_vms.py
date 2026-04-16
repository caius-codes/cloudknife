# src/clouds/azure/modules/enumeration/enumerate_sql_vms.py

import requests
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_sql_vms(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all Azure SQL Virtual Machines in the current subscription.

    Collects:
    - Basic info (name, location, resource group, SQL image)
    - SQL Server version and edition
    - License type and offer
    - Auto patching and backup settings
    - Key Vault integration
    - SQL connectivity settings
    - Associated VM

    Security Analysis:
    - Identifies SQL VMs with auto patching disabled
    - Detects SQL VMs without Key Vault integration
    - Shows public connectivity settings
    - Highlights unencrypted backups

    Returns:
        List of SQL VM dictionaries with detailed information
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating SQL Virtual Machines in subscription: {subscription_id}[/bold blue]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.SqlVirtualMachine/sqlVirtualMachines?api-version=2022-08-01-preview"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        sql_vms = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not sql_vms:
        console.print("[yellow]No SQL Virtual Machines found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(sql_vms)} SQL Virtual Machine(s).[/green]")

    # Parse and analyze SQL VMs
    simplified_sql_vms = []
    sql_vms_without_patching = []
    sql_vms_without_keyvault = []
    sql_vms_with_public_access = []

    for sql_vm in sql_vms:
        properties = sql_vm.get("properties") or {}

        sql_vm_id = sql_vm.get("id", "")
        resource_group = sql_vm_id.split("/")[4] if len(sql_vm_id.split("/")) > 4 else ""
        sql_vm_name = sql_vm.get("name", "")

        # Basic info
        location = sql_vm.get("location", "")
        provisioning_state = properties.get("provisioningState", "")

        # Virtual machine ID
        virtual_machine_resource_id = properties.get("virtualMachineResourceId", "")

        # SQL Server configuration
        sql_server_license_type = properties.get("sqlServerLicenseType", "")
        sql_image_offer = properties.get("sqlImageOffer", "")
        sql_image_sku = properties.get("sqlImageSku", "")
        sql_management_mode = properties.get("sqlManagement", "")

        # Auto patching
        auto_patching_settings = properties.get("autoPatchingSettings", {})
        enable_auto_patching = auto_patching_settings.get("enable", False)

        if not enable_auto_patching:
            sql_vms_without_patching.append(sql_vm_name)

        # Auto backup
        auto_backup_settings = properties.get("autoBackupSettings", {})
        enable_auto_backup = auto_backup_settings.get("enable", False)
        backup_encryption_enabled = auto_backup_settings.get("enableEncryption", False)

        # Key Vault credential
        key_vault_credential_settings = properties.get("keyVaultCredentialSettings", {})
        enable_key_vault = key_vault_credential_settings.get("enable", False)

        if not enable_key_vault:
            sql_vms_without_keyvault.append(sql_vm_name)

        # Server configurations
        server_configurations_management_settings = properties.get("serverConfigurationsManagementSettings", {})
        sql_connectivity_update_settings = server_configurations_management_settings.get("sqlConnectivityUpdateSettings", {})
        connectivity_type = sql_connectivity_update_settings.get("connectivityType", "")
        port = sql_connectivity_update_settings.get("port", 1433)

        if connectivity_type == "PUBLIC":
            sql_vms_with_public_access.append(sql_vm_name)

        # Storage configuration
        storage_configuration_settings = properties.get("storageConfigurationSettings", {})
        disk_configuration_type = storage_configuration_settings.get("diskConfigurationType", "")

        # Assessment settings
        assessment_settings = properties.get("assessmentSettings", {})
        enable_assessment = assessment_settings.get("enable", False)

        # Tags
        tags = sql_vm.get("tags", {})

        simplified_sql_vms.append({
            # Basic info
            "id": sql_vm_id,
            "name": sql_vm_name,
            "location": location,
            "resource_group": resource_group,
            "provisioning_state": provisioning_state,

            # VM association
            "virtual_machine_resource_id": virtual_machine_resource_id,

            # SQL Server
            "sql_server_license_type": sql_server_license_type,
            "sql_image_offer": sql_image_offer,
            "sql_image_sku": sql_image_sku,
            "sql_management_mode": sql_management_mode,

            # Auto patching
            "enable_auto_patching": enable_auto_patching,
            "auto_patching_settings": auto_patching_settings,

            # Auto backup
            "enable_auto_backup": enable_auto_backup,
            "backup_encryption_enabled": backup_encryption_enabled,
            "auto_backup_settings": auto_backup_settings,

            # Key Vault
            "enable_key_vault": enable_key_vault,

            # Connectivity
            "connectivity_type": connectivity_type,
            "port": port,
            "is_public": connectivity_type == "PUBLIC",

            # Storage
            "disk_configuration_type": disk_configuration_type,

            # Assessment
            "enable_assessment": enable_assessment,

            # Tags
            "tags": tags,
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("sql_virtual_machines", simplified_sql_vms)

    # Display results table
    table = Table(title=f"Azure SQL Virtual Machines ({len(simplified_sql_vms)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Location", style="green")
    table.add_column("SKU", style="magenta")
    table.add_column("License", style="blue")
    table.add_column("Patching", style="white")
    table.add_column("KeyVault", style="white")
    table.add_column("Public", style="red")

    for sql_vm in simplified_sql_vms:
        name = sql_vm.get("name", "")
        rg = sql_vm.get("resource_group", "")
        location = sql_vm.get("location", "")
        sku = sql_vm.get("sql_image_sku", "")
        license_type = sql_vm.get("sql_server_license_type", "")
        auto_patching = sql_vm.get("enable_auto_patching", False)
        key_vault = sql_vm.get("enable_key_vault", False)
        is_public = sql_vm.get("is_public", False)

        patching_display = "[green]✓[/green]" if auto_patching else "[red]✗[/red]"
        keyvault_display = "[green]✓[/green]" if key_vault else "[red]✗[/red]"
        public_display = "[red bold]✓[/red bold]" if is_public else "–"

        table.add_row(
            name,
            rg,
            location,
            sku,
            license_type,
            patching_display,
            keyvault_display,
            public_display
        )

    console.print(table)

    # Security warnings
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if sql_vms_without_patching:
        console.print(
            f"\n[yellow]⚠️ Auto Patching Disabled:[/yellow] {len(sql_vms_without_patching)} SQL VM(s) without auto patching"
        )
        console.print("[dim]Manual patching required - consider enabling auto patching for security updates[/dim]")
        for vm_name in sql_vms_without_patching[:5]:
            console.print(f"  • {vm_name}")
        if len(sql_vms_without_patching) > 5:
            console.print(f"  [dim]... and {len(sql_vms_without_patching) - 5} more[/dim]")

    if sql_vms_without_keyvault:
        console.print(
            f"\n[yellow]🔑 No Key Vault Integration:[/yellow] {len(sql_vms_without_keyvault)} SQL VM(s) without Key Vault"
        )
        console.print("[dim]Key Vault integration recommended for secure credential management[/dim]")

    if sql_vms_with_public_access:
        console.print(
            f"\n[red bold]🌐 Public Connectivity:[/red bold] {len(sql_vms_with_public_access)} SQL VM(s) with public connectivity"
        )
        console.print("[yellow]SQL Server is accessible from the internet - review NSG rules and firewall settings[/yellow]")
        for vm_name in sql_vms_with_public_access[:5]:
            console.print(f"  • {vm_name}")
        if len(sql_vms_with_public_access) > 5:
            console.print(f"  [dim]... and {len(sql_vms_with_public_access) - 5} more[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ SQL VM enumeration complete. {len(simplified_sql_vms)} SQL VMs stored under 'sql_virtual_machines' in session.[/green]"
    )
    console.print("[dim]Saved as 'sql_virtual_machines' in this session's enumeration data.[/dim]")

    return simplified_sql_vms
