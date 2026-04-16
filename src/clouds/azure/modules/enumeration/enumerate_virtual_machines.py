# src/clouds/azure/modules/enumeration/enumerate_virtual_machines.py

import base64
import requests
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def _get_tag_value(tags: Dict[str, str] | None, key: str) -> str:
    """Extract a specific tag value (case-insensitive)."""
    if not tags:
        return ""
    for tag_key, tag_value in tags.items():
        if tag_key.lower() == key.lower():
            return tag_value
    return ""


def _get_network_interface_details(
    nic_id: str,
    token: str,
    subscription_id: str
) -> Dict[str, Any]:
    """
    Retrieve network interface details including private and public IPs.

    Returns:
        Dict with 'private_ips' (list), 'public_ips' (list), and 'nsg' (str)
    """
    if not nic_id:
        return {"private_ips": [], "public_ips": [], "nsg": ""}

    url = f"https://management.azure.com{nic_id}?api-version=2023-05-01"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        nic_data = response.json()

        properties = nic_data.get("properties", {})
        ip_configs = properties.get("ipConfigurations", [])

        private_ips = []
        public_ip_ids = []

        for ip_config in ip_configs:
            ip_props = ip_config.get("properties", {})

            # Private IP
            private_ip = ip_props.get("privateIPAddress")
            if private_ip:
                private_ips.append(private_ip)

            # Public IP reference
            public_ip_ref = ip_props.get("publicIPAddress")
            if public_ip_ref:
                public_ip_ids.append(public_ip_ref.get("id"))

        # Retrieve public IPs
        public_ips = []
        for pub_ip_id in public_ip_ids:
            if pub_ip_id:
                pub_ip = _get_public_ip_address(pub_ip_id, token)
                if pub_ip:
                    public_ips.append(pub_ip)

        # Network Security Group
        nsg = properties.get("networkSecurityGroup", {}).get("id", "")
        nsg_name = nsg.split("/")[-1] if nsg else ""

        return {
            "private_ips": private_ips,
            "public_ips": public_ips,
            "nsg": nsg_name
        }

    except Exception:
        return {"private_ips": [], "public_ips": [], "nsg": ""}


def _get_public_ip_address(public_ip_id: str, token: str) -> str:
    """Retrieve the actual public IP address from a public IP resource ID."""
    if not public_ip_id:
        return ""

    url = f"https://management.azure.com{public_ip_id}?api-version=2023-05-01"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        ip_address = data.get("properties", {}).get("ipAddress", "")
        return ip_address
    except Exception:
        return ""


def _get_vm_instance_view(vm_id: str, token: str) -> Dict[str, Any]:
    """
    Get VM instance view for runtime information (power state, extensions).

    Returns:
        Dict with 'power_state' and 'extensions' list
    """
    url = f"https://management.azure.com{vm_id}/instanceView?api-version=2023-03-01"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        instance_view = response.json()

        # Power state
        statuses = instance_view.get("statuses", [])
        power_state = "unknown"
        for status in statuses:
            code = status.get("code", "")
            if code.startswith("PowerState/"):
                power_state = code.replace("PowerState/", "")
                break

        # Extensions (VM agents/scripts that could contain secrets)
        extensions = instance_view.get("extensions", [])
        extension_list = []
        for ext in extensions:
            ext_name = ext.get("name", "")
            ext_type = ext.get("type", "")
            extension_list.append(f"{ext_name} ({ext_type})")

        return {
            "power_state": power_state,
            "extensions": extension_list
        }
    except Exception:
        return {"power_state": "unknown", "extensions": []}


def _get_vm_user_data(vm_id: str, token: str) -> str:
    """
    Retrieve VM userData field (separate from customData).

    userData is a newer Azure feature that stores base64-encoded data.
    Unlike customData (which is only available at creation), userData can be
    retrieved and updated after VM creation.

    Returns:
        Decoded userData string, or empty string if not present
    """
    # Use $expand=userData to include userData in response
    url = f"https://management.azure.com{vm_id}?$expand=userData&api-version=2023-03-01"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        vm_data = response.json()

        # userData is base64-encoded at the properties level
        properties = vm_data.get("properties", {})
        user_data_encoded = properties.get("userData", "")

        if user_data_encoded:
            # Decode from base64
            try:
                user_data = base64.b64decode(user_data_encoded).decode("utf-8", errors="replace")
                return user_data
            except Exception:
                return "[ERROR decoding userData]"
        return ""
    except Exception:
        return ""


def enumerate_virtual_machines(session_mgr: AzureSessionManager) -> list:
    """
    Comprehensive Azure Virtual Machine enumeration with security-focused analysis.

    Collects:
    - Basic metadata (name, location, resource group, size, OS, state)
    - Networking (private IPs, public IPs, NSGs)
    - Security (managed identity, admin username, SSH key)
    - CustomData (legacy, set at creation only - may contain secrets)
    - UserData (newer feature, can be updated - may contain secrets)
    - VM extensions (scripts and configurations)

    Security Analysis:
    - Identifies VMs with public IPs (internet exposure)
    - Highlights VMs with managed identities (privilege escalation vectors)
    - Detects customData/userData presence (potential secrets)
    - Lists VM extensions (may contain sensitive configurations)

    Returns:
        List of VM dictionaries with detailed information
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating Virtual Machines in subscription: {subscription_id}[/bold blue]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        vms = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not vms:
        console.print("[yellow]No Virtual Machines found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(vms)} Virtual Machine(s). Enriching with network and extension data...[/green]")

    # Parse and enrich VM data
    simplified_vms = []
    vms_with_public_ip = []
    vms_with_identity = []
    vms_with_custom_data = []

    for vm in vms:
        # Use 'or {}' to handle None values
        properties = vm.get("properties") or {}
        hardware_profile = properties.get("hardwareProfile") or {}
        os_profile = properties.get("osProfile") or {}
        storage_profile = properties.get("storageProfile") or {}
        network_profile = properties.get("networkProfile") or {}
        os_disk = storage_profile.get("osDisk") or {}
        image_reference = storage_profile.get("imageReference") or {}

        vm_id = vm.get("id", "")
        resource_group = vm_id.split("/")[4] if len(vm_id.split("/")) > 4 else ""
        vm_name = vm.get("name", "")

        # Basic info
        location = vm.get("location", "")
        vm_size = hardware_profile.get("vmSize", "")
        os_type = os_disk.get("osType", "")
        computer_name = os_profile.get("computerName", "")
        admin_username = os_profile.get("adminUsername", "")
        provisioning_state = properties.get("provisioningState", "")
        vm_unique_id = properties.get("vmId", "")

        # Identity (managed identity = privilege escalation vector!)
        identity = vm.get("identity", {})
        has_identity = bool(identity)
        identity_type = identity.get("type", "") if has_identity else ""
        identity_principal_id = identity.get("principalId", "") if has_identity else ""

        if has_identity:
            vms_with_identity.append(vm_name)

        # Custom data (similar to AWS UserData - may contain secrets!)
        custom_data_encoded = os_profile.get("customData", "")
        custom_data = ""
        has_custom_data = bool(custom_data_encoded)

        if has_custom_data:
            try:
                custom_data = base64.b64decode(custom_data_encoded).decode("utf-8", errors="replace")
                vms_with_custom_data.append(vm_name)
            except Exception:
                custom_data = "[ERROR decoding custom data]"

        # Network interfaces
        nic_references = network_profile.get("networkInterfaces", [])
        nic_ids = [nic.get("id", "") for nic in nic_references]

        # Retrieve IP addresses from NICs
        all_private_ips = []
        all_public_ips = []
        all_nsgs = []

        for nic_id in nic_ids:
            nic_details = _get_network_interface_details(nic_id, token, subscription_id)
            all_private_ips.extend(nic_details["private_ips"])
            all_public_ips.extend(nic_details["public_ips"])
            if nic_details["nsg"]:
                all_nsgs.append(nic_details["nsg"])

        if all_public_ips:
            vms_with_public_ip.append(vm_name)

        # VM instance view (power state, extensions)
        instance_view = _get_vm_instance_view(vm_id, token)
        power_state = instance_view["power_state"]
        extensions = instance_view["extensions"]

        # UserData (newer Azure feature - separate from customData)
        user_data = _get_vm_user_data(vm_id, token)
        has_user_data = bool(user_data)
        if has_user_data:
            vms_with_custom_data.append(vm_name)  # Track both customData and userData together

        # Tags
        tags = vm.get("tags", {})
        description = _get_tag_value(tags, "Description")
        environment = _get_tag_value(tags, "Environment")
        owner = _get_tag_value(tags, "Owner")

        # SSH keys
        linux_config = os_profile.get("linuxConfiguration", {})
        ssh_keys = linux_config.get("ssh", {}).get("publicKeys", [])
        has_ssh_keys = len(ssh_keys) > 0

        simplified_vms.append({
            # Basic info
            "id": vm_id,
            "name": vm_name,
            "location": location,
            "resource_group": resource_group,
            "vm_size": vm_size,
            "os_type": os_type,
            "computer_name": computer_name,
            "admin_username": admin_username,
            "provisioning_state": provisioning_state,
            "power_state": power_state,
            "vm_id": vm_unique_id,

            # Image info
            "image_publisher": image_reference.get("publisher", ""),
            "image_offer": image_reference.get("offer", ""),
            "image_sku": image_reference.get("sku", ""),

            # Networking
            "private_ips": all_private_ips,
            "public_ips": all_public_ips,
            "network_security_groups": all_nsgs,
            "network_interface_ids": nic_ids,

            # Security
            "identity": identity,
            "has_identity": has_identity,
            "identity_type": identity_type,
            "identity_principal_id": identity_principal_id,
            "has_ssh_keys": has_ssh_keys,

            # Custom data & user data (CRITICAL - may contain secrets!)
            "custom_data": custom_data,
            "has_custom_data": has_custom_data,
            "user_data": user_data,
            "has_user_data": has_user_data,

            # Extensions (may contain scripts/configurations)
            "extensions": extensions,

            # Tags
            "zones": vm.get("zones", []),
            "tags": tags,
            "description": description,
            "environment": environment,
            "owner": owner,
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("virtual_machines", simplified_vms)

    # Display results table
    table = Table(title=f"Azure Virtual Machines ({len(simplified_vms)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Location", style="green")
    table.add_column("VM Size", style="magenta")
    table.add_column("OS", style="blue")
    table.add_column("State", style="white")
    table.add_column("Private IP", overflow="fold")
    table.add_column("Public IP", overflow="fold")
    table.add_column("Identity", style="red")
    table.add_column("Data", style="yellow")

    for vm in simplified_vms:
        name = vm.get("name", "")
        rg = vm.get("resource_group", "")
        location = vm.get("location", "")
        vm_size = vm.get("vm_size", "")
        os_type = vm.get("os_type", "")
        power_state = vm.get("power_state", "")

        # IPs
        private_ips = ", ".join(vm.get("private_ips", [])) or "–"
        public_ips = ", ".join(vm.get("public_ips", [])) or "–"

        # Identity indicator
        has_identity = vm.get("has_identity", False)
        identity_display = "[green bold]✓ Identity[/green bold]" if has_identity else "–"

        # Custom data or user data indicator
        has_custom_data = vm.get("has_custom_data", False)
        has_user_data = vm.get("has_user_data", False)
        if has_custom_data and has_user_data:
            data_display = "[yellow bold]📜 Both[/yellow bold]"
        elif has_custom_data:
            data_display = "[yellow bold]📜 Custom[/yellow bold]"
        elif has_user_data:
            data_display = "[yellow bold]📜 User[/yellow bold]"
        else:
            data_display = "–"

        table.add_row(
            name,
            rg,
            location,
            vm_size,
            os_type,
            power_state,
            private_ips,
            public_ips,
            identity_display,
            data_display
        )

    console.print(table)

    # Security warnings and actionable intelligence
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if vms_with_public_ip:
        console.print(
            f"\n[cyan]🌐 Public Exposure:[/cyan] {len(vms_with_public_ip)} VM(s) with public IPs"
        )
        console.print("[dim]These VMs are directly accessible from the internet (check NSGs).[/dim]")
        for vm_name in vms_with_public_ip[:5]:
            console.print(f"  • {vm_name}")
        if len(vms_with_public_ip) > 5:
            console.print(f"  [dim]... and {len(vms_with_public_ip) - 5} more[/dim]")

    if vms_with_identity:
        console.print(
            f"\n[green bold]🎯 Privilege Escalation Vector:[/green bold] {len(vms_with_identity)} VM(s) with managed identities"
        )
        console.print("[yellow]RCE on these VMs = automatic identity assumption[/yellow]")
        console.print("[dim]Use 'vm_run_command' to execute commands if you have permissions.[/dim]")
        for vm_name in vms_with_identity[:5]:
            console.print(f"  • {vm_name}")
        if len(vms_with_identity) > 5:
            console.print(f"  [dim]... and {len(vms_with_identity) - 5} more[/dim]")

    if vms_with_custom_data:
        console.print(
            f"\n[yellow]📜 CustomData/UserData Found:[/yellow] {len(vms_with_custom_data)} VM(s) have customData or userData"
        )
        console.print("[dim]CustomData and userData often contain secrets (credentials, tokens, API keys, scripts).[/dim]")
        console.print("[dim]Inspect the 'custom_data' and 'user_data' fields in saved enumeration data.[/dim]")
        for vm_name in vms_with_custom_data[:5]:
            console.print(f"  • {vm_name}")
        if len(vms_with_custom_data) > 5:
            console.print(f"  [dim]... and {len(vms_with_custom_data) - 5} more[/dim]")

        # Ask user if they want to view decoded data
        from rich.prompt import Prompt
        view_data = Prompt.ask(
            "\n[cyan]Do you want to view the decoded customData/userData?[/cyan]",
            choices=["y", "n"],
            default="n"
        )

        if view_data.lower() == "y":
            console.print("\n[bold cyan]Decoded CustomData/UserData:[/bold cyan]\n")
            for vm in simplified_vms:
                custom_data = vm.get("custom_data", "")
                user_data = vm.get("user_data", "")

                if custom_data or user_data:
                    console.print(f"[bold yellow]VM: {vm['name']}[/bold yellow]")
                    console.print(f"[dim]Resource Group: {vm['resource_group']}[/dim]\n")

                    if custom_data:
                        console.print("[cyan]CustomData:[/cyan]")
                        console.print(f"[white]{custom_data}[/white]\n")

                    if user_data:
                        console.print("[cyan]UserData:[/cyan]")
                        console.print(f"[white]{user_data}[/white]\n")

                    console.print("[dim]" + "─" * 80 + "[/dim]\n")

    # Extensions warning
    vms_with_extensions = [vm for vm in simplified_vms if vm.get("extensions")]
    if vms_with_extensions:
        console.print(
            f"\n[magenta]🔌 VM Extensions:[/magenta] {len(vms_with_extensions)} VM(s) have extensions"
        )
        console.print("[dim]Extensions may contain scripts, configurations, or sensitive data.[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ VM enumeration complete. {len(simplified_vms)} VMs stored under 'virtual_machines' in session.[/green]"
    )
    console.print("[dim]Saved as 'virtual_machines' in this session's enumeration data.[/dim]")

    return simplified_vms
