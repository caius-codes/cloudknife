# src/clouds/azure/modules/enumeration/enumerate_nics.py

import requests
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_nics(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all Azure Network Interfaces (NICs) in the current subscription.

    Collects:
    - Basic info (name, location, resource group, MAC address)
    - IP configurations (private and public IPs)
    - Associated VM (if any)
    - NSG associations
    - Accelerated networking status
    - DNS settings

    Security Analysis:
    - Identifies NICs with public IPs (internet exposure)
    - Detects unattached NICs (potential forgotten resources)
    - Shows NICs without NSGs
    - Highlights IP forwarding enabled

    Returns:
        List of NIC dictionaries with detailed information
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating Network Interfaces in subscription: {subscription_id}[/bold blue]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/networkInterfaces?api-version=2023-05-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        nics = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not nics:
        console.print("[yellow]No Network Interfaces found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(nics)} Network Interface(s).[/green]")

    # Parse and analyze NICs
    simplified_nics = []
    nics_with_public_ips = []
    unattached_nics = []
    nics_without_nsgs = []
    nics_with_ip_forwarding = []

    for nic in nics:
        properties = nic.get("properties") or {}

        nic_id = nic.get("id", "")
        resource_group = nic_id.split("/")[4] if len(nic_id.split("/")) > 4 else ""
        nic_name = nic.get("name", "")

        # Basic info
        location = nic.get("location", "")
        provisioning_state = properties.get("provisioningState", "")
        mac_address = properties.get("macAddress", "")

        # VM association
        virtual_machine = properties.get("virtualMachine", {})
        vm_id = virtual_machine.get("id", "") if virtual_machine else ""
        is_attached = bool(vm_id)

        if not is_attached:
            unattached_nics.append(nic_name)

        # NSG
        network_security_group = properties.get("networkSecurityGroup", {})
        nsg_id = network_security_group.get("id", "") if network_security_group else ""

        if not nsg_id:
            nics_without_nsgs.append(nic_name)

        # IP forwarding
        enable_ip_forwarding = properties.get("enableIPForwarding", False)

        if enable_ip_forwarding:
            nics_with_ip_forwarding.append(nic_name)

        # Accelerated networking
        enable_accelerated_networking = properties.get("enableAcceleratedNetworking", False)

        # DNS settings
        dns_settings = properties.get("dnsSettings", {})
        dns_servers = dns_settings.get("dnsServers", [])
        internal_dns_name_label = dns_settings.get("internalDnsNameLabel", "")

        # IP configurations
        ip_configurations = properties.get("ipConfigurations", [])
        ip_config_details = []
        private_ips = []
        public_ips = []

        for ip_config in ip_configurations:
            ip_config_props = ip_config.get("properties", {})
            ip_config_name = ip_config.get("name", "")

            # Private IP
            private_ip = ip_config_props.get("privateIPAddress", "")
            private_ip_allocation = ip_config_props.get("privateIPAllocationMethod", "")

            if private_ip:
                private_ips.append(private_ip)

            # Public IP
            public_ip_address = ip_config_props.get("publicIPAddress", {})
            public_ip_id = public_ip_address.get("id", "") if public_ip_address else ""

            # Subnet
            subnet = ip_config_props.get("subnet", {})
            subnet_id = subnet.get("id", "") if subnet else ""

            # Primary
            is_primary = ip_config_props.get("primary", False)

            ip_config_info = {
                "name": ip_config_name,
                "private_ip": private_ip,
                "private_ip_allocation": private_ip_allocation,
                "public_ip_id": public_ip_id,
                "subnet_id": subnet_id,
                "is_primary": is_primary,
            }

            ip_config_details.append(ip_config_info)

            if public_ip_id:
                nics_with_public_ips.append(nic_name)
                # Note: actual public IP address would need another API call

        # Tags
        tags = nic.get("tags", {})

        simplified_nics.append({
            # Basic info
            "id": nic_id,
            "name": nic_name,
            "location": location,
            "resource_group": resource_group,
            "provisioning_state": provisioning_state,
            "mac_address": mac_address,

            # VM association
            "vm_id": vm_id,
            "is_attached": is_attached,

            # NSG
            "nsg_id": nsg_id,
            "has_nsg": bool(nsg_id),

            # Features
            "enable_ip_forwarding": enable_ip_forwarding,
            "enable_accelerated_networking": enable_accelerated_networking,

            # DNS
            "dns_servers": dns_servers,
            "internal_dns_name_label": internal_dns_name_label,

            # IP configurations
            "ip_configurations": ip_config_details,
            "private_ips": private_ips,
            "has_public_ip": len(public_ips) > 0 or any(cfg["public_ip_id"] for cfg in ip_config_details),

            # Tags
            "tags": tags,
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("network_interfaces", simplified_nics)

    # Display results table
    table = Table(title=f"Azure Network Interfaces ({len(simplified_nics)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Location", style="green")
    table.add_column("Private IP", overflow="fold")
    table.add_column("Attached", style="blue")
    table.add_column("NSG", style="white")
    table.add_column("Public IP", style="red")
    table.add_column("Forwarding", style="magenta")

    for nic in simplified_nics:
        name = nic.get("name", "")
        rg = nic.get("resource_group", "")
        location = nic.get("location", "")
        private_ips = ", ".join(nic.get("private_ips", [])) or "–"
        is_attached = nic.get("is_attached", False)
        has_nsg = nic.get("has_nsg", False)
        has_public_ip = nic.get("has_public_ip", False)
        ip_forwarding = nic.get("enable_ip_forwarding", False)

        attached_display = "[green]✓[/green]" if is_attached else "[yellow]✗[/yellow]"
        nsg_display = "[green]✓[/green]" if has_nsg else "[red]✗[/red]"
        public_ip_display = "[red bold]✓[/red bold]" if has_public_ip else "–"
        forwarding_display = "[yellow]✓[/yellow]" if ip_forwarding else "–"

        table.add_row(
            name,
            rg,
            location,
            private_ips,
            attached_display,
            nsg_display,
            public_ip_display,
            forwarding_display
        )

    console.print(table)

    # Security warnings
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if nics_with_public_ips:
        console.print(
            f"\n[cyan]🌐 Public IP Exposure:[/cyan] {len(nics_with_public_ips)} NIC(s) with public IP addresses"
        )
        console.print("[dim]These NICs are directly accessible from the internet[/dim]")

    if unattached_nics:
        console.print(
            f"\n[yellow]💸 Unattached NICs:[/yellow] {len(unattached_nics)} NIC(s) not attached to any VM"
        )
        console.print("[dim]These NICs may be forgotten resources consuming costs[/dim]")
        for nic_name in unattached_nics[:5]:
            console.print(f"  • {nic_name}")
        if len(unattached_nics) > 5:
            console.print(f"  [dim]... and {len(unattached_nics) - 5} more[/dim]")

    if nics_without_nsgs:
        console.print(
            f"\n[yellow]🔓 NICs Without NSGs:[/yellow] {len(nics_without_nsgs)} NIC(s) without Network Security Groups"
        )
        console.print("[dim]NICs without NSGs have no firewall protection (unless subnet-level NSG exists)[/dim]")

    if nics_with_ip_forwarding:
        console.print(
            f"\n[magenta]🔀 IP Forwarding Enabled:[/magenta] {len(nics_with_ip_forwarding)} NIC(s) with IP forwarding enabled"
        )
        console.print("[dim]IP forwarding allows traffic routing - verify this is intentional[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ NIC enumeration complete. {len(simplified_nics)} NICs stored under 'network_interfaces' in session.[/green]"
    )
    console.print("[dim]Saved as 'network_interfaces' in this session's enumeration data.[/dim]")

    return simplified_nics
