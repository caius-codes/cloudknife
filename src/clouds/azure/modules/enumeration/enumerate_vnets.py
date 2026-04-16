# src/clouds/azure/modules/enumeration/enumerate_vnets.py

import requests
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_vnets(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all Azure Virtual Networks (VNets) in the current subscription.

    Collects:
    - Basic info (name, location, resource group, address space)
    - Subnets with address prefixes and NSGs
    - VNet peerings (connections to other VNets)
    - DNS servers configuration
    - DDOS protection status
    - Service endpoints

    Security Analysis:
    - Identifies VNets without DDoS protection
    - Detects overlapping address spaces in peerings
    - Shows subnets without NSGs
    - Highlights public DNS usage

    Returns:
        List of VNet dictionaries with detailed information
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating Virtual Networks in subscription: {subscription_id}[/bold blue]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/virtualNetworks?api-version=2023-05-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        vnets = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not vnets:
        console.print("[yellow]No Virtual Networks found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(vnets)} Virtual Network(s).[/green]")

    # Parse and analyze VNets
    simplified_vnets = []
    vnets_without_ddos = []
    vnets_with_peerings = []
    subnets_without_nsgs = []

    for vnet in vnets:
        properties = vnet.get("properties") or {}

        vnet_id = vnet.get("id", "")
        resource_group = vnet_id.split("/")[4] if len(vnet_id.split("/")) > 4 else ""
        vnet_name = vnet.get("name", "")

        # Basic info
        location = vnet.get("location", "")
        provisioning_state = properties.get("provisioningState", "")

        # Address space
        address_space = properties.get("addressSpace", {})
        address_prefixes = address_space.get("addressPrefixes", [])

        # DNS servers
        dhcp_options = properties.get("dhcpOptions", {})
        dns_servers = dhcp_options.get("dnsServers", [])

        # DDoS protection
        ddos_protection_plan = properties.get("ddosProtectionPlan", {})
        enable_ddos_protection = properties.get("enableDdosProtection", False)

        if not enable_ddos_protection:
            vnets_without_ddos.append(vnet_name)

        # Subnets
        subnets = properties.get("subnets", [])
        subnet_details = []

        for subnet in subnets:
            subnet_props = subnet.get("properties", {})
            subnet_name = subnet.get("name", "")
            subnet_prefix = subnet_props.get("addressPrefix", "")
            subnet_nsg = subnet_props.get("networkSecurityGroup", {})
            subnet_nsg_id = subnet_nsg.get("id", "") if subnet_nsg else ""

            # Service endpoints
            service_endpoints = subnet_props.get("serviceEndpoints", [])
            endpoint_services = [ep.get("service", "") for ep in service_endpoints]

            # Delegations
            delegations = subnet_props.get("delegations", [])
            delegation_services = [d.get("properties", {}).get("serviceName", "") for d in delegations]

            subnet_info = {
                "name": subnet_name,
                "address_prefix": subnet_prefix,
                "nsg_id": subnet_nsg_id,
                "has_nsg": bool(subnet_nsg_id),
                "service_endpoints": endpoint_services,
                "delegations": delegation_services,
            }

            subnet_details.append(subnet_info)

            if not subnet_nsg_id:
                subnets_without_nsgs.append(f"{vnet_name}/{subnet_name}")

        # VNet peerings
        peerings = properties.get("virtualNetworkPeerings", [])
        peering_details = []

        for peering in peerings:
            peering_props = peering.get("properties", {})
            peering_name = peering.get("name", "")
            remote_vnet = peering_props.get("remoteVirtualNetwork", {})
            remote_vnet_id = remote_vnet.get("id", "")
            peering_state = peering_props.get("peeringState", "")
            allow_forwarded_traffic = peering_props.get("allowForwardedTraffic", False)
            allow_gateway_transit = peering_props.get("allowGatewayTransit", False)
            use_remote_gateways = peering_props.get("useRemoteGateways", False)

            peering_info = {
                "name": peering_name,
                "remote_vnet_id": remote_vnet_id,
                "state": peering_state,
                "allow_forwarded_traffic": allow_forwarded_traffic,
                "allow_gateway_transit": allow_gateway_transit,
                "use_remote_gateways": use_remote_gateways,
            }

            peering_details.append(peering_info)

        if peerings:
            vnets_with_peerings.append(vnet_name)

        # VM protection
        enable_vm_protection = properties.get("enableVmProtection", False)

        # Tags
        tags = vnet.get("tags", {})

        simplified_vnets.append({
            # Basic info
            "id": vnet_id,
            "name": vnet_name,
            "location": location,
            "resource_group": resource_group,
            "provisioning_state": provisioning_state,

            # Address space
            "address_prefixes": address_prefixes,

            # DNS
            "dns_servers": dns_servers,
            "uses_custom_dns": bool(dns_servers),

            # DDoS protection
            "enable_ddos_protection": enable_ddos_protection,
            "ddos_protection_plan_id": ddos_protection_plan.get("id", ""),

            # Subnets
            "subnets": subnet_details,
            "subnet_count": len(subnets),

            # Peerings
            "peerings": peering_details,
            "peering_count": len(peerings),

            # VM protection
            "enable_vm_protection": enable_vm_protection,

            # Tags
            "tags": tags,
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("virtual_networks", simplified_vnets)

    # Display results table
    table = Table(title=f"Azure Virtual Networks ({len(simplified_vnets)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Location", style="green")
    table.add_column("Address Space", overflow="fold")
    table.add_column("Subnets", style="magenta")
    table.add_column("Peerings", style="blue")
    table.add_column("DDoS", style="white")

    for vnet in simplified_vnets:
        name = vnet.get("name", "")
        rg = vnet.get("resource_group", "")
        location = vnet.get("location", "")
        address_prefixes = ", ".join(vnet.get("address_prefixes", [])) or "–"
        subnet_count = vnet.get("subnet_count", 0)
        peering_count = vnet.get("peering_count", 0)
        has_ddos = vnet.get("enable_ddos_protection", False)

        ddos_display = "[green]✓[/green]" if has_ddos else "[red]✗[/red]"

        table.add_row(
            name,
            rg,
            location,
            address_prefixes,
            str(subnet_count),
            str(peering_count),
            ddos_display
        )

    console.print(table)

    # Security warnings
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if vnets_without_ddos:
        console.print(
            f"\n[yellow]⚠️ No DDoS Protection:[/yellow] {len(vnets_without_ddos)} VNet(s) without DDoS protection enabled"
        )
        console.print("[dim]Consider enabling Azure DDoS Protection Standard for production VNets[/dim]")
        for vnet_name in vnets_without_ddos[:5]:
            console.print(f"  • {vnet_name}")
        if len(vnets_without_ddos) > 5:
            console.print(f"  [dim]... and {len(vnets_without_ddos) - 5} more[/dim]")

    if subnets_without_nsgs:
        console.print(
            f"\n[yellow]🔓 Subnets Without NSGs:[/yellow] {len(subnets_without_nsgs)} subnet(s) without Network Security Groups"
        )
        console.print("[dim]Subnets without NSGs have no firewall protection[/dim]")
        for subnet_name in subnets_without_nsgs[:5]:
            console.print(f"  • {subnet_name}")
        if len(subnets_without_nsgs) > 5:
            console.print(f"  [dim]... and {len(subnets_without_nsgs) - 5} more[/dim]")

    if vnets_with_peerings:
        console.print(
            f"\n[cyan]🔗 VNet Peerings:[/cyan] {len(vnets_with_peerings)} VNet(s) with peering connections"
        )
        console.print("[dim]Review peering configurations for potential lateral movement paths[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ VNet enumeration complete. {len(simplified_vnets)} VNets stored under 'virtual_networks' in session.[/green]"
    )
    console.print("[dim]Saved as 'virtual_networks' in this session's enumeration data.[/dim]")

    return simplified_vnets
