# src/clouds/azure/modules/enumeration/enumerate_public_ips.py

import requests
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_public_ips(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all Azure Public IP Addresses in the current subscription.

    Collects:
    - IP address (if allocated)
    - Allocation method (Static/Dynamic)
    - SKU (Basic/Standard)
    - Associated resource (VM, Load Balancer, NAT Gateway, etc.)
    - DNS settings
    - Location and zones
    - Tags

    Security insights:
    - Identifies all internet-exposed resources
    - Detects orphaned public IPs (allocated but not associated)
    - Maps public IPs to backend resources for attack surface analysis

    Returns:
        List of public IP dictionaries with detailed information
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating Public IP Addresses in subscription: {subscription_id}[/bold blue]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-05-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        public_ips = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not public_ips:
        console.print("[yellow]No Public IP Addresses found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(public_ips)} Public IP Address(es).[/green]")

    # Parse and simplify data
    simplified_ips = []
    orphaned_ips = []
    static_ips = []

    for pip in public_ips:
        properties = pip.get("properties") or {}
        sku = pip.get("sku") or {}
        dns_settings = properties.get("dnsSettings") or {}

        pip_id = pip.get("id", "")
        resource_group = pip_id.split("/")[4] if len(pip_id.split("/")) > 4 else ""
        pip_name = pip.get("name", "")

        # Basic info
        location = pip.get("location", "")
        ip_address = properties.get("ipAddress", "")
        allocation_method = properties.get("publicIPAllocationMethod", "")
        sku_name = sku.get("name", "")
        sku_tier = sku.get("tier", "")
        ip_version = properties.get("publicIPAddressVersion", "IPv4")
        provisioning_state = properties.get("provisioningState", "")

        # DNS settings
        fqdn = dns_settings.get("fqdn", "")
        domain_name_label = dns_settings.get("domainNameLabel", "")

        # Associated resource (NIC, Load Balancer, NAT Gateway, etc.)
        ip_configuration = properties.get("ipConfiguration")
        nat_gateway = properties.get("natGateway")

        associated_resource_id = ""
        associated_resource_type = ""
        is_orphaned = False

        if ip_configuration:
            associated_resource_id = ip_configuration.get("id", "")
            # Extract resource type from ID (e.g., networkInterfaces, loadBalancers)
            if "/networkInterfaces/" in associated_resource_id:
                associated_resource_type = "Network Interface"
            elif "/loadBalancers/" in associated_resource_id:
                associated_resource_type = "Load Balancer"
            else:
                associated_resource_type = "Unknown"
        elif nat_gateway:
            associated_resource_id = nat_gateway.get("id", "")
            associated_resource_type = "NAT Gateway"
        else:
            # Orphaned public IP (allocated but not attached to anything)
            is_orphaned = True
            associated_resource_type = "Orphaned"
            orphaned_ips.append(pip_name)

        # Track static IPs
        if allocation_method.lower() == "static":
            static_ips.append(pip_name)

        # Idle timeout
        idle_timeout_minutes = properties.get("idleTimeoutInMinutes", 4)

        # Zones
        zones = pip.get("zones", [])

        # Tags
        tags = pip.get("tags", {})

        simplified_ips.append({
            # Basic info
            "id": pip_id,
            "name": pip_name,
            "location": location,
            "resource_group": resource_group,
            "ip_address": ip_address,
            "allocation_method": allocation_method,
            "sku_name": sku_name,
            "sku_tier": sku_tier,
            "ip_version": ip_version,
            "provisioning_state": provisioning_state,

            # DNS
            "fqdn": fqdn,
            "domain_name_label": domain_name_label,

            # Association
            "associated_resource_id": associated_resource_id,
            "associated_resource_type": associated_resource_type,
            "is_orphaned": is_orphaned,

            # Configuration
            "idle_timeout_minutes": idle_timeout_minutes,
            "zones": zones,

            # Tags
            "tags": tags,
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("public_ip_addresses", simplified_ips)

    # Display results table
    table = Table(title=f"Azure Public IP Addresses ({len(simplified_ips)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Location", style="green")
    table.add_column("IP Address", style="magenta", overflow="fold")
    table.add_column("Allocation", style="blue")
    table.add_column("SKU", style="white")
    table.add_column("Associated To", overflow="fold")
    table.add_column("FQDN", overflow="fold")

    for pip in simplified_ips:
        name = pip.get("name", "")
        rg = pip.get("resource_group", "")
        location = pip.get("location", "")
        ip_address = pip.get("ip_address", "")
        allocation = pip.get("allocation_method", "")
        sku = pip.get("sku_name", "")
        associated = pip.get("associated_resource_type", "")
        fqdn = pip.get("fqdn", "")

        # Color orphaned IPs
        if pip.get("is_orphaned"):
            associated = "[red]Orphaned[/red]"

        # Color static IPs
        if allocation.lower() == "static":
            allocation = f"[green]{allocation}[/green]"

        # IP address display
        ip_display = ip_address if ip_address else "[dim]Not allocated[/dim]"

        table.add_row(
            name,
            rg,
            location,
            ip_display,
            allocation,
            sku,
            associated,
            fqdn if fqdn else "–"
        )

    console.print(table)

    # Security insights
    console.print("\n[bold cyan]Security Insights:[/bold cyan]")

    if orphaned_ips:
        console.print(
            f"\n[yellow]💸 Orphaned Public IPs:[/yellow] {len(orphaned_ips)} IP(s) allocated but not associated"
        )
        console.print("[dim]These IPs are being billed but not used. Consider releasing them.[/dim]")
        for ip_name in orphaned_ips[:5]:
            console.print(f"  • {ip_name}")
        if len(orphaned_ips) > 5:
            console.print(f"  [dim]... and {len(orphaned_ips) - 5} more[/dim]")

    if static_ips:
        console.print(
            f"\n[green]📌 Static IPs:[/green] {len(static_ips)} IP(s) with static allocation"
        )
        console.print("[dim]Static IPs persist even when resources are stopped/deallocated.[/dim]")

    # Total exposure
    allocated_ips = [pip for pip in simplified_ips if pip.get("ip_address")]
    console.print(
        f"\n[cyan]🌐 Internet Exposure:[/cyan] {len(allocated_ips)} IP(s) currently allocated"
    )
    console.print("[dim]These represent your external attack surface.[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ Public IP enumeration complete. {len(simplified_ips)} IPs stored under 'public_ip_addresses' in session.[/green]"
    )
    console.print("[dim]Saved as 'public_ip_addresses' in this session's enumeration data.[/dim]")

    return simplified_ips
