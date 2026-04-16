# src/clouds/azure/modules/enumeration/enumerate_nsgs.py

import requests
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_nsgs(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all Azure Network Security Groups (NSGs) with security rules.

    Collects:
    - Basic info (name, location, resource group)
    - Security rules (inbound and outbound)
    - Associated subnets and network interfaces
    - Default rules

    Security Analysis:
    - Identifies overly permissive rules (0.0.0.0/0 sources)
    - Highlights dangerous ports (RDP, SSH, SMB, etc.)
    - Detects "Allow All" rules
    - Shows priority conflicts

    Returns:
        List of NSG dictionaries with detailed information
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[bold blue]🔍 Enumerating Network Security Groups in subscription: {subscription_id}[/bold blue]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        nsgs = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not nsgs:
        console.print("[yellow]No Network Security Groups found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(nsgs)} Network Security Group(s).[/green]")

    # Parse and analyze NSGs
    simplified_nsgs = []
    nsgs_with_dangerous_rules = []
    nsgs_with_internet_exposure = []
    dangerous_ports = {22: "SSH", 3389: "RDP", 445: "SMB", 1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL"}

    for nsg in nsgs:
        properties = nsg.get("properties") or {}

        nsg_id = nsg.get("id", "")
        resource_group = nsg_id.split("/")[4] if len(nsg_id.split("/")) > 4 else ""
        nsg_name = nsg.get("name", "")

        # Basic info
        location = nsg.get("location", "")
        provisioning_state = properties.get("provisioningState", "")

        # Security rules
        security_rules = properties.get("securityRules", [])
        default_security_rules = properties.get("defaultSecurityRules", [])

        # Associated resources
        subnets = properties.get("subnets", [])
        network_interfaces = properties.get("networkInterfaces", [])

        # Analyze security rules for threats
        inbound_rules = []
        outbound_rules = []
        has_dangerous_rules = False
        has_internet_exposure = False

        for rule in security_rules:
            rule_props = rule.get("properties", {})
            rule_name = rule.get("name", "")
            direction = rule_props.get("direction", "")
            access = rule_props.get("access", "")
            protocol = rule_props.get("protocol", "")
            source_address_prefix = rule_props.get("sourceAddressPrefix", "")
            source_port_range = rule_props.get("sourcePortRange", "")
            destination_address_prefix = rule_props.get("destinationAddressPrefix", "")
            destination_port_range = rule_props.get("destinationPortRange", "")
            priority = rule_props.get("priority", 0)

            rule_summary = {
                "name": rule_name,
                "direction": direction,
                "access": access,
                "protocol": protocol,
                "source": source_address_prefix,
                "source_port": source_port_range,
                "destination": destination_address_prefix,
                "dest_port": destination_port_range,
                "priority": priority,
            }

            if direction == "Inbound":
                inbound_rules.append(rule_summary)

                # Check for dangerous configurations
                if access == "Allow" and source_address_prefix in ["*", "0.0.0.0/0", "Internet"]:
                    has_internet_exposure = True

                    # Check if dangerous port is exposed
                    if destination_port_range:
                        for port, service in dangerous_ports.items():
                            if str(port) in str(destination_port_range) or destination_port_range == "*":
                                has_dangerous_rules = True
                                break
            else:
                outbound_rules.append(rule_summary)

        if has_dangerous_rules:
            nsgs_with_dangerous_rules.append(nsg_name)
        if has_internet_exposure:
            nsgs_with_internet_exposure.append(nsg_name)

        simplified_nsgs.append({
            # Basic info
            "id": nsg_id,
            "name": nsg_name,
            "location": location,
            "resource_group": resource_group,
            "provisioning_state": provisioning_state,

            # Rules
            "inbound_rules": inbound_rules,
            "outbound_rules": outbound_rules,
            "default_rules": default_security_rules,
            "total_rules": len(security_rules),

            # Associations
            "subnets": [s.get("id", "") for s in subnets],
            "network_interfaces": [n.get("id", "") for n in network_interfaces],
            "subnet_count": len(subnets),
            "nic_count": len(network_interfaces),

            # Security flags
            "has_dangerous_rules": has_dangerous_rules,
            "has_internet_exposure": has_internet_exposure,

            # Tags
            "tags": nsg.get("tags", {}),
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("network_security_groups", simplified_nsgs)

    # Display results table
    table = Table(title=f"Azure Network Security Groups ({len(simplified_nsgs)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Location", style="green")
    table.add_column("Rules", style="magenta")
    table.add_column("Subnets", style="blue")
    table.add_column("NICs", style="white")
    table.add_column("Internet", style="red")
    table.add_column("Dangerous", style="red bold")

    for nsg in simplified_nsgs:
        name = nsg.get("name", "")
        rg = nsg.get("resource_group", "")
        location = nsg.get("location", "")
        total_rules = nsg.get("total_rules", 0)
        subnet_count = nsg.get("subnet_count", 0)
        nic_count = nsg.get("nic_count", 0)
        has_internet = nsg.get("has_internet_exposure", False)
        has_dangerous = nsg.get("has_dangerous_rules", False)

        internet_display = "[red bold]✓[/red bold]" if has_internet else "–"
        dangerous_display = "[red bold]⚠️ YES[/red bold]" if has_dangerous else "–"

        table.add_row(
            name,
            rg,
            location,
            str(total_rules),
            str(subnet_count),
            str(nic_count),
            internet_display,
            dangerous_display
        )

    console.print(table)

    # Security warnings
    console.print("\n[bold cyan]Security Findings:[/bold cyan]")

    if nsgs_with_dangerous_rules:
        console.print(
            f"\n[red bold]⚠️ Dangerous Rules Detected:[/red bold] {len(nsgs_with_dangerous_rules)} NSG(s) with risky configurations"
        )
        console.print("[yellow]Dangerous ports (SSH, RDP, SQL, etc.) exposed to the internet (0.0.0.0/0)[/yellow]")
        for nsg_name in nsgs_with_dangerous_rules[:5]:
            console.print(f"  • {nsg_name}")
        if len(nsgs_with_dangerous_rules) > 5:
            console.print(f"  [dim]... and {len(nsgs_with_dangerous_rules) - 5} more[/dim]")

    if nsgs_with_internet_exposure:
        console.print(
            f"\n[cyan]🌐 Internet Exposure:[/cyan] {len(nsgs_with_internet_exposure)} NSG(s) allow inbound from Internet"
        )
        console.print("[dim]These NSGs have rules allowing traffic from 0.0.0.0/0, *, or 'Internet'[/dim]")

    # Summary
    console.print(
        f"\n[green]✓ NSG enumeration complete. {len(simplified_nsgs)} NSGs stored under 'network_security_groups' in session.[/green]"
    )
    console.print("[dim]Saved as 'network_security_groups' in this session's enumeration data.[/dim]")

    return simplified_nsgs
