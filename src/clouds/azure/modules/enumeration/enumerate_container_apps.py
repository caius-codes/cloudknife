# src/clouds/azure/modules/enumeration/enumerate_container_apps.py

import requests
from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_container_apps(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all Azure Container Apps in the current subscription.

    Uses Azure Management REST API directly.

    Returns:
        List of container app dictionaries
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[cyan]Enumerating Container Apps in subscription: {subscription_id}[/cyan]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return []

    # Call Azure Management API
    url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.App/containerApps?api-version=2023-05-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling Azure Management API...[/dim]")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        container_apps = data.get("value", [])

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return []

    if not container_apps:
        console.print("[yellow]No Container Apps found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(container_apps)} Container App(s).[/green]")

    # Parse and simplify data
    simplified_apps = []
    for app in container_apps:
        # Use 'or {}' to handle None values
        properties = app.get("properties") or {}
        configuration = properties.get("configuration") or {}
        ingress = configuration.get("ingress") or {}

        simplified_apps.append({
            "id": app.get("id", ""),
            "name": app.get("name", ""),
            "location": app.get("location", ""),
            "resource_group": app.get("id", "").split("/")[4] if len(app.get("id", "").split("/")) > 4 else "",
            "provisioning_state": properties.get("provisioningState", ""),
            "running_status": properties.get("runningStatus", ""),
            "environment_id": properties.get("environmentId", ""),
            "latest_revision": properties.get("latestRevisionName", ""),
            "ingress_fqdn": ingress.get("fqdn", ""),
            "ingress_external": ingress.get("external", False),
        })

    # Save enumeration data
    session_mgr.save_enumeration_data("container_apps", simplified_apps)

    # Display results
    table = Table(title=f"Azure Container Apps ({len(simplified_apps)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Location", style="green")
    table.add_column("Resource Group", style="yellow", overflow="fold")
    table.add_column("Status", style="magenta")
    table.add_column("FQDN", style="blue", overflow="fold")

    for app in simplified_apps:
        name = app.get("name", "")
        location = app.get("location", "")
        rg = app.get("resource_group", "")
        status = app.get("running_status", app.get("provisioning_state", ""))
        fqdn = app.get("ingress_fqdn", "N/A")

        table.add_row(name, location, rg, status, fqdn)

    console.print(table)
    console.print("[dim]Saved as 'container_apps' in this session's enumeration data.[/dim]")

    return simplified_apps
