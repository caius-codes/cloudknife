# src/clouds/azure/modules/enumeration/enumerate_container_apps_full.py

import requests
from rich.console import Console
from rich.tree import Tree
from rich.prompt import Confirm

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_container_apps_full(session_mgr: AzureSessionManager) -> dict:
    """
    Complete Container Apps enumeration: apps → secrets.

    Enumerates all Container Apps in the subscription, then optionally
    extracts secrets from each one using the /listSecrets endpoint.

    Returns:
        Dictionary with full Container Apps hierarchy including secrets
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return {}

    console.print("[bold cyan]🐳 Full Container Apps Enumeration[/bold cyan]")
    console.print(f"[dim]Subscription: {subscription_id}[/dim]\n")

    # Step 1: Enumerate Container Apps
    console.print("[cyan]Step 1: Enumerating Container Apps...[/cyan]")

    token = session_mgr.get_access_token(scope="management")
    if not token:
        console.print("[red]Management authentication required.[/red]")
        return {}

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
        return {}
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return {}

    if not container_apps:
        console.print("[yellow]No Container Apps found in this subscription.[/yellow]")
        return {}

    console.print(f"[green]Found {len(container_apps)} Container App(s).[/green]\n")

    # Step 2: Ask if user wants to extract secrets
    extract_secrets = Confirm.ask(
        f"[cyan]Extract secrets from all {len(container_apps)} Container App(s)?[/cyan]",
        default=True
    )

    full_hierarchy = {
        "subscription_id": subscription_id,
        "container_apps": []
    }

    # Create tree for visualization
    tree = Tree(f"[bold cyan]Subscription: {subscription_id}[/bold cyan]")

    total_secrets = 0

    for app in container_apps:
        app_name = app.get("name", "")
        app_id = app.get("id", "")

        # Use 'or {}' to handle None values
        properties = app.get("properties") or {}
        configuration = properties.get("configuration") or {}
        ingress = configuration.get("ingress") or {}

        app_data = {
            "id": app_id,
            "name": app_name,
            "location": app.get("location", ""),
            "resource_group": app_id.split("/")[4] if len(app_id.split("/")) > 4 else "",
            "provisioning_state": properties.get("provisioningState", ""),
            "running_status": properties.get("runningStatus", ""),
            "environment_id": properties.get("environmentId", ""),
            "latest_revision": properties.get("latestRevisionName", ""),
            "ingress_fqdn": ingress.get("fqdn", ""),
            "ingress_external": ingress.get("external", False),
            "secrets": None
        }

        app_node = tree.add(f"[cyan]Container App: {app_name}[/cyan] [dim]({app_data['location']})[/dim]")

        # Extract secrets if requested
        if extract_secrets:
            console.print(f"[dim]Extracting secrets from {app_name}...[/dim]")

            try:
                # Call listSecrets endpoint
                secrets_url = f"https://management.azure.com{app_id}/listSecrets?api-version=2023-05-01"
                secrets_response = requests.post(secrets_url, headers=headers, json={}, timeout=30)
                secrets_response.raise_for_status()

                secrets_data = secrets_response.json()
                app_data["secrets"] = secrets_data

                # Display secrets in tree
                if "value" in secrets_data and secrets_data["value"]:
                    secrets_count = len(secrets_data["value"])
                    total_secrets += secrets_count
                    secrets_node = app_node.add(f"[yellow]Secrets ({secrets_count})[/yellow]")

                    for secret in secrets_data["value"]:
                        secret_name = secret.get("name", "N/A")
                        secret_value = secret.get("value", "N/A")
                        # Truncate long values for display
                        display_value = secret_value[:30] + "..." if len(secret_value) > 30 else secret_value
                        secrets_node.add(f"[dim]{secret_name}:[/dim] {display_value}")
                else:
                    app_node.add("[dim]No secrets found[/dim]")

            except requests.exceptions.RequestException as e:
                app_node.add(f"[red]Error extracting secrets: {str(e)[:50]}...[/red]")
            except Exception as e:
                app_node.add(f"[red]Error: {str(e)[:50]}...[/red]")
        else:
            app_node.add("[dim]Secrets not extracted[/dim]")

        full_hierarchy["container_apps"].append(app_data)

    # Display tree
    console.print()
    console.print(tree)
    console.print()

    # Summary
    console.print("[bold green]Summary:[/bold green]")
    console.print(f"  Container Apps: {len(container_apps)}")
    if extract_secrets:
        console.print(f"  Total Secrets Extracted: {total_secrets}")
    console.print()

    # Save enumeration data
    session_mgr.save_enumeration_data("container_apps_full_hierarchy", full_hierarchy)
    console.print("[dim]Saved as 'container_apps_full_hierarchy' in this session's enumeration data.[/dim]")

    return full_hierarchy
