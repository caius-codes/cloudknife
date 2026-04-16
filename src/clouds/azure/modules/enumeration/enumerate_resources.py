# src/clouds/azure/modules/enumeration/enumerate_resources.py

import subprocess
import json
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table

from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import AzureError

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def enumerate_resources(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate all resources in the current subscription.

    Uses Azure SDK (azure-mgmt-resource) with fallback to Azure CLI
    if SDK authentication fails.
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return

    console.print(f"[cyan]Enumerating resources in subscription: {subscription_id}[/cyan]")

    resources = []
    used_fallback = False

    # Try Azure SDK first
    try:
        credential = session_mgr.get_credential(scope="management")
        if not credential:
            console.print("[yellow]No credentials available. Trying Azure CLI fallback...[/yellow]")
            raise Exception("No credentials")

        # Create Resource Management client
        resource_client = ResourceManagementClient(credential, subscription_id)

        # List all resources
        console.print("[dim]Using Azure SDK to enumerate resources...[/dim]")
        resource_list = resource_client.resources.list()

        for resource in resource_list:
            resources.append({
                "id": resource.id,
                "name": resource.name,
                "type": resource.type,
                "kind": resource.kind if hasattr(resource, 'kind') else "",
                "location": resource.location,
                "resource_group": resource.id.split("/")[4] if len(resource.id.split("/")) > 4 else "",
                "tags": resource.tags or {},
            })

    except AzureError as e:
        console.print(f"[yellow]Azure SDK failed: {e}[/yellow]")
        console.print("[cyan]Attempting fallback to Azure CLI...[/cyan]")
        used_fallback = True

    except Exception as e:
        console.print(f"[yellow]SDK error: {e}[/yellow]")
        console.print("[cyan]Attempting fallback to Azure CLI...[/cyan]")
        used_fallback = True

    # Fallback to Azure CLI
    if used_fallback:
        try:
            console.print("[dim]Using Azure CLI to enumerate resources...[/dim]")
            result = subprocess.run(
                ["az", "resource", "list", "--subscription", subscription_id, "--output", "json"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            result.check_returncode()

            cli_resources = json.loads(result.stdout)

            for resource in cli_resources:
                resources.append({
                    "id": resource.get("id", ""),
                    "name": resource.get("name", ""),
                    "type": resource.get("type", ""),
                    "kind": resource.get("kind", ""),
                    "location": resource.get("location", ""),
                    "resource_group": resource.get("resourceGroup", ""),
                    "tags": resource.get("tags", {}),
                })

            console.print("[green]Azure CLI fallback successful![/green]")

        except FileNotFoundError:
            console.print("[red]Azure CLI (az) not found. Please install it.[/red]")
            console.print("[yellow]https://docs.microsoft.com/en-us/cli/azure/install-azure-cli[/yellow]")
            return
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Azure CLI command failed: {e.stderr}[/red]")
            return
        except subprocess.TimeoutExpired:
            console.print("[red]Azure CLI command timed out.[/red]")
            return
        except json.JSONDecodeError as e:
            console.print(f"[red]Failed to parse Azure CLI output: {e}[/red]")
            return
        except Exception as e:
            console.print(f"[red]Fallback failed: {e}[/red]")
            return

    if not resources:
        console.print("[yellow]No resources found in this subscription.[/yellow]")
        return

    console.print(f"[green]Found {len(resources)} resource(s).[/green]")

    # Save enumeration data
    session_mgr.save_enumeration_data("resources", resources)

    # Display results
    table = Table(title=f"Azure Resources in Subscription {subscription_id} ({len(resources)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Type", style="magenta", overflow="fold")
    table.add_column("Kind", style="blue")
    table.add_column("Resource Group", style="green")
    table.add_column("Location", style="yellow")

    for r in resources:
        name = r.get("name", "")
        rtype = r.get("type", "")
        kind = r.get("kind", "")
        rg = r.get("resource_group", "")
        location = r.get("location", "")

        table.add_row(name, rtype, kind, rg, location)

    console.print(table)
    console.print("[dim]Saved as 'resources' in this session's enumeration data.[/dim]")

    if used_fallback:
        console.print("[yellow]Note: Used Azure CLI fallback. Some features may be limited.[/yellow]")
