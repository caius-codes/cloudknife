# src/clouds/azure/modules/enumeration/enumerate_webapps.py

import subprocess
import json
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from azure.mgmt.web import WebSiteManagementClient
from azure.core.exceptions import AzureError

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def enumerate_webapps(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate Azure Web Apps in the subscription.

    Uses Azure SDK (azure-mgmt-web) with fallback to Azure CLI
    if SDK authentication fails.
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return

    # Optional: filter by resource group
    filter_rg = Confirm.ask(
        "[cyan]Filter by resource group?[/cyan]",
        default=False
    )

    resource_group = None
    if filter_rg:
        resource_group = Prompt.ask("[cyan]Resource Group[/cyan]").strip()
        if not resource_group:
            console.print("[red]Resource Group is required when filtering.[/red]")
            return

    if resource_group:
        console.print(f"[cyan]Enumerating Web Apps in Resource Group:[/cyan] {resource_group}")
    else:
        console.print(f"[cyan]Enumerating all Web Apps in subscription:[/cyan] {subscription_id}")

    webapps = []
    used_fallback = False

    # Try Azure SDK first
    try:
        credential = session_mgr.get_credential(scope="management")
        if not credential:
            console.print("[yellow]No credentials available. Trying Azure CLI fallback...[/yellow]")
            raise Exception("No credentials")

        # Create Web Management client
        web_client = WebSiteManagementClient(credential, subscription_id)

        # List web apps
        console.print("[dim]Using Azure SDK to enumerate Web Apps...[/dim]")

        if resource_group:
            webapp_list = web_client.web_apps.list_by_resource_group(resource_group)
        else:
            webapp_list = web_client.web_apps.list()

        for webapp in webapp_list:
            webapps.append({
                "name": webapp.name,
                "id": webapp.id,
                "type": webapp.type,
                "kind": webapp.kind,
                "location": webapp.location,
                "resource_group": webapp.id.split("/")[4] if len(webapp.id.split("/")) > 4 else "",
                "state": webapp.state,
                "default_host_name": webapp.default_host_name,
                "enabled_host_names": getattr(webapp, 'enabled_host_names', []) or [],
                "enabled": webapp.enabled,
                "https_only": getattr(webapp, 'https_only', False),
                "repository_site_name": getattr(webapp, 'repository_site_name', ''),
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
            console.print("[dim]Using Azure CLI to enumerate Web Apps...[/dim]")

            cmd = [
                "az", "webapp", "list",
                "--subscription", subscription_id,
                "--output", "json"
            ]

            if resource_group:
                cmd.extend(["--resource-group", resource_group])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            result.check_returncode()

            cli_webapps = json.loads(result.stdout)

            for webapp in cli_webapps:
                webapps.append({
                    "name": webapp.get("name", ""),
                    "id": webapp.get("id", ""),
                    "type": webapp.get("type", ""),
                    "kind": webapp.get("kind", ""),
                    "location": webapp.get("location", ""),
                    "resource_group": webapp.get("resourceGroup", ""),
                    "state": webapp.get("state", ""),
                    "default_host_name": webapp.get("defaultHostName", ""),
                    "enabled_host_names": webapp.get("enabledHostNames", []) or [],
                    "enabled": webapp.get("enabled", True),
                    "https_only": webapp.get("httpsOnly", False),
                    "repository_site_name": webapp.get("repositorySiteName", ""),
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

    if not webapps:
        console.print("[yellow]No Web Apps found.[/yellow]")
        return

    console.print(f"[green]Found {len(webapps)} Web App(s).[/green]")

    # Save enumeration data
    session_mgr.save_enumeration_data("webapps", webapps)

    # Display results
    if resource_group:
        title = f"Azure Web Apps in Resource Group: {resource_group} ({len(webapps)} found)"
    else:
        title = f"Azure Web Apps in Subscription ({len(webapps)} found)"

    table = Table(title=title)
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Resource Group", style="green")
    table.add_column("Location", style="yellow")
    table.add_column("State", style="magenta")
    table.add_column("Hostnames", style="blue", overflow="fold")

    for w in webapps:
        name = w.get("name", "")
        rg = w.get("resource_group", "")
        location = w.get("location", "")
        state = w.get("state", "")

        # Get all enabled hostnames or fallback to default hostname
        enabled_hostnames = w.get("enabled_host_names", [])
        if enabled_hostnames:
            host = ", ".join(enabled_hostnames)
        else:
            host = w.get("default_host_name", "")

        table.add_row(name, rg, location, state, host)

    console.print(table)
    console.print("[dim]Saved as 'webapps' in this session's enumeration data.[/dim]")

    if used_fallback:
        console.print("[yellow]Note: Used Azure CLI fallback. Some features may be limited.[/yellow]")
