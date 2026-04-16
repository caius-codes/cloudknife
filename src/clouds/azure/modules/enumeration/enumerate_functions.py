# src/clouds/azure/modules/enumeration/enumerate_functions.py

import subprocess
import json
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from azure.mgmt.web import WebSiteManagementClient
from azure.core.exceptions import AzureError

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def enumerate_functions(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate functions in an Azure Function App.

    Uses Azure SDK (azure-mgmt-web) with fallback to Azure CLI
    if SDK authentication fails.
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return

    # Prompt for function app details
    function_app_name = Prompt.ask("[cyan]Function App name[/cyan]").strip()
    if not function_app_name:
        console.print("[red]Function App name is required.[/red]")
        return

    resource_group = Prompt.ask("[cyan]Resource Group[/cyan]").strip()
    if not resource_group:
        console.print("[red]Resource Group is required.[/red]")
        return

    console.print(
        f"[cyan]Enumerating functions in[/cyan] {function_app_name} "
        f"[cyan](Resource Group:[/cyan] {resource_group}[cyan])[/cyan]"
    )

    functions = []
    used_fallback = False

    # Try Azure SDK first
    try:
        credential = session_mgr.get_credential(scope="management")
        if not credential:
            console.print("[yellow]No credentials available. Trying Azure CLI fallback...[/yellow]")
            raise Exception("No credentials")

        # Create Web Management client
        web_client = WebSiteManagementClient(credential, subscription_id)

        # List functions in the function app
        console.print("[dim]Using Azure SDK to enumerate functions...[/dim]")
        function_list = web_client.web_apps.list_functions(resource_group, function_app_name)

        for function in function_list:
            # Get function details
            func_name = function.name.split('/')[-1] if function.name else ""

            functions.append({
                "name": func_name,
                "id": function.id,
                "type": function.type,
                "config": function.config if hasattr(function, 'config') else None,
                "script_root_path_href": getattr(function, 'script_root_path_href', ''),
                "script_href": getattr(function, 'script_href', ''),
                "config_href": getattr(function, 'config_href', ''),
                "test_data_href": getattr(function, 'test_data_href', ''),
                "invoke_url_template": getattr(function, 'invoke_url_template', ''),
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
            console.print("[dim]Using Azure CLI to enumerate functions...[/dim]")
            result = subprocess.run(
                [
                    "az", "functionapp", "function", "list",
                    "-n", function_app_name,
                    "--resource-group", resource_group,
                    "--subscription", subscription_id,
                    "--output", "json"
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            result.check_returncode()

            cli_functions = json.loads(result.stdout)

            for function in cli_functions:
                functions.append({
                    "name": function.get("name", ""),
                    "id": function.get("id", ""),
                    "type": function.get("type", ""),
                    "config": function.get("config"),
                    "script_root_path_href": function.get("scriptRootPathHref", ""),
                    "script_href": function.get("scriptHref", ""),
                    "config_href": function.get("configHref", ""),
                    "test_data_href": function.get("testDataHref", ""),
                    "invoke_url_template": function.get("invokeUrlTemplate", ""),
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

    if not functions:
        console.print("[yellow]No functions found in this Function App.[/yellow]")
        return

    console.print(f"[green]Found {len(functions)} function(s).[/green]")

    # Save enumeration data
    session_mgr.save_enumeration_data("functions", functions)

    # Display results
    table = Table(
        title=f"Azure Functions in {function_app_name} (Resource Group: {resource_group}) - {len(functions)} found"
    )
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Type", style="magenta")
    table.add_column("Invoke URL Template", style="green", overflow="fold")

    for f in functions:
        name = f.get("name", "")
        ftype = f.get("type", "")
        invoke_url = f.get("invoke_url_template", "")

        table.add_row(name, ftype, invoke_url)

    console.print(table)
    console.print("[dim]Saved as 'functions' in this session's enumeration data.[/dim]")

    if used_fallback:
        console.print("[yellow]Note: Used Azure CLI fallback. Some features may be limited.[/yellow]")
