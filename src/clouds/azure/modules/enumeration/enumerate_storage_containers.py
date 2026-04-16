# src/clouds/azure/modules/enumeration/enumerate_storage_containers.py

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import AzureError

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def enumerate_storage_containers(session_mgr: AzureSessionManager, account_name: str = None, resource_group: str = None) -> list:
    """
    Enumerate all containers in an Azure Storage account using Management API.

    Uses Azure Management API (management.azure.com) instead of Storage Data Plane.
    This only requires management_access_token, not storage_access_token.

    Args:
        session_mgr: Azure session manager
        account_name: Optional storage account name (prompts if not provided)
        resource_group: Optional resource group name (auto-detected if not provided)

    Returns:
        List of container dictionaries
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    # Get storage account name
    if not account_name:
        account_name = Prompt.ask("[cyan]Storage account name[/cyan]").strip()

    if not account_name:
        console.print("[red]Storage account name is required.[/red]")
        return []

    console.print(f"[cyan]Enumerating containers in storage account: {account_name}[/cyan]")

    try:
        # Get management credential
        credential = session_mgr.get_credential(scope="management")
        if not credential:
            console.print("[red]Management authentication required. Use a login command first.[/red]")
            return []

        # Create Storage Management client
        storage_client = StorageManagementClient(credential, subscription_id)

        # If resource group not provided, find it by listing all storage accounts
        if not resource_group:
            console.print("[dim]Finding resource group for storage account...[/dim]")
            for account in storage_client.storage_accounts.list():
                if account.name == account_name:
                    resource_group = account.id.split("/")[4]
                    console.print(f"[dim]Found in resource group: {resource_group}[/dim]")
                    break

            if not resource_group:
                console.print(f"[red]Storage account '{account_name}' not found in subscription.[/red]")
                return []

        # List all containers using Management API
        console.print("[dim]Listing containers via Management API...[/dim]")
        containers_iter = storage_client.blob_containers.list(resource_group, account_name)

        containers = []
        for container in containers_iter:
            containers.append({
                "name": container.name,
                "last_modified": container.last_modified.isoformat() if container.last_modified else None,
                "metadata": container.metadata or {},
                "public_access": container.public_access,
                "has_immutability_policy": container.has_immutability_policy,
                "has_legal_hold": container.has_legal_hold,
                "deleted": container.deleted if hasattr(container, 'deleted') else False,
            })

    except AzureError as e:
        handle_azure_error(e, "enumerating storage containers", account_name)
        return []
    except Exception as e:
        console.print(f"[red]Error listing containers: {e}[/red]")
        return []

    if not containers:
        console.print(f"[yellow]No containers found in storage account '{account_name}'.[/yellow]")
        return []

    console.print(f"[green]Found {len(containers)} container(s).[/green]")

    # Save enumeration data
    session_mgr.save_enumeration_data(f"storage_containers_{account_name}", containers)

    # Display results
    table = Table(title=f"Storage Containers in {account_name} ({len(containers)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Last Modified", style="green")
    table.add_column("Public Access", style="yellow")
    table.add_column("Immutability Policy", style="magenta")
    table.add_column("Legal Hold", style="red")

    for container in containers:
        name = container.get("name", "")
        last_modified = container.get("last_modified", "")[:19] if container.get("last_modified") else ""
        public_access = container.get("public_access") or "None"
        has_policy = "Yes" if container.get("has_immutability_policy") else "No"
        has_hold = "Yes" if container.get("has_legal_hold") else "No"

        table.add_row(name, last_modified, public_access, has_policy, has_hold)

    console.print(table)
    console.print(f"[dim]Saved as 'storage_containers_{account_name}' in this session's enumeration data.[/dim]")

    return containers
