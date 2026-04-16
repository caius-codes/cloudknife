# src/clouds/azure/modules/enumeration/enumerate_storage_accounts.py

from rich.console import Console
from rich.table import Table

from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import AzureError

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def enumerate_storage_accounts(session_mgr: AzureSessionManager) -> list:
    """
    Enumerate all storage accounts in the current subscription.

    Returns:
        List of storage account dictionaries
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return []

    console.print(f"[cyan]Enumerating storage accounts in subscription: {subscription_id}[/cyan]")

    try:
        credential = session_mgr.get_credential(scope="management")
        if not credential:
            console.print("[red]Authentication required. Use one of the login commands first.[/red]")
            return []

        # Create Storage Management client
        storage_client = StorageManagementClient(credential, subscription_id)

        # List all storage accounts
        console.print("[dim]Listing storage accounts...[/dim]")
        storage_accounts_iter = storage_client.storage_accounts.list()

        storage_accounts = []
        for account in storage_accounts_iter:
            storage_accounts.append({
                "name": account.name,
                "id": account.id,
                "location": account.location,
                "kind": account.kind,
                "sku_name": account.sku.name if account.sku else None,
                "resource_group": account.id.split("/")[4] if len(account.id.split("/")) > 4 else "",
                "primary_endpoints": {
                    "blob": account.primary_endpoints.blob if account.primary_endpoints else None,
                    "file": account.primary_endpoints.file if account.primary_endpoints else None,
                    "queue": account.primary_endpoints.queue if account.primary_endpoints else None,
                    "table": account.primary_endpoints.table if account.primary_endpoints else None,
                },
                "provisioning_state": account.provisioning_state,
                "creation_time": account.creation_time.isoformat() if account.creation_time else None,
            })

    except AzureError as e:
        handle_azure_error(e, "enumerating storage accounts", subscription_id)
        return []
    except Exception as e:
        console.print(f"[red]Error listing storage accounts: {e}[/red]")
        return []

    if not storage_accounts:
        console.print("[yellow]No storage accounts found in this subscription.[/yellow]")
        return []

    console.print(f"[green]Found {len(storage_accounts)} storage account(s).[/green]")

    # Save enumeration data
    session_mgr.save_enumeration_data("storage_accounts", storage_accounts)

    # Display results
    table = Table(title=f"Azure Storage Accounts ({len(storage_accounts)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Location", style="green")
    table.add_column("Kind", style="magenta")
    table.add_column("SKU", style="yellow")
    table.add_column("Resource Group", style="dim", overflow="fold")
    table.add_column("Blob Endpoint", style="blue", overflow="fold")

    for account in storage_accounts:
        name = account.get("name", "")
        location = account.get("location", "")
        kind = account.get("kind", "")
        sku = account.get("sku_name", "")
        rg = account.get("resource_group", "")
        blob_endpoint = account.get("primary_endpoints", {}).get("blob", "")

        table.add_row(name, location, kind, sku, rg, blob_endpoint)

    console.print(table)
    console.print("[dim]Saved as 'storage_accounts' in this session's enumeration data.[/dim]")

    return storage_accounts
