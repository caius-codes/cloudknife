from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def enumerate_storage_blobs(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate blobs in an Azure Storage container.

    Uses Azure SDK (azure-storage-blob) with support for both
    AAD authentication and SAS token authentication.
    """

    # Prompt for authentication method
    use_sas = Confirm.ask(
        "[cyan]Use SAS token for authentication?[/cyan] (otherwise uses AAD)",
        default=False
    )

    sas_token = None
    if use_sas:
        sas_token = Prompt.ask("[cyan]SAS token[/cyan]", password=True).strip()
        if not sas_token:
            console.print("[red]SAS token is required.[/red]")
            return

    # Prompt for storage account and container
    account = Prompt.ask("[cyan]Storage account name[/cyan]").strip()
    if not account:
        console.print("[red]Storage account name is required.[/red]")
        return

    container = Prompt.ask("[cyan]Container name[/cyan]").strip()
    if not container:
        console.print("[red]Container name is required.[/red]")
        return

    console.print(
        f"[cyan]Listing blobs for[/cyan] account=[green]{account}[/green], "
        f"container=[green]{container}[/green]"
    )

    # Build account URL
    account_url = f"https://{account}.blob.core.windows.net"

    try:
        # Create BlobServiceClient
        if use_sas:
            # SAS token authentication
            blob_service_client = BlobServiceClient(
                account_url=account_url,
                credential=sas_token
            )
        else:
            # AAD authentication
            credential = session_mgr.get_credential(scope="storage")
            if not credential:
                console.print("[red]Authentication required. Use one of the login commands first.[/red]")
                return

            blob_service_client = BlobServiceClient(
                account_url=account_url,
                credential=credential
            )

        # Get container client
        container_client = blob_service_client.get_container_client(container)

        # List blobs (includes snapshots, versions, deleted blobs)
        blob_list = container_client.list_blobs(
            include=["snapshots", "versions", "deleted", "metadata"]
        )

        # Convert to list of dicts
        blobs = []
        for blob in blob_list:
            blob_dict = {
                "name": blob.name,
                "size": blob.size,
                "content_type": blob.content_settings.content_type if blob.content_settings else None,
                "last_modified": blob.last_modified.isoformat() if blob.last_modified else None,
                "is_current_version": getattr(blob, "is_current_version", None),
                "version_id": getattr(blob, "version_id", None),
                "deleted": getattr(blob, "deleted", False),
            }
            blobs.append(blob_dict)

    except AzureError as e:
        handle_azure_error(e, "enumerating storage blobs", f"{account}/{container}")
        return
    except Exception as e:
        console.print(f"[red]Error listing blobs: {e}[/red]")
        return

    if not blobs:
        console.print("[yellow]No blobs found in this container.[/yellow]")
        return

    console.print(f"[green]Found {len(blobs)} blob(s).[/green]")

    # Save enumeration data
    session_mgr.save_enumeration_data("storage_blobs", blobs)

    # Display results
    table = Table(title=f"Azure Storage Blobs in {account}/{container} ({len(blobs)} found)")
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Size", style="magenta")
    table.add_column("Last Modified", style="green")
    table.add_column("Version ID", style="dim", overflow="fold")
    table.add_column("Current", style="yellow")

    for b in blobs:
        name = b.get("name", "")
        size = str(b.get("size", 0))
        last_modified = b.get("last_modified", "")[:19] if b.get("last_modified") else ""
        version_id = b.get("version_id", "") or ""
        is_current = "Yes" if b.get("is_current_version") else "No"

        table.add_row(name, size, last_modified, version_id, is_current)

    console.print(table)
    console.print("[dim]Saved as 'storage_blobs' in this session's enumeration data.[/dim]")
