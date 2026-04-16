from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm

from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def download_storage_blob(session_mgr: AzureSessionManager) -> None:
    """
    Download an Azure Storage blob.

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

    # Prompt for blob details
    account = Prompt.ask("[cyan]Storage account name[/cyan]").strip()
    if not account:
        console.print("[red]Storage account name is required.[/red]")
        return

    container = Prompt.ask("[cyan]Container name[/cyan]").strip()
    if not container:
        console.print("[red]Container name is required.[/red]")
        return

    blob_name = Prompt.ask("[cyan]Blob name to download[/cyan]").strip()
    if not blob_name:
        console.print("[red]Blob name is required.[/red]")
        return

    version_id = Prompt.ask(
        "[cyan]Version ID (empty for latest)[/cyan]",
        default=""
    ).strip()

    # Determine destination path
    exfil_dir = session_mgr.get_exfil_dir("blobs")
    default_dest = str(exfil_dir / blob_name.split("/")[-1])
    dest = Prompt.ask(
        "[cyan]Local path to save blob[/cyan]",
        default=default_dest
    ).strip()

    dest_path = Path(dest) if dest else exfil_dir

    if dest_path.is_dir():
        dest_file = dest_path / blob_name.split("/")[-1]
    else:
        dest_file = dest_path

    console.print(
        f"[cyan]Downloading blob[/cyan] {blob_name} "
        f"[cyan]from[/cyan] {account}/{container} "
        f"[cyan]to[/cyan] {dest_file}"
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

        # Get blob client
        blob_client = blob_service_client.get_blob_client(
            container=container,
            blob=blob_name,
            version_id=version_id if version_id else None
        )

        # Download blob data first
        download_stream = blob_client.download_blob()
        blob_data = download_stream.readall()

        # Calculate size before writing
        size_bytes = len(blob_data)
        size_mb = size_bytes / (1024 * 1024)

        # Write to file
        with open(dest_file, "wb") as f:
            f.write(blob_data)

        console.print(f"[green]Download completed: {dest_file} ({size_mb:.2f} MB)[/green]")

    except AzureError as e:
        handle_azure_error(e, "downloading blob", f"{account}/{container}/{blob_name}")
    except OSError as e:
        console.print(f"[red]File system error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error downloading blob: {e}[/red]")

