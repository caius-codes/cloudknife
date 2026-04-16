# src/clouds/azure/modules/enumeration/enumerate_storage_full.py

from rich.console import Console
from rich.tree import Tree
from rich.prompt import Confirm

from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_storage_full(session_mgr: AzureSessionManager) -> dict:
    """
    Complete storage enumeration: accounts → containers → (optional) blob counts.

    Enumerates all storage accounts in the subscription, then all containers
    in each account using Management API (only requires management token).

    Optionally counts blobs in each container (requires storage token).

    Returns:
        Dictionary with full storage hierarchy
    """

    # Get subscription ID
    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[red]No subscription configured. Use a login command first.[/red]")
        return {}

    console.print("[bold cyan]🗄️  Full Storage Enumeration[/bold cyan]")
    console.print(f"[dim]Subscription: {subscription_id}[/dim]\n")

    # Step 1: Enumerate storage accounts
    console.print("[cyan]Step 1: Enumerating storage accounts...[/cyan]")

    try:
        credential_mgmt = session_mgr.get_credential(scope="management")
        if not credential_mgmt:
            console.print("[red]Management authentication required.[/red]")
            return {}

        storage_client = StorageManagementClient(credential_mgmt, subscription_id)
        storage_accounts_iter = storage_client.storage_accounts.list()

        storage_accounts = []
        for account in storage_accounts_iter:
            storage_accounts.append({
                "name": account.name,
                "id": account.id,
                "location": account.location,
                "resource_group": account.id.split("/")[4] if len(account.id.split("/")) > 4 else "",
            })

    except Exception as e:
        console.print(f"[red]Error listing storage accounts: {e}[/red]")
        return {}

    if not storage_accounts:
        console.print("[yellow]No storage accounts found.[/yellow]")
        return {}

    console.print(f"[green]Found {len(storage_accounts)} storage account(s).[/green]\n")

    # Step 2: Check if user wants to enumerate containers
    enumerate_containers = Confirm.ask(
        f"[cyan]Enumerate containers for all {len(storage_accounts)} account(s)?[/cyan]",
        default=True
    )

    # Step 3: Check if user wants to count blobs (requires storage token)
    count_blobs = False
    credential_storage = None
    if enumerate_containers:
        count_blobs = Confirm.ask(
            "[cyan]Count blobs in each container (requires storage token, slower)?[/cyan]",
            default=False
        )
        if count_blobs:
            credential_storage = session_mgr.get_credential(scope="storage")
            if not credential_storage:
                console.print("[yellow]Storage token not available. Blob counting will be skipped.[/yellow]")
                console.print("[yellow]Tip: Run 'audit_mfa_gaps' with -r https://storage.azure.com[/yellow]")
                count_blobs = False

    full_hierarchy = {
        "subscription_id": subscription_id,
        "storage_accounts": []
    }

    # Create tree for visualization
    tree = Tree(f"[bold cyan]Subscription: {subscription_id}[/bold cyan]")

    total_containers = 0
    total_blobs = 0

    for account in storage_accounts:
        account_name = account["name"]
        account_data = {
            "name": account_name,
            "location": account["location"],
            "resource_group": account["resource_group"],
            "containers": []
        }

        account_node = tree.add(f"[cyan]Storage Account: {account_name}[/cyan] [dim]({account['location']})[/dim]")

        if enumerate_containers:
            console.print(f"[dim]Enumerating containers for {account_name}...[/dim]")

            try:
                # Use Management API to list containers (no storage token needed!)
                resource_group = account["resource_group"]
                containers_iter = storage_client.blob_containers.list(resource_group, account_name)
                containers = list(containers_iter)

                for container in containers:
                    container_name = container.name
                    container_data = {
                        "name": container_name,
                        "blob_count": None
                    }

                    # Count blobs in container if storage token available (requires data plane access)
                    if count_blobs and credential_storage:
                        try:
                            from azure.storage.blob import BlobServiceClient
                            account_url = f"https://{account_name}.blob.core.windows.net"
                            blob_service_client = BlobServiceClient(
                                account_url=account_url,
                                credential=credential_storage
                            )
                            container_client = blob_service_client.get_container_client(container_name)
                            blob_count = sum(1 for _ in container_client.list_blobs())
                            container_data["blob_count"] = blob_count
                            total_blobs += blob_count

                            account_node.add(f"[yellow]Container: {container_name}[/yellow] [dim]({blob_count} blobs)[/dim]")
                        except Exception:
                            # If blob count fails, still show container
                            account_node.add(f"[yellow]Container: {container_name}[/yellow] [dim](count unavailable)[/dim]")
                    else:
                        # Just show container without blob count
                        account_node.add(f"[yellow]Container: {container_name}[/yellow]")

                    account_data["containers"].append(container_data)

                total_containers += len(containers)

            except AzureError as e:
                account_node.add(f"[red]Error: {str(e)[:50]}...[/red]")
            except Exception as e:
                account_node.add(f"[red]Error enumerating containers: {str(e)[:50]}...[/red]")
        else:
            account_node.add("[dim]Containers not enumerated[/dim]")

        full_hierarchy["storage_accounts"].append(account_data)

    # Display tree
    console.print()
    console.print(tree)
    console.print()

    # Summary
    console.print("[bold green]Summary:[/bold green]")
    console.print(f"  Storage Accounts: {len(storage_accounts)}")
    if enumerate_containers:
        console.print(f"  Total Containers: {total_containers}")
        console.print(f"  Total Blobs: {total_blobs}")
    console.print()

    # Save enumeration data
    session_mgr.save_enumeration_data("storage_full_hierarchy", full_hierarchy)
    console.print("[dim]Saved as 'storage_full_hierarchy' in this session's enumeration data.[/dim]")

    return full_hierarchy
