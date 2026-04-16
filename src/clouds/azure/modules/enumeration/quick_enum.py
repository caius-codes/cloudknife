"""
Azure Quick Enumeration Module.

Lightweight multi-service overview for quick reconnaissance:
- Resources (all types)
- Virtual Machines
- Storage Accounts
- Key Vaults
- Function Apps
- Web Apps
- Users (Graph API)
- Groups (Graph API)

Uses only cheap list/count calls without deep enumeration.
"""

from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table

import requests

from ...azure_session import AzureSessionManager

console = Console()

# Import Azure SDKs lazily to avoid hard dependency
try:
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.core.exceptions import AzureError
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False


def _count_resources(subscription_id: str, credential) -> int:
    """Count all resources in subscription using ARM API."""
    try:
        resource_client = ResourceManagementClient(credential, subscription_id)
        resources = list(resource_client.resources.list())
        return len(resources)
    except Exception:
        return -1


def _count_vms(subscription_id: str, credential) -> int:
    """Count virtual machines in subscription."""
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)
        vms = list(compute_client.virtual_machines.list_all())
        return len(vms)
    except Exception:
        return -1


def _count_storage_accounts(subscription_id: str, credential) -> int:
    """Count storage accounts in subscription."""
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        accounts = list(storage_client.storage_accounts.list())
        return len(accounts)
    except Exception:
        return -1


def _count_key_vaults(subscription_id: str, credential) -> int:
    """Count key vaults in subscription."""
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(kv_client.vaults.list())
        return len(vaults)
    except Exception:
        return -1


def _count_function_apps(subscription_id: str, credential) -> int:
    """Count function apps in subscription."""
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
        # List all web apps and filter for kind="functionapp"
        apps = [app for app in web_client.web_apps.list() if app.kind and "functionapp" in app.kind.lower()]
        return len(apps)
    except Exception:
        return -1


def _count_web_apps(subscription_id: str, credential) -> int:
    """Count web apps (excluding function apps) in subscription."""
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
        # List all web apps and exclude function apps
        apps = [app for app in web_client.web_apps.list() if not (app.kind and "functionapp" in app.kind.lower())]
        return len(apps)
    except Exception:
        return -1


def _count_users_graph(access_token: str) -> int:
    """Count users via Microsoft Graph API."""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        # Use $count with ConsistencyLevel header
        url = "https://graph.microsoft.com/v1.0/users/$count"
        headers["ConsistencyLevel"] = "eventual"
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            return int(resp.text)
        return -1
    except Exception:
        return -1


def _count_groups_graph(access_token: str) -> int:
    """Count groups via Microsoft Graph API."""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        # Use $count with ConsistencyLevel header
        url = "https://graph.microsoft.com/v1.0/groups/$count"
        headers["ConsistencyLevel"] = "eventual"
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            return int(resp.text)
        return -1
    except Exception:
        return -1


def quick_enum(session_mgr: AzureSessionManager) -> None:
    """
    Quick enumeration of key Azure services.

    Provides a fast overview without deep enumeration.
    """
    if not AZURE_SDK_AVAILABLE:
        console.print("[red]Azure SDK not available. Install required packages:[/red]")
        console.print("[yellow]pip install azure-mgmt-compute azure-mgmt-resource azure-mgmt-storage azure-mgmt-keyvault azure-mgmt-web[/yellow]")
        return

    subscription_id = session_mgr.current_session_data.get("subscription_id")
    if not subscription_id:
        console.print("[yellow]No subscription configured. Some services will be skipped.[/yellow]")
        console.print("[dim]Use 'set_subscription' or a login command to configure a subscription.[/dim]\n")

    console.print("[bold blue]🔍 Running Azure quick_enum[/bold blue]\n")

    summary: List[Dict[str, Any]] = []

    # Get credentials for ARM API (management scope)
    credential = None
    if subscription_id:
        try:
            credential = session_mgr.get_credential(scope="management")
        except Exception:
            pass

    # Get Graph API token for users/groups
    graph_token = session_mgr.current_session_data.get("graph_access_token")

    # Parallel enumeration tasks
    tasks = {}

    if credential and subscription_id:
        with ThreadPoolExecutor(max_workers=6) as executor:
            # Submit all ARM tasks in parallel
            tasks["resources"] = executor.submit(_count_resources, subscription_id, credential)
            tasks["vms"] = executor.submit(_count_vms, subscription_id, credential)
            tasks["storage"] = executor.submit(_count_storage_accounts, subscription_id, credential)
            tasks["keyvaults"] = executor.submit(_count_key_vaults, subscription_id, credential)
            tasks["functions"] = executor.submit(_count_function_apps, subscription_id, credential)
            tasks["webapps"] = executor.submit(_count_web_apps, subscription_id, credential)

            # Process results as they complete
            console.print("[dim]Enumerating ARM resources...[/dim]")
            for service, future in tasks.items():
                try:
                    count = future.result(timeout=60)
                    if count >= 0:
                        summary.append({
                            "service": service,
                            "count": count,
                            "status": "OK" if count > 0 else "EMPTY",
                            "hint": f"enumerate_{service}" if count > 0 else "no resources found",
                        })
                    else:
                        summary.append({
                            "service": service,
                            "count": 0,
                            "status": "ERROR",
                            "hint": "missing permissions or service unavailable",
                        })
                except Exception as e:
                    summary.append({
                        "service": service,
                        "count": 0,
                        "status": "ERROR",
                        "hint": str(e)[:50] if str(e) else "unknown error",
                    })

    # Graph API enumeration (Users & Groups)
    if graph_token:
        console.print("[dim]Enumerating Graph API resources...[/dim]")

        # Users
        users_count = _count_users_graph(graph_token)
        if users_count >= 0:
            summary.append({
                "service": "users",
                "count": users_count,
                "status": "OK" if users_count > 0 else "EMPTY",
                "hint": "enum_users" if users_count > 0 else "no users found",
            })
        else:
            summary.append({
                "service": "users",
                "count": 0,
                "status": "ERROR",
                "hint": "missing Graph permissions (User.Read.All)",
            })

        # Groups
        groups_count = _count_groups_graph(graph_token)
        if groups_count >= 0:
            summary.append({
                "service": "groups",
                "count": groups_count,
                "status": "OK" if groups_count > 0 else "EMPTY",
                "hint": "enum_groups" if groups_count > 0 else "no groups found",
            })
        else:
            summary.append({
                "service": "groups",
                "count": 0,
                "status": "ERROR",
                "hint": "missing Graph permissions (Group.Read.All)",
            })
    else:
        console.print("[yellow]No Graph API token available. Skipping users/groups enumeration.[/yellow]")
        console.print("[dim]Use a login command or 'set_token' to authenticate with Graph API.[/dim]\n")

    # Print summary table
    if not summary:
        console.print("[yellow]No services enumerated. Configure credentials and subscription first.[/yellow]")
        return

    table = Table(title="Azure Quick Enumeration Summary")
    table.add_column("Service", style="cyan")
    table.add_column("Resources", justify="right")
    table.add_column("Status")
    table.add_column("Next step")

    for row in summary:
        status = row.get("status", "UNKNOWN")
        if status == "OK":
            status_str = "[green]OK[/green]"
        elif status == "EMPTY":
            status_str = "[yellow]EMPTY[/yellow]"
        elif status == "ERROR":
            status_str = "[red]ERROR[/red]"
        else:
            status_str = status

        table.add_row(
            row["service"],
            str(row["count"]),
            status_str,
            row["hint"],
        )

    console.print(table)
    console.print("\n[dim]Tip: Use the suggested commands in 'Next step' column for detailed enumeration.[/dim]")
