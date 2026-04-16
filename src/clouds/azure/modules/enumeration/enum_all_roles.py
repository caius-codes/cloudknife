# src/clouds/azure/modules/enumeration/enum_all_roles.py

from typing import Any, Dict, List

import requests
from rich.console import Console
from rich.table import Table

from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.subscription import SubscriptionClient

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"


def _resolve_principal_names(
    principal_ids: List[str],
    graph_token: str,
) -> Dict[str, str]:
    """
    Resolve a list of principal UUIDs to display names via Graph API.

    Uses POST /v1.0/directoryObjects/getByIds for batch resolution (up to 1000 IDs per call).

    Returns:
        Dict mapping principal_id -> display name (or "" if not resolved)
    """
    result: Dict[str, str] = {}
    if not principal_ids or not graph_token:
        return result

    headers = {
        "Authorization": f"Bearer {graph_token}",
        "Content-Type": "application/json",
    }

    # Process in batches of 1000 (Graph API limit)
    batch_size = 1000
    for i in range(0, len(principal_ids), batch_size):
        batch = principal_ids[i : i + batch_size]
        try:
            response = requests.post(
                f"{GRAPH_ENDPOINT}/directoryObjects/getByIds",
                headers=headers,
                json={"ids": batch, "types": ["user", "group", "servicePrincipal", "device"]},
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                for obj in data.get("value", []):
                    obj_id = obj.get("id", "")
                    # Use displayName if available; fall back to userPrincipalName for users
                    name = obj.get("displayName") or obj.get("userPrincipalName") or ""
                    if obj_id:
                        result[obj_id] = name
            elif response.status_code == 403:
                console.print("[yellow]Graph API: insufficient permissions to resolve principal names.[/yellow]")
                break
            elif response.status_code == 401:
                console.print("[yellow]Graph token expired. Principal names will not be resolved.[/yellow]")
                break
            else:
                # Non-fatal: just skip name resolution for this batch
                console.print(f"[dim]Graph API returned {response.status_code} for name resolution.[/dim]")
        except Exception:
            # Non-fatal — table will just show empty names
            pass

    return result


def enumerate_all_role_assignments(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate ALL role assignments visible to the current user in the subscription.

    Uses Azure SDK (azure-mgmt-authorization) instead of Azure CLI.
    """

    # Get credential
    credential = session_mgr.get_credential(scope="management")
    if not credential:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    # Get subscription ID
    data = session_mgr.current_session_data or {}
    subscription_id = data.get("subscription_id")

    if not subscription_id:
        console.print("[yellow]No subscription_id in session. Attempting to discover subscriptions...[/yellow]")
        try:
            # Use SubscriptionClient to list accessible subscriptions
            sub_client = SubscriptionClient(credential)
            subscriptions = list(sub_client.subscriptions.list())

            if not subscriptions:
                console.print("[red]No accessible subscriptions found.[/red]")
                return

            # Use first subscription
            subscription_id = subscriptions[0].subscription_id
            session_mgr.current_session_data["subscription_id"] = subscription_id
            session_mgr.current_session_data["subscription_name"] = subscriptions[0].display_name
            session_mgr.save_current_session()
            console.print(f"[green]Using subscription: {subscriptions[0].display_name} ({subscription_id})[/green]")

        except Exception as e:
            handle_azure_error(e, "discovering subscriptions")
            return

    console.print("[cyan]Enumerating all role assignments in subscription...[/cyan]")

    try:
        # Create AuthorizationManagementClient
        auth_client = AuthorizationManagementClient(
            credential=credential,
            subscription_id=subscription_id,
        )

        # List all role assignments in subscription
        role_assignments_iter = auth_client.role_assignments.list_for_subscription()

        # Convert to list and extract data
        assignments: List[Dict[str, Any]] = []
        for assignment in role_assignments_iter:
            # Get role definition name
            role_name = ""
            if assignment.role_definition_id:
                try:
                    role_def = auth_client.role_definitions.get_by_id(assignment.role_definition_id)
                    role_name = role_def.role_name
                except Exception:
                    # If we can't get the name, use the ID
                    role_name = assignment.role_definition_id.split("/")[-1]

            assignments.append({
                "id": assignment.id,
                "name": assignment.name,
                "scope": assignment.scope,
                "roleDefinitionId": assignment.role_definition_id,
                "roleDefinitionName": role_name,
                "principalId": assignment.principal_id,
                "principalType": assignment.principal_type,
                "principalName": "",
            })

    except Exception as e:
        handle_azure_error(e, "enumerating all role assignments", subscription_id)
        return

    if not assignments:
        console.print("[yellow]No role assignments found.[/yellow]")
        return

    # Attempt to resolve principal names using Graph API
    graph_token = session_mgr.get_access_token(scope="graph")
    principal_names: Dict[str, str] = {}

    if graph_token:
        console.print("[dim]Resolving principal names via Graph API...[/dim]")
        unique_ids = list({a["principalId"] for a in assignments if a.get("principalId")})
        principal_names = _resolve_principal_names(unique_ids, graph_token)
        if principal_names:
            console.print(f"[dim]Resolved {len(principal_names)}/{len(unique_ids)} principal name(s).[/dim]")
            # Populate principalName in each assignment
            for a in assignments:
                pid = a.get("principalId", "")
                a["principalName"] = principal_names.get(pid, "")
    else:
        console.print("[dim]No Graph token available — principal names will not be resolved. Use 'get_graph_token' or 'login_interactive' first.[/dim]")

    # Save data in session for reuse
    session_mgr.save_enumeration_data("all_role_assignments", assignments)

    # Print summary table
    table = Table(
        title=f"Azure Role Assignments (ALL) - {len(assignments)} found",
        show_lines=False,
    )
    table.add_column("Principal Name", style="cyan", overflow="fold", max_width=35)
    table.add_column("Principal ID", style="dim", overflow="fold", max_width=38)
    table.add_column("Principal Type", style="magenta")
    table.add_column("Role", style="green")
    table.add_column("Scope", style="white", overflow="fold", no_wrap=False)

    for ra in assignments:
        principal_id = ra.get("principalId") or ""
        principal_type = ra.get("principalType") or ""
        principal_name = ra.get("principalName") or ""
        role_name = ra.get("roleDefinitionName") or ""
        scope = ra.get("scope") or ""

        table.add_row(principal_name, principal_id, principal_type, role_name, scope)

    console.print(table)
    console.print("[dim]Saved as 'all_role_assignments' in this session's enumeration data.[/dim]")
    console.print(f"[green]Enumerated {len(assignments)} role assignment(s).[/green]")
