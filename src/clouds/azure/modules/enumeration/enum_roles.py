from rich.console import Console
from rich.table import Table

from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.subscription import SubscriptionClient

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()


def enumerate_role_assignments(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate role assignments for the signed-in user.

    Uses Azure SDK (azure-mgmt-authorization) instead of Azure CLI.
    """

    # Get credential
    credential = session_mgr.get_credential(scope="management")
    if not credential:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    # Get user_id from session data (if available from legacy CLI auth)
    user = session_mgr.current_session_data or {}
    assignee_id = user.get("user_id")

    # Get subscription ID
    subscription_id = user.get("subscription_id")
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

    if assignee_id:
        console.print(f"[cyan]Enumerating role assignments for assignee:[/cyan] {assignee_id}")
    else:
        console.print("[cyan]Enumerating all role assignments in subscription[/cyan]")

    try:
        # Create AuthorizationManagementClient
        auth_client = AuthorizationManagementClient(
            credential=credential,
            subscription_id=subscription_id,
        )

        # List role assignments
        # If we have assignee_id, filter by it; otherwise get all
        if assignee_id:
            role_assignments_iter = auth_client.role_assignments.list_for_subscription(
                filter=f"assignedTo('{assignee_id}')"
            )
        else:
            role_assignments_iter = auth_client.role_assignments.list_for_subscription()

        # Convert to list and extract data
        assignments = []
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
            })

    except Exception as e:
        handle_azure_error(e, "enumerating role assignments", subscription_id)
        return

    if not assignments:
        console.print("[yellow]No role assignments found.[/yellow]")
        return

    # Save enumeration data
    session_mgr.save_enumeration_data("role_assignments", assignments)

    table = Table(title="Azure Role Assignments")
    table.add_column(
        "Scope",
        style="cyan",
        overflow="fold",
        no_wrap=False,
    )
    table.add_column("Role")
    table.add_column("Principal type")

    for a in assignments:
        scope = a.get("scope", "")
        role = a.get("roleDefinitionName") or a.get("roleDefinitionId", "")
        ptype = a.get("principalType", "")
        table.add_row(scope, role, ptype)

    console.print(table)
    console.print(f"[green]Found {len(assignments)} role assignment(s).[/green]")
