"""
GCP Service Account IAM Policy Enumeration for Cloud Knife.

Retrieves the IAM policy bound to a service account, showing:
- Who can impersonate the service account
- Role bindings on the service account resource
- Conditions on bindings
"""

import base64
from typing import Dict, Any, Optional, TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from google.cloud import iam_admin_v1
from google.iam.v1 import iam_policy_pb2

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()


def describe_service_account_iam_policy(
    session_mgr: "GCPSessionManager",
    service_account_email: str = None,
) -> Optional[Dict[str, Any]]:
    """
    Describe the IAM policy for a service account.

    This shows who has permissions ON the service account itself,
    such as iam.serviceAccountUser (can impersonate) or
    iam.serviceAccountTokenCreator (can generate tokens).

    Args:
        session_mgr: GCP session manager with valid credentials
        service_account_email: Service account email. If None, uses the
                               service account from the current session.

    Returns:
        Dictionary containing the IAM policy bindings
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' or 'set_token' first.[/red]")
        return None

    # Always prompt user first, with session default if available
    if not service_account_email:
        session_default = session_mgr.current_session_data.get("service_account_email", "")
        console.print("[bold yellow]🔍 Get Service Account IAM Policy[/bold yellow]")
        console.print("[dim]Shows who can impersonate this service account[/dim]")

        service_account_email = Prompt.ask(
            "[cyan]Service account email[/cyan]",
            default=session_default if session_default else ""
        )

        if not service_account_email:
            console.print("[red]No service account specified.[/red]")
            return None

    # Validate email format
    if "@" not in service_account_email:
        console.print(f"[red]Invalid service account email format: {service_account_email}[/red]")
        return None

    console.print(f"[dim]Fetching IAM policy for: {service_account_email}[/dim]")

    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)

        # Build the resource name
        # Format: projects/{project}/serviceAccounts/{email}
        # We need to extract project from the email (format: sa@project.iam.gserviceaccount.com)
        if ".iam.gserviceaccount.com" in service_account_email:
            project = service_account_email.split("@")[1].replace(".iam.gserviceaccount.com", "")
        else:
            # Fallback to session project
            project = session_mgr.default_project
            if not project:
                console.print("[red]Could not determine project. Use 'set_project' first.[/red]")
                return None

        resource_name = f"projects/{project}/serviceAccounts/{service_account_email}"

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=resource_name,
        )

        policy = client.get_iam_policy(request=request)

        # Parse the policy
        policy_data = {
            "service_account": service_account_email,
            "project": project,
            "version": policy.version,
            "etag": base64.b64encode(policy.etag).decode("ascii") if isinstance(policy.etag, bytes) else policy.etag,
            "bindings": [],
        }

        for binding in policy.bindings:
            binding_data = {
                "role": binding.role,
                "members": list(binding.members),
            }

            # Check for conditions
            if binding.condition and binding.condition.expression:
                binding_data["condition"] = {
                    "title": binding.condition.title,
                    "description": binding.condition.description,
                    "expression": binding.condition.expression,
                }

            policy_data["bindings"].append(binding_data)

        # Display results
        _display_sa_iam_policy(policy_data)

        # Save to enumeration data
        session_mgr.save_enumeration_data(
            f"sa_iam_policy_{service_account_email}",
            policy_data
        )

        return policy_data

    except Exception as e:
        console.print(f"[red]Error fetching IAM policy: {str(e)}[/red]")
        return None


def _display_sa_iam_policy(policy_data: Dict[str, Any]) -> None:
    """Display the service account IAM policy."""
    console.print(f"\n[bold cyan]IAM Policy for Service Account[/bold cyan]")
    console.print(f"[dim]Email: {policy_data['service_account']}[/dim]")
    console.print(f"[dim]Project: {policy_data['project']}[/dim]")

    if not policy_data["bindings"]:
        console.print("\n[yellow]No IAM bindings found on this service account.[/yellow]")
        console.print("[dim]This means no external principals can impersonate this SA.[/dim]")
        return

    # Create table
    table = Table(title=f"IAM Bindings ({len(policy_data['bindings'])} found)")
    table.add_column("Role", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Members", overflow="fold", no_wrap=False)
    table.add_column("Condition", overflow="fold", no_wrap=False)

    # Interesting roles for service accounts
    dangerous_roles = [
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.workloadIdentityUser",
        "roles/owner",
        "roles/editor",
    ]

    for binding in policy_data["bindings"]:
        role = binding["role"]
        members = binding["members"]
        condition = binding.get("condition")

        # Highlight dangerous roles
        if role in dangerous_roles:
            role_display = f"[bold red]{role}[/bold red]"
        else:
            role_display = role

        # Format members
        member_lines = []
        for member in members:
            if member in ("allUsers", "allAuthenticatedUsers"):
                member_lines.append(f"[bold red]{member}[/bold red]")
            elif member.startswith("serviceAccount:"):
                member_lines.append(f"[yellow]{member}[/yellow]")
            else:
                member_lines.append(member)

        members_display = "\n".join(member_lines)

        # Format condition
        if condition:
            condition_display = f"[dim]{condition.get('title', 'Conditional')}[/dim]"
        else:
            condition_display = "[dim]-[/dim]"

        table.add_row(role_display, members_display, condition_display)

    console.print(table)

    # Show warnings for dangerous configurations
    _show_security_warnings(policy_data)


def _show_security_warnings(policy_data: Dict[str, Any]) -> None:
    """Show security warnings for the IAM policy."""
    warnings = []

    for binding in policy_data["bindings"]:
        role = binding["role"]
        members = binding["members"]

        # Check for public access
        if "allUsers" in members:
            warnings.append(f"[bold red]CRITICAL: allUsers has {role} - anyone can access![/bold red]")
        if "allAuthenticatedUsers" in members:
            warnings.append(f"[bold red]WARNING: allAuthenticatedUsers has {role} - any Google account![/bold red]")

        # Check for impersonation roles
        if role == "roles/iam.serviceAccountUser":
            for member in members:
                if member not in ("allUsers", "allAuthenticatedUsers"):
                    warnings.append(f"[yellow]Impersonation: {member} can act as this SA[/yellow]")

        if role == "roles/iam.serviceAccountTokenCreator":
            for member in members:
                if member not in ("allUsers", "allAuthenticatedUsers"):
                    warnings.append(f"[yellow]Token Creation: {member} can generate tokens for this SA[/yellow]")

    if warnings:
        console.print("\n[bold]Security Findings:[/bold]")
        for warning in warnings:
            console.print(f"  {warning}")
