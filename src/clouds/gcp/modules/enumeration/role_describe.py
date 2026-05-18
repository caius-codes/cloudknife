"""
GCP IAM Role Description for Cloud Knife.

Describes an IAM role showing:
- Role metadata (title, description, stage)
- Included permissions
- Permission analysis (dangerous permissions highlighted)
"""

import base64
from typing import Dict, Any, Optional, List, TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from google.cloud import iam_admin_v1

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()

# Permissions that are particularly interesting for security research
DANGEROUS_PERMISSIONS = {
    # IAM permissions
    "iam.serviceAccounts.actAs": "Can impersonate service accounts",
    "iam.serviceAccounts.getAccessToken": "Can generate SA access tokens",
    "iam.serviceAccounts.getOpenIdToken": "Can generate SA OIDC tokens",
    "iam.serviceAccounts.implicitDelegation": "Can delegate SA credentials",
    "iam.serviceAccounts.signBlob": "Can sign data as SA",
    "iam.serviceAccounts.signJwt": "Can sign JWTs as SA",
    "iam.serviceAccountKeys.create": "Can create SA keys (persistence)",
    "iam.roles.create": "Can create custom roles",
    "iam.roles.update": "Can modify roles",
    "resourcemanager.projects.setIamPolicy": "Can modify project IAM",
    "resourcemanager.folders.setIamPolicy": "Can modify folder IAM",
    "resourcemanager.organizations.setIamPolicy": "Can modify org IAM",

    # Compute permissions
    "compute.instances.setMetadata": "Can modify instance metadata (SSH keys)",
    "compute.instances.setServiceAccount": "Can change instance SA",
    "compute.projects.setCommonInstanceMetadata": "Can set project-wide SSH keys",
    "compute.instances.osLogin": "Can SSH via OS Login",
    "compute.instances.osAdminLogin": "Can SSH as admin via OS Login",

    # Storage permissions
    "storage.buckets.setIamPolicy": "Can modify bucket IAM",
    "storage.objects.setIamPolicy": "Can modify object IAM",

    # Cloud Functions / Run
    "cloudfunctions.functions.setIamPolicy": "Can modify function IAM",
    "run.services.setIamPolicy": "Can modify Cloud Run IAM",

    # Secret Manager
    "secretmanager.secrets.get": "Can read secrets",
    "secretmanager.versions.access": "Can access secret values",

    # Other dangerous
    "deploymentmanager.deployments.create": "Can deploy resources",
    "cloudbuild.builds.create": "Can create builds (code execution)",
}


def describe_role(
    session_mgr: "GCPSessionManager",
    role_name: str = None,
    project_id: str = None,
) -> Optional[Dict[str, Any]]:
    """
    Describe an IAM role and its permissions.

    Args:
        session_mgr: GCP session manager with valid credentials
        role_name: Role to describe. Can be:
                   - Predefined: roles/editor, roles/iam.serviceAccountUser
                   - Custom: projects/{project}/roles/{role} or organizations/{org}/roles/{role}
        project_id: Project ID (required for custom project roles)

    Returns:
        Dictionary containing role details and permissions
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' or 'set_token' first.[/red]")
        return None

    # Prompt for role if not provided
    if not role_name:
        console.print("[bold yellow]🔍 Describe IAM Role[/bold yellow]")
        console.print("[dim]Examples:[/dim]")
        console.print("[dim]  - roles/editor (predefined)[/dim]")
        console.print("[dim]  - roles/iam.serviceAccountUser (predefined)[/dim]")
        console.print("[dim]  - projects/my-project/roles/customRole (custom)[/dim]")

        role_name = Prompt.ask("[cyan]Role name[/cyan]")

        if not role_name:
            console.print("[red]No role specified.[/red]")
            return None

    # Determine if this is a custom role or predefined
    is_custom_role = "/" in role_name and not role_name.startswith("roles/")

    # For custom roles without full path, we need project
    if role_name.startswith("roles/") is False and "projects/" not in role_name and "organizations/" not in role_name:
        # Assume it's a custom project role
        if not project_id:
            project_id = session_mgr.default_project
            if not project_id:
                project_id = Prompt.ask("[cyan]Project ID (for custom role)[/cyan]")
                if not project_id:
                    console.print("[red]Project ID required for custom roles.[/red]")
                    return None

        role_name = f"projects/{project_id}/roles/{role_name}"

    console.print(f"[dim]Fetching role: {role_name}[/dim]")

    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)

        request = iam_admin_v1.GetRoleRequest(name=role_name)
        role = client.get_role(request=request)

        # Parse role data
        role_data = {
            "name": role.name,
            "title": role.title,
            "description": role.description,
            "stage": iam_admin_v1.Role.RoleLaunchStage(role.stage).name if role.stage else "GA",
            "etag": base64.b64encode(role.etag).decode("ascii") if isinstance(role.etag, bytes) else role.etag,
            "deleted": role.deleted,
            "included_permissions": list(role.included_permissions),
            "permission_count": len(role.included_permissions),
        }

        # Analyze permissions
        role_data["dangerous_permissions"] = _analyze_permissions(role_data["included_permissions"])

        # Display results
        _display_role(role_data)

        # Save to enumeration data
        safe_name = role_name.replace("/", "_").replace(":", "_")
        session_mgr.save_enumeration_data(f"role_{safe_name}", role_data)

        return role_data

    except Exception as e:
        error_msg = str(e)
        if "404" in error_msg or "not found" in error_msg.lower():
            console.print(f"[red]Role not found: {role_name}[/red]")
            console.print("[dim]For custom roles, use the full path: projects/PROJECT/roles/ROLE[/dim]")
        else:
            console.print(f"[red]Error fetching role: {error_msg}[/red]")
        return None


def _analyze_permissions(permissions: List[str]) -> List[Dict[str, str]]:
    """Analyze permissions and identify dangerous ones."""
    dangerous = []

    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            dangerous.append({
                "permission": perm,
                "risk": DANGEROUS_PERMISSIONS[perm],
            })
        else:
            # Check for wildcards or broad patterns
            if perm.endswith("*"):
                dangerous.append({
                    "permission": perm,
                    "risk": "Wildcard permission - broad access",
                })
            elif ".setIamPolicy" in perm:
                dangerous.append({
                    "permission": perm,
                    "risk": "Can modify IAM policies",
                })
            elif ".create" in perm and ("serviceAccount" in perm or "key" in perm.lower()):
                dangerous.append({
                    "permission": perm,
                    "risk": "Can create credentials/keys",
                })

    return dangerous


def _display_role(role_data: Dict[str, Any]) -> None:
    """Display role details."""
    console.print(f"\n[bold cyan]IAM Role: {role_data['title'] or role_data['name']}[/bold cyan]")

    # Metadata table
    meta_table = Table(show_header=False, box=None, padding=(0, 2))
    meta_table.add_column("Field", style="cyan")
    meta_table.add_column("Value")

    meta_table.add_row("Name", role_data["name"])
    meta_table.add_row("Title", role_data["title"] or "[dim]N/A[/dim]")
    meta_table.add_row("Stage", role_data["stage"])
    meta_table.add_row("Permissions", str(role_data["permission_count"]))

    if role_data["deleted"]:
        meta_table.add_row("Status", "[red]DELETED[/red]")

    console.print(meta_table)

    if role_data["description"]:
        console.print(f"\n[dim]Description: {role_data['description']}[/dim]")

    # Show dangerous permissions first
    dangerous = role_data.get("dangerous_permissions", [])
    if dangerous:
        console.print(f"\n[bold red]Dangerous Permissions ({len(dangerous)}):[/bold red]")
        for item in dangerous:
            console.print(f"  [red]⚠[/red] {item['permission']}")
            console.print(f"      [dim]{item['risk']}[/dim]")

    # Show all permissions (grouped by service)
    console.print(f"\n[bold]All Permissions ({role_data['permission_count']}):[/bold]")

    # Group by service
    permissions_by_service: Dict[str, List[str]] = {}
    for perm in sorted(role_data["included_permissions"]):
        service = perm.split(".")[0] if "." in perm else "other"
        permissions_by_service.setdefault(service, []).append(perm)

    for service in sorted(permissions_by_service.keys()):
        perms = permissions_by_service[service]
        console.print(f"\n  [cyan]{service}[/cyan] ({len(perms)} permissions)")
        for perm in perms:
            # Highlight dangerous permissions
            if any(d["permission"] == perm for d in dangerous):
                console.print(f"    [red]• {perm}[/red]")
            else:
                console.print(f"    [dim]•[/dim] {perm}")


def enumerate_predefined_roles(
    session_mgr: "GCPSessionManager",
    filter_pattern: str = None,
) -> Optional[List[Dict[str, str]]]:
    """
    Enumerate predefined GCP roles.

    Args:
        session_mgr: GCP session manager
        filter_pattern: Optional pattern to filter roles (e.g., "iam", "compute")

    Returns:
        List of role summaries
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured.[/red]")
        return None

    if not filter_pattern:
        filter_pattern = Prompt.ask(
            "[cyan]Filter pattern (e.g., 'iam', 'compute', or empty for all)[/cyan]",
            default=""
        )

    console.print("[dim]Fetching predefined roles...[/dim]")

    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)

        request = iam_admin_v1.ListRolesRequest(
            view=iam_admin_v1.RoleView.BASIC,
        )

        roles = []
        for role in client.list_roles(request=request):
            # Filter if pattern specified
            if filter_pattern:
                if filter_pattern.lower() not in role.name.lower() and \
                   filter_pattern.lower() not in (role.title or "").lower():
                    continue

            roles.append({
                "name": role.name,
                "title": role.title,
                "description": role.description[:80] + "..." if role.description and len(role.description) > 80 else role.description,
            })

        # Display results
        if not roles:
            console.print("[yellow]No roles found matching the filter.[/yellow]")
            return []

        table = Table(title=f"Predefined Roles ({len(roles)} found)")
        table.add_column("Role Name", style="cyan", overflow="fold", no_wrap=False)
        table.add_column("Title", overflow="fold", no_wrap=False)
        table.add_column("Description", style="dim", overflow="fold", no_wrap=False)

        for role in roles[:50]:  # Limit display to 50
            table.add_row(
                role["name"],
                role["title"] or "-",
                role["description"] or "-",
            )

        console.print(table)

        if len(roles) > 50:
            console.print(f"[dim]...and {len(roles) - 50} more roles. Use a filter to narrow down.[/dim]")

        return roles

    except Exception as e:
        console.print(f"[red]Error listing roles: {str(e)}[/red]")
        return None
