"""
GCP IAM Policy Enumeration for Cloud Knife.

Enumerates IAM configuration across projects, including:
- Project-level IAM bindings
- Service accounts and their keys
- Custom roles
- Workload identity configurations
"""

from typing import List, Dict, Any, TYPE_CHECKING
import subprocess
import json as json_lib
import tempfile
import os

from rich.console import Console
from rich.table import Table
from google.cloud import resourcemanager_v3
from google.cloud import iam_admin_v1
from google.iam.v1 import iam_policy_pb2

from src.clouds.gcp.utils.projects import resolve_projects

if TYPE_CHECKING:
    from src.clouds.gcp.gcp_session import GCPSessionManager

console = Console()


def enumerate_iam_policies(session_mgr: "GCPSessionManager") -> Dict[str, Any]:
    """
    Enumerate IAM policies, service accounts, and roles across projects.

    Args:
        session_mgr: GCP session manager with valid credentials

    Returns:
        Dictionary containing IAM data for all projects
    """
    credentials = session_mgr.get_credentials()
    if not credentials:
        console.print("[red]No credentials configured. Use 'set_credentials' first.[/red]")
        return {}

    projects = resolve_projects(session_mgr)
    if not projects:
        console.print("[red]No projects accessible. Check credentials or set a project.[/red]")
        return {}

    iam_data: Dict[str, Any] = {
        "project_policies": [],
        "service_accounts": [],
        "service_account_keys": [],
        "custom_roles": [],
        "org_policy": None,
        "deny_policies": [],
        "gcloud_policies": [],
    }

    # Try to enumerate organization-level policy (if accessible)
    _enumerate_organization_policy(credentials, iam_data)

    # Enumerate each project
    for project in projects:
        console.print(f"[dim]Scanning IAM for project: {project}[/dim]")

        # Get project-level IAM policy
        _enumerate_project_policy(credentials, project, iam_data)

        # Get custom roles
        _enumerate_custom_roles(credentials, project, iam_data)

        # Get service accounts
        _enumerate_service_accounts(credentials, project, iam_data)

        # Get deny policies (if available)
        _enumerate_deny_policies(credentials, project, iam_data)

        # Get additional policy info via gcloud CLI
        _enumerate_via_gcloud(credentials, project, iam_data)

    # Save enumeration results
    session_mgr.save_enumeration_data("iam_policies", iam_data)

    # Display results
    _display_iam_summary(iam_data)

    return iam_data


def _enumerate_organization_policy(
    credentials: Any,
    iam_data: Dict[str, Any]
) -> None:
    """Enumerate organization-level IAM policy (if accessible)."""
    try:
        # Try to get the organization
        client = resourcemanager_v3.OrganizationsClient(credentials=credentials)

        # Search for organizations accessible to the current user
        for org in client.search_organizations():
            if org.state.name != "ACTIVE":
                continue

            console.print(f"[dim]Found organization: {org.display_name} ({org.name})[/dim]")

            # Get organization IAM policy
            projects_client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=org.name,
            )

            policy = projects_client.get_iam_policy(request=request)

            bindings = []
            for binding in policy.bindings:
                binding_data = {
                    "role": binding.role,
                    "members": list(binding.members),
                    "condition": {
                        "title": binding.condition.title,
                        "description": binding.condition.description,
                        "expression": binding.condition.expression,
                    } if binding.condition and binding.condition.expression else None,
                }
                bindings.append(binding_data)

            iam_data["org_policy"] = {
                "organization": org.name,
                "display_name": org.display_name,
                "bindings": bindings,
                "version": policy.version,
            }

            break  # Only process first accessible org

    except Exception as e:
        # Organization access may not be available
        console.print(f"[dim]No organization access: {str(e)}[/dim]")


def _enumerate_project_policy(
    credentials: Any,
    project: str,
    iam_data: Dict[str, Any]
) -> None:
    """Enumerate IAM policy bindings at the project level."""
    try:
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project}",
        )

        policy = client.get_iam_policy(request=request)

        bindings = []
        for binding in policy.bindings:
            binding_data = {
                "role": binding.role,
                "members": list(binding.members),
                "condition": {
                    "title": binding.condition.title,
                    "description": binding.condition.description,
                    "expression": binding.condition.expression,
                } if binding.condition and binding.condition.expression else None,
            }
            bindings.append(binding_data)

        iam_data["project_policies"].append({
            "project": project,
            "bindings": bindings,
            "version": policy.version,
        })

    except Exception as e:
        console.print(f"[dim red]Could not get IAM policy for {project}: {str(e)}[/dim red]")


def _enumerate_service_accounts(
    credentials: Any,
    project: str,
    iam_data: Dict[str, Any]
) -> None:
    """Enumerate service accounts and their keys."""
    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)

        # List service accounts
        request = iam_admin_v1.ListServiceAccountsRequest(
            name=f"projects/{project}",
        )

        for sa in client.list_service_accounts(request=request):
            sa_data = {
                "project": project,
                "email": sa.email,
                "name": sa.name,
                "display_name": sa.display_name,
                "description": sa.description,
                "unique_id": sa.unique_id,
                "disabled": sa.disabled,
                "oauth2_client_id": sa.oauth2_client_id,
            }
            iam_data["service_accounts"].append(sa_data)

            # List keys for this service account
            _enumerate_sa_keys(client, sa.name, project, sa.email, iam_data)

    except Exception as e:
        console.print(f"[dim red]Could not list service accounts for {project}: {str(e)}[/dim red]")


def _enumerate_sa_keys(
    client: iam_admin_v1.IAMClient,
    sa_name: str,
    project: str,
    sa_email: str,
    iam_data: Dict[str, Any]
) -> None:
    """Enumerate keys for a service account."""
    try:
        request = iam_admin_v1.ListServiceAccountKeysRequest(
            name=sa_name,
            key_types=[
                iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED,
            ],
        )

        for key in client.list_service_account_keys(request=request):
            # Parse key metadata
            key_data = {
                "project": project,
                "service_account": sa_email,
                "key_name": key.name.split("/")[-1] if key.name else None,
                "key_type": iam_admin_v1.ServiceAccountKey.ServiceAccountKeyType(key.key_type).name,
                "valid_after": key.valid_after_time.isoformat() if key.valid_after_time else None,
                "valid_before": key.valid_before_time.isoformat() if key.valid_before_time else None,
                "key_origin": iam_admin_v1.ServiceAccountKey.ServiceAccountKeyOrigin(key.key_origin).name if key.key_origin else None,
                "disabled": key.disabled,
            }
            iam_data["service_account_keys"].append(key_data)

    except Exception:
        # Keys may not be accessible
        pass


def _enumerate_custom_roles(
    credentials: Any,
    project: str,
    iam_data: Dict[str, Any]
) -> None:
    """Enumerate custom IAM roles defined in the project."""
    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)

        request = iam_admin_v1.ListRolesRequest(
            parent=f"projects/{project}",
            show_deleted=False,
        )

        for role in client.list_roles(request=request):
            role_data = {
                "project": project,
                "name": role.name,
                "title": role.title,
                "description": role.description,
                "stage": role.stage.name if role.stage else None,
                "permissions": list(role.included_permissions),
                "deleted": role.deleted,
            }
            iam_data["custom_roles"].append(role_data)

    except Exception as e:
        console.print(f"[dim red]Could not list custom roles for {project}: {str(e)}[/dim red]")


def _enumerate_deny_policies(
    credentials: Any,
    project: str,
    iam_data: Dict[str, Any]
) -> None:
    """Enumerate IAM deny policies (Preview feature)."""
    try:
        # IAM Deny Policies are a newer feature - may not be available
        from google.cloud import iam_v2

        client = iam_v2.PoliciesClient(credentials=credentials)

        # List deny policies for the project
        request = iam_v2.ListPoliciesRequest(
            parent=f"projects/{project}",
        )

        for policy in client.list_policies(request=request):
            policy_data = {
                "project": project,
                "name": policy.name,
                "display_name": policy.display_name,
                "kind": policy.kind,
                "rules": [],
            }

            # Extract deny rules
            for rule in policy.rules:
                if rule.deny_rule:
                    deny_rule = {
                        "denied_principals": list(rule.deny_rule.denied_principals),
                        "denied_permissions": list(rule.deny_rule.denied_permissions),
                        "exception_principals": list(rule.deny_rule.exception_principals) if rule.deny_rule.exception_principals else [],
                        "denial_condition": rule.deny_rule.denial_condition.expression if rule.deny_rule.denial_condition else None,
                    }
                    policy_data["rules"].append(deny_rule)

            if policy_data["rules"]:
                iam_data["deny_policies"].append(policy_data)

    except ImportError:
        # iam_v2 may not be available in older versions
        pass
    except Exception:
        # Deny policies may not be accessible or enabled
        pass


def _enumerate_via_gcloud(
    credentials: Any,
    project: str,
    iam_data: Dict[str, Any]
) -> None:
    """
    Enumerate IAM policy using gcloud CLI command.

    Executes 'gcloud projects get-iam-policy' to get additional policy information
    that may not be available through the API.
    """
    temp_token_file = None
    temp_token_path = None

    try:
        # Extract token from credentials
        from google.auth.transport.requests import Request

        if credentials:
            if not credentials.valid:
                credentials.refresh(Request())
            token = credentials.token
        else:
            console.print(f"[dim red]No credentials available for gcloud command[/dim red]")
            return

        # Write token to temp file with restrictive permissions
        fd, temp_token_path = tempfile.mkstemp(suffix='.txt')
        temp_token_file = os.fdopen(fd, 'w')
        temp_token_file.write(token)
        temp_token_file.close()
        os.chmod(temp_token_path, 0o600)

        # Build gcloud command
        cmd = [
            "gcloud",
            "projects",
            "get-iam-policy",
            project,
            "--format=json",
            f"--access-token-file={temp_token_path}"
        ]

        # Execute command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            try:
                gcloud_policy = json_lib.loads(result.stdout)

                # Add to iam_data
                if "gcloud_policies" not in iam_data:
                    iam_data["gcloud_policies"] = []

                iam_data["gcloud_policies"].append({
                    "project": project,
                    "policy": gcloud_policy
                })

            except json_lib.JSONDecodeError as e:
                console.print(f"[dim red]Could not parse gcloud output for {project}: {str(e)}[/dim red]")
        else:
            console.print(f"[dim red]gcloud command failed for {project}: {result.stderr}[/dim red]")

    except FileNotFoundError:
        console.print(f"[dim yellow]gcloud CLI not found - skipping gcloud enumeration[/dim yellow]")
    except subprocess.TimeoutExpired:
        console.print(f"[dim red]gcloud command timed out for {project}[/dim red]")
    except Exception as e:
        console.print(f"[dim red]gcloud enumeration failed for {project}: {str(e)}[/dim red]")
    finally:
        # Clean up temp token file
        if temp_token_path and os.path.exists(temp_token_path):
            try:
                os.unlink(temp_token_path)
            except Exception:
                pass


def _display_iam_summary(iam_data: Dict[str, Any]) -> None:
    """Display IAM enumeration summary."""
    # Organization policy summary
    if iam_data.get("org_policy"):
        org_policy = iam_data["org_policy"]
        console.print("\n[bold magenta]Organization IAM Policy[/bold magenta]")
        console.print(f"[cyan]Organization: {org_policy['display_name']} ({org_policy['organization']})[/cyan]")
        console.print(f"[dim]Total bindings: {len(org_policy['bindings'])}[/dim]")

        # Show high-privilege bindings at org level
        for binding in org_policy["bindings"]:
            role = binding["role"]
            if any(x in role.lower() for x in ["owner", "admin", "editor"]):
                console.print(f"  [yellow]{role}[/yellow]: {len(binding['members'])} member(s)")
                if binding.get("condition"):
                    console.print(f"    [dim]Condition: {binding['condition']['title']}[/dim]")

    # Project policies summary
    console.print("\n[bold]Project IAM Policies[/bold]")

    if not iam_data["project_policies"]:
        console.print("[yellow]No project policies found.[/yellow]")
    else:
        for policy in iam_data["project_policies"]:
            console.print(f"\n[cyan]Project: {policy['project']}[/cyan]")

            # Find interesting bindings
            conditional_count = 0
            for binding in policy["bindings"]:
                role = binding["role"]
                members = binding["members"]

                # Count conditional bindings
                if binding.get("condition"):
                    conditional_count += 1

                # Highlight owner/editor/admin roles
                if any(x in role.lower() for x in ["owner", "editor", "admin"]):
                    console.print(f"  [yellow]{role}[/yellow]: {len(members)} member(s)")

                # Highlight allUsers/allAuthenticatedUsers
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    console.print(f"  [bold red]PUBLIC ACCESS: {role}[/bold red]")
                    for m in members:
                        if m in ("allUsers", "allAuthenticatedUsers"):
                            console.print(f"    [red]- {m}[/red]")

            # Show count of bindings
            console.print(f"  [dim]Total bindings: {len(policy['bindings'])} ({conditional_count} conditional)[/dim]")

    # Service accounts table
    service_accounts = iam_data.get("service_accounts", [])
    if service_accounts:
        console.print("\n")
        table = Table(title=f"Service Accounts ({len(service_accounts)} found)")
        table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
        table.add_column("Email", style="green", overflow="fold", no_wrap=False)
        table.add_column("Display Name", overflow="fold", no_wrap=False)
        table.add_column("Status")
        table.add_column("User Keys", style="yellow")

        # Count keys per service account
        keys_by_sa = {}
        for key in iam_data.get("service_account_keys", []):
            sa = key["service_account"]
            keys_by_sa[sa] = keys_by_sa.get(sa, 0) + 1

        for sa in service_accounts:
            status = "[red]Disabled[/red]" if sa["disabled"] else "[green]Active[/green]"
            key_count = keys_by_sa.get(sa["email"], 0)
            key_display = f"[yellow]{key_count}[/yellow]" if key_count > 0 else "[dim]0[/dim]"

            table.add_row(
                sa["project"],
                sa["email"],
                sa["display_name"] or "-",
                status,
                key_display,
            )

        console.print(table)

    # Service account keys warning
    user_keys = [k for k in iam_data.get("service_account_keys", []) if not k.get("disabled")]
    if user_keys:
        console.print(f"\n[yellow]Found {len(user_keys)} user-managed service account key(s).[/yellow]")
        console.print("[dim]User-managed keys are a security risk - consider using workload identity.[/dim]")

    # Custom roles table
    custom_roles = iam_data.get("custom_roles", [])
    if custom_roles:
        console.print("\n")
        table = Table(title=f"Custom IAM Roles ({len(custom_roles)} found)")
        table.add_column("Project", style="cyan", overflow="fold", no_wrap=False)
        table.add_column("Name", style="green", overflow="fold", no_wrap=False)
        table.add_column("Title", overflow="fold", no_wrap=False)
        table.add_column("Stage")
        table.add_column("Permissions", style="yellow")

        for role in custom_roles:
            stage = (role.get("stage") or "").replace("_", " ")
            perm_count = len(role.get("permissions", []))

            # Extract short name from full path
            role_short = role["name"].split("/")[-1] if "/" in role["name"] else role["name"]

            table.add_row(
                role["project"],
                role_short,
                role.get("title") or "-",
                stage or "-",
                str(perm_count),
            )

        console.print(table)

    # Deny policies table
    deny_policies = iam_data.get("deny_policies", [])
    if deny_policies:
        console.print("\n")
        table = Table(title=f"IAM Deny Policies ({len(deny_policies)} found)")
        table.add_column("Project", style="cyan")
        table.add_column("Display Name", style="red")
        table.add_column("Rules", style="yellow")
        table.add_column("Denied Principals")

        for policy in deny_policies:
            principals_summary = []
            for rule in policy.get("rules", []):
                principals_summary.extend(rule.get("denied_principals", []))

            # Deduplicate and limit to first 3
            principals_summary = list(set(principals_summary))[:3]
            principals_display = ", ".join(principals_summary)
            if len(policy.get("rules", [])) > 3:
                principals_display += "..."

            table.add_row(
                policy["project"],
                policy.get("display_name") or "-",
                str(len(policy.get("rules", []))),
                principals_display or "-",
            )

        console.print(table)
        console.print("[dim]Deny policies explicitly block access even if allow policies grant it.[/dim]")

    # gcloud policy data - DETAILED OUTPUT
    gcloud_policies = iam_data.get("gcloud_policies", [])
    if gcloud_policies:
        console.print("\n[bold cyan]═══ Additional IAM Data (via gcloud) ═══[/bold cyan]")
        for gcloud_data in gcloud_policies:
            project = gcloud_data["project"]
            policy = gcloud_data["policy"]

            console.print(f"\n[bold cyan]Project: {project}[/bold cyan]")

            # Show etag and version
            if "etag" in policy:
                console.print(f"[dim]Policy etag: {policy['etag']}[/dim]")
            if "version" in policy:
                console.print(f"[dim]Policy version: {policy['version']}[/dim]")

            # Show all bindings with members
            bindings = policy.get("bindings", [])
            console.print(f"\n[bold]IAM Bindings: {len(bindings)} total[/bold]")

            # Collect all unique members by type
            all_users = set()
            all_service_accounts = set()
            all_groups = set()
            all_domains = set()
            public_members = set()

            for binding in bindings:
                role = binding.get("role", "")
                members = binding.get("members", [])
                condition = binding.get("condition")

                # Categorize members
                for member in members:
                    if member in ("allUsers", "allAuthenticatedUsers"):
                        public_members.add(member)
                    elif member.startswith("user:"):
                        all_users.add(member)
                    elif member.startswith("serviceAccount:"):
                        all_service_accounts.add(member)
                    elif member.startswith("group:"):
                        all_groups.add(member)
                    elif member.startswith("domain:"):
                        all_domains.add(member)

                # Display binding details
                console.print(f"\n  [cyan]{role}[/cyan]")

                # Highlight public access
                if any(m in members for m in ("allUsers", "allAuthenticatedUsers")):
                    console.print(f"    [bold red]⚠ PUBLIC ACCESS[/bold red]")

                # Show condition if present
                if condition:
                    cond_title = condition.get("title", "Untitled")
                    cond_expr = condition.get("expression", "")
                    console.print(f"    [yellow]Condition: {cond_title}[/yellow]")
                    if cond_expr:
                        console.print(f"    [dim]Expression: {cond_expr[:80]}{'...' if len(cond_expr) > 80 else ''}[/dim]")

                # Show members grouped by type
                member_types = {
                    "Users": [m for m in members if m.startswith("user:")],
                    "Service Accounts": [m for m in members if m.startswith("serviceAccount:")],
                    "Groups": [m for m in members if m.startswith("group:")],
                    "Domains": [m for m in members if m.startswith("domain:")],
                    "Public": [m for m in members if m in ("allUsers", "allAuthenticatedUsers")],
                    "Other": [m for m in members if not any(m.startswith(p) for p in ("user:", "serviceAccount:", "group:", "domain:")) and m not in ("allUsers", "allAuthenticatedUsers")]
                }

                for member_type, type_members in member_types.items():
                    if type_members:
                        console.print(f"    [dim]{member_type} ({len(type_members)}):[/dim]")
                        for member in sorted(type_members)[:10]:  # Show first 10
                            # Extract email/identifier
                            display_member = member.split(":", 1)[-1] if ":" in member else member
                            color = "red" if member in ("allUsers", "allAuthenticatedUsers") else "green"
                            console.print(f"      [{color}]• {display_member}[/{color}]")
                        if len(type_members) > 10:
                            console.print(f"      [dim]... and {len(type_members) - 10} more[/dim]")

            # Summary section
            console.print(f"\n[bold yellow]Summary for {project}:[/bold yellow]")
            if all_users:
                console.print(f"  [green]Users discovered: {len(all_users)}[/green]")
                for user in sorted(all_users)[:5]:
                    console.print(f"    • {user.split(':', 1)[-1]}")
                if len(all_users) > 5:
                    console.print(f"    [dim]... and {len(all_users) - 5} more[/dim]")

            if all_groups:
                console.print(f"  [blue]Groups: {len(all_groups)}[/blue]")
                for group in sorted(all_groups)[:3]:
                    console.print(f"    • {group.split(':', 1)[-1]}")
                if len(all_groups) > 3:
                    console.print(f"    [dim]... and {len(all_groups) - 3} more[/dim]")

            if all_domains:
                console.print(f"  [magenta]Domains: {len(all_domains)}[/magenta]")
                for domain in sorted(all_domains):
                    console.print(f"    • {domain.split(':', 1)[-1]}")

            if public_members:
                console.print(f"  [bold red]⚠ Public Access: {', '.join(public_members)}[/bold red]")

            # Detailed Service Accounts section with roles
            if all_service_accounts:
                console.print(f"\n[bold cyan]Service Accounts Details ({len(all_service_accounts)} total):[/bold cyan]")

                # Build a mapping of service account -> roles
                sa_roles_map = {}
                for binding in bindings:
                    role = binding.get("role", "")
                    members = binding.get("members", [])
                    condition = binding.get("condition")

                    for member in members:
                        if member.startswith("serviceAccount:"):
                            if member not in sa_roles_map:
                                sa_roles_map[member] = []

                            role_info = {"role": role}
                            if condition:
                                role_info["condition"] = condition.get("title", "Conditional")
                            sa_roles_map[member].append(role_info)

                # Display each service account with its roles
                for sa in sorted(sa_roles_map.keys()):
                    sa_email = sa.split(":", 1)[-1]
                    roles = sa_roles_map[sa]

                    console.print(f"\n  [cyan]📧 {sa_email}[/cyan]")
                    console.print(f"     [dim]Roles: {len(roles)}[/dim]")

                    # Group roles by privilege level
                    high_priv_roles = [r for r in roles if any(x in r["role"].lower() for x in ["owner", "admin", "editor"])]
                    other_roles = [r for r in roles if r not in high_priv_roles]

                    # Show high privilege roles first
                    if high_priv_roles:
                        console.print(f"     [bold yellow]High Privilege:[/bold yellow]")
                        for role_info in high_priv_roles[:5]:
                            role_display = role_info["role"].replace("roles/", "")
                            if "condition" in role_info:
                                console.print(f"       [yellow]• {role_display}[/yellow] [dim](conditional: {role_info['condition']})[/dim]")
                            else:
                                console.print(f"       [yellow]• {role_display}[/yellow]")
                        if len(high_priv_roles) > 5:
                            console.print(f"       [dim]... and {len(high_priv_roles) - 5} more high-privilege roles[/dim]")

                    # Show other roles
                    if other_roles:
                        if high_priv_roles:
                            console.print(f"     [dim]Other Roles:[/dim]")
                        for role_info in other_roles[:5]:
                            role_display = role_info["role"].replace("roles/", "")
                            if "condition" in role_info:
                                console.print(f"       [dim]• {role_display} (conditional: {role_info['condition']})[/dim]")
                            else:
                                console.print(f"       [dim]• {role_display}[/dim]")
                        if len(other_roles) > 5:
                            console.print(f"       [dim]... and {len(other_roles) - 5} more roles[/dim]")

            # Highlight any audit configs if present
            audit_configs = policy.get("auditConfigs", [])
            if audit_configs:
                console.print(f"\n[yellow]Audit Logging Configurations: {len(audit_configs)} service(s)[/yellow]")
                for audit_config in audit_configs:
                    service = audit_config.get("service", "unknown")
                    log_configs = audit_config.get("auditLogConfigs", [])
                    log_types = [lc.get("logType", "UNKNOWN") for lc in log_configs]
                    console.print(f"  • {service}: {', '.join(log_types)}")

                    # Show exempted members if any
                    for lc in log_configs:
                        exempted = lc.get("exemptedMembers", [])
                        if exempted:
                            console.print(f"    [dim]Exempted from {lc.get('logType')}: {len(exempted)} member(s)[/dim]")
                            for exempt_member in exempted[:3]:
                                console.print(f"      [dim]- {exempt_member}[/dim]")
