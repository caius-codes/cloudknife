import json
from typing import Optional, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from botocore.exceptions import ClientError

from ...aws_session import AWSSessionManager


console = Console()


def _find_policy_in_cache(session_mgr: AWSSessionManager, arn: str) -> Optional[Dict[str, Any]]:
    """
    Cerca una policy già enumerata in iam_policies (per avere metadata subito).
    """
    session_name = session_mgr.current_session
    if not session_name:
        return None
    policies = (
        session_mgr.enumerated_data.get(session_name, {}).get("iam_policies")
        if session_name in session_mgr.enumerated_data
        else None
    )
    if not policies:
        return None
    for p in policies:
        if p.get("Arn") == arn:
            return p
    return None


def show_managed_policy_document(session_mgr: AWSSessionManager, arn: str) -> None:
    """
    Fetch and show managed policy document by ARN.
    Allows selecting which version to view if multiple versions exist.
    """
    console.print(f"[bold blue]🔍 Fetching managed policy document for ARN:[/bold blue] {arn}")

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    document = None
    selected_version_id = None
    default_version_id = None
    all_versions = []

    try:
        # 1) Get policy metadata and list all versions
        policy_meta = iam.get_policy(PolicyArn=arn)
        policy = policy_meta["Policy"]
        default_version_id = policy["DefaultVersionId"]

        # List all versions
        try:
            versions_resp = iam.list_policy_versions(PolicyArn=arn)
            all_versions = versions_resp.get("Versions", [])

            if len(all_versions) > 1:
                console.print(f"\n[bold yellow]Found {len(all_versions)} versions for this policy:[/bold yellow]")

                # Display versions table
                versions_table = Table(title="Available Policy Versions")
                versions_table.add_column("Version ID", style="cyan")
                versions_table.add_column("Is Default", style="green")
                versions_table.add_column("Created", style="dim")

                for v in all_versions:
                    is_default = "✓" if v["IsDefaultVersion"] else ""
                    versions_table.add_row(
                        v["VersionId"],
                        is_default,
                        str(v.get("CreateDate", ""))[:19]
                    )

                console.print(versions_table)

                # Ask which version to view
                version_ids = [v["VersionId"] for v in all_versions]
                selected_version_id = Prompt.ask(
                    f"[cyan]Which version to view?[/cyan]",
                    choices=version_ids,
                    default=default_version_id
                )
            else:
                selected_version_id = default_version_id
                console.print(f"[dim]Using version {selected_version_id} (only version available)[/dim]")

        except Exception as e:
            console.print(f"[yellow]Could not list policy versions: {str(e)}[/yellow]")
            console.print(f"[dim]Using default version {default_version_id}[/dim]")
            selected_version_id = default_version_id

        # 2) Fetch the selected version
        version_resp = iam.get_policy_version(
            PolicyArn=arn,
            VersionId=selected_version_id,
        )
        document = version_resp["PolicyVersion"]["Document"]

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        # If GetPolicy permission is missing, fallback to direct GetPolicyVersion
        if code in ("AccessDenied", "AccessDeniedException"):
            console.print(
                "[yellow]AccessDenied on iam:GetPolicy. Trying direct iam:GetPolicyVersion.[/yellow]"
            )
            # Try v1 as default, or ask the user
            version_id = Prompt.ask("[cyan]Policy VersionId to fetch (e.g. v1)[/cyan]", default="v1")
            try:
                version_resp = iam.get_policy_version(
                    PolicyArn=arn,
                    VersionId=version_id,
                )
                document = version_resp["PolicyVersion"]["Document"]
                selected_version_id = version_resp["PolicyVersion"]["VersionId"]
            except Exception as e2:
                console.print(f"[red]Failed to get policy version: {str(e2)}[/red]")
                console.print(
                    "[yellow]Ensure iam:GetPolicyVersion permission on the target policy.[/yellow]"
                )
                return
        else:
            console.print(f"[red]Failed to get policy document: {str(e)}[/red]")
            console.print(
                "[yellow]Ensure iam:GetPolicy and/or iam:GetPolicyVersion permissions.[/yellow]"
            )
            return
    except Exception as e:
        console.print(f"[red]Failed to get policy document: {str(e)}[/red]")
        console.print(
            "[yellow]Ensure iam:GetPolicy and/or iam:GetPolicyVersion permissions.[/yellow]"
        )
        return

    # Save to session data
    session_mgr.save_enumeration_data("iam_policy_document", {
        "Arn": arn,
        "VersionId": selected_version_id,
        "Document": document,
        "TotalVersions": len(all_versions)
    })

    # Output tabellare + JSON pretty
    cached = _find_policy_in_cache(session_mgr, arn)

    meta_table = Table(title="Managed Policy Metadata")
    meta_table.add_column("Field", style="cyan")
    meta_table.add_column("Value")
    meta_table.add_row("Arn", arn)
    if selected_version_id:
        is_default = " (default)" if selected_version_id == default_version_id else ""
        meta_table.add_row("Viewing Version", f"{selected_version_id}{is_default}")
    if len(all_versions) > 0:
        meta_table.add_row("Total Versions", str(len(all_versions)))
    if cached:
        meta_table.add_row("PolicyName", cached.get("PolicyName", ""))
        meta_table.add_row(
            "Scope",
            "AWS" if cached["Arn"].startswith("arn:aws:iam::aws:policy/") else "Local",
        )
        meta_table.add_row("AttachmentCount", str(cached.get("AttachmentCount", 0)))
    console.print(meta_table)

    console.print("[bold cyan]Policy Document:[/bold cyan]")
    pretty = json.dumps(document, indent=2)
    console.print(pretty)

    console.print(
        "[green]Policy document stored under key 'iam_policy_document' in session data.[/green]"
    )


def show_inline_policy_document(session_mgr: AWSSessionManager, entity_type: str, entity_name: str, policy_name: str) -> None:
    """
    Fetch and show inline policy document for a user or role.

    Args:
        entity_type: "user" or "role"
        entity_name: username or role name
        policy_name: inline policy name
    """
    console.print(f"[bold blue]🔍 Fetching inline policy document:[/bold blue]")
    console.print(f"  Type: {entity_type}")
    console.print(f"  {entity_type.capitalize()}: {entity_name}")
    console.print(f"  Policy: {policy_name}")

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    document = None

    try:
        if entity_type == "user":
            response = iam.get_user_policy(UserName=entity_name, PolicyName=policy_name)
        elif entity_type == "role":
            response = iam.get_role_policy(RoleName=entity_name, PolicyName=policy_name)
        else:
            console.print(f"[red]Invalid entity type: {entity_type}[/red]")
            return

        document = response.get("PolicyDocument")

        # Display metadata
        meta_table = Table(title="Inline Policy Metadata")
        meta_table.add_column("Field", style="cyan")
        meta_table.add_column("Value")
        meta_table.add_row("Type", "Inline")
        meta_table.add_row("Entity Type", entity_type.capitalize())
        meta_table.add_row(entity_type.capitalize() + " Name", entity_name)
        meta_table.add_row("Policy Name", policy_name)
        console.print(meta_table)

        console.print("[bold cyan]Policy Document:[/bold cyan]")
        pretty = json.dumps(document, indent=2)
        console.print(pretty)

        # Save to session
        session_mgr.save_enumeration_data("iam_inline_policy_document", {
            "EntityType": entity_type,
            "EntityName": entity_name,
            "PolicyName": policy_name,
            "Document": document
        })
        console.print(
            "[green]Inline policy document stored under key 'iam_inline_policy_document' in session data.[/green]"
        )

    except Exception as e:
        console.print(f"[red]Failed to get inline policy: {str(e)}[/red]")
        if entity_type == "user":
            console.print("[yellow]Ensure iam:GetUserPolicy permission.[/yellow]")
        else:
            console.print("[yellow]Ensure iam:GetRolePolicy permission.[/yellow]")


def show_attached_policies(session_mgr: AWSSessionManager, entity_type: str, entity_name: str) -> None:
    """
    List and optionally view attached managed policies for a user or role.

    Args:
        entity_type: "user" or "role"
        entity_name: username or role name
    """
    console.print(f"[bold blue]🔍 Listing attached policies for {entity_type}: {entity_name}[/bold blue]")

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    try:
        if entity_type == "user":
            response = iam.list_attached_user_policies(UserName=entity_name)
        elif entity_type == "role":
            response = iam.list_attached_role_policies(RoleName=entity_name)
        else:
            console.print(f"[red]Invalid entity type: {entity_type}[/red]")
            return

        attached_policies = response.get("AttachedPolicies", [])

        if not attached_policies:
            console.print(f"[yellow]No attached policies found for {entity_type} '{entity_name}'.[/yellow]")
            return

        # Display table of attached policies
        table = Table(title=f"Attached Policies for {entity_type.capitalize()}: {entity_name}")
        table.add_column("Policy Name", style="cyan", overflow="fold", no_wrap=False)
        table.add_column("Policy ARN", style="dim", overflow="fold", no_wrap=False)

        for policy in attached_policies:
            table.add_row(
                policy.get("PolicyName", ""),
                policy.get("PolicyArn", "")
            )

        console.print(table)
        console.print(f"\n[green]Found {len(attached_policies)} attached policy/policies.[/green]")

        # Ask if user wants to view one of the policy documents
        if Confirm.ask("[cyan]View one of these policy documents?[/cyan]", default=False):
            policy_names = [p["PolicyName"] for p in attached_policies]
            selected_name = Prompt.ask(
                "[cyan]Select policy name[/cyan]",
                choices=policy_names
            )

            # Find the ARN for the selected policy
            selected_arn = next(
                (p["PolicyArn"] for p in attached_policies if p["PolicyName"] == selected_name),
                None
            )

            if selected_arn:
                console.print()
                show_managed_policy_document(session_mgr, selected_arn)

    except Exception as e:
        console.print(f"[red]Failed to list attached policies: {str(e)}[/red]")
        if entity_type == "user":
            console.print("[yellow]Ensure iam:ListAttachedUserPolicies permission.[/yellow]")
        else:
            console.print("[yellow]Ensure iam:ListAttachedRolePolicies permission.[/yellow]")


def show_policy_document(session_mgr: AWSSessionManager, arn: Optional[str] = None) -> None:
    """
    Interactive wrapper to fetch and show IAM policy documents.
    Supports:
    - Managed policies (by ARN)
    - Inline policies (by name + entity)
    - Attached policies (list attached policies for user/role)
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    console.print("[bold yellow]🔍 IAM Policy Document Viewer[/bold yellow]")
    console.print("[dim]Choose policy type:[/dim]\n")

    console.print("[1] Managed policy (requires ARN)")
    console.print("[2] Inline user policy (requires username + policy name)")
    console.print("[3] Inline role policy (requires role name + policy name)")
    console.print("[4] Attached policies for user (list + view)")
    console.print("[5] Attached policies for role (list + view)")

    choice = Prompt.ask("[cyan]Select option[/cyan]", choices=["1", "2", "3", "4", "5"], default="1")

    if choice == "1":
        # Managed policy
        if not arn:
            arn = Prompt.ask("[cyan]Policy ARN[/cyan]").strip()
        show_managed_policy_document(session_mgr, arn)

    elif choice == "2":
        # Inline user policy
        username = Prompt.ask("[cyan]Username[/cyan]").strip()
        policy_name = Prompt.ask("[cyan]Policy name[/cyan]").strip()
        show_inline_policy_document(session_mgr, "user", username, policy_name)

    elif choice == "3":
        # Inline role policy
        rolename = Prompt.ask("[cyan]Role name[/cyan]").strip()
        policy_name = Prompt.ask("[cyan]Policy name[/cyan]").strip()
        show_inline_policy_document(session_mgr, "role", rolename, policy_name)

    elif choice == "4":
        # Attached user policies
        username = Prompt.ask("[cyan]Username[/cyan]").strip()
        show_attached_policies(session_mgr, "user", username)

    elif choice == "5":
        # Attached role policies
        rolename = Prompt.ask("[cyan]Role name[/cyan]").strip()
        show_attached_policies(session_mgr, "role", rolename)
