from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...aws_session import AWSSessionManager

console = Console()


def enumerate_policies(session_mgr: AWSSessionManager, scope: str = "All", only_attached: bool = False) -> None:
    """
    Enumerate IAM policies with pagination and filters.
    - scope: All | AWS | Local
    - only_attached: if True, returns only policies that are attached at least once.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    scope = scope.capitalize()
    if scope not in ("All", "Aws", "Local"):
        console.print("[red]Invalid scope. Use: All, AWS, Local.[/red]")
        return
    if scope == "Aws":
        scope = "AWS"  # AWS API expects 'AWS'

    console.print(
        f"[bold blue]🔍 Enumerating IAM policies (Scope={scope}, OnlyAttached={only_attached})...[/bold blue]"
    )

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    paginator = iam.get_paginator("list_policies")
    policies: List[Dict] = []

    try:
        for page in paginator.paginate(Scope=scope, OnlyAttached=only_attached, MaxItems=1000):
            for p in page.get("Policies", []):
                policies.append(
                    {
                        "PolicyName": p["PolicyName"],
                        "PolicyId": p["PolicyId"],
                        "Arn": p["Arn"],
                        "Path": p["Path"],
                        "DefaultVersionId": p["DefaultVersionId"],
                        "AttachmentCount": p.get("AttachmentCount", 0),
                        "IsAttachable": p.get("IsAttachable", True),
                        "CreateDate": str(p["CreateDate"])[:19],
                        "UpdateDate": str(p["UpdateDate"])[:19] if "UpdateDate" in p else "",
                    }
                )
    except Exception as e:
        console.print(f"[red]Policy enumeration failed: {str(e)}[/red]")
        console.print("[yellow]Ensure IAM:ListPolicies permission.[/yellow]")
        return

    # Save to session
    session_mgr.save_enumeration_data("iam_policies", policies)

    if not policies:
        console.print("[yellow]No IAM policies found with the given filters.[/yellow]")
        return

    # Output tabellare (riassunto)
    table = Table(title=f"IAM Policies (total: {len(policies)})")
    table.add_column("PolicyName", style="cyan")
    table.add_column("Scope")
    table.add_column("Attached")
    table.add_column("Arn", no_wrap=True, overflow="fold")
    table.add_column("Created")

    for p in policies:
        scope_str = "AWS" if p["Arn"].startswith("arn:aws:iam::aws:policy/") else "Local"
        attached = "Yes" if p["AttachmentCount"] > 0 else "No"
        table.add_row(
            p["PolicyName"],
            scope_str,
            attached,
            p["Arn"],
            p["CreateDate"],
        )

    console.print(table)
    console.print("[green]IAM policies enumeration stored under key 'iam_policies' in session data.[/green]")
    console.print(
        "[dim]Tip: use this together with bruteforce_permissions to understand effective permission landscape.[/dim]"
    )


def enumerate_inline_user_policies(session_mgr: AWSSessionManager, username: str = None) -> None:
    """
    Enumerate inline policies for IAM users.
    If username is provided, enumerate only for that user.
    Otherwise, enumerate for all users.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    users_to_check = []

    # Get list of users
    if username:
        users_to_check = [username]
        console.print(f"[bold blue]🔍 Enumerating inline policies for user: {username}...[/bold blue]")
    else:
        console.print("[bold blue]🔍 Enumerating inline policies for all users...[/bold blue]")
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    users_to_check.append(user["UserName"])
        except Exception as e:
            console.print(f"[red]Failed to list users: {str(e)}[/red]")
            return

    results = []

    for user in users_to_check:
        try:
            response = iam.list_user_policies(UserName=user)
            policy_names = response.get("PolicyNames", [])

            for policy_name in policy_names:
                # Get policy document
                try:
                    policy_doc = iam.get_user_policy(UserName=user, PolicyName=policy_name)
                    results.append({
                        "Type": "Inline",
                        "EntityType": "User",
                        "EntityName": user,
                        "PolicyName": policy_name,
                        "PolicyDocument": policy_doc.get("PolicyDocument", {})
                    })
                except Exception as e:
                    console.print(f"[yellow]Failed to get policy {policy_name} for user {user}: {str(e)}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Failed to list policies for user {user}: {str(e)}[/yellow]")

    if not results:
        console.print("[yellow]No inline user policies found.[/yellow]")
        return

    # Display results
    table = Table(title=f"Inline User Policies (total: {len(results)})")
    table.add_column("User", style="cyan")
    table.add_column("Policy Name", style="green")

    for r in results:
        table.add_row(r["EntityName"], r["PolicyName"])

    console.print(table)

    # Save to session
    session_mgr.save_enumeration_data("iam_inline_user_policies", results)
    console.print("[green]Inline user policies saved to session data under 'iam_inline_user_policies'.[/green]")


def enumerate_inline_role_policies(session_mgr: AWSSessionManager, rolename: str = None) -> None:
    """
    Enumerate inline policies for IAM roles.
    If rolename is provided, enumerate only for that role.
    Otherwise, enumerate for all roles.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    roles_to_check = []

    # Get list of roles
    if rolename:
        roles_to_check = [rolename]
        console.print(f"[bold blue]🔍 Enumerating inline policies for role: {rolename}...[/bold blue]")
    else:
        console.print("[bold blue]🔍 Enumerating inline policies for all roles...[/bold blue]")
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    roles_to_check.append(role["RoleName"])
        except Exception as e:
            console.print(f"[red]Failed to list roles: {str(e)}[/red]")
            return

    results = []

    for role in roles_to_check:
        try:
            response = iam.list_role_policies(RoleName=role)
            policy_names = response.get("PolicyNames", [])

            for policy_name in policy_names:
                # Get policy document
                try:
                    policy_doc = iam.get_role_policy(RoleName=role, PolicyName=policy_name)
                    results.append({
                        "Type": "Inline",
                        "EntityType": "Role",
                        "EntityName": role,
                        "PolicyName": policy_name,
                        "PolicyDocument": policy_doc.get("PolicyDocument", {})
                    })
                except Exception as e:
                    console.print(f"[yellow]Failed to get policy {policy_name} for role {role}: {str(e)}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Failed to list policies for role {role}: {str(e)}[/yellow]")

    if not results:
        console.print("[yellow]No inline role policies found.[/yellow]")
        return

    # Display results
    table = Table(title=f"Inline Role Policies (total: {len(results)})")
    table.add_column("Role", style="cyan")
    table.add_column("Policy Name", style="green")

    for r in results:
        table.add_row(r["EntityName"], r["PolicyName"])

    console.print(table)

    # Save to session
    session_mgr.save_enumeration_data("iam_inline_role_policies", results)
    console.print("[green]Inline role policies saved to session data under 'iam_inline_role_policies'.[/green]")


def enumerate_attached_user_policies(session_mgr: AWSSessionManager, username: str = None) -> None:
    """
    Enumerate managed policies attached to IAM users.
    If username is provided, enumerate only for that user.
    Otherwise, enumerate for all users.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    users_to_check = []

    # Get list of users
    if username:
        users_to_check = [username]
        console.print(f"[bold blue]🔍 Enumerating attached policies for user: {username}...[/bold blue]")
    else:
        console.print("[bold blue]🔍 Enumerating attached policies for all users...[/bold blue]")
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    users_to_check.append(user["UserName"])
        except Exception as e:
            console.print(f"[red]Failed to list users: {str(e)}[/red]")
            return

    results = []

    for user in users_to_check:
        try:
            response = iam.list_attached_user_policies(UserName=user)
            attached_policies = response.get("AttachedPolicies", [])

            for policy in attached_policies:
                results.append({
                    "Type": "Attached",
                    "EntityType": "User",
                    "EntityName": user,
                    "PolicyName": policy["PolicyName"],
                    "PolicyArn": policy["PolicyArn"]
                })
        except Exception as e:
            console.print(f"[yellow]Failed to list attached policies for user {user}: {str(e)}[/yellow]")

    if not results:
        console.print("[yellow]No attached user policies found.[/yellow]")
        return

    # Display results
    table = Table(title=f"Attached User Policies (total: {len(results)})")
    table.add_column("User", style="cyan")
    table.add_column("Policy Name", style="green")
    table.add_column("Policy ARN", no_wrap=True, overflow="fold")

    for r in results:
        table.add_row(r["EntityName"], r["PolicyName"], r["PolicyArn"])

    console.print(table)

    # Save to session
    session_mgr.save_enumeration_data("iam_attached_user_policies", results)
    console.print("[green]Attached user policies saved to session data under 'iam_attached_user_policies'.[/green]")


def enumerate_attached_role_policies(session_mgr: AWSSessionManager, rolename: str = None) -> None:
    """
    Enumerate managed policies attached to IAM roles.
    If rolename is provided, enumerate only for that role.
    Otherwise, enumerate for all roles.
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    roles_to_check = []

    # Get list of roles
    if rolename:
        roles_to_check = [rolename]
        console.print(f"[bold blue]🔍 Enumerating attached policies for role: {rolename}...[/bold blue]")
    else:
        console.print("[bold blue]🔍 Enumerating attached policies for all roles...[/bold blue]")
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    roles_to_check.append(role["RoleName"])
        except Exception as e:
            console.print(f"[red]Failed to list roles: {str(e)}[/red]")
            return

    results = []

    for role in roles_to_check:
        try:
            response = iam.list_attached_role_policies(RoleName=role)
            attached_policies = response.get("AttachedPolicies", [])

            for policy in attached_policies:
                results.append({
                    "Type": "Attached",
                    "EntityType": "Role",
                    "EntityName": role,
                    "PolicyName": policy["PolicyName"],
                    "PolicyArn": policy["PolicyArn"]
                })
        except Exception as e:
            console.print(f"[yellow]Failed to list attached policies for role {role}: {str(e)}[/yellow]")

    if not results:
        console.print("[yellow]No attached role policies found.[/yellow]")
        return

    # Display results
    table = Table(title=f"Attached Role Policies (total: {len(results)})")
    table.add_column("Role", style="cyan")
    table.add_column("Policy Name", style="green")
    table.add_column("Policy ARN", no_wrap=True, overflow="fold")

    for r in results:
        table.add_row(r["EntityName"], r["PolicyName"], r["PolicyArn"])

    console.print(table)

    # Save to session
    session_mgr.save_enumeration_data("iam_attached_role_policies", results)
    console.print("[green]Attached role policies saved to session data under 'iam_attached_role_policies'.[/green]")


def enumerate_policies_interactive(session_mgr: AWSSessionManager) -> None:
    """
    Interactive wrapper for policy enumeration with multiple options.
    """
    console.print("[bold yellow]🔍 IAM Policy Enumeration[/bold yellow]")
    console.print("[dim]Choose what type of policies to enumerate:[/dim]\n")

    console.print("[1] Managed policies (AWS-managed and customer-managed)")
    console.print("[2] Inline policies for users")
    console.print("[3] Inline policies for roles")
    console.print("[4] Attached policies for users")
    console.print("[5] Attached policies for roles")

    choice = Prompt.ask("[cyan]Select option[/cyan]", choices=["1", "2", "3", "4", "5"], default="1")

    if choice == "1":
        # Original managed policies enumeration
        scope = Prompt.ask("[cyan]Scope (All/AWS/Local)[/cyan]", default="All")
        only_attached_str = Prompt.ask("[cyan]Only attached? (y/N)[/cyan]", default="N")
        only_attached = only_attached_str.lower().startswith("y")
        enumerate_policies(session_mgr, scope=scope, only_attached=only_attached)

    elif choice == "2":
        # Inline user policies
        specify = Confirm.ask("[cyan]Specify a user? (No = enumerate all users)[/cyan]", default=False)
        if specify:
            username = Prompt.ask("[cyan]Username[/cyan]").strip()
            enumerate_inline_user_policies(session_mgr, username if username else None)
        else:
            enumerate_inline_user_policies(session_mgr)

    elif choice == "3":
        # Inline role policies
        specify = Confirm.ask("[cyan]Specify a role? (No = enumerate all roles)[/cyan]", default=False)
        if specify:
            rolename = Prompt.ask("[cyan]Role name[/cyan]").strip()
            enumerate_inline_role_policies(session_mgr, rolename if rolename else None)
        else:
            enumerate_inline_role_policies(session_mgr)

    elif choice == "4":
        # Attached user policies
        specify = Confirm.ask("[cyan]Specify a user? (No = enumerate all users)[/cyan]", default=False)
        if specify:
            username = Prompt.ask("[cyan]Username[/cyan]").strip()
            enumerate_attached_user_policies(session_mgr, username if username else None)
        else:
            enumerate_attached_user_policies(session_mgr)

    elif choice == "5":
        # Attached role policies
        specify = Confirm.ask("[cyan]Specify a role? (No = enumerate all roles)[/cyan]", default=False)
        if specify:
            rolename = Prompt.ask("[cyan]Role name[/cyan]").strip()
            enumerate_attached_role_policies(session_mgr, rolename if rolename else None)
        else:
            enumerate_attached_role_policies(session_mgr)
