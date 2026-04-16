"""
Vulnerable OIDC Provider Enumeration Module

Detects insecure GitHub OIDC configurations in AWS IAM roles.
Identifies two main vulnerability types:
1. Missing subject validation - roles without 'sub' claim conditions
2. Bypassable subject patterns - overly permissive wildcard patterns

Inspired by Rezonate.io's github-oidc-checker.
"""

import json
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ...aws_session import AWSSessionManager

console = Console()


def check_vulnerable_subject_pattern(sub_patterns: Any) -> bool:
    """
    Check if subject pattern has wildcard before repository path.

    Vulnerable pattern example: repo:org/*:ref:refs/heads/main
    The wildcard appears before the '/' which should separate org/repo.

    Safe pattern example: repo:org/myrepo:*

    Args:
        sub_patterns: Subject pattern(s) from condition

    Returns:
        True if pattern is vulnerable, False otherwise
    """
    if not isinstance(sub_patterns, list):
        sub_patterns = [sub_patterns]

    for pattern in sub_patterns:
        if not isinstance(pattern, str):
            continue

        # Check if wildcard exists
        if "*" not in pattern:
            continue

        # Check if there's a forward slash after the wildcard
        try:
            wildcard_index = pattern.index("*")
            slash_index = pattern.index("/")

            # Vulnerable if wildcard comes before the slash
            # This means wildcard is in the org position, not repo
            if wildcard_index > 0 and wildcard_index < slash_index:
                return True
        except ValueError:
            # No slash found or other parsing issue
            continue

    return False


def enumerate_vulnerable_oidc(session_mgr: AWSSessionManager, provider_filter: Optional[str] = None) -> None:
    """
    Enumerate OIDC providers and identify vulnerable IAM role trust policies.

    Focuses on GitHub OIDC (token.actions.githubusercontent.com) by default.

    Args:
        session_mgr: Session manager instance
        provider_filter: Optional filter for specific OIDC provider URL pattern
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    console.print("[bold blue]🔍 Scanning for vulnerable OIDC configurations...[/bold blue]\n")

    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    # Step 1: List OIDC providers
    try:
        console.print("[dim]→ Enumerating OIDC identity providers...[/dim]")
        oidc_providers = iam.list_open_id_connect_providers()
    except Exception as e:
        console.print(f"[red]Failed to list OIDC providers: {str(e)}[/red]")
        return

    if not oidc_providers.get("OpenIDConnectProviderList"):
        console.print("[yellow]No OIDC identity providers found in this account.[/yellow]")
        return

    # Step 2: Filter for GitHub (or custom provider)
    github_providers = []
    target_suffix = "token.actions.githubusercontent.com"

    if provider_filter:
        target_suffix = provider_filter

    for provider in oidc_providers["OpenIDConnectProviderList"]:
        provider_arn = provider["Arn"]
        if provider_arn.endswith(target_suffix):
            github_providers.append(provider_arn)

    if not github_providers:
        console.print(f"[yellow]No OIDC provider found for '{target_suffix}'.[/yellow]")
        return

    console.print(f"[green]✓ Found {len(github_providers)} GitHub OIDC provider(s)[/green]")
    for arn in github_providers:
        console.print(f"  [dim]{arn}[/dim]")

    # Step 3: Enumerate all IAM roles
    console.print("\n[dim]→ Enumerating IAM roles...[/dim]")

    try:
        paginator = iam.get_paginator("list_roles")
        all_roles = []

        for page in paginator.paginate():
            all_roles.extend(page.get("Roles", []))

        console.print(f"[green]✓ Found {len(all_roles)} IAM roles[/green]")
    except Exception as e:
        console.print(f"[red]Failed to enumerate roles: {str(e)}[/red]")
        return

    # Step 4: Find roles that trust GitHub OIDC
    console.print("\n[dim]→ Analyzing trust policies for GitHub OIDC...[/dim]")

    github_roles = []

    for role in all_roles:
        assume_role_policy = role.get("AssumeRolePolicyDocument")
        if not assume_role_policy:
            continue

        statements = assume_role_policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            # Only check Allow statements
            if statement.get("Effect") != "Allow":
                continue

            # Check principals
            principals = statement.get("Principal", {})
            if isinstance(principals, str):
                principals = {"Federated": principals}

            # Check if Federated principal is GitHub OIDC
            federated = principals.get("Federated", "")
            if isinstance(federated, str) and federated.endswith("oidc-provider/token.actions.githubusercontent.com"):
                github_roles.append({
                    "role": role,
                    "statement": statement
                })
                break

    if not github_roles:
        console.print("[yellow]No IAM roles found that trust GitHub OIDC.[/yellow]")
        return

    console.print(f"[green]✓ Found {len(github_roles)} role(s) trusting GitHub OIDC[/green]\n")

    # Step 5: Check for vulnerabilities
    console.print("[bold]→ Checking for vulnerabilities...[/bold]\n")

    vulnerable_missing_subject = []
    vulnerable_bypassable_subject = []
    secure_roles = []

    for item in github_roles:
        role = item["role"]
        statement = item["statement"]
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # Check if there's a Condition on the subject claim
        condition = statement.get("Condition", {})
        condition_json = json.dumps(condition, default=str)

        # Vulnerability 1: Missing subject validation
        if not condition or "token.actions.githubusercontent.com:sub" not in condition_json:
            vulnerable_missing_subject.append({
                "name": role_name,
                "arn": role_arn,
                "created": str(role.get("CreateDate", ""))[:19],
                "description": role.get("Description", ""),
            })
            continue

        # Vulnerability 2: Bypassable subject pattern
        # Check StringLike conditions
        string_like = condition.get("StringLike", {})
        subject_patterns = string_like.get("token.actions.githubusercontent.com:sub")

        if subject_patterns and check_vulnerable_subject_pattern(subject_patterns):
            vulnerable_bypassable_subject.append({
                "name": role_name,
                "arn": role_arn,
                "created": str(role.get("CreateDate", ""))[:19],
                "pattern": subject_patterns if isinstance(subject_patterns, str) else json.dumps(subject_patterns),
            })
            continue

        # Role appears secure
        secure_roles.append({
            "name": role_name,
            "arn": role_arn,
        })

    # Step 6: Display results
    total_vulnerable = len(vulnerable_missing_subject) + len(vulnerable_bypassable_subject)

    if total_vulnerable == 0:
        console.print(Panel(
            "[green]✓ No vulnerable OIDC configurations detected!\n\n"
            f"All {len(secure_roles)} GitHub OIDC roles have proper subject validation.[/green]",
            title="[bold green]Security Check: PASSED[/bold green]",
            border_style="green"
        ))
    else:
        console.print(Panel(
            f"[red]⚠ Found {total_vulnerable} vulnerable role(s)!\n\n"
            f"• Missing subject validation: {len(vulnerable_missing_subject)}\n"
            f"• Bypassable subject pattern: {len(vulnerable_bypassable_subject)}[/red]",
            title="[bold red]Security Check: FAILED[/bold red]",
            border_style="red"
        ))

    # Display vulnerable roles - Missing Subject
    if vulnerable_missing_subject:
        console.print("\n[bold red]🚨 Vulnerable: Missing Subject Validation[/bold red]")
        console.print("[dim]These roles allow ANY GitHub repository to assume them![/dim]\n")

        table = Table(title="Missing Subject Validation")
        table.add_column("Role Name", style="red")
        table.add_column("ARN", no_wrap=True, overflow="fold")
        table.add_column("Created", style="dim")

        for vuln_role in vulnerable_missing_subject:
            table.add_row(
                vuln_role["name"],
                vuln_role["arn"],
                vuln_role["created"]
            )

        console.print(table)
        console.print("\n[yellow]Remediation:[/yellow] Add a Condition on 'token.actions.githubusercontent.com:sub'")
        console.print("[dim]Example: StringEquals: {'token.actions.githubusercontent.com:sub': 'repo:org/repo:ref:refs/heads/main'}[/dim]\n")

    # Display vulnerable roles - Bypassable Subject
    if vulnerable_bypassable_subject:
        console.print("\n[bold red]🚨 Vulnerable: Bypassable Subject Pattern[/bold red]")
        console.print("[dim]These roles use wildcards that can be bypassed![/dim]\n")

        table = Table(title="Bypassable Subject Pattern")
        table.add_column("Role Name", style="red")
        table.add_column("ARN", no_wrap=True, overflow="fold")
        table.add_column("Vulnerable Pattern", style="yellow")

        for vuln_role in vulnerable_bypassable_subject:
            table.add_row(
                vuln_role["name"],
                vuln_role["arn"],
                vuln_role["pattern"]
            )

        console.print(table)
        console.print("\n[yellow]Remediation:[/yellow] Move wildcards to AFTER the repository path")
        console.print("[dim]❌ Bad:  repo:org/*:ref:refs/heads/main[/dim]")
        console.print("[dim]✅ Good: repo:org/myrepo:*[/dim]\n")

    # Display secure roles
    if secure_roles:
        console.print("\n[bold green]✓ Secure Roles[/bold green]")
        console.print("[dim]These roles have proper subject validation[/dim]\n")

        table = Table(title=f"Secure OIDC Roles ({len(secure_roles)})")
        table.add_column("Role Name", style="green")
        table.add_column("ARN", no_wrap=True, overflow="fold", style="dim")

        for secure_role in secure_roles:
            table.add_row(
                secure_role["name"],
                secure_role["arn"]
            )

        console.print(table)

    # Save results to session
    results = {
        "vulnerable_missing_subject": vulnerable_missing_subject,
        "vulnerable_bypassable_subject": vulnerable_bypassable_subject,
        "secure_roles": secure_roles,
        "total_github_roles": len(github_roles),
        "total_vulnerable": total_vulnerable,
    }

    session_mgr.save_enumeration_data("vulnerable_oidc", results)
    console.print("\n[green]Results saved to session data under 'vulnerable_oidc'.[/green]")
