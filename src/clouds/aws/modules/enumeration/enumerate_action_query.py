"""
IAM Action Query Module

Query IAM permissions for users and roles to identify which principals
have specific permissions and on which resources.

Inspired by Pacu's iam__enum_action_query module.
"""

import fnmatch
import json
from typing import List, Dict, Set, Optional, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ...aws_session import AWSSessionManager

console = Console()


def expand_action_pattern(pattern: str, all_actions: Set[str]) -> Set[str]:
    """
    Expand action pattern with wildcards to matching actions.

    Examples:
        s3:* -> all s3 actions
        s3:Get* -> s3:GetObject, s3:GetBucket, etc.
        iam:List* -> iam:ListUsers, iam:ListRoles, etc.

    Args:
        pattern: Action pattern (e.g., "s3:GetObject", "s3:*")
        all_actions: Set of all known actions to match against

    Returns:
        Set of matching actions
    """
    # If pattern has no wildcard, return as-is
    if '*' not in pattern and '?' not in pattern:
        return {pattern}

    # Match pattern against all known actions
    matched = set()
    for action in all_actions:
        if fnmatch.fnmatch(action, pattern):
            matched.add(action)

    return matched


def extract_actions_from_policy_document(policy_doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Extract actions and resources from a policy document.

    Returns:
        Dict with "Allow" and "Deny" keys, each containing:
        {
            action: {
                "Resources": [...],
                "Conditions": {...}
            }
        }
    """
    result = {"Allow": {}, "Deny": {}}

    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect", "")
        if effect not in ("Allow", "Deny"):
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        condition = statement.get("Condition", {})

        for action in actions:
            # Expand wildcard actions
            if '*' in action:
                # Store wildcard pattern as-is for later matching
                result[effect][action] = {
                    "Resources": resources,
                    "Conditions": condition
                }
            else:
                result[effect][action] = {
                    "Resources": resources,
                    "Conditions": condition
                }

    return result


def get_all_actions_from_policies(permissions_data: Dict[str, Dict[str, Any]]) -> Set[str]:
    """
    Extract all unique actions from permissions data.
    Used for wildcard expansion.
    """
    actions = set()

    for effect in ["Allow", "Deny"]:
        for action in permissions_data.get(effect, {}).keys():
            # Don't add wildcard patterns themselves
            if '*' not in action and '?' not in action:
                actions.add(action)

    return actions


def match_action_against_permissions(query_action: str, permissions: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check if a query action is covered by the permissions (including wildcards).

    Args:
        query_action: Specific action to check (e.g., "s3:GetObject")
        permissions: Dict of {action: {Resources, Conditions}}

    Returns:
        Permission details if matched, None otherwise
    """
    # Direct match
    if query_action in permissions:
        return permissions[query_action]

    # Check wildcard patterns
    for perm_action, perm_details in permissions.items():
        if '*' in perm_action or '?' in perm_action:
            if fnmatch.fnmatch(query_action, perm_action):
                return perm_details

    return None


def enumerate_action_query(
    session_mgr: AWSSessionManager,
    query: str,
    all_or_none: bool = False,
    role_filter: Optional[str] = None,
    user_filter: Optional[str] = None
):
    """
    Query IAM permissions to find which users/roles have specific actions.

    Args:
        session_mgr: Session manager instance
        query: Comma-separated actions to query (e.g., "s3:GetObject,iam:ListUsers")
        all_or_none: If True, only show principals with ALL queried actions
        role_filter: Filter to specific role(s), comma-separated
        user_filter: Filter to specific user(s), comma-separated
    """
    if not session_mgr.current_session_data.get("access_key"):
        console.print("[red]No credentials in current session. Run 'set_keys'.[/red]")
        return

    # Parse query actions
    query_actions = [action.strip() for action in query.split(",")]
    if not query_actions:
        console.print("[red]No actions specified in query.[/red]")
        return

    console.print(f"[bold blue]🔍 Querying IAM permissions for actions: {', '.join(query_actions)}[/bold blue]")
    if all_or_none:
        console.print("[dim]Mode: ALL-OR-NONE (showing only principals with ALL queried actions)[/dim]")

    # Parse filters
    role_filters = set()
    user_filters = set()
    if role_filter:
        role_filters = {r.strip() for r in role_filter.split(",")}
    if user_filter:
        user_filters = {u.strip() for u in user_filter.split(",")}

    # Load enumerated policy data from session
    inline_user_policies = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_inline_user_policies", [])
    inline_role_policies = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_inline_role_policies", [])
    attached_user_policies = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_attached_user_policies", [])
    attached_role_policies = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_attached_role_policies", [])

    # Auto-enumerate if no policy data found
    if not any([inline_user_policies, inline_role_policies, attached_user_policies, attached_role_policies]):
        console.print("[yellow]No policy data found in session. Enumerating policies automatically...[/yellow]")

        # Import the enumeration functions
        from .iam_policies import (
            enumerate_inline_user_policies,
            enumerate_inline_role_policies,
            enumerate_attached_user_policies,
            enumerate_attached_role_policies,
        )

        # Enumerate all policies
        console.print("[dim]→ Enumerating inline user policies...[/dim]")
        enumerate_inline_user_policies(session_mgr)

        console.print("[dim]→ Enumerating inline role policies...[/dim]")
        enumerate_inline_role_policies(session_mgr)

        console.print("[dim]→ Enumerating attached user policies...[/dim]")
        enumerate_attached_user_policies(session_mgr)

        console.print("[dim]→ Enumerating attached role policies...[/dim]")
        enumerate_attached_role_policies(session_mgr)

        console.print("[green]✓ Policy enumeration complete[/green]\n")

        # Reload data after enumeration
        inline_user_policies = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_inline_user_policies", [])
        inline_role_policies = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_inline_role_policies", [])
        attached_user_policies = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_attached_user_policies", [])
        attached_role_policies = session_mgr.enumerated_data.get(session_mgr.current_session, {}).get("iam_attached_role_policies", [])

        if not any([inline_user_policies, inline_role_policies, attached_user_policies, attached_role_policies]):
            console.print("[red]Still no policy data after enumeration. Check IAM permissions.[/red]")
            return

    # Build permissions database
    # Structure: {principal_name: {type: user/role, permissions: {Allow: {...}, Deny: {...}}}}
    principals_db: Dict[str, Dict[str, Any]] = {}

    # Process inline user policies
    for policy in inline_user_policies:
        entity_name = policy["EntityName"]
        if user_filters and entity_name not in user_filters:
            continue

        if entity_name not in principals_db:
            principals_db[entity_name] = {
                "type": "User",
                "permissions": {"Allow": {}, "Deny": {}}
            }

        policy_doc = policy.get("PolicyDocument", {})
        extracted = extract_actions_from_policy_document(policy_doc)

        # Merge permissions
        for effect in ["Allow", "Deny"]:
            principals_db[entity_name]["permissions"][effect].update(extracted[effect])

    # Process inline role policies
    for policy in inline_role_policies:
        entity_name = policy["EntityName"]
        if role_filters and entity_name not in role_filters:
            continue

        if entity_name not in principals_db:
            principals_db[entity_name] = {
                "type": "Role",
                "permissions": {"Allow": {}, "Deny": {}}
            }

        policy_doc = policy.get("PolicyDocument", {})
        extracted = extract_actions_from_policy_document(policy_doc)

        # Merge permissions
        for effect in ["Allow", "Deny"]:
            principals_db[entity_name]["permissions"][effect].update(extracted[effect])

    # Process attached user policies (need to fetch policy documents)
    aws_sess = session_mgr.get_boto3_session()
    iam = aws_sess.client("iam")

    for policy_attachment in attached_user_policies:
        entity_name = policy_attachment["EntityName"]
        if user_filters and entity_name not in user_filters:
            continue

        if entity_name not in principals_db:
            principals_db[entity_name] = {
                "type": "User",
                "permissions": {"Allow": {}, "Deny": {}}
            }

        # Fetch policy document
        policy_arn = policy_attachment["PolicyArn"]
        try:
            policy_response = iam.get_policy(PolicyArn=policy_arn)
            default_version_id = policy_response["Policy"]["DefaultVersionId"]

            policy_version_response = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            policy_doc = policy_version_response["PolicyVersion"]["Document"]

            extracted = extract_actions_from_policy_document(policy_doc)

            # Merge permissions
            for effect in ["Allow", "Deny"]:
                principals_db[entity_name]["permissions"][effect].update(extracted[effect])
        except Exception as e:
            console.print(f"[yellow]Failed to fetch policy {policy_arn}: {str(e)}[/yellow]")

    # Process attached role policies
    for policy_attachment in attached_role_policies:
        entity_name = policy_attachment["EntityName"]
        if role_filters and entity_name not in role_filters:
            continue

        if entity_name not in principals_db:
            principals_db[entity_name] = {
                "type": "Role",
                "permissions": {"Allow": {}, "Deny": {}}
            }

        # Fetch policy document
        policy_arn = policy_attachment["PolicyArn"]
        try:
            policy_response = iam.get_policy(PolicyArn=policy_arn)
            default_version_id = policy_response["Policy"]["DefaultVersionId"]

            policy_version_response = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            policy_doc = policy_version_response["PolicyVersion"]["Document"]

            extracted = extract_actions_from_policy_document(policy_doc)

            # Merge permissions
            for effect in ["Allow", "Deny"]:
                principals_db[entity_name]["permissions"][effect].update(extracted[effect])
        except Exception as e:
            console.print(f"[yellow]Failed to fetch policy {policy_arn}: {str(e)}[/yellow]")

    if not principals_db:
        console.print("[yellow]No principals found matching filters.[/yellow]")
        return

    # Query matching
    results = []

    for principal_name, principal_data in principals_db.items():
        principal_type = principal_data["type"]
        permissions = principal_data["permissions"]

        # Check which query actions are allowed
        matched_actions = {}

        for query_action in query_actions:
            # Expand wildcards in query
            # Get all known actions from this principal's permissions
            all_known_actions = get_all_actions_from_policies(permissions)

            # Expand query pattern
            expanded_query_actions = expand_action_pattern(query_action, all_known_actions)
            if not expanded_query_actions:
                # Pattern didn't match anything, but still check if it's literally in permissions
                expanded_query_actions = {query_action}

            # Check each expanded action
            for expanded_action in expanded_query_actions:
                # Check if allowed
                allow_match = match_action_against_permissions(expanded_action, permissions["Allow"])
                deny_match = match_action_against_permissions(expanded_action, permissions["Deny"])

                # Deny takes precedence
                if deny_match:
                    continue

                if allow_match:
                    matched_actions[expanded_action] = allow_match

        # Apply all-or-none filter
        if all_or_none:
            # Check if ALL query actions (or their expansions) are present
            all_query_expanded = set()
            for q_action in query_actions:
                all_known_actions = get_all_actions_from_policies(permissions)
                expanded = expand_action_pattern(q_action, all_known_actions)
                if expanded:
                    all_query_expanded.update(expanded)
                else:
                    all_query_expanded.add(q_action)

            # Only include if all expanded actions are matched
            if not all_query_expanded.issubset(set(matched_actions.keys())):
                continue

        # Only include principals with at least one match
        if matched_actions:
            results.append({
                "principal_name": principal_name,
                "principal_type": principal_type,
                "matched_actions": matched_actions
            })

    # Display results
    if not results:
        console.print("[yellow]No principals found with the queried actions.[/yellow]")
        return

    console.print(f"\n[bold green]✓ Found {len(results)} principal(s) with matching permissions[/bold green]\n")

    for result in results:
        principal_name = result["principal_name"]
        principal_type = result["principal_type"]
        matched_actions = result["matched_actions"]

        # Create panel for each principal
        panel_content = f"[bold cyan]{principal_type}: {principal_name}[/bold cyan]\n\n"

        for action, details in sorted(matched_actions.items()):
            panel_content += f"[green]✓ {action}[/green]\n"

            resources = details.get("Resources", [])
            if resources:
                panel_content += f"  Resources: {', '.join(resources)}\n"
            else:
                panel_content += "  Resources: *\n"

            conditions = details.get("Conditions", {})
            if conditions:
                panel_content += f"  Conditions: {json.dumps(conditions, indent=2)}\n"

            panel_content += "\n"

        console.print(Panel(panel_content, border_style="blue", expand=False))

    # Summary table
    summary_table = Table(title="Summary")
    summary_table.add_column("Principal", style="cyan")
    summary_table.add_column("Type", style="magenta")
    summary_table.add_column("Matched Actions", style="green", justify="right")

    for result in results:
        summary_table.add_row(
            result["principal_name"],
            result["principal_type"],
            str(len(result["matched_actions"]))
        )

    console.print(summary_table)
    console.print(f"\n[dim]Total principals with matches: {len(results)}[/dim]")
