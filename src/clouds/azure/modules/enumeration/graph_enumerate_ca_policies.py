# src/clouds/azure/modules/enumeration/graph_enumerate_ca_policies.py

import json
from typing import List, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm

from ...azure_session import AzureSessionManager
from ...utils.graph_helpers import (
    paginated_graph_request,
    check_token_scopes
)

console = Console()

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"


def enumerate_ca_policies(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate Conditional Access policies using Graph API.

    Displays:
    1. Policy name, state, and creation date
    2. Conditions (users, apps, locations, platforms, devices)
    3. Grant controls (MFA, compliant device, etc.)
    4. Session controls

    Requires: Policy.Read.All
    """
    console.print("[cyan]Microsoft Graph - Conditional Access Policies[/cyan]")

    # Get access token
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]No Graph API access token available. Please authenticate first.[/red]")
        return

    # Check token scopes
    check_token_scopes(access_token, ["Policy.Read.All"])

    # Fetch policies
    console.print("\n[cyan]Fetching Conditional Access policies...[/cyan]")

    url = f"{GRAPH_ENDPOINT}/identity/conditionalAccess/policies"

    policies = paginated_graph_request(access_token, url)

    # policies is None if there was an API error (403, 404, etc.)
    # policies is [] if the API succeeded but returned no policies
    if policies is None:
        console.print("[red]Failed to fetch Conditional Access policies due to an error (see above).[/red]")
        return

    if not policies:
        console.print("[yellow]No Conditional Access policies found.[/yellow]")
        console.print("[dim]This tenant has no Conditional Access policies configured.[/dim]")
        return

    console.print(f"[green]Found {len(policies)} policy/policies.[/green]")

    # Save to session data
    session_mgr.save_enumeration_data("conditional_access_policies", policies)

    # Display summary
    _display_policies_summary(policies)

    # Display detailed conditions for each policy
    console.print("\n[cyan]Policy Details:[/cyan]\n")
    for i, policy in enumerate(policies, 1):
        _display_policy_details(policy, i)

    # Offer to export
    if Confirm.ask("\n[cyan]Export detailed policies to JSON file?[/cyan]", default=False):
        _export_policies_to_json(policies, session_mgr)


def _display_policies_summary(policies: List[Dict[str, Any]]) -> None:
    """Display CA policies summary table."""
    table = Table(title=f"Conditional Access Policies ({len(policies)} found)")
    table.add_column("Display Name", style="cyan", overflow="fold", max_width=40)
    table.add_column("State", style="magenta", justify="center")
    table.add_column("Created", style="yellow", max_width=18)
    table.add_column("Modified", style="green", max_width=18)

    for policy in policies:
        display_name = policy.get("displayName", "")
        state = policy.get("state", "")

        # Color code state
        if state == "enabled":
            state_colored = f"[green]{state}[/green]"
        elif state == "disabled":
            state_colored = f"[red]{state}[/red]"
        elif state == "enabledForReportingButNotEnforced":
            state_colored = f"[yellow]report-only[/yellow]"
        else:
            state_colored = state

        # Parse dates
        created_str = policy.get("createdDateTime", "")
        if created_str:
            try:
                created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                created = created_dt.strftime("%Y-%m-%d")
            except:
                created = created_str[:10]
        else:
            created = ""

        modified_str = policy.get("modifiedDateTime", "")
        if modified_str:
            try:
                modified_dt = datetime.fromisoformat(modified_str.replace('Z', '+00:00'))
                modified = modified_dt.strftime("%Y-%m-%d")
            except:
                modified = modified_str[:10]
        else:
            modified = ""

        table.add_row(display_name, state_colored, created, modified)

    console.print(table)


def _display_policy_details(policy: Dict[str, Any], index: int) -> None:
    """Display detailed information for a single CA policy."""
    display_name = policy.get("displayName", "Unknown Policy")
    state = policy.get("state", "unknown")

    console.print(f"[bold cyan]{index}. {display_name}[/bold cyan] [dim]({state})[/dim]")

    # Conditions
    conditions = policy.get("conditions", {})

    # Users
    users = conditions.get("users", {})
    include_users = users.get("includeUsers", [])
    exclude_users = users.get("excludeUsers", [])
    include_groups = users.get("includeGroups", [])
    exclude_groups = users.get("excludeGroups", [])

    console.print(f"  [yellow]Users:[/yellow]")
    if include_users:
        if "All" in include_users:
            console.print(f"    Include: All users")
        else:
            console.print(f"    Include: {len(include_users)} user(s)")
    if include_groups:
        console.print(f"    Include Groups: {len(include_groups)} group(s)")
    if exclude_users:
        console.print(f"    Exclude: {len(exclude_users)} user(s)")
    if exclude_groups:
        console.print(f"    Exclude Groups: {len(exclude_groups)} group(s)")

    # Applications
    apps = conditions.get("applications", {})
    include_apps = apps.get("includeApplications", [])
    exclude_apps = apps.get("excludeApplications", [])

    console.print(f"  [yellow]Applications:[/yellow]")
    if include_apps:
        if "All" in include_apps:
            console.print(f"    Include: All applications")
        else:
            console.print(f"    Include: {len(include_apps)} app(s)")
    if exclude_apps:
        console.print(f"    Exclude: {len(exclude_apps)} app(s)")

    # Locations
    locations = conditions.get("locations", {})
    if locations:
        include_locs = locations.get("includeLocations", [])
        exclude_locs = locations.get("excludeLocations", [])

        if include_locs or exclude_locs:
            console.print(f"  [yellow]Locations:[/yellow]")
            if include_locs:
                if "All" in include_locs:
                    console.print(f"    Include: All locations")
                else:
                    console.print(f"    Include: {', '.join(include_locs)}")
            if exclude_locs:
                console.print(f"    Exclude: {', '.join(exclude_locs)}")

    # Platforms
    platforms = conditions.get("platforms", {})
    if platforms:
        include_platforms = platforms.get("includePlatforms", [])
        exclude_platforms = platforms.get("excludePlatforms", [])

        if include_platforms or exclude_platforms:
            console.print(f"  [yellow]Platforms:[/yellow]")
            if include_platforms:
                if "all" in include_platforms:
                    console.print(f"    Include: All platforms")
                else:
                    console.print(f"    Include: {', '.join(include_platforms)}")
            if exclude_platforms:
                console.print(f"    Exclude: {', '.join(exclude_platforms)}")

    # Grant Controls
    grant_controls = policy.get("grantControls")
    if grant_controls:
        built_in_controls = grant_controls.get("builtInControls", [])
        operator = grant_controls.get("operator", "AND")

        if built_in_controls:
            console.print(f"  [yellow]Grant Controls ({operator}):[/yellow]")
            for control in built_in_controls:
                # Highlight MFA
                if control == "mfa":
                    console.print(f"    [red]• Require MFA[/red]")
                elif control == "compliantDevice":
                    console.print(f"    • Require compliant device")
                elif control == "domainJoinedDevice":
                    console.print(f"    • Require domain-joined device")
                elif control == "approvedApplication":
                    console.print(f"    • Require approved application")
                elif control == "compliantApplication":
                    console.print(f"    • Require compliant application")
                else:
                    console.print(f"    • {control}")

    # Session Controls
    session_controls = policy.get("sessionControls")
    if session_controls:
        console.print(f"  [yellow]Session Controls:[/yellow]")

        sign_in_frequency = session_controls.get("signInFrequency")
        if sign_in_frequency:
            value = sign_in_frequency.get("value")
            type_ = sign_in_frequency.get("type")
            console.print(f"    • Sign-in frequency: {value} {type_}(s)")

        persistent_browser = session_controls.get("persistentBrowser")
        if persistent_browser:
            mode = persistent_browser.get("mode")
            console.print(f"    • Persistent browser: {mode}")

    console.print()  # Blank line between policies


def _export_policies_to_json(policies: List[Dict[str, Any]], session_mgr: AzureSessionManager) -> None:
    """Export CA policies to JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"conditional_access_policies_{timestamp}.json"

    exfil_dir = session_mgr.get_exfil_dir("ca_policies")
    file_path = exfil_dir / filename

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(policies, f, indent=2, ensure_ascii=False)

        console.print(f"[green]Exported {len(policies)} policy/policies to:[/green] {file_path.resolve()}")

    except Exception as e:
        console.print(f"[red]Failed to export: {e}[/red]")
