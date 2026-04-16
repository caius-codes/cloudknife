"""
MFA Bypass Auditing Core Logic.

Based on FindMeAccess by Ryan McFarland (MIT License)
https://github.com/absolomb/FindMeAccess

This module tests ROPC (Resource Owner Password Credentials) authentication
across various combinations of Azure Client IDs and Resources to identify
configurations that don't enforce MFA.
"""

import json
import requests
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .client_ids import CLIENT_IDS, PRIORITY_CLIENTS
from .resources import RESOURCES, PRIORITY_RESOURCES
from .user_agents import DEFAULT_USER_AGENT

console = Console()

# Disable SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TokenResult:
    """Result of a successful ROPC token acquisition."""
    client_name: str
    client_id: str
    resource_name: str
    resource_url: str
    access_token: str
    refresh_token: Optional[str]
    token_type: str
    expires_in: int
    scope: str
    user_agent: str


@dataclass
class BypassResult:
    """Result of MFA bypass discovery."""
    client_name: str
    client_id: str
    resource_name: str
    resource_url: str
    access_token: str
    refresh_token: Optional[str] = None
    scope: str = ""
    expires_in: int = 3600


def test_ropc_combination(
    username: str,
    password: str,
    client_id: str,
    resource: str,
    user_agent: str = DEFAULT_USER_AGENT,
    tenant_id: str = "organizations",
    timeout: int = 10
) -> Optional[TokenResult]:
    """
    Test a single ROPC combination.

    Args:
        username: User email/UPN
        password: User password
        client_id: Azure AD Client ID
        resource: Resource URL (audience)
        user_agent: HTTP User-Agent string
        tenant_id: Tenant ID or "organizations" for multi-tenant
        timeout: Request timeout in seconds

    Returns:
        TokenResult if successful, None if MFA required or authentication failed
    """
    url = f"https://login.microsoft.com/{tenant_id}/oauth2/token"

    headers = {
        "User-Agent": user_agent,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    data = {
        "resource": resource,
        "client_id": client_id,
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid",
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            data=data,
            timeout=timeout,
            verify=False  # For testing environments
        )

        if response.status_code == 200:
            result = response.json()
            return TokenResult(
                client_name="",  # Will be filled by caller
                client_id=client_id,
                resource_name="",  # Will be filled by caller
                resource_url=resource,
                access_token=result.get("access_token", ""),
                refresh_token=result.get("refresh_token"),
                token_type=result.get("token_type", "Bearer"),
                expires_in=result.get("expires_in", 3600),
                scope=result.get("scope", ""),
                user_agent=user_agent,
            )
        else:
            # Authentication failed (MFA required, invalid credentials, etc.)
            return None

    except requests.exceptions.Timeout:
        # Timeout - skip this combination
        return None
    except Exception:
        # Any other error - skip this combination
        return None


def _test_combination_wrapper(args: Tuple) -> Optional[Tuple[str, str, str, TokenResult]]:
    """
    Wrapper for test_ropc_combination for use with ThreadPoolExecutor.

    Returns:
        Tuple of (client_name, resource_name, user_agent_name, TokenResult) if successful, None otherwise
    """
    client_name, client_id, resource_name, resource_url, user_agent_name, user_agent, username, password, tenant_id = args

    result = test_ropc_combination(
        username=username,
        password=password,
        client_id=client_id,
        resource=resource_url,
        user_agent=user_agent,
        tenant_id=tenant_id
    )

    if result:
        result.client_name = client_name
        result.resource_name = resource_name
        return (client_name, resource_name, user_agent_name, result)

    return None


def audit_mfa_gaps(
    username: str,
    password: str,
    tenant_id: str = "organizations",
    fast_mode: bool = True,
    test_all_user_agents: bool = False,
    specific_resource: str = None,
    max_workers: int = 5
) -> List[BypassResult]:
    """
    Audit MFA configuration gaps by testing ROPC across client/resource combinations.

    Args:
        username: User email/UPN
        password: User password
        tenant_id: Tenant ID or "organizations" for multi-tenant
        fast_mode: If True, test only priority clients/resources. If False, test all.
        test_all_user_agents: If True, test all user agents (like FindMeAccess --ua_all)
        specific_resource: If set, test only this resource URL (like FindMeAccess -r)
        max_workers: Number of parallel threads for testing

    Returns:
        List of BypassResult objects for successful bypasses
    """
    console.print("\n[bold cyan]🔍 MFA Bypass Audit[/bold cyan]")
    mode_desc = 'Fast (priority targets)' if fast_mode else 'Full (all combinations)'
    if test_all_user_agents:
        mode_desc += ' + All User Agents'
    if specific_resource:
        mode_desc += f' + Specific Resource: {specific_resource}'
    console.print(f"[dim]Mode: {mode_desc}[/dim]\n")

    # Determine which clients and resources to test
    if fast_mode:
        clients_to_test = {name: CLIENT_IDS[name] for name in PRIORITY_CLIENTS if name in CLIENT_IDS}
        resources_to_test = {name: RESOURCES[name] for name in PRIORITY_RESOURCES if name in RESOURCES}
    else:
        clients_to_test = CLIENT_IDS
        resources_to_test = RESOURCES

    # If specific resource is requested, use only that
    if specific_resource:
        # Find resource name or use URL as name
        resource_name = None
        for name, url in RESOURCES.items():
            if url == specific_resource:
                resource_name = name
                break
        if not resource_name:
            resource_name = specific_resource.split('/')[2] if '//' in specific_resource else 'Custom'
        resources_to_test = {resource_name: specific_resource}

    # Determine which user agents to test
    if test_all_user_agents:
        from .user_agents import USER_AGENTS
        user_agents_to_test = USER_AGENTS
    else:
        user_agents_to_test = {"Windows 10 Chrome": DEFAULT_USER_AGENT}

    # Build list of combinations to test
    test_combinations = []
    for client_name, client_id in clients_to_test.items():
        for resource_name, resource_url in resources_to_test.items():
            for ua_name, ua_string in user_agents_to_test.items():
                test_combinations.append((
                    client_name,
                    client_id,
                    resource_name,
                    resource_url,
                    ua_name,
                    ua_string,
                    username,
                    password,
                    tenant_id
                ))

    total_tests = len(test_combinations)
    console.print(f"[cyan]Testing {total_tests} combinations with {max_workers} threads...[/cyan]\n")

    bypasses: List[BypassResult] = []

    # Test combinations in parallel with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Testing...", total=total_tests)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_test_combination_wrapper, combo): combo
                for combo in test_combinations
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    client_name, resource_name, user_agent_name, token_result = result

                    # Create BypassResult
                    bypass = BypassResult(
                        client_name=client_name,
                        client_id=token_result.client_id,
                        resource_name=resource_name,
                        resource_url=token_result.resource_url,
                        access_token=token_result.access_token,
                        refresh_token=token_result.refresh_token,
                        scope=token_result.scope,
                        expires_in=token_result.expires_in,
                    )
                    bypasses.append(bypass)

                    # Show immediate feedback
                    ua_info = f" [dim]({user_agent_name})[/dim]" if test_all_user_agents else ""
                    console.print(
                        f"  [green]✓[/green] Found bypass: [cyan]{client_name}[/cyan] → [yellow]{resource_name}[/yellow]{ua_info}"
                    )

                progress.update(task, advance=1)

    return bypasses


def display_bypass_results(bypasses: List[BypassResult]) -> None:
    """
    Display bypass results in a formatted table.

    Args:
        bypasses: List of BypassResult objects to display
    """
    if not bypasses:
        console.print("\n[yellow]No MFA bypasses found.[/yellow]")
        console.print("[dim]All tested combinations require MFA or failed authentication.[/dim]")
        return

    console.print(f"\n[bold green]✓ Found {len(bypasses)} MFA bypass(es)![/bold green]\n")

    table = Table(title=f"MFA Bypass Results ({len(bypasses)} found)")
    table.add_column("Client", style="cyan", overflow="fold", max_width=30)
    table.add_column("Resource", style="yellow", overflow="fold", max_width=30)
    table.add_column("Status", style="green", justify="center")
    table.add_column("Scope/Scopes", style="dim", overflow="fold", max_width=40)

    for bypass in bypasses:
        # Truncate scope for display
        scope_display = bypass.scope[:37] + "..." if len(bypass.scope) > 40 else bypass.scope

        table.add_row(
            bypass.client_name,
            bypass.resource_name,
            "✓ OK",
            scope_display or "[dim]N/A[/dim]"
        )

    console.print(table)

    # Show additional tips
    console.print("\n[dim]Tip: These bypasses can be used to create CloudKnife sessions[/dim]")
    console.print("[dim]     with access tokens that don't require MFA.[/dim]")
