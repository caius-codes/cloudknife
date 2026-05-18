"""
Token Exchange Service Discovery Module.

Inspired by the CloudProwl technique by Pwned Labs
https://github.com/pwnedlabs/cloudprowl

Independently implemented using the OAuth 2.0 token exchange standard (RFC 6749).

This module takes a Microsoft refresh token and discovers which Microsoft
services are accessible via token exchange. It systematically attempts to
exchange the refresh token for access tokens to various Microsoft services
and reports which ones grant access.

Services tested:
1. Microsoft Graph
2. Azure Resource Manager
3. Azure DevOps
4. Power Platform (BAP)
5. Power Apps
6. Microsoft Flow
7. Dataverse
8. Microsoft Teams
9. Outlook/Exchange Online
"""

import json
import requests
from typing import Dict, Any, Optional, Tuple, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.clouds.azure.azure_session import AzureSessionManager

console = Console()

# Microsoft Office CLI client ID (well-known, used by Azure CLI)
OFFICE_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

# Service definitions: (name, resource_uri, test_endpoint, description)
SERVICES = [
    (
        "Microsoft Graph",
        "https://graph.microsoft.com/",
        "https://graph.microsoft.com/v1.0/me",
        "Access to user profile, email, calendar, directory",
    ),
    (
        "Azure Resource Manager",
        "https://management.azure.com/",
        "https://management.azure.com/subscriptions?api-version=2022-12-01",
        "Manage Azure resources (VMs, storage, networks)",
    ),
    (
        "Azure DevOps",
        "https://app.vssps.visualstudio.com/",
        "https://app.vssps.visualstudio.com/_apis/accounts?api-version=7.0",
        "Access to Azure DevOps organizations and projects",
    ),
    (
        "Power Platform (BAP)",
        "https://api.bap.microsoft.com/",
        "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments?api-version=2020-10-01",
        "Business Application Platform environments",
    ),
    (
        "Power Apps",
        "https://api.powerapps.com/",
        "https://api.powerapps.com/providers/Microsoft.PowerApps/apps?api-version=2016-11-01",
        "Power Apps canvas and model-driven applications",
    ),
    (
        "Microsoft Flow",
        "https://service.flow.microsoft.com/",
        "https://service.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments?api-version=2016-11-01",
        "Power Automate flows and environments",
    ),
    (
        "Microsoft Teams",
        "https://api.spaces.skype.com/",
        "https://teams.microsoft.com/api/mt/part/emea-03/beta/users/tenants",
        "Teams channels, messages, and tenant access",
    ),
    (
        "Outlook/Exchange Online",
        "https://outlook.office365.com/",
        "https://outlook.office365.com/api/v2.0/me",
        "Exchange Online mailbox access",
    ),
]


def exchange_refresh_token(
    refresh_token: str,
    resource: str,
    tenant_id: str = "organizations",
    client_id: str = OFFICE_CLIENT_ID,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Exchange a refresh token for a service-specific access token.

    This uses the OAuth 2.0 refresh token grant to obtain new access tokens
    scoped to different Microsoft services.

    Args:
        refresh_token: Microsoft refresh token
        resource: Target resource URI (e.g., https://graph.microsoft.com/)
        tenant_id: Tenant ID or "organizations" for multi-tenant
        client_id: Azure AD application client ID

    Returns:
        Tuple of (access_token, new_refresh_token, tenant_id)
        Returns (None, None, None) on failure
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "resource": resource,
    }

    try:
        response = requests.post(url, data=data, timeout=15)

        if response.status_code == 200:
            tokens = response.json()
            return (
                tokens.get("access_token"),
                tokens.get("refresh_token"),
                tokens.get("tenant_id"),
            )
        else:
            # Token exchange failed
            return (None, None, None)

    except requests.exceptions.RequestException:
        return (None, None, None)


def test_service_access(
    access_token: str,
    endpoint: str,
) -> Tuple[bool, Optional[str], Optional[int]]:
    """
    Test if an access token grants access to a service endpoint.

    Args:
        access_token: Service-specific access token
        endpoint: API endpoint to test

    Returns:
        Tuple of (has_access, summary, status_code)
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(endpoint, headers=headers, timeout=15)

        status = response.status_code

        # Success codes indicate access
        if status in [200, 201, 204]:
            try:
                data = response.json()
                summary = _extract_summary(endpoint, data)
                return (True, summary, status)
            except:
                return (True, "Access granted", status)

        # Forbidden/Unauthorized = no access
        elif status in [401, 403]:
            return (False, "Access denied", status)

        # 404 might indicate access (resource not found but we could query)
        elif status == 404:
            return (True, "Access granted (404 - resource not found)", status)

        # Other codes
        else:
            return (False, f"Unexpected status: {status}", status)

    except requests.exceptions.RequestException as e:
        return (False, f"Request failed: {str(e)[:50]}", None)


def _extract_summary(endpoint: str, data: Dict[str, Any]) -> str:
    """Extract meaningful summary from API response."""

    # Graph API /me endpoint
    if "graph.microsoft.com/v1.0/me" in endpoint:
        display_name = data.get("displayName", "")
        upn = data.get("userPrincipalName", "")
        return f"User: {display_name} ({upn})"

    # Azure Resource Manager subscriptions
    elif "management.azure.com/subscriptions" in endpoint:
        subs = data.get("value", [])
        count = len(subs)
        if count > 0:
            names = [s.get("displayName", "Unknown") for s in subs[:3]]
            return f"{count} subscription(s): {', '.join(names)}"
        return "Access granted (no subscriptions)"

    # Azure DevOps accounts
    elif "vssps.visualstudio.com/_apis/accounts" in endpoint:
        accounts = data.get("value", [])
        count = len(accounts)
        if count > 0:
            names = [a.get("accountName", "Unknown") for a in accounts[:3]]
            return f"{count} organization(s): {', '.join(names)}"
        return "Access granted (no organizations)"

    # Power Platform environments
    elif "bap.microsoft.com" in endpoint or "flow.microsoft.com" in endpoint:
        envs = data.get("value", [])
        count = len(envs)
        if count > 0:
            names = [e.get("name", "Unknown") for e in envs[:3]]
            return f"{count} environment(s): {', '.join(names)}"
        return "Access granted (no environments)"

    # Power Apps
    elif "powerapps.com" in endpoint:
        apps = data.get("value", [])
        count = len(apps)
        if count > 0:
            return f"{count} app(s) found"
        return "Access granted (no apps)"

    # Teams
    elif "teams.microsoft.com" in endpoint:
        return "Teams access granted"

    # Exchange/Outlook
    elif "outlook.office365.com" in endpoint:
        email = data.get("EmailAddress", "")
        return f"Mailbox: {email}" if email else "Mailbox access granted"

    # Default
    return "Access granted"


def enumerate_accessible_services(
    session_mgr: AzureSessionManager,
) -> Optional[Dict[str, Any]]:
    """
    Discover which Microsoft services are accessible via token exchange.

    This function takes a refresh token from the session and systematically
    attempts to exchange it for access tokens to various Microsoft services.
    For each successful exchange, it tests access to a representative endpoint
    to confirm permissions.

    Args:
        session_mgr: Azure session manager with refresh token configured

    Returns:
        Dictionary with discovery results or None on error
    """
    if not session_mgr.current_session_data:
        console.print("[red]No active session. Create or load a session first.[/red]")
        return None

    refresh_token = session_mgr.current_session_data.get("refresh_token")

    if not refresh_token:
        console.print(
            "[red]No refresh token configured. Use set_refresh_token first.[/red]"
        )
        return None

    console.print("\n[bold cyan]🔍 Microsoft Service Discovery via Token Exchange[/bold cyan]")
    console.print("[dim]Testing access to 8 Microsoft services...[/dim]\n")

    tenant_id = session_mgr.current_session_data.get("tenant_id", "organizations")

    results = []
    discovered_tenant = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Exchanging tokens and testing access...",
            total=len(SERVICES),
        )

        for service_name, resource, endpoint, description in SERVICES:
            progress.update(task, description=f"[cyan]Testing {service_name}...")

            # Exchange refresh token for service-specific access token
            access_token, new_refresh_token, tenant = exchange_refresh_token(
                refresh_token, resource, tenant_id
            )

            # Update refresh token and tenant if exchange succeeded
            if new_refresh_token:
                refresh_token = new_refresh_token
                session_mgr.current_session_data["refresh_token"] = new_refresh_token

            if tenant and not discovered_tenant:
                discovered_tenant = tenant
                session_mgr.current_session_data["tenant_id"] = tenant

            result = {
                "service": service_name,
                "resource": resource,
                "description": description,
                "token_obtained": access_token is not None,
                "access_granted": False,
                "summary": None,
                "status_code": None,
            }

            if access_token:
                # Test actual access to service
                has_access, summary, status = test_service_access(access_token, endpoint)
                result["access_granted"] = has_access
                result["summary"] = summary
                result["status_code"] = status

            results.append(result)
            progress.advance(task)

    # Save results
    session_mgr.save_session()

    discovery_data = {
        "tenant_id": discovered_tenant or tenant_id,
        "services_tested": len(SERVICES),
        "services_accessible": sum(1 for r in results if r["access_granted"]),
        "results": results,
    }

    session_mgr.save_enumeration_data("token_exchange_discovery", discovery_data)

    # Display results
    _display_results(results, discovered_tenant)

    return discovery_data


def _display_results(results: List[Dict[str, Any]], tenant_id: Optional[str]):
    """Display discovery results in formatted tables."""

    console.print("\n[bold blue]📊 Service Discovery Results[/bold blue]\n")

    if tenant_id:
        console.print(f"[cyan]Tenant ID:[/cyan] {tenant_id}\n")

    # Summary counts
    total = len(results)
    accessible = sum(1 for r in results if r["access_granted"])
    denied = sum(1 for r in results if r["token_obtained"] and not r["access_granted"])
    token_failed = sum(1 for r in results if not r["token_obtained"])

    console.print(f"[green]✅ Accessible:[/green] {accessible}/{total}")
    console.print(f"[red]❌ Denied:[/red] {denied}/{total}")
    console.print(f"[yellow]⚠️  Token Exchange Failed:[/yellow] {token_failed}/{total}\n")

    # Detailed results table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Service", style="white", no_wrap=True)
    table.add_column("Status", style="white", justify="center")
    table.add_column("Details", style="dim")

    for result in results:
        service = result["service"]

        if result["access_granted"]:
            status = "[green]✅ ACCESS[/green]"
            details = result["summary"] or "Access confirmed"
        elif result["token_obtained"]:
            status = "[red]❌ DENIED[/red]"
            details = result["summary"] or "No access"
        else:
            status = "[yellow]⚠️  TOKEN FAIL[/yellow]"
            details = "Token exchange failed"

        table.add_row(service, status, details)

    console.print(table)
    console.print()

    # Highlight accessible services with exploitation potential
    accessible_services = [r for r in results if r["access_granted"]]

    if accessible_services:
        console.print("[bold green]🎯 Accessible Services - Exploitation Paths:[/bold green]\n")

        for result in accessible_services:
            service = result["service"]
            desc = result["description"]
            console.print(f"[green]✓[/green] [bold]{service}[/bold]")
            console.print(f"  [dim]{desc}[/dim]")

            # Service-specific exploitation hints
            if service == "Microsoft Graph":
                console.print("  [cyan]→ Use graph_mail, graph_teams, graph_files for enumeration[/cyan]")
            elif service == "Azure Resource Manager":
                console.print("  [cyan]→ Use enum_resources, enum_vms for enumeration[/cyan]")
            elif service == "Azure DevOps":
                console.print("  [cyan]→ Enumerate repositories, pipelines, secrets[/cyan]")
            elif "Power" in service:
                console.print("  [cyan]→ Enumerate Power Apps, Flows, Dataverse data[/cyan]")
            elif service == "Outlook/Exchange Online":
                console.print("  [cyan]→ Use graph_mail or direct Exchange API enumeration[/cyan]")

            console.print()

    console.print("[green]Results saved under key 'token_exchange_discovery' in session data.[/green]")
