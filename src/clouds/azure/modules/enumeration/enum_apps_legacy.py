"""
Azure AD Graph API (LEGACY) - Application & Service Principal Enumeration Module.

⚠️  DEPRECATED API - Azure AD Graph API was retired in June 2023.
    This module is for compatibility with legacy tokens (graph.windows.net).
    Use Microsoft Graph API (graph.microsoft.com) whenever possible.

Enumerates applications and service principals from Azure AD using legacy graph.windows.net endpoint.
"""

from typing import Any, Dict, List
import base64
import json
import time
import requests

from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_apps_legacy(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate applications and service principals via Azure AD Graph API (LEGACY).

    ⚠️  Uses deprecated graph.windows.net endpoint (retired June 2023).
        Use enumerate_apps (Microsoft Graph) whenever possible.
    """
    console.print("[bold yellow]⚠️  Azure AD Graph API (Legacy) - Application Enumeration[/bold yellow]")
    console.print("[dim]Using deprecated graph.windows.net endpoint[/dim]\n")

    # Get Azure AD Graph API access token
    access_token = None

    # Check if we have a stored token with graph.windows.net audience
    stored_token = session_mgr.current_session_data.get("graph_access_token")
    if stored_token:
        try:
            parts = stored_token.split(".")
            if len(parts) == 3:
                payload = parts[1]
                payload += "=" * (4 - len(payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload))

                aud = claims.get("aud", "")
                if aud == "https://graph.windows.net":
                    access_token = stored_token
                else:
                    console.print(f"[yellow]Token has wrong audience: {aud}[/yellow]")
                    console.print("[yellow]Expected: https://graph.windows.net[/yellow]")
        except Exception:
            pass

    if not access_token:
        console.print("[red]No Azure AD Graph API token available.[/red]")
        console.print("[cyan]Get a token with audience 'https://graph.windows.net' and use:[/cyan]")
        console.print("  set_token /path/to/aad_graph_token.txt")
        return

    # Get tenant ID
    tenant_id = session_mgr.current_session_data.get("tenant_id")
    if not tenant_id:
        try:
            parts = access_token.split(".")
            if len(parts) == 3:
                payload = parts[1]
                payload += "=" * (4 - len(payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload))
                tenant_id = claims.get("tid")
        except Exception:
            pass

    if not tenant_id:
        console.print("[red]Could not determine tenant ID.[/red]")
        return

    # Ask what to enumerate
    console.print("[cyan]What would you like to enumerate?[/cyan]")
    console.print("  [bold]1[/bold]  Applications")
    console.print("  [bold]2[/bold]  Service Principals")
    console.print("  [bold]3[/bold]  Both")

    from rich.prompt import Prompt
    choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="3")

    enumerate_applications = choice in ["1", "3"]
    enumerate_service_principals = choice in ["2", "3"]

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # Enumerate Applications
    if enumerate_applications:
        console.print(f"\n[cyan]Enumerating applications from tenant: {tenant_id}...[/cyan]")

        all_apps: List[Dict[str, Any]] = []
        next_link = f"https://graph.windows.net/{tenant_id}/applications?api-version=1.6"
        page = 1
        retry_count = 0
        max_retries = 3

        while next_link:
            console.print(f"[dim]Fetching applications (page {page})...[/dim]")

            try:
                response = requests.get(next_link, headers=headers, timeout=60)
                response.raise_for_status()

                data = response.json()
                page_apps = data.get("value", [])
                all_apps.extend(page_apps)

                console.print(f"[dim]Page {page}: {len(page_apps)} applications[/dim]")

                next_link = data.get("odata.nextLink")
                page += 1
                retry_count = 0  # Reset on success

                # Add delay between requests
                if next_link:
                    time.sleep(1)

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    console.print("[red]Authentication failed. Token may be expired.[/red]")
                    break
                elif e.response.status_code == 403:
                    console.print("[red]Permission denied. Insufficient privileges to list applications.[/red]")
                    console.print("[yellow]Required permission: Application.Read.All or Directory.Read.All[/yellow]")
                    break
                elif e.response.status_code == 429:
                    if retry_count >= max_retries:
                        console.print(f"[red]Rate limit exceeded. Max retries ({max_retries}) reached.[/red]")
                        break
                    retry_after = int(e.response.headers.get("Retry-After", 5))
                    console.print(f"[yellow]Rate limited (429). Waiting {retry_after}s before retry {retry_count + 1}/{max_retries}...[/yellow]")
                    time.sleep(retry_after)
                    retry_count += 1
                    continue
                else:
                    console.print(f"[red]HTTP {e.response.status_code} error[/red]")
                    break

            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                break

        if all_apps:
            console.print(f"\n[green]Found {len(all_apps)} application(s).[/green]\n")

            # Save enumeration data
            session_mgr.save_enumeration_data("applications_legacy", all_apps)

            # Display applications
            table = Table(title=f"Applications (Legacy API) - {len(all_apps)} found")
            table.add_column("Display Name", style="cyan")
            table.add_column("App ID", style="green")
            table.add_column("Object ID", style="dim")
            table.add_column("Available to Other Tenants", style="yellow")

            for app in all_apps[:100]:
                display_name = app.get("displayName", "N/A")
                app_id = app.get("appId", "N/A")
                object_id = app.get("objectId", "N/A")
                available_to_other_tenants = "Yes" if app.get("availableToOtherTenants") else "No"

                table.add_row(
                    display_name,
                    app_id,
                    object_id,
                    available_to_other_tenants
                )

            console.print(table)

            if len(all_apps) > 100:
                console.print(f"\n[dim]... and {len(all_apps) - 100} more applications (showing first 100)[/dim]")

            console.print(f"\n[dim]Saved as 'applications_legacy' in enumeration data[/dim]")

        else:
            console.print("[yellow]No applications found.[/yellow]")

    # Enumerate Service Principals
    if enumerate_service_principals:
        console.print(f"\n[cyan]Enumerating service principals from tenant: {tenant_id}...[/cyan]")

        all_sps: List[Dict[str, Any]] = []
        next_link = f"https://graph.windows.net/{tenant_id}/servicePrincipals?api-version=1.6"
        page = 1
        retry_count = 0
        max_retries = 3

        while next_link:
            console.print(f"[dim]Fetching service principals (page {page})...[/dim]")

            try:
                response = requests.get(next_link, headers=headers, timeout=60)
                response.raise_for_status()

                data = response.json()
                page_sps = data.get("value", [])
                all_sps.extend(page_sps)

                console.print(f"[dim]Page {page}: {len(page_sps)} service principals[/dim]")

                next_link = data.get("odata.nextLink")
                page += 1
                retry_count = 0  # Reset on success

                # Add delay between requests
                if next_link:
                    time.sleep(1)

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    console.print("[red]Authentication failed. Token may be expired.[/red]")
                    break
                elif e.response.status_code == 403:
                    console.print("[red]Permission denied. Insufficient privileges to list service principals.[/red]")
                    console.print("[yellow]Required permission: Application.Read.All or Directory.Read.All[/yellow]")
                    break
                elif e.response.status_code == 429:
                    if retry_count >= max_retries:
                        console.print(f"[red]Rate limit exceeded. Max retries ({max_retries}) reached.[/red]")
                        break
                    retry_after = int(e.response.headers.get("Retry-After", 5))
                    console.print(f"[yellow]Rate limited (429). Waiting {retry_after}s before retry {retry_count + 1}/{max_retries}...[/yellow]")
                    time.sleep(retry_after)
                    retry_count += 1
                    continue
                else:
                    console.print(f"[red]HTTP {e.response.status_code} error[/red]")
                    break

            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                break

        if all_sps:
            console.print(f"\n[green]Found {len(all_sps)} service principal(s).[/green]\n")

            # Save enumeration data
            session_mgr.save_enumeration_data("service_principals_legacy", all_sps)

            # Analyze service principals
            microsoft_sps = [sp for sp in all_sps if sp.get("publisherName") == "Microsoft"]
            third_party_sps = [sp for sp in all_sps if sp.get("publisherName") != "Microsoft"]

            console.print(f"[dim]Microsoft service principals: {len(microsoft_sps)}[/dim]")
            console.print(f"[dim]Third-party service principals: {len(third_party_sps)}[/dim]\n")

            # Display service principals
            table = Table(title=f"Service Principals (Legacy API) - {len(all_sps)} found")
            table.add_column("Display Name", style="cyan")
            table.add_column("App ID", style="green")
            table.add_column("Object ID", style="dim")
            table.add_column("Publisher", style="yellow")
            table.add_column("Account Enabled", style="magenta")

            for sp in all_sps[:100]:
                display_name = sp.get("displayName", "N/A")
                app_id = sp.get("appId", "N/A")
                object_id = sp.get("objectId", "N/A")
                publisher = sp.get("publisherName", "N/A")
                account_enabled = "Yes" if sp.get("accountEnabled") else "No"

                table.add_row(
                    display_name,
                    app_id,
                    object_id,
                    publisher,
                    account_enabled
                )

            console.print(table)

            if len(all_sps) > 100:
                console.print(f"\n[dim]... and {len(all_sps) - 100} more service principals (showing first 100)[/dim]")

            # Highlight third-party apps (potential security risk)
            if third_party_sps:
                console.print(f"\n[bold yellow]⚠️  Found {len(third_party_sps)} third-party service principal(s):[/bold yellow]")
                for sp in third_party_sps[:10]:
                    publisher = sp.get("publisherName", "Unknown")
                    console.print(f"  [yellow]• {sp.get('displayName')}[/yellow] [dim]({publisher})[/dim]")
                if len(third_party_sps) > 10:
                    console.print(f"  [dim]... and {len(third_party_sps) - 10} more[/dim]")

            console.print(f"\n[dim]Saved as 'service_principals_legacy' in enumeration data[/dim]")

        else:
            console.print("[yellow]No service principals found.[/yellow]")
