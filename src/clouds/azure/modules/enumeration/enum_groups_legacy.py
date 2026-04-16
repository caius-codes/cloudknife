"""
Azure AD Graph API (LEGACY) - Group Enumeration Module.

⚠️  DEPRECATED API - Azure AD Graph API was retired in June 2023.
    This module is for compatibility with legacy tokens (graph.windows.net).
    Use Microsoft Graph API (graph.microsoft.com) whenever possible.

Enumerates groups from Azure AD using the legacy graph.windows.net endpoint.
"""

from typing import Any, Dict, List
import base64
import json
import time
import requests

from rich.console import Console
from rich.table import Table

from ...azure_session import AzureSessionManager

console = Console()


def enumerate_groups_legacy(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate all visible Entra ID groups via Azure AD Graph API (LEGACY).

    ⚠️  Uses deprecated graph.windows.net endpoint (retired June 2023).
        Use enumerate_groups (Microsoft Graph) whenever possible.
    """
    console.print("[bold yellow]⚠️  Azure AD Graph API (Legacy) - Group Enumeration[/bold yellow]")
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

    console.print(f"[cyan]Enumerating groups from tenant: {tenant_id}...[/cyan]")

    # Implement pagination
    all_groups: List[Dict[str, Any]] = []
    next_link = f"https://graph.windows.net/{tenant_id}/groups?api-version=1.6"
    page = 1

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    retry_count = 0
    max_retries = 3

    while next_link:
        console.print(f"[dim]Fetching groups (page {page})...[/dim]")

        try:
            response = requests.get(next_link, headers=headers, timeout=60)
            response.raise_for_status()

            data = response.json()
            page_groups = data.get("value", [])
            all_groups.extend(page_groups)

            console.print(f"[dim]Page {page}: {len(page_groups)} groups[/dim]")

            # Check for next page
            next_link = data.get("odata.nextLink")
            page += 1
            retry_count = 0  # Reset retry count on success

            # Add delay between requests to avoid rate limiting
            if next_link:
                time.sleep(1)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                console.print("[red]Authentication failed. Token may be expired.[/red]")
                break
            elif e.response.status_code == 403:
                console.print("[red]Permission denied. Insufficient privileges to list groups.[/red]")
                console.print("[yellow]Required permission: Group.Read.All or Directory.Read.All[/yellow]")
                break
            elif e.response.status_code == 429:
                # Rate limited - retry with backoff
                if retry_count >= max_retries:
                    console.print(f"[red]Rate limit exceeded. Max retries ({max_retries}) reached.[/red]")
                    break

                retry_after = int(e.response.headers.get("Retry-After", 5))
                console.print(f"[yellow]Rate limited (429). Waiting {retry_after}s before retry {retry_count + 1}/{max_retries}...[/yellow]")
                time.sleep(retry_after)
                retry_count += 1
                continue  # Retry same request
            else:
                console.print(f"[red]HTTP {e.response.status_code} error on page {page}[/red]")
                break

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error on page {page}: {e}[/red]")
            break

        except Exception as e:
            console.print(f"[red]Error parsing response on page {page}: {e}[/red]")
            break

    if not all_groups:
        console.print("[yellow]No groups found.[/yellow]")
        return

    console.print(f"\n[green]Found {len(all_groups)} group(s).[/green]\n")

    # Save enumeration data
    session_mgr.save_enumeration_data("groups_legacy", all_groups)

    # Analyze group types
    security_groups = [g for g in all_groups if g.get("securityEnabled")]
    mail_groups = [g for g in all_groups if g.get("mailEnabled")]
    role_assignable = [g for g in all_groups if g.get("isAssignableToRole")]

    console.print(f"[dim]Security groups: {len(security_groups)}[/dim]")
    console.print(f"[dim]Mail-enabled groups: {len(mail_groups)}[/dim]")
    console.print(f"[dim]Role-assignable groups: {len(role_assignable)}[/dim]\n")

    # Display groups in a table
    table = Table(title=f"Entra ID Groups (Legacy API) - {len(all_groups)} found")
    table.add_column("Display Name", style="cyan")
    table.add_column("Object ID", style="dim")
    table.add_column("Mail", style="green")
    table.add_column("Security", style="yellow")
    table.add_column("Mail Enabled", style="magenta")

    for group in all_groups[:100]:  # Limit display to 100
        display_name = group.get("displayName", "N/A")
        object_id = group.get("objectId", "N/A")
        mail = group.get("mail", "N/A")
        security_enabled = "Yes" if group.get("securityEnabled") else "No"
        mail_enabled = "Yes" if group.get("mailEnabled") else "No"

        table.add_row(
            display_name,
            object_id,
            mail,
            security_enabled,
            mail_enabled
        )

    console.print(table)

    if len(all_groups) > 100:
        console.print(f"\n[dim]... and {len(all_groups) - 100} more groups (showing first 100)[/dim]")

    # Highlight role-assignable groups (privilege escalation risk)
    if role_assignable:
        console.print(f"\n[bold yellow]⚠️  Found {len(role_assignable)} role-assignable group(s):[/bold yellow]")
        for group in role_assignable[:10]:
            console.print(f"  [yellow]• {group.get('displayName')}[/yellow] [dim]({group.get('objectId')})[/dim]")
        if len(role_assignable) > 10:
            console.print(f"  [dim]... and {len(role_assignable) - 10} more[/dim]")

    console.print(f"\n[dim]Saved as 'groups_legacy' in enumeration data[/dim]")
