"""
Azure AD Graph API (LEGACY) - User Enumeration Module.

⚠️  DEPRECATED API - Azure AD Graph API was retired in June 2023.
    This module is for compatibility with legacy tokens (graph.windows.net).
    Use Microsoft Graph API (graph.microsoft.com) whenever possible.

Enumerates users from Azure AD using the legacy graph.windows.net endpoint.
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


def enumerate_users_legacy(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate all visible Entra ID users via Azure AD Graph API (LEGACY).

    ⚠️  Uses deprecated graph.windows.net endpoint (retired June 2023).
        Use enumerate_users (Microsoft Graph) whenever possible.
    """
    console.print("[bold yellow]⚠️  Azure AD Graph API (Legacy) - User Enumeration[/bold yellow]")
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

    console.print(f"[cyan]Enumerating users from tenant: {tenant_id}...[/cyan]")

    # Implement pagination
    all_users: List[Dict[str, Any]] = []
    next_link = f"https://graph.windows.net/{tenant_id}/users?api-version=1.6"
    page = 1

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    retry_count = 0
    max_retries = 3

    while next_link:
        console.print(f"[dim]Fetching users (page {page})...[/dim]")

        try:
            response = requests.get(next_link, headers=headers, timeout=60)
            response.raise_for_status()

            data = response.json()
            page_users = data.get("value", [])
            all_users.extend(page_users)

            console.print(f"[dim]Page {page}: {len(page_users)} users[/dim]")

            # Check for next page (Azure AD Graph uses odata.nextLink)
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
                console.print("[red]Permission denied. Insufficient privileges to list users.[/red]")
                console.print("[yellow]Required permission: User.Read.All or Directory.Read.All[/yellow]")
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

    if not all_users:
        console.print("[yellow]No users found.[/yellow]")
        return

    console.print(f"\n[green]Found {len(all_users)} user(s).[/green]\n")

    # Save enumeration data
    session_mgr.save_enumeration_data("users_legacy", all_users)

    # Display users in a table
    table = Table(title=f"Entra ID Users (Legacy API) - {len(all_users)} found")
    table.add_column("Display Name", style="cyan")
    table.add_column("User Principal Name", style="green")
    table.add_column("Object ID", style="dim")
    table.add_column("Account Enabled", style="yellow")
    table.add_column("User Type", style="magenta")

    for user in all_users[:100]:  # Limit display to 100
        display_name = user.get("displayName", "N/A")
        upn = user.get("userPrincipalName", "N/A")
        object_id = user.get("objectId", "N/A")
        account_enabled = "Yes" if user.get("accountEnabled") else "No"
        user_type = user.get("userType", "N/A")

        table.add_row(
            display_name,
            upn,
            object_id,
            account_enabled,
            user_type
        )

    console.print(table)

    if len(all_users) > 100:
        console.print(f"\n[dim]... and {len(all_users) - 100} more users (showing first 100)[/dim]")

    console.print(f"\n[dim]Saved as 'users_legacy' in enumeration data[/dim]")
