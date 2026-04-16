# src/clouds/azure/modules/enumeration/enum_external_users.py

from typing import Any, Dict, List
import requests

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from ...azure_session import AzureSessionManager
from ...utils.error_handler import handle_azure_error

console = Console()

# Graph requires these headers for advanced ($filter on mail/otherMails,
# startswith, endswith, or userType) queries.
_ADVANCED_HEADERS = {
    "ConsistencyLevel": "eventual",
}


def enumerate_external_users(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate external/guest users via Microsoft Graph advanced filtering.

    Standard /v1.0/users does not return users filtered by mail prefix without
    ConsistencyLevel: eventual + $count=true. This module handles that correctly.

    Strategies:
      1. Filter by mail prefix (e.g. 'ext.') — finds member AND guest accounts
         whose primary mail starts with the prefix
      2. Filter by userType = Guest — finds all B2B guest accounts regardless
         of their mail format
    Results are merged (deduplicated by id) and displayed together.
    """

    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]Authentication required. Use one of the login commands first.[/red]")
        return

    mail_prefix = Prompt.ask(
        "[cyan]Mail prefix to search (e.g. 'ext.', 'ext-', leave empty to skip)[/cyan]",
        default="ext."
    ).strip()

    domain_filter = Prompt.ask(
        "[cyan]Restrict to domain (e.g. 'contoso.com', leave empty for any)[/cyan]",
        default=""
    ).strip().lower()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "ConsistencyLevel": "eventual",
    }

    seen_ids: set = set()
    all_users: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 1. Filter by mail prefix  (requires ConsistencyLevel + $count)
    # ------------------------------------------------------------------
    if mail_prefix:
        console.print(f"[cyan]Searching users with mail starting with '{mail_prefix}'...[/cyan]")
        users = _fetch_users_with_filter(
            headers=headers,
            odata_filter=f"startswith(mail,'{mail_prefix}')",
            label=f"mail prefix '{mail_prefix}'",
        )
        for u in users:
            uid = u.get("id")
            if uid and uid not in seen_ids:
                seen_ids.add(uid)
                all_users.append(u)

        # Also search userPrincipalName (member accounts with external-style UPN, e.g. ext.john@domain.com)
        console.print(f"[cyan]Searching users with UPN starting with '{mail_prefix}'...[/cyan]")
        users_upn = _fetch_users_with_filter(
            headers=headers,
            odata_filter=f"startswith(userPrincipalName,'{mail_prefix}')",
            label=f"UPN prefix '{mail_prefix}'",
        )
        for u in users_upn:
            uid = u.get("id")
            if uid and uid not in seen_ids:
                seen_ids.add(uid)
                all_users.append(u)

        # Also search otherMails (external accounts often store original mail there)
        console.print(f"[cyan]Searching users with otherMails starting with '{mail_prefix}'...[/cyan]")
        users2 = _fetch_users_with_filter(
            headers=headers,
            odata_filter=f"otherMails/any(m:startswith(m,'{mail_prefix}'))",
            label=f"otherMails prefix '{mail_prefix}'",
        )
        for u in users2:
            uid = u.get("id")
            if uid and uid not in seen_ids:
                seen_ids.add(uid)
                all_users.append(u)

    # ------------------------------------------------------------------
    # 2. All Guest accounts (userType eq 'Guest')
    # ------------------------------------------------------------------
    console.print("[cyan]Searching guest accounts (userType = Guest)...[/cyan]")
    guests = _fetch_users_with_filter(
        headers=headers,
        odata_filter="userType eq 'Guest'",
        label="guest accounts",
    )
    for u in guests:
        uid = u.get("id")
        if uid and uid not in seen_ids:
            seen_ids.add(uid)
            all_users.append(u)

    # ------------------------------------------------------------------
    # 3. Optional domain filter (client-side, after collection)
    # ------------------------------------------------------------------
    if domain_filter:
        def _matches_domain(u: Dict[str, Any]) -> bool:
            mail = (u.get("mail") or "").lower()
            upn = (u.get("userPrincipalName") or "").lower()
            other = [m.lower() for m in (u.get("otherMails") or [])]
            return (
                mail.endswith(f"@{domain_filter}")
                or upn.endswith(f"@{domain_filter}")
                or any(m.endswith(f"@{domain_filter}") for m in other)
            )

        before = len(all_users)
        all_users = [u for u in all_users if _matches_domain(u)]
        console.print(
            f"[dim]Domain filter '@{domain_filter}': {before} → {len(all_users)} user(s)[/dim]"
        )

    if not all_users:
        console.print("[yellow]No external users found with the given criteria.[/yellow]")
        return

    console.print(f"[green]Total external users found: {len(all_users)}[/green]")

    # Save in session
    session_mgr.save_enumeration_data("external_users", all_users)

    # Display
    table = Table(
        title=f"External / Guest Users ({len(all_users)} found)",
        show_lines=False,
    )
    table.add_column("DisplayName", style="cyan")
    table.add_column("Mail", style="yellow")
    table.add_column("UPN", style="magenta")
    table.add_column("Type", style="green")
    table.add_column("OtherMails", style="dim")

    for u in all_users:
        other = ", ".join(u.get("otherMails") or [])
        table.add_row(
            u.get("displayName") or "",
            u.get("mail") or "",
            u.get("userPrincipalName") or "",
            u.get("userType") or "",
            other,
        )

    console.print(table)
    console.print("[dim]Saved as 'external_users' in this session's enumeration data.[/dim]")
    console.print(f"[green]Enumerated {len(all_users)} external/guest user(s).[/green]")


def _fetch_users_with_filter(
    headers: Dict[str, str],
    odata_filter: str,
    label: str,
) -> List[Dict[str, Any]]:
    """
    Paginate through /v1.0/users with the given OData $filter.
    Uses ConsistencyLevel: eventual + $count=true for advanced queries.
    Returns a flat list of user dicts.
    """
    select = "id,displayName,userPrincipalName,mail,otherMails,userType,jobTitle,department,accountEnabled"
    url = (
        f"https://graph.microsoft.com/v1.0/users"
        f"?$filter={requests.utils.quote(odata_filter, safe='')}"
        f"&$select={select}"
        f"&$count=true"
        f"&$top=999"
    )

    users: List[Dict[str, Any]] = []
    page = 1

    while url:
        try:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            page_users = data.get("value", [])
            users.extend(page_users)
            console.print(f"[dim]{label} — page {page}: {len(page_users)} user(s)[/dim]")
            url = data.get("@odata.nextLink")
            page += 1

        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            if status == 400:
                # Filter not supported — log and skip silently
                console.print(f"[dim]{label}: filter not supported ({e.response.text[:120]})[/dim]")
            elif status == 403:
                console.print(f"[yellow]{label}: permission denied (need User.Read.All or Directory.Read.All)[/yellow]")
            else:
                console.print(f"[yellow]{label}: HTTP {status} — {e}[/yellow]")
            break

        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]{label}: network error — {e}[/yellow]")
            break

    return users
