# src/clouds/azure/modules/enumeration/enum_group_members.py

import subprocess
import json
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from ...azure_session import AzureSessionManager
from ...utils.graph_helpers import paginated_graph_request

console = Console()

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"

_UUID_CHARS = set("0123456789abcdefABCDEF-")


def _looks_like_uuid(value: str) -> bool:
    return len(value) == 36 and all(c in _UUID_CHARS for c in value)


def _resolve_group_id(access_token: str, name_or_id: str) -> Optional[str]:
    """
    If name_or_id is already a UUID, return it directly.
    Otherwise search by displayName and let the user pick if there are multiple matches.
    """
    if _looks_like_uuid(name_or_id):
        return name_or_id

    # Search by displayName (exact match first, then startsWith)
    headers = {"Authorization": f"Bearer {access_token}"}
    search_url = (
        f"{GRAPH_ENDPOINT}/groups"
        f"?$filter=displayName eq '{name_or_id}'"
        f"&$select=id,displayName,description,mail"
        f"&$top=10"
    )
    try:
        response = requests.get(search_url, headers=headers, timeout=30)
        if response.status_code == 200:
            groups = response.json().get("value", [])
        elif response.status_code == 400:
            # $filter may require ConsistencyLevel: eventual
            response2 = requests.get(
                search_url,
                headers={**headers, "ConsistencyLevel": "eventual"},
                timeout=30,
            )
            groups = response2.json().get("value", []) if response2.status_code == 200 else []
        else:
            groups = []
    except Exception as e:
        console.print(f"[red]Group search failed: {e}[/red]")
        return None

    if not groups:
        console.print(f"[yellow]No group found with displayName '{name_or_id}'.[/yellow]")
        return None

    if len(groups) == 1:
        g = groups[0]
        console.print(f"[green]Resolved group:[/green] {g.get('displayName')} ({g.get('id')})")
        return g["id"]

    # Multiple matches — show table and ask user to pick
    console.print(f"[yellow]Multiple groups found matching '{name_or_id}':[/yellow]")
    table = Table(show_header=True)
    table.add_column("#", style="dim")
    table.add_column("Display Name", style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Mail")
    for i, g in enumerate(groups, 1):
        table.add_row(str(i), g.get("displayName", ""), g.get("id", ""), g.get("mail") or "")
    console.print(table)

    choices = [str(i) for i in range(1, len(groups) + 1)]
    pick = Prompt.ask("[cyan]Select group number[/cyan]", choices=choices)
    selected = groups[int(pick) - 1]
    return selected["id"]


def _get_members_via_graph(access_token: str, group_id: str) -> Optional[List[Dict[str, Any]]]:
    """Fetch group members with full pagination via Graph API."""
    url = (
        f"{GRAPH_ENDPOINT}/groups/{group_id}/members"
        f"?$select=id,displayName,userPrincipalName,jobTitle,mail,userType"
    )
    members = paginated_graph_request(access_token, url)
    return members if members is not None else None


def _get_members_via_cli(group_id: str) -> Optional[List[Dict[str, Any]]]:
    """Fallback: fetch group members via az CLI."""
    try:
        result = subprocess.run(
            ["az", "ad", "group", "member", "list", "--group", group_id, "--output", "json"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            console.print(f"[red]az CLI error: {result.stderr.strip()}[/red]")
            return None
        return json.loads(result.stdout)
    except FileNotFoundError:
        console.print("[red]az CLI not found.[/red]")
        return None
    except Exception as e:
        console.print(f"[red]az CLI fallback failed: {e}[/red]")
        return None


def enumerate_group_members(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate members of an Entra ID group.

    Accepts either an objectId (UUID) or a display name.
    Uses Graph API with az CLI fallback.
    """
    name_or_id = Prompt.ask("[cyan]Group name or objectId[/cyan]").strip()
    if not name_or_id:
        console.print("[red]Group not specified.[/red]")
        return

    access_token = session_mgr.get_access_token(scope="graph")

    group_id: Optional[str] = None
    members: Optional[List[Dict[str, Any]]] = None

    if access_token:
        # Step 1: resolve name → UUID if needed
        group_id = _resolve_group_id(access_token, name_or_id)
        if not group_id:
            console.print("[yellow]Could not resolve group. Trying az CLI fallback...[/yellow]")
            members = _get_members_via_cli(name_or_id)
            group_id = name_or_id
        else:
            # Step 2: fetch members via Graph API
            console.print(f"[cyan]Enumerating members of group: {group_id}[/cyan]")
            members = _get_members_via_graph(access_token, group_id)

            if members is None:
                console.print("[yellow]Graph API failed. Falling back to az CLI...[/yellow]")
                members = _get_members_via_cli(group_id)
    else:
        # No graph token — go straight to az CLI
        console.print("[yellow]No Graph token available. Using az CLI...[/yellow]")
        group_id = name_or_id
        members = _get_members_via_cli(name_or_id)

    if not members:
        console.print("[yellow]No members found (or group is empty / access denied).[/yellow]")
        return

    console.print(f"[green]Found {len(members)} member(s).[/green]")

    # Save in session
    key = f"group_members:{group_id}"
    session_mgr.save_enumeration_data(key, members)

    # Display results
    table = Table(
        title=f"Members of group: {name_or_id} ({len(members)} found)",
        show_lines=False,
    )
    table.add_column("Display Name", style="cyan")
    table.add_column("UPN / Mail", style="magenta")
    table.add_column("Job Title", style="green")
    table.add_column("Type", style="dim")

    for m in members:
        display_name = m.get("displayName") or ""
        upn = m.get("userPrincipalName") or m.get("mail") or ""
        job = m.get("jobTitle") or ""
        user_type = m.get("userType") or m.get("@odata.type", "").split(".")[-1]
        table.add_row(display_name, upn, job, user_type)

    console.print(table)
    console.print(f"[dim]Saved as '{key}' in this session's enumeration data.[/dim]")
