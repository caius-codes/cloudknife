# src/clouds/azure/modules/enumeration/graph_enumerate_teams.py

import json
import requests
from datetime import datetime
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...azure_session import AzureSessionManager
from ...utils.graph_helpers import (
    paginated_graph_request,
    graph_api_call,
    check_token_scopes
)

console = Console()

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"


def enumerate_teams(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate Microsoft Teams, channels, and messages using Graph API.

    Workflow:
    1. Search messages by keyword (like GraphRunner Invoke-SearchTeams)
    2. OR browse: list joined teams → channels → messages

    Requires: Team.ReadBasic.All, ChannelMessage.Read.All
    """
    console.print("[cyan]Microsoft Graph - Teams Enumeration[/cyan]")

    # Get access token
    access_token = session_mgr.get_access_token(scope="graph")
    if not access_token:
        console.print("[red]No Graph API access token available. Please authenticate first.[/red]")
        return

    # Check token scopes
    check_token_scopes(access_token, ["Team.ReadBasic.All", "ChannelMessage.Read.All"])

    # Choose mode
    console.print("\n[dim]Select mode:[/dim]")
    console.print("  [bold]1[/bold]  Search messages by keyword  [dim](like GraphRunner Invoke-SearchTeams)[/dim]")
    console.print("  [bold]2[/bold]  Browse teams → channels → messages")
    mode = Prompt.ask("Mode", choices=["1", "2"], default="1")

    if mode == "1":
        _search_teams_messages(access_token, session_mgr)
        return

    # Step 1: List joined teams
    console.print("\n[cyan]Fetching joined teams...[/cyan]")
    teams = _list_joined_teams(access_token, session_mgr)

    # teams is None if there was an API error (403, 404, etc.)
    # teams is [] if the API succeeded but returned no teams
    if teams is None:
        console.print("[red]Failed to fetch teams due to an error (see above).[/red]")
        return

    if not teams:
        console.print("[yellow]No teams found.[/yellow]")
        console.print("[dim]This user is not a member of any Teams.[/dim]")
        return

    console.print(f"[green]Found {len(teams)} team(s).[/green]")
    _display_teams(teams)

    # Ask if user wants to enumerate channels
    if not Confirm.ask("\n[cyan]Enumerate channels for a team?[/cyan]", default=True):
        return

    # Step 2: Select team and list channels
    team_id = Prompt.ask("\n[cyan]Enter Team ID").strip()

    selected_team = None
    for team in teams:
        if team.get("id") == team_id:
            selected_team = team
            break

    if not selected_team:
        console.print(f"[yellow]Team with ID '{team_id}' not found in list. Trying anyway...[/yellow]")
        selected_team = {"id": team_id, "displayName": "Unknown Team"}

    team_name = selected_team.get("displayName", "Unknown")
    console.print(f"\n[cyan]Enumerating channels in team:[/cyan] {team_name}")

    channels = _list_team_channels(access_token, team_id, team_name, session_mgr)

    if not channels:
        console.print(f"[yellow]No channels found in {team_name}.[/yellow]")
        return

    console.print(f"[green]Found {len(channels)} channel(s).[/green]")
    _display_channels(channels, team_name)

    # Ask if user wants to view messages
    if not Confirm.ask("\n[cyan]View messages in a channel?[/cyan]", default=True):
        return

    # Step 3: Select channel and list messages
    channel_id = Prompt.ask("\n[cyan]Enter Channel ID").strip()

    selected_channel = None
    for channel in channels:
        if channel.get("id") == channel_id:
            selected_channel = channel
            break

    if not selected_channel:
        console.print(f"[yellow]Channel with ID '{channel_id}' not found in list. Trying anyway...[/yellow]")
        selected_channel = {"id": channel_id, "displayName": "Unknown Channel"}

    channel_name = selected_channel.get("displayName", "Unknown")
    console.print(f"\n[cyan]Enumerating messages in channel:[/cyan] {channel_name}")

    messages = _list_channel_messages(access_token, team_id, channel_id, team_name, channel_name, session_mgr)

    if not messages:
        console.print(f"[yellow]No messages found in {channel_name}.[/yellow]")
        console.print()
        console.print("[dim]Tip: Reading channel messages via Graph API requires the[/dim]")
        console.print("[dim]     ChannelMessage.Read.All scope (requires admin consent).[/dim]")
        console.print("[yellow]Use 'get_teams_token' + 'teams_messages' to read messages[/yellow]")
        console.print("[yellow]via the native Teams API, which bypasses this requirement.[/yellow]")
        return

    console.print(f"[green]Found {len(messages)} message(s).[/green]")
    _display_messages(messages, team_name, channel_name)

    # Offer to download
    if Confirm.ask("\n[cyan]Download full conversation to JSON?[/cyan]", default=False):
        _download_conversation(access_token, team_id, channel_id, messages, team_name, channel_name, session_mgr)


def _search_teams_messages(access_token: str, session_mgr: AzureSessionManager) -> None:
    """
    Search Teams messages by keyword using the Microsoft Search API.

    Replicates GraphRunner's Invoke-SearchTeams.
    Uses POST /v1.0/search/query with entityTypes: ["chatMessage"].

    Requires: ChannelMessage.Read.All or Chat.Read
    """
    search_term = Prompt.ask("[cyan]Search term (e.g. password, vpn, credentials)[/cyan]").strip()
    if not search_term:
        console.print("[red]Search term cannot be empty.[/red]")
        return

    page_size = 25
    from_offset = 0
    all_hits: List[Dict[str, Any]] = []

    console.print(f"\n[cyan]Searching Teams messages for:[/cyan] {search_term}")
    console.print("[dim]Note: requires a Graph token (get_graph_token), not a Teams native token (get_teams_token).[/dim]")

    while True:
        body = {
            "requests": [
                {
                    "entityTypes": ["chatMessage"],
                    "query": {"queryString": search_term},
                    "from": from_offset,
                    "size": page_size,
                    "fields": [
                        "id", "body", "subject", "summary",
                        "from", "createdDateTime", "lastModifiedDateTime",
                        "webUrl", "channelIdentity", "chatId", "importance"
                    ],
                }
            ]
        }

        try:
            response = requests.post(
                f"{GRAPH_ENDPOINT}/search/query",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=30,
            )

            if response.status_code in (401, 403):
                try:
                    err = response.json()
                    err_code = err.get("error", {}).get("code", "")
                    err_msg = err.get("error", {}).get("message", response.text[:300])
                except Exception:
                    err_code = ""
                    err_msg = response.text[:300]

                if response.status_code == 401:
                    console.print(f"[red]Unauthorized (401): {err_msg}[/red]")
                    console.print("[yellow]Token is expired or has the wrong audience.[/yellow]")
                    console.print("[dim]Teams search requires a Graph token (get_graph_token), not a Teams native token (get_teams_token).[/dim]")
                else:
                    console.print(f"[red]Permission denied (403):[/red] {err_code} — {err_msg}")
                    console.print()
                    console.print("[yellow]Note: Teams message search via Graph requires a Graph API token.[/yellow]")
                    console.print("[dim]  • Use 'get_graph_token' (ROPC), NOT 'get_teams_token'[/dim]")
                    console.print("[dim]  • ChannelMessage.Read.All requires admin consent[/dim]")
                    console.print("[dim]  • Chat.Read covers personal/group chats (no admin consent needed)[/dim]")
                    console.print("[dim]  • If you're using the right token, the tenant may restrict search[/dim]")
                return
            if response.status_code != 200:
                console.print(f"[red]Search API error {response.status_code}: {response.text[:300]}[/red]")
                return

            data = response.json()
            value = data.get("value", [])
            if not value:
                break

            hits_container = value[0].get("hitsContainers", [])
            if not hits_container:
                break

            container = hits_container[0]
            hits = container.get("hits", [])
            total = container.get("total", 0)
            more_results = container.get("moreResultsAvailable", False)

            if from_offset == 0:
                console.print(f"[green]Total results: {total}[/green]")

            for hit in hits:
                resource = hit.get("resource", {})
                # Attach summary/preview from hit if available
                resource["_summary"] = hit.get("summary", "")
                all_hits.append(resource)

            console.print(f"[dim]Fetched {len(all_hits)}/{total} results...[/dim]")

            if not more_results or len(all_hits) >= total:
                break

            from_offset += page_size

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Search request failed: {e}[/red]")
            return

    if not all_hits:
        console.print(f"[yellow]No messages found for '{search_term}'.[/yellow]")
        return

    console.print(f"[green]Found {len(all_hits)} message(s) for '{search_term}'.[/green]")

    # Save to session
    session_mgr.save_enumeration_data(
        f"teams_search_{search_term.replace(' ', '_').lower()[:30]}",
        all_hits
    )

    # Display results
    display_limit = 50
    to_display = all_hits[:display_limit]

    table = Table(title=f"Teams Search: '{search_term}' ({len(all_hits)} results)")
    table.add_column("From", style="cyan", overflow="fold", max_width=25)
    table.add_column("Preview / Summary", style="green", overflow="fold", max_width=55)
    table.add_column("Team / Channel", style="yellow", overflow="fold", max_width=30)
    table.add_column("Date", style="dim", max_width=17)

    for msg in to_display:
        # Sender
        from_data = msg.get("from", {})
        from_user = from_data.get("user", {}) if from_data else {}
        sender = from_user.get("displayName", "") if from_user else ""

        # Preview: prefer _summary (hit highlight), then body
        summary = msg.get("_summary", "").strip()
        if not summary:
            body = msg.get("body", {})
            content = body.get("content", "") if body else ""
            import re
            content = re.sub(r"<[^>]+>", "", content)
            summary = content[:120] + ("..." if len(content) > 120 else "")

        # Team / Channel context
        channel_identity = msg.get("channelIdentity", {})
        if channel_identity:
            team_id = channel_identity.get("teamId", "")
            channel_id = channel_identity.get("channelId", "")
            location = f"team:{team_id[:8]}... ch:{channel_id[:8]}..." if team_id else ""
        else:
            chat_id = msg.get("chatId", "")
            location = f"chat:{chat_id[:16]}..." if chat_id else ""

        # Date
        created_str = msg.get("createdDateTime", "")
        if created_str:
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except Exception:
                created = created_str[:16]
        else:
            created = ""

        table.add_row(sender, summary, location, created)

    console.print(table)

    if len(all_hits) > display_limit:
        console.print(f"[dim]... and {len(all_hits) - display_limit} more result(s)[/dim]")

    # Offer to save full results to JSON
    if Confirm.ask("\n[cyan]Save full results to JSON?[/cyan]", default=False):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_term = search_term.replace(" ", "_").replace("/", "_")[:30]
        filename = f"teams_search_{safe_term}_{timestamp}.json"
        exfil_dir = session_mgr.get_exfil_dir("teams")
        file_path = exfil_dir / filename
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(all_hits, f, indent=2, ensure_ascii=False)
            console.print(f"[green]Saved {len(all_hits)} result(s) to:[/green] {file_path}")
        except Exception as e:
            console.print(f"[red]Failed to save: {e}[/red]")


def _list_joined_teams(access_token: str, session_mgr: AzureSessionManager) -> List[Dict[str, Any]]:
    """List all teams the user has joined."""
    url = f"{GRAPH_ENDPOINT}/me/joinedTeams"

    teams = paginated_graph_request(access_token, url)

    # Save to session data
    if teams:
        session_mgr.save_enumeration_data("teams_joined", teams)

    return teams


def _display_teams(teams: List[Dict[str, Any]]) -> None:
    """Display teams in a table."""
    table = Table(title=f"Joined Teams ({len(teams)} found)")
    table.add_column("Display Name", style="cyan", overflow="fold", max_width=40)
    table.add_column("ID", style="dim", overflow="fold")
    table.add_column("Description", style="yellow", overflow="fold", max_width=50)
    table.add_column("Visibility", style="magenta")

    for team in teams:
        display_name = team.get("displayName", "")
        team_id = team.get("id", "")
        description = team.get("description", "")[:100] if team.get("description") else ""
        visibility = team.get("visibility", "")

        table.add_row(display_name, team_id, description, visibility)

    console.print(table)


def _list_team_channels(
    access_token: str,
    team_id: str,
    team_name: str,
    session_mgr: AzureSessionManager
) -> List[Dict[str, Any]]:
    """List all channels in a team."""
    url = f"{GRAPH_ENDPOINT}/teams/{team_id}/channels"

    channels = paginated_graph_request(access_token, url)

    # Save to session data
    if channels:
        session_mgr.save_enumeration_data(f"teams_{team_id}_channels", channels)

    return channels


def _display_channels(channels: List[Dict[str, Any]], team_name: str) -> None:
    """Display channels in a table."""
    table = Table(title=f"Channels in {team_name} ({len(channels)} found)")
    table.add_column("Display Name", style="cyan", overflow="fold", max_width=40)
    table.add_column("ID", style="dim", overflow="fold")
    table.add_column("Description", style="yellow", overflow="fold", max_width=50)
    table.add_column("Membership Type", style="magenta")

    for channel in channels:
        display_name = channel.get("displayName", "")
        channel_id = channel.get("id", "")
        description = channel.get("description", "")[:100] if channel.get("description") else ""
        membership_type = channel.get("membershipType", "")

        table.add_row(display_name, channel_id, description, membership_type)

    console.print(table)


def _list_channel_messages(
    access_token: str,
    team_id: str,
    channel_id: str,
    team_name: str,
    channel_name: str,
    session_mgr: AzureSessionManager
) -> List[Dict[str, Any]]:
    """List messages in a channel."""
    url = f"{GRAPH_ENDPOINT}/teams/{team_id}/channels/{channel_id}/messages"

    # Select specific fields to reduce payload
    url += "?$select=id,createdDateTime,lastModifiedDateTime,subject,body,from,importance"
    url += "&$top=50"  # 50 messages per page

    messages = paginated_graph_request(access_token, url, limit=500)  # Limit to 500 messages

    # Save to session data
    if messages:
        session_mgr.save_enumeration_data(f"teams_{team_id}_channel_{channel_id}_messages", messages)

    return messages


def _display_messages(messages: List[Dict[str, Any]], team_name: str, channel_name: str) -> None:
    """Display messages in a table."""
    # Limit display to first 30 messages
    display_limit = 30
    messages_to_display = messages[:display_limit]

    table = Table(title=f"Messages in {team_name} / {channel_name} (showing {len(messages_to_display)} of {len(messages)})")
    table.add_column("From", style="cyan", overflow="fold", max_width=25)
    table.add_column("Subject/Preview", style="green", overflow="fold", max_width=50)
    table.add_column("Created", style="yellow", max_width=18)
    table.add_column("Importance", style="magenta", justify="center")

    for msg in messages_to_display:
        # Extract sender
        from_data = msg.get("from", {})
        from_user = from_data.get("user", {}) if from_data else {}
        from_name = from_user.get("displayName", "Unknown") if from_user else "Unknown"

        # Subject or body preview
        subject = msg.get("subject", "")
        body = msg.get("body", {})
        body_content = body.get("content", "") if body else ""

        # Use subject if available, otherwise first 100 chars of body
        if subject:
            preview = subject
        else:
            # Strip HTML tags from body (simple approach)
            import re
            body_text = re.sub('<[^<]+?>', '', body_content)
            preview = body_text[:100] + "..." if len(body_text) > 100 else body_text

        # Parse created date
        created_str = msg.get("createdDateTime", "")
        if created_str:
            try:
                created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                created = created_dt.strftime("%Y-%m-%d %H:%M")
            except:
                created = created_str[:16]
        else:
            created = ""

        importance = msg.get("importance", "normal")

        table.add_row(from_name, preview, created, importance)

    console.print(table)

    if len(messages) > display_limit:
        console.print(f"[dim]... and {len(messages) - display_limit} more message(s)[/dim]")


def _download_conversation(
    access_token: str,
    team_id: str,
    channel_id: str,
    messages: List[Dict[str, Any]],
    team_name: str,
    channel_name: str,
    session_mgr: AzureSessionManager
) -> None:
    """
    Download full conversation including replies.

    Args:
        access_token: Graph API token
        team_id: Team ID
        channel_id: Channel ID
        messages: List of message summaries
        team_name: Team display name
        channel_name: Channel display name
        session_mgr: Session manager
    """
    console.print(f"\n[cyan]Downloading full conversation with replies...[/cyan]")

    full_messages = []

    for i, msg in enumerate(messages, 1):
        msg_id = msg.get("id")
        if not msg_id:
            continue

        console.print(f"[dim]Fetching message {i}/{len(messages)}...[/dim]")

        # Get full message details
        url = f"{GRAPH_ENDPOINT}/teams/{team_id}/channels/{channel_id}/messages/{msg_id}"
        full_msg = graph_api_call(access_token, "GET", url)

        if full_msg:
            # Get replies if this is a root message
            replies_url = f"{GRAPH_ENDPOINT}/teams/{team_id}/channels/{channel_id}/messages/{msg_id}/replies"
            replies_data = paginated_graph_request(access_token, replies_url)

            if replies_data:
                full_msg["replies"] = replies_data

            full_messages.append(full_msg)

    if not full_messages:
        console.print("[yellow]No messages could be downloaded.[/yellow]")
        return

    # Save to JSON file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_team_name = team_name.lower().replace(' ', '_').replace('/', '_')
    safe_channel_name = channel_name.lower().replace(' ', '_').replace('/', '_')
    filename = f"teams_{safe_team_name}_{safe_channel_name}_{timestamp}.json"

    exfil_dir = session_mgr.get_exfil_dir("teams")
    file_path = exfil_dir / filename

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(full_messages, f, indent=2, ensure_ascii=False)

        console.print(f"[green]Downloaded {len(full_messages)} message(s) with replies to:[/green] {file_path}")

        # Also save to session data
        session_mgr.save_enumeration_data(
            f"teams_{team_id}_channel_{channel_id}_full",
            full_messages
        )

    except Exception as e:
        console.print(f"[red]Failed to save conversation: {e}[/red]")
